# WAF 反向代理

**文件**: `waf/waf_proxy.py`

WAF 代理是一个独立的 FastAPI 服务，在 HTTP 流量转发路径上执行**双重威胁检测**（规则引擎 + ET-BERT），并将告警写入日志文件供主智能体消费。

---

## 1. 架构位置

```svg
<svg viewBox="0 0 720 280" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="720" height="280" fill="#0f1117" rx="10"/>
  <text x="360" y="28" text-anchor="middle" font-size="15" font-weight="bold" fill="#e2e8f0">WAF 代理流量处理流程</text>

  <defs>
    <marker id="waf" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#60a5fa"/>
    </marker>
    <marker id="waf2" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#f87171"/>
    </marker>
    <marker id="waf3" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#6ee7b7"/>
    </marker>
  </defs>

  <!-- 客户端 -->
  <rect x="20" y="110" width="100" height="44" rx="6" fill="#1e293b" stroke="#475569" stroke-width="1.5"/>
  <text x="70" y="130" text-anchor="middle" font-size="11" fill="#94a3b8" font-weight="bold">HTTP 客户端</text>
  <text x="70" y="145" text-anchor="middle" font-size="10" fill="#64748b">攻击者 / 用户</text>

  <!-- WAF 代理 -->
  <rect x="155" y="70" width="200" height="125" rx="8" fill="#1e3a5f" stroke="#3b82f6" stroke-width="2"/>
  <text x="255" y="92" text-anchor="middle" font-size="13" fill="#93c5fd" font-weight="bold">FastAPI WAF 代理</text>
  <text x="255" y="110" text-anchor="middle" font-size="10" fill="#60a5fa">:9090</text>

  <rect x="170" y="118" width="170" height="22" rx="4" fill="#1e40af" stroke="none"/>
  <text x="255" y="133" text-anchor="middle" font-size="10" fill="#bfdbfe">① 规则引擎检测</text>
  <rect x="170" y="144" width="170" height="22" rx="4" fill="#1e40af" stroke="none"/>
  <text x="255" y="159" text-anchor="middle" font-size="10" fill="#bfdbfe">② ET-BERT ONNX 推理</text>
  <rect x="170" y="170" width="170" height="18" rx="4" fill="#1e40af" stroke="none"/>
  <text x="255" y="183" text-anchor="middle" font-size="10" fill="#bfdbfe">③ 写 waf_alerts.log</text>

  <!-- 后端应用 -->
  <rect x="400" y="110" width="130" height="44" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="465" y="130" text-anchor="middle" font-size="11" fill="#6ee7b7" font-weight="bold">后端应用</text>
  <text x="465" y="145" text-anchor="middle" font-size="10" fill="#34d399">BACKEND_URL</text>

  <!-- WAFLogMonitor -->
  <rect x="400" y="200" width="160" height="55" rx="6" fill="#2e1065" stroke="#a855f7" stroke-width="1.5"/>
  <text x="480" y="222" text-anchor="middle" font-size="11" fill="#d8b4fe" font-weight="bold">WAFLogMonitor</text>
  <text x="480" y="238" text-anchor="middle" font-size="10" fill="#c084fc">tail -F 实时读取</text>
  <text x="480" y="253" text-anchor="middle" font-size="10" fill="#c084fc">→ LangGraph 告警</text>

  <!-- 箭头 -->
  <line x1="120" y1="132" x2="153" y2="132" stroke="#3b82f6" stroke-width="2" marker-end="url(#waf)"/>
  <line x1="355" y1="132" x2="398" y2="132" stroke="#6ee7b7" stroke-width="2" marker-end="url(#waf3)"/>
  <text x="377" y="125" text-anchor="middle" font-size="9" fill="#6ee7b7">正常转发</text>
  <line x1="255" y1="195" x2="440" y2="198" stroke="#a855f7" stroke-width="1.5" stroke-dasharray="4,2" marker-end="url(#waf)"/>
  <text x="340" y="192" text-anchor="middle" font-size="9" fill="#f87171">威胁写日志</text>

  <!-- 被拦截 -->
  <rect x="560" y="55" width="140" height="44" rx="6" fill="#450a0a" stroke="#ef4444" stroke-width="1.5"/>
  <text x="630" y="74" text-anchor="middle" font-size="11" fill="#fca5a5" font-weight="bold">HTTP 403</text>
  <text x="630" y="89" text-anchor="middle" font-size="10" fill="#f87171">威胁请求被拦截</text>

  <line x1="355" y1="110" x2="558" y2="77" stroke="#ef4444" stroke-width="1.5" stroke-dasharray="4,2" marker-end="url(#waf2)"/>
  <text x="465" y="88" text-anchor="middle" font-size="9" fill="#f87171">score&gt;0.8 拦截</text>
</svg>
```

---

## 2. 双重检测机制

### 2.1 规则引擎（签名匹配）

基于正则表达式匹配已知攻击模式：

| 规则类别 | 匹配模式示例 | 说明 |
|---------|------------|------|
| SQL 注入 | `SELECT.*FROM`, `UNION.*SELECT`, `' OR '1'='1` | 数据库注入 |
| XSS | `<script>`, `javascript:`, `onerror=` | 跨站脚本 |
| 路径遍历 | `../`, `..\\`, `/etc/passwd` | 目录穿越 |
| 命令注入 | `; cat /etc/`, `| id`, `&& wget` | OS 命令注入 |
| Log4Shell | `${jndi:ldap://`, `${jndi:rmi://` | Log4j RCE |
| 扫描探测 | `sqlmap`, `nmap`, `nikto`, `masscan` | 扫描工具 UA |

### 2.2 ET-BERT 在线推理

```python
def _onnx_score(self, text: str) -> float:
    """字节级分词 + ONNX 推理，返回威胁概率"""
    tokens = [ord(c) + 3 for c in text[:510]]
    input_ids = [1] + tokens + [2] + [0] * (512 - len(tokens) - 2)
    attention_mask = [1] * (len(tokens) + 2) + [0] * (512 - len(tokens) - 2)

    result = self.session.run(None, {
        "input_ids": np.array([input_ids], dtype=np.int64),
        "attention_mask": np.array([attention_mask], dtype=np.int64)
    })
    return float(sigmoid(result[0][0]))
```

---

## 3. 告警日志格式

WAF 将威胁写入 `waf_alerts.log`，每行一个 JSON：

```json
{
  "timestamp": "2024-01-15T10:23:45.123Z",
  "client_ip": "10.0.0.5",
  "method": "POST",
  "path": "/api/login",
  "rule_match": "SQL Injection",
  "onnx_score": 0.94,
  "action": "block",
  "payload_snippet": "' OR '1'='1' --"
}
```

`WAFLogMonitor` 通过 `tail -f` 方式实时读取此日志，触发 LangGraph 工作流。

---

## 4. 启动方式

```bash
cd waf

# 开发模式（自动重载）
uvicorn waf_proxy:app --host 0.0.0.0 --port 9090 --reload

# 生产模式
uvicorn waf_proxy:app --host 0.0.0.0 --port 9090 --workers 4
```

**Nginx 集成示例**:

```nginx
location / {
    proxy_pass http://127.0.0.1:9090;  # WAF 代理
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```
