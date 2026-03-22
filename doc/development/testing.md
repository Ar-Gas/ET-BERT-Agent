# 测试指南

---

## 1. 测试体系概览

```svg
<svg viewBox="0 0 700 300" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="700" height="300" fill="#0f1117" rx="10"/>
  <text x="350" y="28" text-anchor="middle" font-size="15" font-weight="bold" fill="#e2e8f0">测试层级</text>

  <defs>
    <marker id="ta" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#6ee7b7"/>
    </marker>
  </defs>

  <!-- 单元测试 -->
  <rect x="30" y="55" width="190" height="105" rx="8" fill="#064e3b" stroke="#10b981" stroke-width="2"/>
  <text x="125" y="78" text-anchor="middle" font-size="13" fill="#6ee7b7" font-weight="bold">单元测试</text>
  <text x="125" y="97" text-anchor="middle" font-size="10" fill="#34d399">test_unit.py</text>
  <rect x="45" y="106" width="160" height="20" rx="3" fill="#0d3320" stroke="none"/>
  <text x="125" y="120" text-anchor="middle" font-size="10" fill="#6ee7b7">AlertDedup 去重逻辑</text>
  <rect x="45" y="130" width="160" height="20" rx="3" fill="#0d3320" stroke="none"/>
  <text x="125" y="144" text-anchor="middle" font-size="10" fill="#6ee7b7">IncidentLogger 文件创建</text>
  <text x="125" y="155" text-anchor="middle" font-size="9" fill="#64748b">不依赖 C++ 二进制</text>

  <!-- 集成测试 -->
  <rect x="255" y="55" width="190" height="105" rx="8" fill="#451a03" stroke="#f59e0b" stroke-width="2"/>
  <text x="350" y="78" text-anchor="middle" font-size="13" fill="#fcd34d" font-weight="bold">集成测试</text>
  <text x="350" y="97" text-anchor="middle" font-size="10" fill="#fbbf24">test_integration.py</text>
  <rect x="270" y="106" width="160" height="20" rx="3" fill="#1a0a00" stroke="none"/>
  <text x="350" y="120" text-anchor="middle" font-size="10" fill="#fcd34d">MCP HTTP 工具调用</text>
  <rect x="270" y="130" width="160" height="20" rx="3" fill="#1a0a00" stroke="none"/>
  <text x="350" y="144" text-anchor="middle" font-size="10" fill="#fcd34d">/proc 真实解析</text>
  <text x="350" y="155" text-anchor="middle" font-size="9" fill="#64748b">需要 C++ 二进制</text>

  <!-- 攻击模拟 -->
  <rect x="480" y="55" width="190" height="105" rx="8" fill="#2e1065" stroke="#a855f7" stroke-width="2"/>
  <text x="575" y="78" text-anchor="middle" font-size="13" fill="#d8b4fe" font-weight="bold">攻击模拟</text>
  <text x="575" y="97" text-anchor="middle" font-size="10" fill="#c084fc">run_attack_test.py</text>
  <rect x="495" y="106" width="160" height="20" rx="3" fill="#1a0040" stroke="none"/>
  <text x="575" y="120" text-anchor="middle" font-size="10" fill="#d8b4fe">模拟挖矿/扫描流量</text>
  <rect x="495" y="130" width="160" height="20" rx="3" fill="#1a0040" stroke="none"/>
  <text x="575" y="144" text-anchor="middle" font-size="10" fill="#d8b4fe">端到端封锁验证</text>
  <text x="575" y="155" text-anchor="middle" font-size="9" fill="#64748b">需要 root + 完整系统</text>

  <!-- 依赖关系 -->
  <text x="350" y="200" text-anchor="middle" font-size="11" fill="#475569">运行顺序</text>
  <rect x="60" y="215" width="100" height="30" rx="5" fill="#1e293b" stroke="#64748b" stroke-width="1"/>
  <text x="110" y="234" text-anchor="middle" font-size="10" fill="#94a3b8">单元测试</text>
  <line x1="160" y1="230" x2="198" y2="230" stroke="#64748b" stroke-width="1.5" marker-end="url(#ta)"/>
  <rect x="200" y="215" width="100" height="30" rx="5" fill="#1e293b" stroke="#64748b" stroke-width="1"/>
  <text x="250" y="234" text-anchor="middle" font-size="10" fill="#94a3b8">集成测试</text>
  <line x1="300" y1="230" x2="338" y2="230" stroke="#64748b" stroke-width="1.5" marker-end="url(#ta)"/>
  <rect x="340" y="215" width="100" height="30" rx="5" fill="#1e293b" stroke="#64748b" stroke-width="1"/>
  <text x="390" y="234" text-anchor="middle" font-size="10" fill="#94a3b8">攻击模拟</text>
  <line x1="440" y1="230" x2="478" y2="230" stroke="#64748b" stroke-width="1.5" marker-end="url(#ta)"/>
  <rect x="480" y="215" width="120" height="30" rx="5" fill="#064e3b" stroke="#10b981" stroke-width="1"/>
  <text x="540" y="234" text-anchor="middle" font-size="10" fill="#6ee7b7">生产部署</text>
</svg>
```

---

## 2. 单元测试

**文件**: `scripts/tests/test_unit.py`

无需 C++ 二进制，纯 Python 逻辑测试：

```bash
cd scripts
python3 -m pytest tests/test_unit.py -v
```

### 测试用例

| 测试类 | 测试方法 | 验证内容 |
|-------|---------|---------|
| `TestAlertDedup` | `test_first_alert_passes` | 首次告警通过 |
| `TestAlertDedup` | `test_duplicate_within_window` | 60s内重复被过滤 |
| `TestAlertDedup` | `test_alert_after_window_expires` | 窗口过期后重新通过 |
| `TestAlertDedup` | `test_thread_safety` | 并发调用线程安全 |
| `TestIncidentLogger` | `test_create_incident_file` | JSON 文件按IP命名创建 |
| `TestIncidentLogger` | `test_file_content_structure` | 文件内容字段完整 |
| `TestWAFLogMonitor` | `test_log_parsing` | WAF 日志 JSON 解析 |

---

## 3. 集成测试

**文件**: `scripts/tests/test_integration.py`

需要 C++ 二进制已编译并在运行中：

```bash
# 先启动 C++ 探针（测试模式）
AEGIS_NO_DATAPLANE=1 LD_LIBRARY_PATH=third_party/onnxruntime/lib \
    ./build/aegis_agent &

# 运行集成测试
python3 -m pytest scripts/tests/test_integration.py -v
```

### 测试用例

| 测试方法 | 验证内容 | 预期结果 |
|---------|---------|---------|
| `test_mcp_tools_list` | `GET /message tools/list` | 返回3个工具 |
| `test_get_pid_by_connection` | 查询本地端口对应PID | 返回非空PID |
| `test_analyze_process_behavior` | 分析已知PID进程 | 返回 cmdline 字符串 |
| `test_block_malicious_ip` | 封锁测试IP | 返回 blocked 状态 |
| `test_mcp_server_health` | HTTP 响应码 | 200 OK |

---

## 4. WAF 测试

**文件**: `scripts/tests/test_waf.py`

```bash
# 启动 WAF 代理
cd waf && uvicorn waf_proxy:app --port 9090 &

# 运行 WAF 测试
python3 -m pytest scripts/tests/test_waf.py -v
```

---

## 5. 攻击模拟测试

**文件**: `doc/test_log/run_attack_test.py`

> 详细结果见 [attack_test_report.md](../test_log/attack_test_report.md)

```bash
# 需要 root 权限和完整系统运行
sudo python3 doc/test_log/run_attack_test.py
```

**模拟的攻击场景**:

| 场景 | 描述 | 预期检测时间 |
|------|------|------------|
| 挖矿木马 | `wget miner.sh \| bash` 流量特征 | < 5s |
| 端口扫描 | SYN 扫描包序列 | < 3s |
| SQL 注入 | WAF 层 HTTP payload | < 1s |
| Log4Shell | `${jndi:ldap://}` 利用 | < 1s |
| C2 通信 | 周期性小包 beacon | < 10s |

---

## 6. 手动验证步骤

### 验证 MCP 工具可用

```bash
# 检查工具列表
curl -X POST http://localhost:8080/message \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# 手动调用 IP 封锁（测试IP）
curl -X POST http://localhost:8080/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "block_malicious_ip",
      "arguments": {"ip": "192.0.2.1"}
    }
  }'
```

### 验证 XDP 黑名单

```bash
# 查看 BPF map 内容（需要 bpftool）
sudo bpftool map show name aegis_blacklist
sudo bpftool map dump name aegis_blacklist

# 验证 iptables 规则
sudo iptables -L INPUT -n | grep 192.0.2.1
```

### 验证 AlertDedup

```bash
# 发送重复告警，验证第二次被过滤
python3 -c "
from scripts.multi_agent_soc import AlertDedup
d = AlertDedup(window_seconds=60)
print('第1次:', d.should_process('10.0.0.1'))  # True
print('第2次:', d.should_process('10.0.0.1'))  # False
print('不同IP:', d.should_process('10.0.0.2')) # True
"
```
