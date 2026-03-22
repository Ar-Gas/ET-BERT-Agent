# 配置参考

所有配置通过环境变量传递，推荐使用项目根目录的 `.env` 文件。

---

## C++ 数据平面配置

| 环境变量 | 默认值 | 说明 |
|---------|-------|------|
| `AEGIS_INTERFACE` | `ens33` | libpcap 监听的网络接口 |
| `AEGIS_MODEL` | `models/et_bert_dummy.onnx` | ET-BERT ONNX 模型路径 |
| `AEGIS_THRESHOLD` | `0.95` | 威胁评分阈值，超过则触发告警 |
| `AEGIS_MCP_PORT` | `8080` | MCP 服务器监听端口 |
| `AEGIS_XDP_OBJ` | （未设置） | 编译好的 BPF 对象文件路径 |
| `AEGIS_NO_DATAPLANE` | （未设置） | 设置任意值跳过数据平面线程（测试用） |
| `AEGIS_RATE_WINDOW` | `10` | 告警速率限制窗口（秒，预留） |
| `AEGIS_REQUIRE_APPROVAL` | `false` | 人工审批开关（预留） |
| `LD_LIBRARY_PATH` | 无默认 | **必须**包含 `third_party/onnxruntime/lib` |

---

## Python 控制平面配置

| 环境变量 | 默认值 | 说明 |
|---------|-------|------|
| `OPENAI_API_KEY` | （必填） | LLM API 密钥（DeepSeek/Volcengine/OpenAI） |
| `OPENAI_BASE_URL` | （必填） | LLM API 端点，例如 `https://api.deepseek.com/v1` |
| `MODEL_NAME` | `deepseek-chat` | LLM 模型名称 |
| `EMBEDDING_MODEL_NAME` | `doubao-embedding-vision-251215` | RAG 嵌入模型（Volcengine Doubao） |
| `AEGIS_DEDUP_WINDOW` | `60` | AlertDedup 去重窗口（秒） |

---

## WAF 代理配置

| 环境变量 | 默认值 | 说明 |
|---------|-------|------|
| `BACKEND_URL` | `http://127.0.0.1:8080` | WAF 代理转发的后端地址 |
| `WAF_MODEL_PATH` | `../models/et_bert_dummy.onnx` | WAF 使用的 ONNX 模型 |
| `WAF_ALERT_LOG` | `./waf_alerts.log` | WAF 告警日志路径 |

---

## .env 文件示例

```dotenv
# ===== LLM 配置 =====
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx
OPENAI_BASE_URL=https://api.deepseek.com/v1
MODEL_NAME=deepseek-chat

# ===== 嵌入模型（RAG） =====
EMBEDDING_MODEL_NAME=doubao-embedding-vision-251215

# ===== 数据平面 =====
AEGIS_INTERFACE=eth0
AEGIS_MODEL=models/et_bert_dummy.onnx
AEGIS_THRESHOLD=0.95
AEGIS_MCP_PORT=8080
AEGIS_DEDUP_WINDOW=60

# ===== WAF 代理 =====
BACKEND_URL=http://127.0.0.1:8080
WAF_MODEL_PATH=../models/et_bert_dummy.onnx
WAF_ALERT_LOG=./waf/waf_alerts.log
```

---

## 配置调优建议

```svg
<svg viewBox="0 0 720 320" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="720" height="320" fill="#0f1117" rx="10"/>
  <text x="360" y="28" text-anchor="middle" font-size="15" font-weight="bold" fill="#e2e8f0">关键参数权衡</text>

  <!-- THRESHOLD -->
  <rect x="30" y="55" width="310" height="110" rx="8" fill="#1e293b" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="185" y="78" text-anchor="middle" font-size="13" fill="#fcd34d" font-weight="bold">AEGIS_THRESHOLD</text>
  <text x="185" y="98" text-anchor="middle" font-size="11" fill="#fbbf24">默认: 0.95</text>

  <rect x="50" y="106" width="270" height="22" rx="4" fill="#451a03" stroke="none"/>
  <text x="185" y="121" text-anchor="middle" font-size="10" fill="#fde68a">调低 (0.8): 更敏感，误报增加</text>
  <rect x="50" y="132" width="270" height="22" rx="4" fill="#064e3b" stroke="none"/>
  <text x="185" y="147" text-anchor="middle" font-size="10" fill="#6ee7b7">调高 (0.99): 更精准，漏报增加</text>

  <!-- DEDUP_WINDOW -->
  <rect x="380" y="55" width="310" height="110" rx="8" fill="#1e293b" stroke="#a855f7" stroke-width="1.5"/>
  <text x="535" y="78" text-anchor="middle" font-size="13" fill="#d8b4fe" font-weight="bold">AEGIS_DEDUP_WINDOW</text>
  <text x="535" y="98" text-anchor="middle" font-size="11" fill="#c084fc">默认: 60s</text>

  <rect x="400" y="106" width="270" height="22" rx="4" fill="#451a03" stroke="none"/>
  <text x="535" y="121" text-anchor="middle" font-size="10" fill="#fde68a">调短 (10s): 更及时，LLM 消耗大</text>
  <rect x="400" y="132" width="270" height="22" rx="4" fill="#064e3b" stroke="none"/>
  <text x="535" y="147" text-anchor="middle" font-size="10" fill="#6ee7b7">调长 (300s): 省费用，响应延迟</text>

  <!-- FlowTracker TTL -->
  <rect x="30" y="195" width="310" height="110" rx="8" fill="#1e293b" stroke="#10b981" stroke-width="1.5"/>
  <text x="185" y="218" text-anchor="middle" font-size="13" fill="#6ee7b7" font-weight="bold">FlowTracker TTL</text>
  <text x="185" y="238" text-anchor="middle" font-size="11" fill="#34d399">默认: 60s（代码硬编码）</text>
  <rect x="50" y="246" width="270" height="22" rx="4" fill="#451a03" stroke="none"/>
  <text x="185" y="261" text-anchor="middle" font-size="10" fill="#fde68a">调短: 节省内存，可能丢失慢速扫描</text>
  <rect x="50" y="272" width="270" height="22" rx="4" fill="#064e3b" stroke="none"/>
  <text x="185" y="287" text-anchor="middle" font-size="10" fill="#6ee7b7">调长: 检测慢速扫描，内存消耗增</text>

  <!-- Payload 触发阈值 -->
  <rect x="380" y="195" width="310" height="110" rx="8" fill="#1e293b" stroke="#3b82f6" stroke-width="1.5"/>
  <text x="535" y="218" text-anchor="middle" font-size="13" fill="#93c5fd" font-weight="bold">流触发阈值</text>
  <text x="535" y="238" text-anchor="middle" font-size="11" fill="#60a5fa">默认: 512B（代码硬编码）</text>
  <rect x="400" y="246" width="270" height="22" rx="4" fill="#451a03" stroke="none"/>
  <text x="535" y="261" text-anchor="middle" font-size="10" fill="#fde68a">调小: 更早触发，推理频率高</text>
  <rect x="400" y="272" width="270" height="22" rx="4" fill="#064e3b" stroke="none"/>
  <text x="535" y="287" text-anchor="middle" font-size="10" fill="#6ee7b7">调大: 减少推理，对短 payload 无效</text>
</svg>
```
