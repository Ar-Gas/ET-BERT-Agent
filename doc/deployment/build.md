# 构建与部署

## 1. 系统要求

| 组件 | 最低版本 | 说明 |
|------|---------|------|
| Linux 内核 | 5.10+ | eBPF/XDP 支持（可选） |
| GCC | 11+ | C++20 协程支持 |
| Clang | 14+ | 编译 BPF 程序 |
| Python | 3.10+ | 异步支持 |
| libpcap-dev | 1.10+ | 数据包捕获 |
| Seastar | 任意 | async C++ 框架 |
| ONNX Runtime | 1.18+ | ET-BERT 推理 |

---

## 2. 项目目录结构

```
aegis-agent/
├── src/
│   ├── main.cpp                    # 三线程启动入口
│   ├── capture/
│   │   ├── pcap_sniffer.hpp        # libpcap 封装（模板类）
│   │   ├── flow_tracker.hpp/.cpp   # TCP 流重组
│   │   └── tokenizer.hpp/.cpp      # 分词器（预留）
│   ├── inference/
│   │   └── onnx_engine.hpp/.cpp    # ET-BERT ONNX 推理引擎
│   ├── ebpf/
│   │   ├── xdp_filter.c            # BPF 内核程序
│   │   └── xdp_loader.hpp/.cpp     # libbpf 加载器（可选）
│   ├── core/
│   │   └── alert_queue.hpp         # 告警队列（预留）
│   └── mcp_server/tools/
│       ├── net_tools.hpp/.cpp      # get_pid_by_connection
│       ├── os_tools.hpp/.cpp       # analyze_process_behavior
│       └── sec_tools.hpp/.cpp      # block_malicious_ip
├── third_party/
│   ├── MCP-Server/                 # JSON-RPC 2.0 HTTP 服务框架
│   │   ├── include/mcp/
│   │   │   ├── server/mcp_server.hh
│   │   │   ├── router/json_rpc_dispatcher.hh
│   │   │   └── interfaces.hh       # McpTool 抽象接口
│   │   └── src/mcp/handlers/mcp_handler.cc
│   ├── onnxruntime/                # ONNX Runtime C++ 本地安装
│   │   ├── include/                # C++ API 头文件
│   │   └── lib/                    # .so 动态库
│   └── ET-BERT/                    # 模型训练/推理代码
├── models/
│   ├── et_bert_dummy.onnx          # 模型元数据
│   └── et_bert_dummy.onnx.data     # 模型权重 (~146MB)
├── scripts/
│   ├── multi_agent_soc.py          # Python 主程序
│   ├── agent.py                    # 单智能体示例
│   └── tests/
│       ├── test_unit.py            # 单元测试
│       └── test_integration.py    # 集成测试
├── waf/
│   └── waf_proxy.py                # FastAPI WAF 代理
├── doc/                            # 本文档目录
│   └── test_log/                   # 测试日志（独立维护）
├── CMakeLists.txt
├── requirements.txt
└── .env                            # API 密钥和配置
```

---

## 3. C++ 构建步骤

### 3.1 安装系统依赖

```bash
# Ubuntu/Debian
sudo apt-get install -y \
    build-essential cmake ninja-build \
    libpcap-dev \
    libbpf-dev clang llvm \
    nlohmann-json3-dev

# 安装 Seastar（从源码）
git clone https://github.com/scylladb/seastar
cd seastar && ./configure.py --mode=release
ninja -C build/release install
```

### 3.2 安装 ONNX Runtime

```bash
# 下载预编译包（Linux x86_64）
wget https://github.com/microsoft/onnxruntime/releases/download/v1.18.0/\
onnxruntime-linux-x64-1.18.0.tgz

tar xf onnxruntime-linux-x64-1.18.0.tgz
cp -r onnxruntime-linux-x64-1.18.0/* third_party/onnxruntime/
```

### 3.3 编译 C++ 项目

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

**CMakeLists.txt 关键配置**:

```cmake
cmake_minimum_required(VERSION 3.17)
project(AegisAgent LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)

# 可选 libbpf
pkg_check_modules(LIBBPF libbpf QUIET)
if(LIBBPF_FOUND)
    add_compile_definitions(AEGIS_LIBBPF_AVAILABLE)
endif()

# ONNX Runtime 本地路径
include_directories(${CMAKE_SOURCE_DIR}/third_party/onnxruntime/include)
link_directories(${CMAKE_SOURCE_DIR}/third_party/onnxruntime/lib)

# 所有 .cpp 源文件
file(GLOB_RECURSE SRC_FILES "src/*.cpp")
set(MCP_SRC "third_party/MCP-Server/src/mcp/handlers/mcp_handler.cc")

add_executable(aegis_agent ${SRC_FILES} ${MCP_SRC})
target_link_libraries(aegis_agent PRIVATE
    pthread Seastar::seastar ${PCAP_LIBRARIES}
    onnxruntime nlohmann_json::nlohmann_json
)
```

### 3.4 编译 XDP BPF 程序（可选）

```bash
clang -O2 -target bpf \
    -c src/ebpf/xdp_filter.c \
    -o xdp_filter.o
```

---

## 4. Python 环境配置

```bash
# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

**requirements.txt 关键依赖**:

```
langchain>=0.1.0
langgraph>=0.0.30
langchain-openai>=0.0.5
faiss-cpu>=1.7.4
fastapi>=0.100.0
uvicorn>=0.23.0
onnxruntime>=1.18.0
httpx>=0.24.0
python-dotenv>=1.0.0
```

---

## 5. 运行

### 5.1 配置环境变量

复制并编辑 `.env` 文件：

```bash
cp .env.example .env
```

```dotenv
# LLM 配置
OPENAI_API_KEY=your_deepseek_or_volcengine_key
OPENAI_BASE_URL=https://api.deepseek.com/v1
MODEL_NAME=deepseek-chat

# 嵌入模型（RAG）
EMBEDDING_MODEL_NAME=doubao-embedding-vision-251215

# 数据平面配置
AEGIS_INTERFACE=eth0
AEGIS_MODEL=models/et_bert_dummy.onnx
AEGIS_THRESHOLD=0.95
AEGIS_DEDUP_WINDOW=60
AEGIS_MCP_PORT=8080

# WAF 代理
BACKEND_URL=http://127.0.0.1:8080
WAF_MODEL_PATH=../models/et_bert_dummy.onnx
```

### 5.2 启动 C++ 探针

```bash
# LD_LIBRARY_PATH 必须设置，否则找不到 libonnxruntime.so
export LD_LIBRARY_PATH=third_party/onnxruntime/lib:$LD_LIBRARY_PATH

# 正常启动（需要 root 权限用于 libpcap）
sudo -E ./build/aegis_agent

# 测试模式（跳过数据平面，无需 root）
AEGIS_NO_DATAPLANE=1 ./build/aegis_agent
```

### 5.3 启动 Python 控制平面

```bash
source venv/bin/activate

# 主程序（子进程模式，自动启动 C++ 二进制）
python3 scripts/multi_agent_soc.py

# 或连接到已运行的 C++ 进程
AEGIS_BINARY=./build/aegis_agent python3 scripts/multi_agent_soc.py
```

### 5.4 启动 WAF 代理（可选）

```bash
cd waf
uvicorn waf_proxy:app --host 0.0.0.0 --port 9090
```

---

## 6. 构建流程图

```svg
<svg viewBox="0 0 760 380" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="760" height="380" fill="#0f1117" rx="10"/>
  <text x="380" y="28" text-anchor="middle" font-size="15" font-weight="bold" fill="#e2e8f0">构建与运行依赖关系</text>

  <defs>
    <marker id="bd" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#6ee7b7"/>
    </marker>
    <marker id="bd2" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#c084fc"/>
    </marker>
  </defs>

  <!-- C++ 依赖 -->
  <text x="200" y="58" text-anchor="middle" font-size="12" fill="#10b981" font-weight="bold">C++ 构建依赖</text>
  <rect x="20" y="68" width="110" height="36" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="75" y="91" text-anchor="middle" font-size="11" fill="#6ee7b7">Seastar</text>

  <rect x="150" y="68" width="110" height="36" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="205" y="91" text-anchor="middle" font-size="11" fill="#6ee7b7">libpcap-dev</text>

  <rect x="280" y="68" width="110" height="36" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="335" y="91" text-anchor="middle" font-size="11" fill="#6ee7b7">nlohmann-json</text>

  <rect x="410" y="68" width="110" height="36" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="465" y="91" text-anchor="middle" font-size="11" fill="#6ee7b7">ONNX Runtime</text>

  <rect x="540" y="68" width="110" height="36" rx="6" fill="#1e3a5f" stroke="#3b82f6" stroke-width="1.5"/>
  <text x="595" y="82" text-anchor="middle" font-size="11" fill="#93c5fd">libbpf</text>
  <text x="595" y="97" text-anchor="middle" font-size="9" fill="#60a5fa">（可选）</text>

  <!-- cmake -->
  <rect x="245" y="135" width="155" height="44" rx="8" fill="#064e3b" stroke="#10b981" stroke-width="2"/>
  <text x="322" y="155" text-anchor="middle" font-size="13" fill="#6ee7b7" font-weight="bold">cmake + make</text>
  <text x="322" y="172" text-anchor="middle" font-size="10" fill="#34d399">build/aegis_agent</text>

  <!-- 箭头 deps → cmake -->
  <line x1="75" y1="104" x2="280" y2="148" stroke="#10b981" stroke-width="1" marker-end="url(#bd)"/>
  <line x1="205" y1="104" x2="295" y2="148" stroke="#10b981" stroke-width="1" marker-end="url(#bd)"/>
  <line x1="335" y1="104" x2="330" y2="133" stroke="#10b981" stroke-width="1" marker-end="url(#bd)"/>
  <line x1="465" y1="104" x2="370" y2="133" stroke="#10b981" stroke-width="1" marker-end="url(#bd)"/>
  <line x1="595" y1="104" x2="390" y2="148" stroke="#3b82f6" stroke-width="1" stroke-dasharray="3,2" marker-end="url(#bd)"/>

  <!-- Python 依赖 -->
  <text x="200" y="215" text-anchor="middle" font-size="12" fill="#a855f7" font-weight="bold">Python 依赖</text>
  <rect x="20" y="225" width="100" height="36" rx="6" fill="#2e1065" stroke="#a855f7" stroke-width="1.5"/>
  <text x="70" y="248" text-anchor="middle" font-size="11" fill="#d8b4fe">langchain</text>

  <rect x="135" y="225" width="100" height="36" rx="6" fill="#2e1065" stroke="#a855f7" stroke-width="1.5"/>
  <text x="185" y="248" text-anchor="middle" font-size="11" fill="#d8b4fe">langgraph</text>

  <rect x="250" y="225" width="100" height="36" rx="6" fill="#2e1065" stroke="#a855f7" stroke-width="1.5"/>
  <text x="300" y="248" text-anchor="middle" font-size="11" fill="#d8b4fe">faiss-cpu</text>

  <rect x="365" y="225" width="100" height="36" rx="6" fill="#2e1065" stroke="#a855f7" stroke-width="1.5"/>
  <text x="415" y="248" text-anchor="middle" font-size="11" fill="#d8b4fe">fastapi</text>

  <rect x="480" y="225" width="120" height="36" rx="6" fill="#2e1065" stroke="#a855f7" stroke-width="1.5"/>
  <text x="540" y="248" text-anchor="middle" font-size="11" fill="#d8b4fe">onnxruntime-py</text>

  <!-- pip install -->
  <rect x="245" y="290" width="155" height="44" rx="8" fill="#2e1065" stroke="#a855f7" stroke-width="2"/>
  <text x="322" y="310" text-anchor="middle" font-size="13" fill="#d8b4fe" font-weight="bold">pip install -r</text>
  <text x="322" y="327" text-anchor="middle" font-size="10" fill="#c084fc">requirements.txt</text>

  <line x1="70" y1="261" x2="270" y2="298" stroke="#a855f7" stroke-width="1" marker-end="url(#bd2)"/>
  <line x1="185" y1="261" x2="285" y2="288" stroke="#a855f7" stroke-width="1" marker-end="url(#bd2)"/>
  <line x1="300" y1="261" x2="310" y2="288" stroke="#a855f7" stroke-width="1" marker-end="url(#bd2)"/>
  <line x1="415" y1="261" x2="350" y2="288" stroke="#a855f7" stroke-width="1" marker-end="url(#bd2)"/>
  <line x1="540" y1="261" x2="385" y2="298" stroke="#a855f7" stroke-width="1" marker-end="url(#bd2)"/>

  <!-- 运行时输出 -->
  <rect x="560" y="290" width="170" height="44" rx="8" fill="#1e293b" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="645" y="310" text-anchor="middle" font-size="12" fill="#fcd34d" font-weight="bold">运行时</text>
  <text x="645" y="326" text-anchor="middle" font-size="10" fill="#fbbf24">LD_LIBRARY_PATH 必须设置</text>

  <line x1="322" y1="179" x2="590" y2="298" stroke="#f59e0b" stroke-width="1.5" stroke-dasharray="4,2"/>
</svg>
```

---

## 7. 常见问题排查

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| `libonnxruntime.so: not found` | 缺少 LD_LIBRARY_PATH | `export LD_LIBRARY_PATH=third_party/onnxruntime/lib:$LD_LIBRARY_PATH` |
| `pcap: permission denied` | 非 root 用户 | `sudo ./build/aegis_agent` 或 `setcap cap_net_raw+eip aegis_agent` |
| `XDP load failed` | 未安装 libbpf | 安装 `libbpf-dev`，重新编译；或忽略（自动回退 iptables） |
| LLM 调用失败 | API Key 未配置 | 检查 `.env` 文件的 `OPENAI_API_KEY` 和 `OPENAI_BASE_URL` |
| Seastar 启动崩溃 | 多核 NUMA 配置 | 添加 `--smp 1` 参数限制单核（开发环境） |
