# Aegis-Agent 技术文档

> 自治安全运营中心探针：eBPF/XDP 内核过滤 + ET-BERT ONNX 推理 + LangGraph 多智能体

---

## 文档目录

| 文档 | 说明 |
|------|------|
| [架构总览](architecture/overview.md) | 三层架构、线程模型、关键数据流 |
| [数据平面](architecture/data_plane.md) | C++ 流量捕获、流重组、AI推理 |
| [控制平面](architecture/control_plane.md) | Seastar MCP Server、JSON-RPC、系统工具 |
| [Agent 工作流](architecture/agent_workflow.md) | LangGraph 状态机、RAG检索、事件决策 |
| [FlowTracker](components/flow_tracker.md) | TCP流重组算法、TTL过期机制 |
| [ONNX推理引擎](components/onnx_engine.md) | ET-BERT推理、字节级分词、启发式回退 |
| [MCP工具](components/mcp_tools.md) | net_tools / os_tools / sec_tools 实现细节 |
| [WAF代理](components/waf_proxy.md) | FastAPI反向代理、在线威胁检测 |
| [构建与部署](deployment/build.md) | CMake构建、依赖安装、运行时配置 |
| [配置参考](deployment/configuration.md) | 所有环境变量及默认值 |
| [测试指南](development/testing.md) | 单元测试、集成测试、端到端测试 |

MCP-Server SDK 文档见 [`third_party/MCP-Server/docs/`](../third_party/MCP-Server/docs/)（架构、Transport、API 参考等）。

---

## 快速索引

```
aegis-agent/
├── src/                    # C++ 数据平面 & MCP 服务器
│   ├── main.cpp            # 启动入口：McpServerBuilder + data_plane 线程
│   ├── capture/            # 流量捕获 & 流重组
│   ├── inference/          # ONNX ET-BERT 推理
│   ├── ebpf/               # XDP 内核程序 & 加载器
│   └── mcp_server/tools/   # 系统工具 (网络/进程/封锁)
├── scripts/                # Python 控制平面
│   ├── multi_agent_soc.py  # LangGraph 多智能体主程序
│   └── tests/              # 单元 & 集成测试
├── waf/
│   └── waf_proxy.py        # FastAPI WAF 反向代理
├── models/                 # ET-BERT ONNX 模型文件
├── third_party/
│   ├── MCP-Server/         # Seastar MCP C++ SDK（mcp::McpServerBuilder API）
│   └── onnxruntime/        # ONNX Runtime C++ API
└── doc/                    # 本文档目录
    └── test_log/           # 攻击测试日志 (独立维护)
```

---

## MCP Server 关键 API（速查）

```cpp
// 引入
#include "mcp/mcp.hh"

// 工具基类（继承此类实现业务工具）
class MyTool : public mcp::core::McpTool { ... };

// 服务器构建（main.cpp 中使用的模式）
auto server = mcp::McpServerBuilder()
    .name("aegis-mcp-server").version("1.0.0")
    .with_http(8080)    // HTTP+SSE
    .with_stdio()       // StdIO（供 Python 子进程通信）
    .add_tool<NetTools>().add_tool<OSTools>().add_tool<SecTools>()
    .build();
co_await server->start();
// ...
co_await server->stop();  // StdioTransport 可正常 join，安全退出
```
