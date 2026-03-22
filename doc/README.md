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

---

## 快速索引

```
aegis-agent/
├── src/                    # C++ 数据平面 & MCP 服务器
│   ├── main.cpp            # 三线程启动入口
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
├── third_party/            # Seastar / ONNX Runtime / MCP-Server
└── doc/                    # 本文档目录
    └── test_log/           # 攻击测试日志 (独立维护)
```
