# Aegis-Agent 架构总览

Aegis-Agent 采用**三层防御纵深**架构，将内核级 eBPF 过滤、边缘 AI 推理与 LLM 多智能体决策融合在同一进程的三条独立执行路径中。

---

## 1. 系统全景

```svg
<svg viewBox="0 0 900 620" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <!-- 背景 -->
  <rect width="900" height="620" fill="#0f1117" rx="12"/>

  <!-- 标题 -->
  <text x="450" y="38" text-anchor="middle" font-size="20" font-weight="bold" fill="#e2e8f0">Aegis-Agent 系统架构</text>

  <!-- ===== 外部流量 ===== -->
  <rect x="30" y="70" width="130" height="50" rx="8" fill="#1e293b" stroke="#475569" stroke-width="1.5"/>
  <text x="95" y="91" text-anchor="middle" font-size="12" fill="#94a3b8">Internet / LAN</text>
  <text x="95" y="108" text-anchor="middle" font-size="11" fill="#64748b">攻击者流量</text>

  <!-- ===== Layer 0: XDP/eBPF ===== -->
  <rect x="200" y="55" width="650" height="85" rx="10" fill="#1a1f2e" stroke="#3b82f6" stroke-width="2" stroke-dasharray="6,3"/>
  <text x="215" y="75" font-size="11" fill="#3b82f6" font-weight="bold">Layer 0 · 内核 XDP（可选）</text>

  <rect x="220" y="82" width="180" height="42" rx="6" fill="#1e3a5f" stroke="#3b82f6" stroke-width="1.5"/>
  <text x="310" y="100" text-anchor="middle" font-size="12" fill="#93c5fd" font-weight="bold">xdp_firewall()</text>
  <text x="310" y="116" text-anchor="middle" font-size="10" fill="#60a5fa">BPF_MAP_TYPE_HASH 黑名单</text>

  <rect x="430" y="82" width="180" height="42" rx="6" fill="#1e3a5f" stroke="#3b82f6" stroke-width="1.5"/>
  <text x="520" y="100" text-anchor="middle" font-size="12" fill="#93c5fd">aegis_blacklist</text>
  <text x="520" y="116" text-anchor="middle" font-size="10" fill="#60a5fa">最大 100K 条目</text>

  <!-- 外部→XDP 箭头 -->
  <line x1="160" y1="95" x2="218" y2="103" stroke="#475569" stroke-width="2" marker-end="url(#arr)"/>

  <!-- ===== Layer 1: C++ 数据平面 ===== -->
  <rect x="200" y="165" width="650" height="165" rx="10" fill="#1a1f2e" stroke="#10b981" stroke-width="2"/>
  <text x="215" y="185" font-size="11" fill="#10b981" font-weight="bold">Layer 1 · C++ 数据平面（独立线程）</text>

  <!-- PcapSniffer -->
  <rect x="220" y="195" width="140" height="50" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="290" y="216" text-anchor="middle" font-size="12" fill="#6ee7b7" font-weight="bold">PcapSniffer</text>
  <text x="290" y="232" text-anchor="middle" font-size="10" fill="#34d399">libpcap 混杂模式</text>
  <text x="290" y="246" text-anchor="middle" font-size="10" fill="#34d399">raw packet → bytes</text>

  <!-- FlowTracker -->
  <rect x="390" y="195" width="145" height="50" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="462" y="216" text-anchor="middle" font-size="12" fill="#6ee7b7" font-weight="bold">FlowTracker</text>
  <text x="462" y="232" text-anchor="middle" font-size="10" fill="#34d399">5元组哈希</text>
  <text x="462" y="246" text-anchor="middle" font-size="10" fill="#34d399">≥512B → 触发推理</text>

  <!-- ONNXEngine -->
  <rect x="563" y="195" width="145" height="50" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="635" y="216" text-anchor="middle" font-size="12" fill="#6ee7b7" font-weight="bold">ONNXEngine</text>
  <text x="635" y="232" text-anchor="middle" font-size="10" fill="#34d399">ET-BERT 字节分词</text>
  <text x="635" y="246" text-anchor="middle" font-size="10" fill="#34d399">score &gt; 0.95 告警</text>

  <!-- Layer1 内部箭头 -->
  <line x1="360" y1="220" x2="388" y2="220" stroke="#10b981" stroke-width="2" marker-end="url(#arr2)"/>
  <line x1="535" y1="220" x2="561" y2="220" stroke="#10b981" stroke-width="2" marker-end="url(#arr2)"/>

  <!-- 告警输出文字 -->
  <text x="635" y="270" text-anchor="middle" font-size="10" fill="#6ee7b7">↓ JSON-RPC 通知 (stdout)</text>
  <text x="635" y="283" text-anchor="middle" font-size="10" fill="#4ade80">write_mcp_message() mutex保护</text>

  <!-- ===== Layer 2: C++ 控制平面 ===== -->
  <rect x="200" y="355" width="650" height="130" rx="10" fill="#1a1f2e" stroke="#f59e0b" stroke-width="2"/>
  <text x="215" y="375" font-size="11" fill="#f59e0b" font-weight="bold">Layer 2 · Seastar MCP 服务器（:8080）</text>

  <!-- McpServer -->
  <rect x="220" y="385" width="135" height="50" rx="6" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="287" y="406" text-anchor="middle" font-size="12" fill="#fcd34d" font-weight="bold">HTTP Server</text>
  <text x="287" y="422" text-anchor="middle" font-size="10" fill="#fbbf24">Seastar 协程</text>
  <text x="287" y="438" text-anchor="middle" font-size="10" fill="#fbbf24">JSON-RPC 2.0</text>

  <!-- NetTools -->
  <rect x="383" y="385" width="130" height="50" rx="6" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="448" y="406" text-anchor="middle" font-size="12" fill="#fcd34d" font-weight="bold">NetTools</text>
  <text x="448" y="422" text-anchor="middle" font-size="10" fill="#fbbf24">get_pid_by_connection</text>
  <text x="448" y="438" text-anchor="middle" font-size="10" fill="#fbbf24">/proc/net/tcp 解析</text>

  <!-- OsTools -->
  <rect x="532" y="385" width="130" height="50" rx="6" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="597" y="406" text-anchor="middle" font-size="12" fill="#fcd34d" font-weight="bold">OsTools</text>
  <text x="597" y="422" text-anchor="middle" font-size="10" fill="#fbbf24">analyze_process_behavior</text>
  <text x="597" y="438" text-anchor="middle" font-size="10" fill="#fbbf24">/proc/PID/cmdline 读取</text>

  <!-- SecTools -->
  <rect x="681" y="385" width="130" height="50" rx="6" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="746" y="406" text-anchor="middle" font-size="12" fill="#fcd34d" font-weight="bold">SecTools</text>
  <text x="746" y="422" text-anchor="middle" font-size="10" fill="#fbbf24">block_malicious_ip</text>
  <text x="746" y="438" text-anchor="middle" font-size="10" fill="#fbbf24">eBPF / iptables</text>

  <!-- Layer2 内部 -->
  <line x1="355" y1="410" x2="381" y2="410" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#arr3)"/>
  <line x1="513" y1="410" x2="530" y2="410" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#arr3)"/>
  <line x1="662" y1="410" x2="679" y2="410" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#arr3)"/>

  <!-- ===== Layer 3: Python 控制平面 ===== -->
  <rect x="200" y="510" width="650" height="90" rx="10" fill="#1a1f2e" stroke="#a855f7" stroke-width="2"/>
  <text x="215" y="530" font-size="11" fill="#a855f7" font-weight="bold">Layer 3 · Python LangGraph 多智能体</text>

  <rect x="220" y="540" width="145" height="45" rx="6" fill="#2e1065" stroke="#a855f7" stroke-width="1.5"/>
  <text x="292" y="559" text-anchor="middle" font-size="11" fill="#d8b4fe" font-weight="bold">CppProbeWrapper</text>
  <text x="292" y="574" text-anchor="middle" font-size="10" fill="#c084fc">AlertDedup + HTTP IPC</text>

  <rect x="390" y="540" width="145" height="45" rx="6" fill="#2e1065" stroke="#a855f7" stroke-width="1.5"/>
  <text x="462" y="559" text-anchor="middle" font-size="11" fill="#d8b4fe" font-weight="bold">investigator_node</text>
  <text x="462" y="574" text-anchor="middle" font-size="10" fill="#c084fc">ReAct · PID/进程分析</text>

  <rect x="560" y="540" width="145" height="45" rx="6" fill="#2e1065" stroke="#a855f7" stroke-width="1.5"/>
  <text x="632" y="559" text-anchor="middle" font-size="11" fill="#d8b4fe" font-weight="bold">commander_node</text>
  <text x="632" y="574" text-anchor="middle" font-size="10" fill="#c084fc">RAG + IP封锁决策</text>

  <line x1="365" y1="562" x2="388" y2="562" stroke="#a855f7" stroke-width="2" marker-end="url(#arr4)"/>
  <line x1="535" y1="562" x2="558" y2="562" stroke="#a855f7" stroke-width="2" marker-end="url(#arr4)"/>

  <!-- ===== 跨层箭头 ===== -->
  <!-- XDP → Layer1 -->
  <line x1="310" y1="140" x2="310" y2="163" stroke="#3b82f6" stroke-width="1.5" stroke-dasharray="4,2" marker-end="url(#arr5)"/>
  <text x="320" y="155" font-size="9" fill="#3b82f6">已过滤</text>

  <!-- Layer1 → Layer2 (JSON-RPC) -->
  <line x1="635" y1="300" x2="287" y2="353" stroke="#10b981" stroke-width="2" stroke-dasharray="5,3" marker-end="url(#arr2)"/>
  <text x="430" y="330" font-size="10" fill="#6ee7b7">JSON-RPC通知 (stdout→bridge)</text>

  <!-- Layer3 → Layer2 (HTTP) -->
  <line x1="292" y1="538" x2="287" y2="487" stroke="#a855f7" stroke-width="2" marker-end="url(#arr4)"/>
  <text x="180" y="515" font-size="10" fill="#c084fc">HTTP</text>
  <text x="170" y="528" font-size="10" fill="#c084fc">POST</text>

  <!-- SecTools → XDP -->
  <line x1="746" y1="383" x2="746" y2="200" stroke="#ef4444" stroke-width="2" stroke-dasharray="5,3" marker-end="url(#arr6)"/>
  <text x="755" y="290" font-size="9" fill="#ef4444">BPF_MAP</text>
  <text x="755" y="302" font-size="9" fill="#ef4444">UPDATE</text>

  <!-- 箭头标记定义 -->
  <defs>
    <marker id="arr" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="#475569"/>
    </marker>
    <marker id="arr2" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="#10b981"/>
    </marker>
    <marker id="arr3" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="#f59e0b"/>
    </marker>
    <marker id="arr4" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="#a855f7"/>
    </marker>
    <marker id="arr5" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="#3b82f6"/>
    </marker>
    <marker id="arr6" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="#ef4444"/>
    </marker>
  </defs>
</svg>
```

---

## 2. 线程模型

Aegis-Agent 主进程启动三条**完全隔离**的执行路径：

```svg
<svg viewBox="0 0 860 320" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="860" height="320" fill="#0f1117" rx="10"/>
  <text x="430" y="32" text-anchor="middle" font-size="16" font-weight="bold" fill="#e2e8f0">三线程执行模型（src/main.cpp）</text>

  <!-- main() 启动框 -->
  <rect x="360" y="50" width="140" height="44" rx="8" fill="#1e293b" stroke="#64748b" stroke-width="1.5"/>
  <text x="430" y="70" text-anchor="middle" font-size="13" fill="#cbd5e1" font-weight="bold">main()</text>
  <text x="430" y="86" text-anchor="middle" font-size="10" fill="#94a3b8">Seastar App 启动</text>

  <!-- 三条线 -->
  <line x1="300" y1="94" x2="430" y2="94" stroke="#64748b" stroke-width="1"/>
  <line x1="560" y1="94" x2="430" y2="94" stroke="#64748b" stroke-width="1"/>
  <line x1="430" y1="94" x2="430" y2="114" stroke="#64748b" stroke-width="1"/>
  <line x1="300" y1="94" x2="300" y2="114" stroke="#64748b" stroke-width="1"/>
  <line x1="560" y1="94" x2="560" y2="114" stroke="#64748b" stroke-width="1"/>

  <!-- 线程1: Seastar Reactor -->
  <rect x="180" y="114" width="240" height="140" rx="8" fill="#1e3a5f" stroke="#3b82f6" stroke-width="2"/>
  <text x="300" y="138" text-anchor="middle" font-size="13" fill="#93c5fd" font-weight="bold">Seastar Reactor</text>
  <text x="300" y="156" text-anchor="middle" font-size="10" fill="#60a5fa">HTTP 服务器主循环</text>
  <rect x="200" y="166" width="200" height="24" rx="4" fill="#1e40af" stroke="none"/>
  <text x="300" y="182" text-anchor="middle" font-size="10" fill="#bfdbfe">McpServer :8080</text>
  <rect x="200" y="196" width="200" height="24" rx="4" fill="#1e40af" stroke="none"/>
  <text x="300" y="212" text-anchor="middle" font-size="10" fill="#bfdbfe">JsonRpcDispatcher</text>
  <rect x="200" y="226" width="200" height="20" rx="4" fill="#1e40af" stroke="none"/>
  <text x="300" y="240" text-anchor="middle" font-size="10" fill="#bfdbfe">tools: net / os / sec</text>

  <!-- 线程2: stdio_bridge -->
  <rect x="350" y="114" width="160" height="140" rx="8" fill="#1a2e1a" stroke="#10b981" stroke-width="2"/>
  <text x="430" y="138" text-anchor="middle" font-size="13" fill="#6ee7b7" font-weight="bold">stdio_bridge</text>
  <text x="430" y="156" text-anchor="middle" font-size="10" fill="#34d399">独立线程（detached）</text>
  <rect x="365" y="166" width="130" height="24" rx="4" fill="#064e3b" stroke="none"/>
  <text x="430" y="182" text-anchor="middle" font-size="10" fill="#a7f3d0">读取 stdin</text>
  <rect x="365" y="196" width="130" height="24" rx="4" fill="#064e3b" stroke="none"/>
  <text x="430" y="212" text-anchor="middle" font-size="10" fill="#a7f3d0">POST /message</text>
  <rect x="365" y="226" width="130" height="20" rx="4" fill="#064e3b" stroke="none"/>
  <text x="430" y="240" text-anchor="middle" font-size="10" fill="#a7f3d0">写 stdout</text>

  <!-- 线程3: data_plane -->
  <rect x="530" y="114" width="240" height="140" rx="8" fill="#2d1b02" stroke="#f59e0b" stroke-width="2"/>
  <text x="650" y="138" text-anchor="middle" font-size="13" fill="#fcd34d" font-weight="bold">data_plane</text>
  <text x="650" y="156" text-anchor="middle" font-size="10" fill="#fbbf24">独立线程（永不退出）</text>
  <rect x="548" y="166" width="204" height="24" rx="4" fill="#451a03" stroke="none"/>
  <text x="650" y="182" text-anchor="middle" font-size="10" fill="#fde68a">PcapSniffer::start_capture()</text>
  <rect x="548" y="196" width="204" height="24" rx="4" fill="#451a03" stroke="none"/>
  <text x="650" y="212" text-anchor="middle" font-size="10" fill="#fde68a">FlowTracker::process_packet()</text>
  <rect x="548" y="226" width="204" height="20" rx="4" fill="#451a03" stroke="none"/>
  <text x="650" y="240" text-anchor="middle" font-size="10" fill="#fde68a">ONNXEngine::infer()</text>

  <!-- 关键说明 -->
  <rect x="30" y="270" width="800" height="36" rx="6" fill="#1e293b" stroke="#475569" stroke-width="1"/>
  <text x="430" y="284" text-anchor="middle" font-size="11" fill="#f59e0b" font-weight="bold">⚠ 设计约束</text>
  <text x="430" y="299" text-anchor="middle" font-size="10" fill="#94a3b8">data_plane 线程永不退出 — 防止 ONNXEngine/FlowTracker 在非 Seastar 线程上析构，导致内存分配器崩溃</text>
</svg>
```

---

## 3. 核心数据流：威胁检测与响应

```svg
<svg viewBox="0 0 860 500" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="860" height="500" fill="#0f1117" rx="10"/>
  <text x="430" y="32" text-anchor="middle" font-size="16" font-weight="bold" fill="#e2e8f0">威胁检测完整数据流（以挖矿木马攻击为例）</text>

  <defs>
    <marker id="fa" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#6ee7b7"/></marker>
    <marker id="fb" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#fbbf24"/></marker>
    <marker id="fc" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#c084fc"/></marker>
    <marker id="fd" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#f87171"/></marker>
  </defs>

  <!-- 步骤节点 -->
  <!-- Step 1 -->
  <rect x="30" y="60" width="170" height="56" rx="8" fill="#0f2d1f" stroke="#10b981" stroke-width="1.5"/>
  <text x="115" y="82" text-anchor="middle" font-size="11" fill="#6ee7b7" font-weight="bold">① 数据包到达</text>
  <text x="115" y="98" text-anchor="middle" font-size="10" fill="#34d399">libpcap 混杂模式捕获</text>
  <text x="115" y="112" text-anchor="middle" font-size="10" fill="#34d399">T+0ms</text>

  <!-- Step 2 -->
  <rect x="240" y="60" width="170" height="56" rx="8" fill="#0f2d1f" stroke="#10b981" stroke-width="1.5"/>
  <text x="325" y="82" text-anchor="middle" font-size="11" fill="#6ee7b7" font-weight="bold">② 流重组</text>
  <text x="325" y="98" text-anchor="middle" font-size="10" fill="#34d399">FlowTracker 5元组哈希</text>
  <text x="325" y="112" text-anchor="middle" font-size="10" fill="#34d399">缓冲 ≥ 512B 触发</text>

  <!-- Step 3 -->
  <rect x="450" y="60" width="170" height="56" rx="8" fill="#0f2d1f" stroke="#10b981" stroke-width="1.5"/>
  <text x="535" y="82" text-anchor="middle" font-size="11" fill="#6ee7b7" font-weight="bold">③ ET-BERT 推理</text>
  <text x="535" y="98" text-anchor="middle" font-size="10" fill="#34d399">字节分词 → ONNX Run</text>
  <text x="535" y="112" text-anchor="middle" font-size="10" fill="#34d399">score=0.99 &gt; 0.95 ✓</text>

  <!-- Step 4 -->
  <rect x="660" y="60" width="170" height="56" rx="8" fill="#0f2d1f" stroke="#10b981" stroke-width="1.5"/>
  <text x="745" y="82" text-anchor="middle" font-size="11" fill="#6ee7b7" font-weight="bold">④ JSON-RPC 通知</text>
  <text x="745" y="98" text-anchor="middle" font-size="10" fill="#34d399">write_mcp_message()</text>
  <text x="745" y="112" text-anchor="middle" font-size="10" fill="#34d399">mutex 保护写 stdout</text>

  <!-- 箭头 1→2→3→4 -->
  <line x1="200" y1="88" x2="238" y2="88" stroke="#10b981" stroke-width="2" marker-end="url(#fa)"/>
  <line x1="410" y1="88" x2="448" y2="88" stroke="#10b981" stroke-width="2" marker-end="url(#fa)"/>
  <line x1="620" y1="88" x2="658" y2="88" stroke="#10b981" stroke-width="2" marker-end="url(#fa)"/>

  <!-- 分隔线 -->
  <line x1="30" y1="140" x2="830" y2="140" stroke="#1e293b" stroke-width="1.5"/>
  <text x="430" y="160" text-anchor="middle" font-size="11" fill="#475569">Python 控制平面接管</text>

  <!-- Step 5 -->
  <rect x="30" y="175" width="170" height="56" rx="8" fill="#1e1040" stroke="#a855f7" stroke-width="1.5"/>
  <text x="115" y="197" text-anchor="middle" font-size="11" fill="#d8b4fe" font-weight="bold">⑤ 去重过滤</text>
  <text x="115" y="213" text-anchor="middle" font-size="10" fill="#c084fc">AlertDedup 60s窗口</text>
  <text x="115" y="229" text-anchor="middle" font-size="10" fill="#c084fc">同IP忽略重复告警</text>

  <!-- Step 6 -->
  <rect x="240" y="175" width="170" height="56" rx="8" fill="#1e1040" stroke="#a855f7" stroke-width="1.5"/>
  <text x="325" y="197" text-anchor="middle" font-size="11" fill="#d8b4fe" font-weight="bold">⑥ investigator</text>
  <text x="325" y="213" text-anchor="middle" font-size="10" fill="#c084fc">ReAct: PID查询</text>
  <text x="325" y="229" text-anchor="middle" font-size="10" fill="#c084fc">进程cmdline分析</text>

  <!-- Step 7 -->
  <rect x="450" y="175" width="170" height="56" rx="8" fill="#1e1040" stroke="#a855f7" stroke-width="1.5"/>
  <text x="535" y="197" text-anchor="middle" font-size="11" fill="#d8b4fe" font-weight="bold">⑦ commander</text>
  <text x="535" y="213" text-anchor="middle" font-size="10" fill="#c084fc">RAG 威胁情报检索</text>
  <text x="535" y="229" text-anchor="middle" font-size="10" fill="#c084fc">LLM 封锁决策</text>

  <!-- Step 8 -->
  <rect x="660" y="175" width="170" height="56" rx="8" fill="#1e1040" stroke="#a855f7" stroke-width="1.5"/>
  <text x="745" y="197" text-anchor="middle" font-size="11" fill="#d8b4fe" font-weight="bold">⑧ block_malicious_ip</text>
  <text x="745" y="213" text-anchor="middle" font-size="10" fill="#c084fc">HTTP POST → SecTools</text>
  <text x="745" y="229" text-anchor="middle" font-size="10" fill="#c084fc">inet_pton 验证</text>

  <line x1="200" y1="203" x2="238" y2="203" stroke="#a855f7" stroke-width="2" marker-end="url(#fc)"/>
  <line x1="410" y1="203" x2="448" y2="203" stroke="#a855f7" stroke-width="2" marker-end="url(#fc)"/>
  <line x1="620" y1="203" x2="658" y2="203" stroke="#a855f7" stroke-width="2" marker-end="url(#fc)"/>

  <!-- 分隔线 -->
  <line x1="30" y1="255" x2="830" y2="255" stroke="#1e293b" stroke-width="1.5"/>
  <text x="430" y="275" text-anchor="middle" font-size="11" fill="#475569">内核封锁执行</text>

  <!-- Step 9a: eBPF 路径 -->
  <rect x="200" y="290" width="200" height="60" rx="8" fill="#1e3a5f" stroke="#3b82f6" stroke-width="2"/>
  <text x="300" y="312" text-anchor="middle" font-size="12" fill="#93c5fd" font-weight="bold">⑨a eBPF 路径（优先）</text>
  <text x="300" y="328" text-anchor="middle" font-size="10" fill="#60a5fa">open /sys/fs/bpf/aegis_blacklist</text>
  <text x="300" y="344" text-anchor="middle" font-size="10" fill="#60a5fa">syscall BPF_MAP_UPDATE_ELEM</text>

  <!-- Step 9b: iptables 路径 -->
  <rect x="460" y="290" width="200" height="60" rx="8" fill="#1e293b" stroke="#64748b" stroke-width="1.5"/>
  <text x="560" y="312" text-anchor="middle" font-size="12" fill="#cbd5e1" font-weight="bold">⑨b iptables 回退</text>
  <text x="560" y="328" text-anchor="middle" font-size="10" fill="#94a3b8">fork() + execv()</text>
  <text x="560" y="344" text-anchor="middle" font-size="10" fill="#94a3b8">无 shell 注入风险</text>

  <!-- OR -->
  <text x="430" y="325" text-anchor="middle" font-size="14" fill="#f59e0b" font-weight="bold">OR</text>

  <line x1="745" y1="231" x2="560" y2="288" stroke="#f87171" stroke-width="2" stroke-dasharray="5,3" marker-end="url(#fd)"/>
  <line x1="745" y1="231" x2="300" y2="288" stroke="#3b82f6" stroke-width="2" marker-end="url(#fa)"/>

  <!-- Step 10 -->
  <rect x="310" y="375" width="240" height="60" rx="8" fill="#2d1b02" stroke="#f59e0b" stroke-width="2"/>
  <text x="430" y="397" text-anchor="middle" font-size="12" fill="#fcd34d" font-weight="bold">⑩ XDP 实时拦截</text>
  <text x="430" y="413" text-anchor="middle" font-size="10" fill="#fbbf24">网卡驱动层丢包（XDP_DROP）</text>
  <text x="430" y="429" text-anchor="middle" font-size="10" fill="#fbbf24">MTTR ≈ 5s（传统 30min）</text>

  <line x1="300" y1="350" x2="380" y2="373" stroke="#3b82f6" stroke-width="2" marker-end="url(#fb)"/>
  <line x1="560" y1="350" x2="480" y2="373" stroke="#64748b" stroke-width="2" marker-end="url(#fb)"/>
</svg>
```

---

## 4. 组件依赖关系

| 组件 | 依赖 | 被依赖 |
|------|------|--------|
| `PcapSniffer` | libpcap | `FlowTracker` |
| `FlowTracker` | `PcapSniffer` | `ONNXEngine` |
| `ONNXEngine` | ONNX Runtime C++ | `main()` data_plane 线程 |
| `XDPLoader` | libbpf（可选） | `SecTools` |
| `McpServer` | Seastar, nlohmann_json | `CppProbeWrapper` (Python) |
| `NetTools` | `/proc/net/tcp` | `McpServer` |
| `OsTools` | `/proc/PID/cmdline` | `McpServer` |
| `SecTools` | `XDPLoader`, `iptables` | `McpServer` |
| `CppProbeWrapper` | HTTP + stdio | `SOCWorkflow` (LangGraph) |
| `investigator_node` | LangChain ReAct | LangGraph StateGraph |
| `commander_node` | LangChain ReAct, FAISS | LangGraph StateGraph |
| `WAFProxy` | FastAPI, ONNX Runtime (Python) | 独立服务 |

---

## 5. 关键设计决策

### 5.1 为什么 data_plane 线程永不退出？

Seastar 使用自定义内存分配器，`ONNXEngine` 和 `FlowTracker` 在非 Seastar 线程上析构会触发跨线程内存释放 → 未定义行为 → 崩溃。

**解决方案**：线程函数在 `start_capture()` 返回后进入 `while(true){ sleep(1); }` 死循环。

### 5.2 为什么用 `std::exit(0)` 而不是正常关闭？

`co_await server->stop()` + `server.reset()` 在 stdio_bridge 线程仍活跃时会导致崩溃。`std::exit(0)` 绕过 Seastar 关闭流程直接退出，避免析构竞态。

### 5.3 为什么 iptables 不用 `system()` ？

`system("iptables -A INPUT -s " + ip)` 存在命令注入风险。使用 `fork() + execv(char* args[])` 直接调用，OS 不经 shell 解析，无注入面。

### 5.4 为什么 ET-BERT 用字节级分词？

加密流量（TLS/HTTPS）内容不可读，字节级分词（`token = byte + 3`）对密文、二进制协议同样有效，无需明文解密。
