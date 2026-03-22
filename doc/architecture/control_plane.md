# 控制平面：Seastar MCP 服务器

控制平面基于 **Seastar C++ 框架**实现异步 HTTP 服务，通过 JSON-RPC 2.0 协议暴露三类系统工具，供 Python 智能体调用。

---

## 1. MCP 服务器架构

```svg
<svg viewBox="0 0 820 420" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="820" height="420" fill="#0f1117" rx="10"/>
  <text x="410" y="32" text-anchor="middle" font-size="16" font-weight="bold" fill="#e2e8f0">MCP 服务器请求处理链</text>

  <defs>
    <marker id="cp" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#fbbf24"/>
    </marker>
    <marker id="cp2" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#60a5fa"/>
    </marker>
  </defs>

  <!-- Python Client -->
  <rect x="30" y="60" width="140" height="60" rx="8" fill="#2e1065" stroke="#a855f7" stroke-width="1.5"/>
  <text x="100" y="82" text-anchor="middle" font-size="12" fill="#d8b4fe" font-weight="bold">Python Agent</text>
  <text x="100" y="98" text-anchor="middle" font-size="10" fill="#c084fc">CppProbeWrapper</text>
  <text x="100" y="113" text-anchor="middle" font-size="10" fill="#c084fc">HTTP POST :8080</text>

  <!-- Seastar HTTP Router -->
  <rect x="210" y="60" width="155" height="60" rx="8" fill="#451a03" stroke="#f59e0b" stroke-width="2"/>
  <text x="287" y="82" text-anchor="middle" font-size="12" fill="#fcd34d" font-weight="bold">Seastar HTTP</text>
  <text x="287" y="98" text-anchor="middle" font-size="10" fill="#fbbf24">路由: /message</text>
  <text x="287" y="113" text-anchor="middle" font-size="10" fill="#fbbf24">co_await 处理</text>

  <!-- JsonRpcDispatcher -->
  <rect x="400" y="60" width="160" height="60" rx="8" fill="#451a03" stroke="#f59e0b" stroke-width="2"/>
  <text x="480" y="82" text-anchor="middle" font-size="12" fill="#fcd34d" font-weight="bold">JsonRpcDispatcher</text>
  <text x="480" y="98" text-anchor="middle" font-size="10" fill="#fbbf24">method: tools/call</text>
  <text x="480" y="113" text-anchor="middle" font-size="10" fill="#fbbf24">解析 params.name</text>

  <!-- McpRegistry -->
  <rect x="595" y="60" width="145" height="60" rx="8" fill="#451a03" stroke="#f59e0b" stroke-width="2"/>
  <text x="667" y="82" text-anchor="middle" font-size="12" fill="#fcd34d" font-weight="bold">McpRegistry</text>
  <text x="667" y="98" text-anchor="middle" font-size="10" fill="#fbbf24">工具注册表</text>
  <text x="667" y="113" text-anchor="middle" font-size="10" fill="#fbbf24">dispatch(name)</text>

  <!-- 箭头 -->
  <line x1="170" y1="90" x2="208" y2="90" stroke="#f59e0b" stroke-width="2" marker-end="url(#cp)"/>
  <line x1="365" y1="90" x2="398" y2="90" stroke="#f59e0b" stroke-width="2" marker-end="url(#cp)"/>
  <line x1="560" y1="90" x2="593" y2="90" stroke="#f59e0b" stroke-width="2" marker-end="url(#cp)"/>

  <!-- 三个工具 -->
  <line x1="667" y1="120" x2="667" y2="158" stroke="#f59e0b" stroke-width="1.5"/>
  <line x1="300" y1="158" x2="667" y2="158" stroke="#f59e0b" stroke-width="1.5"/>
  <line x1="300" y1="158" x2="300" y2="178" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#cp)"/>
  <line x1="500" y1="158" x2="500" y2="178" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#cp)"/>
  <line x1="667" y1="158" x2="667" y2="178" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#cp)"/>

  <!-- NetTools -->
  <rect x="155" y="178" width="290" height="100" rx="8" fill="#1a1200" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="300" y="200" text-anchor="middle" font-size="13" fill="#fcd34d" font-weight="bold">NetTools</text>
  <text x="300" y="218" text-anchor="middle" font-size="11" fill="#fbbf24">get_pid_by_connection</text>
  <rect x="170" y="227" width="260" height="20" rx="3" fill="#451a03" stroke="none"/>
  <text x="300" y="241" text-anchor="middle" font-size="10" fill="#fde68a">parse /proc/net/tcp (hex 地址)</text>
  <rect x="170" y="250" width="260" height="20" rx="3" fill="#451a03" stroke="none"/>
  <text x="300" y="264" text-anchor="middle" font-size="10" fill="#fde68a">match socket inode → /proc/PID/fd/</text>

  <!-- OsTools -->
  <rect x="390" y="178" width="220" height="100" rx="8" fill="#1a1200" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="500" y="200" text-anchor="middle" font-size="13" fill="#fcd34d" font-weight="bold">OsTools</text>
  <text x="500" y="218" text-anchor="middle" font-size="11" fill="#fbbf24">analyze_process_behavior</text>
  <rect x="405" y="227" width="190" height="20" rx="3" fill="#451a03" stroke="none"/>
  <text x="500" y="241" text-anchor="middle" font-size="10" fill="#fde68a">读 /proc/PID/cmdline</text>
  <rect x="405" y="250" width="190" height="20" rx="3" fill="#451a03" stroke="none"/>
  <text x="500" y="264" text-anchor="middle" font-size="10" fill="#fde68a">NUL → 空格（可读命令行）</text>

  <!-- SecTools -->
  <rect x="575" y="178" width="220" height="100" rx="8" fill="#1a1200" stroke="#ef4444" stroke-width="2"/>
  <text x="685" y="200" text-anchor="middle" font-size="13" fill="#fca5a5" font-weight="bold">SecTools</text>
  <text x="685" y="218" text-anchor="middle" font-size="11" fill="#f87171">block_malicious_ip</text>
  <rect x="590" y="227" width="190" height="20" rx="3" fill="#450a0a" stroke="none"/>
  <text x="685" y="241" text-anchor="middle" font-size="10" fill="#fca5a5">inet_pton() IP 格式验证</text>
  <rect x="590" y="250" width="190" height="20" rx="3" fill="#450a0a" stroke="none"/>
  <text x="685" y="264" text-anchor="middle" font-size="10" fill="#fca5a5">eBPF map 更新 / iptables</text>

  <!-- stdio_bridge 说明 -->
  <rect x="30" y="300" width="760" height="100" rx="8" fill="#1e293b" stroke="#334155" stroke-width="1"/>
  <text x="410" y="322" text-anchor="middle" font-size="13" fill="#f59e0b" font-weight="bold">stdio_bridge 线程（独立 detached）</text>
  <text x="410" y="342" text-anchor="middle" font-size="11" fill="#94a3b8">从 stdin 读取 JSON-RPC → POST http://localhost:8080/message → 将响应写回 stdout</text>
  <text x="410" y="360" text-anchor="middle" font-size="11" fill="#94a3b8">同时，数据平面通过 write_mcp_message() 直接写 stdout（mutex 保护，避免输出交错）</text>
  <text x="410" y="380" text-anchor="middle" font-size="10" fill="#64748b">用途：允许 Python 子进程通过 stdin/stdout 与 C++ MCP 服务器通信（Claude MCP 兼容）</text>
</svg>
```

---

## 2. JSON-RPC 2.0 协议格式

### 请求格式（Python → C++）

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "block_malicious_ip",
    "arguments": {
      "ip": "192.168.1.100"
    }
  }
}
```

### 响应格式（C++ → Python）

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{
      "type": "text",
      "text": "{\"status\": \"blocked\", \"method\": \"ebpf\", \"ip\": \"192.168.1.100\"}"
    }]
  }
}
```

### 通知格式（C++ 数据平面 → Python，无 id）

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/message",
  "params": {
    "level": "warning",
    "data": {
      "src_ip": "10.0.0.5",
      "src_port": 4444,
      "dst_port": 443,
      "score": 0.99,
      "type": "malicious_flow"
    }
  }
}
```

---

## 3. 三个 MCP 工具详细说明

### 3.1 NetTools — `get_pid_by_connection`

**文件**: `src/mcp_server/tools/net_tools.cpp`

```svg
<svg viewBox="0 0 680 260" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="680" height="260" fill="#0f1117" rx="8"/>
  <text x="340" y="28" text-anchor="middle" font-size="13" font-weight="bold" fill="#fcd34d">get_pid_by_connection 实现流程</text>

  <defs>
    <marker id="nt" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#fbbf24"/>
    </marker>
  </defs>

  <rect x="20" y="50" width="140" height="40" rx="6" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="90" y="68" text-anchor="middle" font-size="11" fill="#fcd34d">输入: ip, port</text>
  <text x="90" y="83" text-anchor="middle" font-size="10" fill="#fbbf24">"192.168.1.1", 443</text>

  <rect x="200" y="50" width="160" height="40" rx="6" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="280" y="68" text-anchor="middle" font-size="11" fill="#fcd34d">解析 /proc/net/tcp</text>
  <text x="280" y="83" text-anchor="middle" font-size="10" fill="#fbbf24">hex IP:Port → 十进制</text>

  <rect x="400" y="50" width="155" height="40" rx="6" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="477" y="68" text-anchor="middle" font-size="11" fill="#fcd34d">匹配 socket inode</text>
  <text x="477" y="83" text-anchor="middle" font-size="10" fill="#fbbf24">记录 inode 号</text>

  <line x1="160" y1="70" x2="198" y2="70" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#nt)"/>
  <line x1="360" y1="70" x2="398" y2="70" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#nt)"/>

  <rect x="140" y="130" width="200" height="40" rx="6" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="240" y="148" text-anchor="middle" font-size="11" fill="#fcd34d">遍历 /proc/*/fd/*</text>
  <text x="240" y="163" text-anchor="middle" font-size="10" fill="#fbbf24">readlink → socket:[inode]</text>

  <rect x="380" y="130" width="170" height="40" rx="6" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="465" y="148" text-anchor="middle" font-size="11" fill="#fcd34d">返回 PID</text>
  <text x="465" y="163" text-anchor="middle" font-size="10" fill="#fbbf24">从路径提取 /proc/PID/</text>

  <line x1="477" y1="90" x2="477" y2="110" stroke="#f59e0b" stroke-width="1.5"/>
  <line x1="477" y1="110" x2="240" y2="110" stroke="#f59e0b" stroke-width="1.5"/>
  <line x1="240" y1="110" x2="240" y2="128" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#nt)"/>
  <line x1="340" y1="150" x2="378" y2="150" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#nt)"/>

  <rect x="30" y="200" width="620" height="45" rx="6" fill="#1e293b" stroke="#334155" stroke-width="1"/>
  <text x="340" y="218" text-anchor="middle" font-size="11" fill="#94a3b8">注意: /proc/net/tcp 中 IP 和端口以 Little-Endian 十六进制存储</text>
  <text x="340" y="235" text-anchor="middle" font-size="10" fill="#64748b">例: 0100007F:01BB = 127.0.0.1:443 (需字节翻转)</text>
</svg>
```

### 3.2 OsTools — `analyze_process_behavior`

**文件**: `src/mcp_server/tools/os_tools.cpp`

```cpp
// /proc/PID/cmdline 中参数以 NUL 字节分隔
// 读取后将 NUL 替换为空格，得到完整命令行
std::string cmdline = read_file("/proc/" + pid + "/cmdline");
std::replace(cmdline.begin(), cmdline.end(), '\0', ' ');
// 输出示例: "python3 /tmp/backdoor.py --host evil.cn --port 4444"
```

### 3.3 SecTools — `block_malicious_ip`

**文件**: `src/mcp_server/tools/sec_tools.cpp`

```svg
<svg viewBox="0 0 700 280" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="700" height="280" fill="#0f1117" rx="8"/>
  <text x="350" y="28" text-anchor="middle" font-size="13" font-weight="bold" fill="#fca5a5">block_malicious_ip 安全执行链</text>

  <defs>
    <marker id="sec" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#f87171"/>
    </marker>
    <marker id="sec2" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#34d399"/>
    </marker>
  </defs>

  <!-- 步骤1: 验证 -->
  <rect x="20" y="55" width="160" height="50" rx="8" fill="#450a0a" stroke="#ef4444" stroke-width="2"/>
  <text x="100" y="75" text-anchor="middle" font-size="12" fill="#fca5a5" font-weight="bold">① IP 验证</text>
  <text x="100" y="91" text-anchor="middle" font-size="10" fill="#f87171">inet_pton(AF_INET, ip)</text>
  <text x="100" y="106" text-anchor="middle" font-size="9" fill="#ef4444">防止格式非法/注入</text>

  <!-- 步骤2: 尝试eBPF -->
  <rect x="220" y="55" width="200" height="50" rx="8" fill="#1e3a5f" stroke="#3b82f6" stroke-width="2"/>
  <text x="320" y="75" text-anchor="middle" font-size="12" fill="#93c5fd" font-weight="bold">② 尝试 eBPF 封锁</text>
  <text x="320" y="91" text-anchor="middle" font-size="10" fill="#60a5fa">open /sys/fs/bpf/aegis_blacklist</text>
  <text x="320" y="106" text-anchor="middle" font-size="9" fill="#3b82f6">syscall BPF_MAP_UPDATE_ELEM</text>

  <!-- 步骤3: 判断 -->
  <polygon points="490,80 580,80 580,105 535,115 490,105" fill="#0d2d0d" stroke="#10b981" stroke-width="1.5"/>
  <text x="535" y="96" text-anchor="middle" font-size="11" fill="#6ee7b7">成功?</text>

  <!-- 成功路径 -->
  <rect x="440" y="140" width="180" height="44" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="530" y="158" text-anchor="middle" font-size="11" fill="#6ee7b7">返回 method: ebpf</text>
  <text x="530" y="174" text-anchor="middle" font-size="10" fill="#34d399">内核 XDP 层生效</text>

  <line x1="535" y1="115" x2="530" y2="138" stroke="#10b981" stroke-width="1.5" marker-end="url(#sec2)"/>
  <text x="545" y="130" text-anchor="middle" font-size="9" fill="#6ee7b7">Yes</text>

  <!-- 失败 → iptables -->
  <rect x="200" y="155" width="200" height="55" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="300" y="175" text-anchor="middle" font-size="12" fill="#6ee7b7" font-weight="bold">③ iptables 回退</text>
  <text x="300" y="191" text-anchor="middle" font-size="10" fill="#34d399">fork() + execv()</text>
  <text x="300" y="207" text-anchor="middle" font-size="10" fill="#34d399">/sbin/iptables -A INPUT -s ip -j DROP</text>

  <line x1="490" y1="97" x2="390" y2="165" stroke="#f87171" stroke-width="1.5" stroke-dasharray="4,2" marker-end="url(#sec)"/>
  <text x="440" y="130" text-anchor="middle" font-size="9" fill="#f87171">No</text>

  <line x1="200" y1="97" x2="218" y2="97" stroke="#ef4444" stroke-width="2" marker-end="url(#sec)"/>
  <line x1="420" y1="97" x2="488" y2="97" stroke="#3b82f6" stroke-width="2" marker-end="url(#sec2)"/>

  <!-- 安全说明 -->
  <rect x="20" y="225" width="660" height="44" rx="6" fill="#1e293b" stroke="#334155" stroke-width="1"/>
  <text x="350" y="242" text-anchor="middle" font-size="11" fill="#f59e0b">🔒 安全设计: fork()+execv(args[]) 而非 system(cmd_str)</text>
  <text x="350" y="258" text-anchor="middle" font-size="10" fill="#94a3b8">OS 直接执行参数数组，不经 shell 解析，从根本上消除命令注入攻击面</text>
</svg>
```

---

## 4. Seastar 协程模型

MCP 服务器利用 Seastar 的 `seastar::future<>` 协程处理并发请求：

```cpp
// 示例：工具调用处理链
seastar::future<> McpHandler::handle_tools_call(Request req) {
    auto params = parse_json(req.body);
    auto tool_name = params["name"].get<std::string>();

    // co_await 让出控制权，不阻塞 reactor
    auto result = co_await registry_.dispatch(tool_name, params["arguments"]);
    co_return make_response(result);
}
```

| Seastar 特性 | 用途 |
|-------------|------|
| `seastar::future<>` | 非阻塞异步操作 |
| `co_await` | 协程挂起/恢复 |
| 单线程 Reactor | 避免锁竞争 |
| `seastar::server_socket` | 高效 TCP 监听 |

**注意**: `/proc` 文件系统读取是阻塞操作，在 Seastar reactor 线程中调用会短暂阻塞事件循环。生产环境可考虑移至线程池执行。
