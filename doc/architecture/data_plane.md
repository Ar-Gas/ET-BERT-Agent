# 数据平面：C++ 流量捕获与 AI 推理

数据平面运行在独立的 `data_plane` 线程中，负责**实时抓包 → 流重组 → ONNX 推理 → 告警输出**四步流水线。

---

## 1. 组件结构

```svg
<svg viewBox="0 0 820 380" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="820" height="380" fill="#0f1117" rx="10"/>
  <text x="410" y="32" text-anchor="middle" font-size="16" font-weight="bold" fill="#e2e8f0">数据平面组件结构</text>

  <defs>
    <marker id="a1" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#10b981"/>
    </marker>
  </defs>

  <!-- NIC -->
  <rect x="30" y="70" width="120" height="50" rx="8" fill="#1e293b" stroke="#475569" stroke-width="1.5"/>
  <text x="90" y="91" text-anchor="middle" font-size="12" fill="#94a3b8" font-weight="bold">网卡 (NIC)</text>
  <text x="90" y="108" text-anchor="middle" font-size="10" fill="#64748b">DMA 接收</text>

  <!-- PcapSniffer -->
  <rect x="190" y="60" width="180" height="70" rx="8" fill="#064e3b" stroke="#10b981" stroke-width="2"/>
  <text x="280" y="85" text-anchor="middle" font-size="13" fill="#6ee7b7" font-weight="bold">PcapSniffer</text>
  <text x="280" y="103" text-anchor="middle" font-size="10" fill="#34d399">pcap_open_live()</text>
  <text x="280" y="118" text-anchor="middle" font-size="10" fill="#34d399">pcap_loop() 回调驱动</text>

  <!-- FlowTracker -->
  <rect x="420" y="55" width="185" height="80" rx="8" fill="#064e3b" stroke="#10b981" stroke-width="2"/>
  <text x="512" y="80" text-anchor="middle" font-size="13" fill="#6ee7b7" font-weight="bold">FlowTracker</text>
  <text x="512" y="97" text-anchor="middle" font-size="10" fill="#34d399">FlowKey 5元组哈希</text>
  <text x="512" y="112" text-anchor="middle" font-size="10" fill="#34d399">FlowState 缓冲区</text>
  <text x="512" y="127" text-anchor="middle" font-size="10" fill="#34d399">≥512B → 返回载荷</text>

  <!-- ONNXEngine -->
  <rect x="660" y="55" width="140" height="80" rx="8" fill="#064e3b" stroke="#10b981" stroke-width="2"/>
  <text x="730" y="80" text-anchor="middle" font-size="13" fill="#6ee7b7" font-weight="bold">ONNXEngine</text>
  <text x="730" y="97" text-anchor="middle" font-size="10" fill="#34d399">tokenize()</text>
  <text x="730" y="112" text-anchor="middle" font-size="10" fill="#34d399">session_→Run()</text>
  <text x="730" y="127" text-anchor="middle" font-size="10" fill="#34d399">score → 告警</text>

  <!-- 箭头 -->
  <line x1="150" y1="95" x2="188" y2="95" stroke="#10b981" stroke-width="2" marker-end="url(#a1)"/>
  <line x1="370" y1="95" x2="418" y2="95" stroke="#10b981" stroke-width="2" marker-end="url(#a1)"/>
  <line x1="605" y1="95" x2="658" y2="95" stroke="#10b981" stroke-width="2" marker-end="url(#a1)"/>

  <!-- 标签 -->
  <text x="168" y="88" text-anchor="middle" font-size="9" fill="#6ee7b7">raw bytes</text>
  <text x="392" y="88" text-anchor="middle" font-size="9" fill="#6ee7b7">packet bytes</text>
  <text x="630" y="88" text-anchor="middle" font-size="9" fill="#6ee7b7">≥512B payload</text>

  <!-- stdout 输出 -->
  <rect x="640" y="175" width="160" height="45" rx="6" fill="#1e293b" stroke="#475569" stroke-width="1"/>
  <text x="720" y="197" text-anchor="middle" font-size="11" fill="#94a3b8" font-weight="bold">stdout</text>
  <text x="720" y="212" text-anchor="middle" font-size="10" fill="#64748b">JSON-RPC notification</text>
  <line x1="730" y1="135" x2="730" y2="173" stroke="#10b981" stroke-width="1.5" stroke-dasharray="4,2" marker-end="url(#a1)"/>
  <text x="740" y="160" font-size="9" fill="#34d399">score&gt;0.95</text>

  <!-- 下方：XDPLoader -->
  <rect x="190" y="215" width="180" height="65" rx="8" fill="#1e3a5f" stroke="#3b82f6" stroke-width="1.5"/>
  <text x="280" y="237" text-anchor="middle" font-size="13" fill="#93c5fd" font-weight="bold">XDPLoader</text>
  <text x="280" y="254" text-anchor="middle" font-size="10" fill="#60a5fa">libbpf 可选</text>
  <text x="280" y="269" text-anchor="middle" font-size="10" fill="#60a5fa">pin /sys/fs/bpf/</text>
  <text x="280" y="284" text-anchor="middle" font-size="9" fill="#3b82f6">AEGIS_LIBBPF_AVAILABLE</text>

  <!-- xdp_filter.c -->
  <rect x="420" y="215" width="185" height="65" rx="8" fill="#1e3a5f" stroke="#3b82f6" stroke-width="1.5"/>
  <text x="512" y="237" text-anchor="middle" font-size="13" fill="#93c5fd" font-weight="bold">xdp_filter.c</text>
  <text x="512" y="254" text-anchor="middle" font-size="10" fill="#60a5fa">BPF 内核程序</text>
  <text x="512" y="269" text-anchor="middle" font-size="10" fill="#60a5fa">aegis_blacklist 查表</text>
  <text x="512" y="284" text-anchor="middle" font-size="10" fill="#60a5fa">XDP_DROP / XDP_PASS</text>

  <line x1="370" y1="248" x2="418" y2="248" stroke="#3b82f6" stroke-width="1.5" marker-end="url(#a1)"/>
  <text x="393" y="242" text-anchor="middle" font-size="9" fill="#60a5fa">加载</text>

  <!-- 说明文字 -->
  <rect x="30" y="310" width="760" height="50" rx="6" fill="#1e293b" stroke="#334155" stroke-width="1"/>
  <text x="410" y="328" text-anchor="middle" font-size="11" fill="#f59e0b" font-weight="bold">关键约束</text>
  <text x="410" y="348" text-anchor="middle" font-size="10" fill="#94a3b8">若 pcap 初始化失败，线程进入 while(true){ sleep(1); } 死循环，而非退出 — 防止 Seastar 非线程析构崩溃</text>
</svg>
```

---

## 2. PcapSniffer — 数据包捕获

**文件**: `src/capture/pcap_sniffer.hpp`

PcapSniffer 是一个**模板类**，通过回调函数将数据包传递给 FlowTracker：

```cpp
// 核心接口
template<typename Callback>
class PcapSniffer {
    pcap_t* handle_;
    void start_capture(Callback cb) {
        handle_ = pcap_open_live(iface, 65535, PROMISCUOUS, 1000, errbuf);
        pcap_loop(handle_, -1, [](u_char* user, ...) {
            auto* cb = reinterpret_cast<Callback*>(user);
            (*cb)(header, packet);
        }, (u_char*)&cb);
    }
};
```

| 参数 | 值 | 说明 |
|------|-----|------|
| snaplen | 65535 | 捕获完整帧 |
| promisc | 1 | 混杂模式（捕获所有帧，非仅本机） |
| timeout | 1000ms | 读取超时 |
| 接口 | `$AEGIS_INTERFACE` | 默认 `ens33` |

---

## 3. FlowTracker — TCP 流重组

**文件**: `src/capture/flow_tracker.{hpp,cpp}`

### 3.1 数据结构

```cpp
struct FlowKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  protocol;
    // hash_combine 使用 0x9e3779b9 黄金比率
};

struct FlowState {
    std::vector<uint8_t> buffer;   // 最大 4096 字节
    time_t last_seen;              // 用于 TTL 过期
};

std::unordered_map<FlowKey, FlowState, FlowKeyHash> flows_;
```

### 3.2 处理流程

```svg
<svg viewBox="0 0 700 320" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="700" height="320" fill="#0f1117" rx="10"/>
  <text x="350" y="28" text-anchor="middle" font-size="14" font-weight="bold" fill="#e2e8f0">FlowTracker::process_packet() 流程</text>

  <defs>
    <marker id="fp" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#10b981"/>
    </marker>
    <marker id="fn" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#f59e0b"/>
    </marker>
  </defs>

  <!-- 步骤框 -->
  <rect x="270" y="45" width="160" height="38" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="350" y="62" text-anchor="middle" font-size="11" fill="#6ee7b7">收到 raw packet</text>
  <text x="350" y="77" text-anchor="middle" font-size="10" fill="#34d399">解析 ETH/IP/TCP 头</text>

  <line x1="350" y1="83" x2="350" y2="103" stroke="#10b981" stroke-width="1.5" marker-end="url(#fp)"/>

  <rect x="230" y="103" width="240" height="38" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="350" y="120" text-anchor="middle" font-size="11" fill="#6ee7b7">构建 FlowKey (5元组)</text>
  <text x="350" y="135" text-anchor="middle" font-size="10" fill="#34d399">src_ip:port → dst_ip:port + proto</text>

  <line x1="350" y1="141" x2="350" y2="161" stroke="#10b981" stroke-width="1.5" marker-end="url(#fp)"/>

  <!-- 决策框 -->
  <polygon points="350,161 450,191 350,221 250,191" fill="#0d2d0d" stroke="#10b981" stroke-width="1.5"/>
  <text x="350" y="188" text-anchor="middle" font-size="11" fill="#6ee7b7">flows_</text>
  <text x="350" y="202" text-anchor="middle" font-size="10" fill="#34d399">已有此流?</text>

  <!-- Yes 路径 -->
  <line x1="450" y1="191" x2="560" y2="191" stroke="#10b981" stroke-width="1.5" marker-end="url(#fp)"/>
  <text x="500" y="183" text-anchor="middle" font-size="10" fill="#6ee7b7">Yes</text>
  <rect x="560" y="173" width="120" height="36" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="620" y="189" text-anchor="middle" font-size="10" fill="#6ee7b7">追加 payload</text>
  <text x="620" y="203" text-anchor="middle" font-size="10" fill="#34d399">更新 last_seen</text>

  <!-- No 路径 -->
  <line x1="250" y1="191" x2="140" y2="191" stroke="#10b981" stroke-width="1.5" marker-end="url(#fp)"/>
  <text x="195" y="183" text-anchor="middle" font-size="10" fill="#6ee7b7">No</text>
  <rect x="30" y="173" width="110" height="36" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="85" y="190" text-anchor="middle" font-size="10" fill="#6ee7b7">创建新流</text>
  <text x="85" y="205" text-anchor="middle" font-size="10" fill="#34d399">FlowState{}</text>

  <!-- 回到判断 ≥512B -->
  <line x1="620" y1="209" x2="620" y2="255" stroke="#10b981" stroke-width="1.5" marker-end="url(#fp)"/>
  <line x1="85" y1="209" x2="85" y2="255" stroke="#10b981" stroke-width="1.5"/>
  <line x1="85" y1="255" x2="240" y2="255" stroke="#10b981" stroke-width="1.5"/>
  <line x1="620" y1="255" x2="460" y2="255" stroke="#10b981" stroke-width="1.5"/>

  <polygon points="350,245 450,265 350,285 250,265" fill="#0d2d0d" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="350" y="262" text-anchor="middle" font-size="11" fill="#fcd34d">buffer.size()</text>
  <text x="350" y="276" text-anchor="middle" font-size="10" fill="#fbbf24">≥ 512B ?</text>

  <!-- ≥512 → 推理 -->
  <line x1="450" y1="265" x2="560" y2="265" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#fn)"/>
  <text x="505" y="257" text-anchor="middle" font-size="10" fill="#fcd34d">Yes</text>
  <rect x="560" y="248" width="120" height="36" rx="6" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="620" y="265" text-anchor="middle" font-size="10" fill="#fcd34d">返回 payload</text>
  <text x="620" y="279" text-anchor="middle" font-size="10" fill="#fbbf24">erase(flow)</text>

  <!-- &lt;512 继续 -->
  <text x="195" y="257" text-anchor="middle" font-size="10" fill="#6ee7b7">No → 继续等待</text>
</svg>
```

### 3.3 TTL 过期机制

每处理 **1000 个数据包**，调用一次 `cleanup_stale()`：

```cpp
void FlowTracker::cleanup_stale(int ttl_seconds = 60) {
    time_t now = time(nullptr);
    for (auto it = flows_.begin(); it != flows_.end(); ) {
        if (now - it->second.last_seen > ttl_seconds)
            it = flows_.erase(it);  // 删除过期流
        else
            ++it;
    }
}
```

---

## 4. ONNXEngine — ET-BERT 推理

**文件**: `src/inference/onnx_engine.{hpp,cpp}`

### 4.1 字节级分词

```cpp
// token_id = byte_value + 3
// 保留 0=PAD, 1=CLS, 2=SEP
std::vector<int64_t> tokenize(const std::vector<uint8_t>& payload) {
    std::vector<int64_t> ids(512, 0);  // PAD 填充
    ids[0] = 1;  // [CLS]
    for (size_t i = 0; i < min(payload.size(), 510UL); i++)
        ids[i+1] = payload[i] + 3;
    ids[min(payload.size()+1, 511UL)] = 2;  // [SEP]
    return ids;
}
```

**为什么字节级分词？**
- 对加密流量（TLS/QUIC）同样有效，无需解密
- 对二进制协议（Telnet、FTP）无需词典
- 对任意语言的 payload 泛化能力强

### 4.2 推理流程

```svg
<svg viewBox="0 0 700 280" xmlns="http://www.w3.org/2000/svg" font-family="'Segoe UI',Arial,sans-serif">
  <rect width="700" height="280" fill="#0f1117" rx="10"/>
  <text x="350" y="28" text-anchor="middle" font-size="14" font-weight="bold" fill="#e2e8f0">ONNXEngine::infer() 推理流程</text>

  <defs>
    <marker id="oe" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#6ee7b7"/>
    </marker>
    <marker id="of" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
      <polygon points="0 0,8 3,0 6" fill="#f87171"/>
    </marker>
  </defs>

  <!-- Input -->
  <rect x="20" y="50" width="130" height="44" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="85" y="68" text-anchor="middle" font-size="11" fill="#6ee7b7">payload bytes</text>
  <text x="85" y="84" text-anchor="middle" font-size="10" fill="#34d399">≥512 触发</text>

  <!-- tokenize -->
  <rect x="185" y="50" width="130" height="44" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="250" y="68" text-anchor="middle" font-size="11" fill="#6ee7b7">tokenize()</text>
  <text x="250" y="84" text-anchor="middle" font-size="10" fill="#34d399">[1, 512] int64</text>

  <!-- input_ids / attention_mask -->
  <rect x="350" y="40" width="140" height="28" rx="4" fill="#1a2e1a" stroke="#10b981" stroke-width="1"/>
  <text x="420" y="57" text-anchor="middle" font-size="10" fill="#6ee7b7">input_ids [1,512]</text>
  <rect x="350" y="74" width="140" height="28" rx="4" fill="#1a2e1a" stroke="#10b981" stroke-width="1"/>
  <text x="420" y="91" text-anchor="middle" font-size="10" fill="#6ee7b7">attention_mask [1,512]</text>

  <!-- session.Run() -->
  <rect x="530" y="50" width="140" height="44" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="2"/>
  <text x="600" y="68" text-anchor="middle" font-size="11" fill="#6ee7b7" font-weight="bold">session_→Run()</text>
  <text x="600" y="84" text-anchor="middle" font-size="10" fill="#34d399">ET-BERT ONNX</text>

  <line x1="150" y1="72" x2="183" y2="72" stroke="#10b981" stroke-width="1.5" marker-end="url(#oe)"/>
  <line x1="315" y1="72" x2="348" y2="72" stroke="#10b981" stroke-width="1.5" marker-end="url(#oe)"/>
  <line x1="490" y1="72" x2="528" y2="72" stroke="#10b981" stroke-width="1.5" marker-end="url(#oe)"/>

  <!-- 输出分支 -->
  <line x1="600" y1="94" x2="600" y2="130" stroke="#10b981" stroke-width="1.5" marker-end="url(#oe)"/>

  <polygon points="600,130 680,155 600,180 520,155" fill="#0d2d0d" stroke="#10b981" stroke-width="1.5"/>
  <text x="600" y="150" text-anchor="middle" font-size="10" fill="#6ee7b7">输出数</text>
  <text x="600" y="165" text-anchor="middle" font-size="10" fill="#34d399">== 1?</text>

  <!-- 单输出 sigmoid -->
  <line x1="680" y1="155" x2="750" y2="155" stroke="#10b981" stroke-width="1.5" marker-end="url(#oe)"/>
  <!-- 截断防止越界 -->

  <rect x="420" y="200" width="160" height="38" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="500" y="218" text-anchor="middle" font-size="11" fill="#6ee7b7">sigmoid(logits[0])</text>
  <text x="500" y="233" text-anchor="middle" font-size="10" fill="#34d399">→ threat_score</text>
  <line x1="600" y1="180" x2="500" y2="198" stroke="#10b981" stroke-width="1.5" marker-end="url(#oe)"/>
  <text x="580" y="194" text-anchor="middle" font-size="9" fill="#6ee7b7">Yes</text>

  <rect x="130" y="200" width="180" height="38" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="220" y="218" text-anchor="middle" font-size="11" fill="#6ee7b7">softmax(logits)</text>
  <text x="220" y="233" text-anchor="middle" font-size="10" fill="#34d399">取最后类别概率</text>
  <line x1="520" y1="155" x2="280" y2="198" stroke="#10b981" stroke-width="1.5" marker-end="url(#oe)"/>
  <text x="390" y="175" text-anchor="middle" font-size="9" fill="#6ee7b7">No (多类别)</text>

  <!-- 启发式回退说明 -->
  <rect x="30" y="250" width="640" height="22" rx="4" fill="#1e293b" stroke="#475569" stroke-width="1"/>
  <text x="350" y="265" text-anchor="middle" font-size="10" fill="#f59e0b">⚠ ONNX Run() 失败时: 回退到 heuristic_score() 字符串特征匹配（wget, curl, /bin/bash, miner.sh...）</text>
</svg>
```

### 4.3 启发式回退

当 ONNX 推理失败时，自动切换到字符串特征匹配：

| 特征字符串 | 分类 |
|-----------|------|
| `wget`, `curl` | 可疑下载 |
| `/bin/bash`, `/bin/sh` | Shell 执行 |
| `miner.sh`, `xmrig` | 挖矿木马 |
| `base64 -d`, `chmod +x` | 混淆 Payload |
| SQL 注入关键词 | Web 攻击 |

---

## 5. XDP 过滤程序

**文件**: `src/ebpf/xdp_filter.c`

```c
// BPF Map：IP 黑名单（最大 100,000 条目）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    // IPv4 地址
    __type(value, __u8);   // 1 = 封锁
    __uint(max_entries, 100000);
} aegis_blacklist SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    // 解析 ETH/IP 头，查 aegis_blacklist
    // 命中 → XDP_DROP（网卡驱动层丢弃，不进内核协议栈）
    // 未命中 → XDP_PASS
}
```

**XDP_DROP 的性能优势**：在网卡驱动层丢包，无上下文切换，无内存分配，吞吐量可达 10Mpps+。
