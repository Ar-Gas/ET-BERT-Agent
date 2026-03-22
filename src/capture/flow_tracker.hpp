#pragma once
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <functional>
#include <chrono>

namespace aegis::capture {
    struct FlowKey {
        uint32_t src_ip, dst_ip;
        uint16_t src_port, dst_port;
        uint8_t protocol;

        bool operator==(const FlowKey& o) const {
            return src_ip == o.src_ip && dst_ip == o.dst_ip &&
                   src_port == o.src_port && dst_port == o.dst_port &&
                   protocol == o.protocol;
        }
    };

    struct FlowState {
        std::vector<uint8_t> buffer;
        std::chrono::steady_clock::time_point last_seen;
    };
}

// 注入 std::hash — 使用 Boost hash_combine 模式，避免简单 XOR 的高碰撞率
namespace std {
    template <>
    struct hash<aegis::capture::FlowKey> {
        size_t operator()(const aegis::capture::FlowKey& k) const {
            size_t seed = 0;
            auto combine = [&](size_t v) {
                seed ^= v + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            };
            combine(hash<uint32_t>()(k.src_ip));
            combine(hash<uint32_t>()(k.dst_ip));
            combine(hash<uint16_t>()(k.src_port));
            combine(hash<uint16_t>()(k.dst_port));
            combine(hash<uint8_t>()(k.protocol));
            return seed;
        }
    };
}

namespace aegis::capture {
    class FlowTracker {
    public:
        // 输入报文，拼装完成（>=512字节）时返回 payload，否则返回空
        std::vector<uint8_t> process_packet(const FlowKey& key, const std::vector<uint8_t>& pkt);

        // 清理超过 timeout_seconds 未活跃的 flow，防止内存无限增长
        void cleanup_stale(int timeout_seconds);

        size_t active_flow_count() const { return active_flows_.size(); }

    private:
        std::unordered_map<FlowKey, FlowState> active_flows_;
        static constexpr size_t MAX_FLOW_BUFFER = 4096;
    };
}
