#pragma once
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <functional>

namespace aegis::capture {
    struct FlowKey {
        uint32_t src_ip, dst_ip;
        uint16_t src_port, dst_port;
        uint8_t protocol;

        bool operator==(const FlowKey& other) const {
            return src_ip == other.src_ip && dst_ip == other.dst_ip &&
                   src_port == other.src_port && dst_port == other.dst_port &&
                   protocol == other.protocol;
        }
    };
}

// 注入 std::hash 以支持 unordered_map
namespace std {
    template <>
    struct hash<aegis::capture::FlowKey> {
        size_t operator()(const aegis::capture::FlowKey& k) const {
            // 简单的组合哈希算法
            return ((hash<uint32_t>()(k.src_ip) ^ (hash<uint32_t>()(k.dst_ip) << 1)) >> 1) ^
                   (hash<uint16_t>()(k.src_port) << 1) ^ (hash<uint16_t>()(k.dst_port) << 2) ^
                   (hash<uint8_t>()(k.protocol) << 3);
        }
    };
}

namespace aegis::capture {
    class FlowTracker {
    public:
        // 核心接口：输入报文，如果拼装完成则返回 payload，否则返回空
        std::vector<uint8_t> process_packet(const FlowKey& key, const std::vector<uint8_t>& pkt);
    private:
        std::unordered_map<FlowKey, std::vector<uint8_t>> active_flows_;
        const size_t MAX_FLOW_BUFFER = 4096; // 最大缓存 4KB 用于 AI 推理即可
    };
}
