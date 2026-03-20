#include "flow_tracker.hpp"

namespace aegis::capture {
    std::vector<uint8_t> FlowTracker::process_packet(const FlowKey& key, const std::vector<uint8_t>& pkt) {
        auto& buffer = active_flows_[key];
        
        // 追加报文载荷
        if (buffer.size() < MAX_FLOW_BUFFER) {
            buffer.insert(buffer.end(), pkt.begin(), pkt.end());
        }

        // 假设达到 512 字节（一个模型截断长度）时，认为可以进行推理提取
        if (buffer.size() >= 512) {
            std::vector<uint8_t> ready_payload = buffer;
            active_flows_.erase(key); // 提取后释放内存，防止 OOM
            return ready_payload;
        }

        return {}; // 尚未就绪
    }
}
