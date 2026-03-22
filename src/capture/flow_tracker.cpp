#include "flow_tracker.hpp"

namespace aegis::capture {

    std::vector<uint8_t> FlowTracker::process_packet(const FlowKey& key, const std::vector<uint8_t>& pkt) {
        auto& state = active_flows_[key];
        state.last_seen = std::chrono::steady_clock::now();

        if (state.buffer.size() < MAX_FLOW_BUFFER) {
            state.buffer.insert(state.buffer.end(), pkt.begin(), pkt.end());
        }

        if (state.buffer.size() >= 512) {
            std::vector<uint8_t> ready_payload = std::move(state.buffer);
            active_flows_.erase(key);
            return ready_payload;
        }

        return {};
    }

    void FlowTracker::cleanup_stale(int timeout_seconds) {
        auto now = std::chrono::steady_clock::now();
        auto timeout = std::chrono::seconds(timeout_seconds);
        for (auto it = active_flows_.begin(); it != active_flows_.end();) {
            if (now - it->second.last_seen > timeout) {
                it = active_flows_.erase(it);
            } else {
                ++it;
            }
        }
    }

}
