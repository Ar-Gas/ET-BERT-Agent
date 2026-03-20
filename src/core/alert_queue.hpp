#pragma once
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace aegis::core {
    struct Alert {
        std::string type;
        float score;
    };

    class AlertQueue {
    public:
        void push(const std::string& type, float score) {
            std::lock_guard<std::mutex> lock(mtx_);
            queue_.push({type, score});
            cv_.notify_one();
        }

        bool pop(Alert& alert) {
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait(lock, [this]() { return !queue_.empty(); });
            alert = queue_.front();
            queue_.pop();
            return true;
        }

    private:
        std::queue<Alert> queue_;
        std::mutex mtx_;
        std::condition_variable cv_;
    };
}
