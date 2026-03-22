#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

// 前向声明，避免在此处引入庞大的 onnxruntime 头文件污染全局空间
namespace Ort {
    class Env;
    class Session;
    struct AllocatorWithDefaultOptions;
}

namespace aegis::inference {
    class ONNXEngine {
    public:
        ONNXEngine(const std::string& model_path);
        ~ONNXEngine();

        // 主接口：输入原始 payload 字节，返回威胁概率 [0,1]
        float infer(const std::vector<uint8_t>& payload);

    private:
        // 将 payload 字节 byte-level 编码为 BERT 风格的 input_ids + attention_mask
        // 截断/padding 至 max_len=512
        void tokenize(const std::vector<uint8_t>& payload,
                      std::vector<int64_t>& input_ids,
                      std::vector<int64_t>& attention_mask) const;

        // 真实 ONNX 推理路径，失败时返回 -1.0f
        float run_model_inference(const std::vector<uint8_t>& payload);

        // 启发式规则 fallback（模型不可用时使用）
        float heuristic_score(const std::vector<uint8_t>& payload) const;

        std::unique_ptr<Ort::Env>     env_;
        std::unique_ptr<Ort::Session> session_;
        std::string model_path_;
        bool model_loaded_ = false;

        // 在 load 时缓存 I/O 名称，避免每次推理重新查询
        std::vector<std::string>    input_names_;
        std::vector<std::string>    output_names_;
        std::vector<const char*>    input_name_ptrs_;
        std::vector<const char*>    output_name_ptrs_;
    };
}
