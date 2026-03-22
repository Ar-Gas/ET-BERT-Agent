#include "onnx_engine.hpp"
#include <iostream>
#include <cmath>
#include <onnxruntime_cxx_api.h>

namespace aegis::inference {

    ONNXEngine::ONNXEngine(const std::string& model_path) : model_path_(model_path) {
        try {
            env_ = std::make_unique<Ort::Env>(ORT_LOGGING_LEVEL_WARNING, "AegisAgent_ET_BERT");

            Ort::SessionOptions opts;
            opts.SetIntraOpNumThreads(1);
            opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);

            session_ = std::make_unique<Ort::Session>(*env_, model_path_.c_str(), opts);

            // 加载时缓存 I/O 名称，避免推理时重复查询
            Ort::AllocatorWithDefaultOptions alloc;
            size_t n_in  = session_->GetInputCount();
            size_t n_out = session_->GetOutputCount();

            input_names_.reserve(n_in);
            output_names_.reserve(n_out);

            for (size_t i = 0; i < n_in; ++i) {
                input_names_.push_back(session_->GetInputNameAllocated(i, alloc).get());
            }
            for (size_t i = 0; i < n_out; ++i) {
                output_names_.push_back(session_->GetOutputNameAllocated(i, alloc).get());
            }
            for (auto& s : input_names_)  input_name_ptrs_.push_back(s.c_str());
            for (auto& s : output_names_) output_name_ptrs_.push_back(s.c_str());

            model_loaded_ = true;
            std::cout << "[ONNXEngine] Model loaded: " << model_path_
                      << " | inputs=" << n_in << " outputs=" << n_out << "\n";
        } catch (const Ort::Exception& e) {
            std::cerr << "[ONNXEngine] Failed to load model, using heuristic fallback. Error: "
                      << e.what() << "\n";
        }
    }

    ONNXEngine::~ONNXEngine() = default;

    // byte-level BERT 编码：每字节值 + 3 作为 token_id（0=PAD, 1=CLS, 2=SEP）
    void ONNXEngine::tokenize(const std::vector<uint8_t>& payload,
                              std::vector<int64_t>& ids,
                              std::vector<int64_t>& mask) const {
        constexpr int MAX_LEN = 512;
        ids.resize(MAX_LEN, 0);
        mask.resize(MAX_LEN, 0);

        ids[0]  = 1; // [CLS]
        mask[0] = 1;

        int fill = std::min((int)payload.size(), MAX_LEN - 2);
        for (int i = 0; i < fill; ++i) {
            ids[i + 1]  = static_cast<int64_t>(payload[i]) + 3;
            mask[i + 1] = 1;
        }

        int sep_pos = fill + 1;
        if (sep_pos < MAX_LEN) {
            ids[sep_pos]  = 2; // [SEP]
            mask[sep_pos] = 1;
        }
    }

    float ONNXEngine::run_model_inference(const std::vector<uint8_t>& payload) {
        if (!model_loaded_) return -1.0f;

        try {
            std::vector<int64_t> input_ids, attention_mask;
            tokenize(payload, input_ids, attention_mask);

            constexpr int64_t SEQ = 512;
            std::array<int64_t, 2> shape{1, SEQ};

            auto mem_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);

            std::vector<Ort::Value> inputs;
            inputs.push_back(Ort::Value::CreateTensor<int64_t>(
                mem_info, input_ids.data(), SEQ, shape.data(), 2));

            if (input_names_.size() >= 2) {
                inputs.push_back(Ort::Value::CreateTensor<int64_t>(
                    mem_info, attention_mask.data(), SEQ, shape.data(), 2));
            }

            auto outputs = session_->Run(
                Ort::RunOptions{nullptr},
                input_name_ptrs_.data(), inputs.data(), inputs.size(),
                output_name_ptrs_.data(), 1);

            auto* logits = outputs[0].GetTensorData<float>();
            auto shape_out = outputs[0].GetTensorTypeAndShapeInfo().GetShape();
            int64_t n_class = shape_out.size() >= 2 ? shape_out[1] : 1;

            if (n_class == 1) {
                // 二分类 sigmoid
                return 1.0f / (1.0f + std::exp(-logits[0]));
            } else {
                // 多分类 softmax，取威胁类（最后一列）
                float max_v = *std::max_element(logits, logits + n_class);
                float sum = 0.0f;
                for (int i = 0; i < n_class; ++i) sum += std::exp(logits[i] - max_v);
                return std::exp(logits[n_class - 1] - max_v) / sum;
            }
        } catch (const Ort::Exception& e) {
            std::cerr << "[ONNXEngine] Inference error: " << e.what() << "\n";
            return -1.0f;
        }
    }

    float ONNXEngine::heuristic_score(const std::vector<uint8_t>& payload) const {
        std::string data(payload.begin(), payload.end());
        const std::vector<std::string> signatures = {
            "wget ", "curl ", "/bin/bash", "-> bash", "miner.sh", "chmod +x",
            "python -c", "perl -e", "base64 -d", ".onion", "xmrig"
        };
        for (const auto& sig : signatures) {
            if (data.find(sig) != std::string::npos) {
                std::cout << "[ONNXEngine] Heuristic hit: '" << sig << "'\n";
                return 0.99f;
            }
        }
        return 0.05f;
    }

    float ONNXEngine::infer(const std::vector<uint8_t>& payload) {
        float score = run_model_inference(payload);
        if (score >= 0.0f) return score;          // 真实推理成功
        return heuristic_score(payload);           // 降级到启发式
    }

}
