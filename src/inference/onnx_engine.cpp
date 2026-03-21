#include "onnx_engine.hpp"
#include <iostream>
// 引入 ONNX Runtime 的 C++ API
#include <onnxruntime_cxx_api.h>

namespace aegis::inference {
    ONNXEngine::ONNXEngine(const std::string& model_path) : model_path_(model_path) {
        try {
            // 1. 初始化 ONNX Runtime 环境，禁用无用日志以提升性能
            env_ = std::make_unique<Ort::Env>(ORT_LOGGING_LEVEL_WARNING, "AegisAgent_ET_BERT");
            
            Ort::SessionOptions session_options;
            session_options.SetIntraOpNumThreads(1); // 绑核单线程，追求极低延迟
            session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);
            
            // 2. 加载预训练的 ET-BERT / 模型权重
            session_ = std::make_unique<Ort::Session>(*env_, model_path_.c_str(), session_options);
            std::cout << "[ONNXEngine] Successfully loaded ONNX model: " << model_path_ << std::endl;
        } catch (const Ort::Exception& e) {
            std::cerr << "[ONNXEngine] Failed to load ONNX model. Make sure onnxruntime is installed. Error: " << e.what() << std::endl;
        }
    }

    ONNXEngine::~ONNXEngine() = default;

    float ONNXEngine::infer(const std::vector<uint8_t>& payload) {
        // 由于真实的张量前向传播代码被注释，这里统一使用启发式特征匹配 (模拟 AI 边缘计算)
        std::string data(payload.begin(), payload.end());
        
        // 简单的恶意行为特征字典
        const std::vector<std::string> signatures = {
            "wget ", "curl ", "/bin/bash", "-> bash", "miner.sh", "chmod +x"
        };
        
        for (const auto& sig : signatures) {
            if (data.find(sig) != std::string::npos) {
                std::cout << "[ONNXEngine] 🚨 AI Simulated Detection: Payload matched signature: '" << sig << "'\n";
                return 0.99f; // High confidence
            }
        }
        return 0.05f; // Benign
    }
}
