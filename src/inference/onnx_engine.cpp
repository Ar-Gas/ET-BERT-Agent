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
        if (!session_) return 0.0f;
        
        // 3. 真实的张量 (Tensor) 构建与推理过程:
        // Ort::MemoryInfo memory_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        // std::vector<int64_t> input_shape = {1, 512};
        // Ort::Value input_tensor = Ort::Value::CreateTensor<int64_t>(...);
        // auto output_tensors = session_->Run(Ort::RunOptions{nullptr}, input_names, &input_tensor, 1, output_names, 1);
        // float* floatarr = output_tensors.front().GetTensorMutableData<float>();
        
        // 目前为了编译通过返回 mock 值，真实开发时填充上方张量转换代码
        return 0.98f; 
    }
}
