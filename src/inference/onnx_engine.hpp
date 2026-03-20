#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

// 前向声明，避免在此处引入庞大的 onnxruntime 头文件污染全局空间
namespace Ort { 
    class Env; 
    class Session; 
}

namespace aegis::inference {
    class ONNXEngine {
    public:
        ONNXEngine(const std::string& model_path);
        ~ONNXEngine();
        
        float infer(const std::vector<uint8_t>& payload);

    private:
        std::unique_ptr<Ort::Env> env_;
        std::unique_ptr<Ort::Session> session_;
        std::string model_path_;
    };
}
