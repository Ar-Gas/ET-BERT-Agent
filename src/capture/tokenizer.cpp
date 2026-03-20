#include "tokenizer.hpp"

namespace aegis::capture {
    std::vector<int64_t> Tokenizer::encode(const std::vector<uint8_t>& payload) {
        std::vector<int64_t> tokens;
        // ET-BERT / 常见网络模型预处理：
        // [CLS] = 101, [SEP] = 102
        tokens.push_back(101); 

        // 简单的 Byte-level Tokenization (以字节为特征)
        // 实际工业界会用 BPE 算法 或 N-gram 哈希
        for (size_t i = 0; i < payload.size() && i < 510; ++i) {
            tokens.push_back(static_cast<int64_t>(payload[i]) + 200); // 偏移映射避免冲突
        }

        tokens.push_back(102); 
        
        // 补齐 Padding 到定长 (如 512)
        while(tokens.size() < 512) {
            tokens.push_back(0); // [PAD] = 0
        }

        return tokens;
    }
}
