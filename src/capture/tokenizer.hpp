#pragma once
#include <vector>
#include <cstdint>

namespace aegis::capture {
    class Tokenizer {
    public:
        static std::vector<int64_t> encode(const std::vector<uint8_t>& payload);
    };
}
