#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include "mcp/core/interfaces.hh"

namespace aegis::mcp::tools {
    class SecTools : public ::mcp::core::McpTool {
    public:
        std::string get_name() const override { return "block_malicious_ip"; }
        
        nlohmann::json get_definition() const override {
            return {
                {"description", "Block a malicious IPv4 address using system iptables firewall."},
                {"inputSchema", {
                    {"type", "object"},
                    {"properties", {
                        {"ip", {{"type", "string"}, {"description", "The malicious IPv4 address to block."}}}
                    }},
                    {"required", {"ip"}}
                }}
            };
        }
        
        seastar::future<nlohmann::json> execute(const nlohmann::json& args) override;
    };
}
