#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include "mcp/interfaces.hh"

namespace aegis::mcp::tools {
    class OSTools : public ::mcp::interfaces::McpTool {
    public:
        std::string get_name() const override { return "analyze_process_behavior"; }
        
        nlohmann::json get_definition() const override {
            return {
                {"description", "Analyze a running process's memory maps and command line to identify malicious behavior."},
                {"inputSchema", {
                    {"type", "object"},
                    {"properties", {
                        {"pid", {"type", "integer", "description", "The Process ID (PID) to inspect."}}
                    }},
                    {"required", {"pid"}}
                }}
            };
        }
        
        seastar::future<nlohmann::json> execute(const nlohmann::json& args) override;
    };
}
