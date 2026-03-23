#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include "mcp/core/interfaces.hh"

namespace aegis::mcp::tools {
    class NetTools : public ::mcp::core::McpTool {
    public:
        std::string get_name() const override { return "get_pid_by_connection"; }
        
        nlohmann::json get_definition() const override {
            return {
                {"description", "Find the process ID (PID) associated with a given IPv4 address and port."},
                {"inputSchema", {
                    {"type", "object"},
                    {"properties", {
                        {"ip",   {{"type", "string"},  {"description", "The IPv4 address (e.g., 1.2.3.4)"}}},
                        {"port", {{"type", "integer"}, {"description", "The network port number (e.g., 443)"}}}
                    }},
                    {"required", {"ip", "port"}}
                }}
            };
        }
        
        seastar::future<nlohmann::json> execute(const nlohmann::json& args) override;

    private:
        int parse_proc_net_tcp(const std::string& ip, int port);
    };
}
