#include "os_tools.hpp"
#include <fstream>
#include <sstream>
#include <seastar/core/coroutine.hh>

namespace aegis::mcp::tools {
    seastar::future<nlohmann::json> OSTools::execute(const nlohmann::json& args) {
        int pid = args["pid"];
        std::string cmdline_path = "/proc/" + std::to_string(pid) + "/cmdline";
        std::ifstream cmd_file(cmdline_path);
        
        if (!cmd_file.is_open()) {
            co_return nlohmann::json{{"status", "failed"}, {"error", "Process not found or access denied."}};
        }

        std::stringstream buffer;
        buffer << cmd_file.rdbuf();
        std::string cmdline = buffer.str();
        
        for (char& c : cmdline) {
            if (c == '\0') c = ' ';
        }

        co_return nlohmann::json{
            {"status", "success"}, 
            {"process_info", {{"cmdline", cmdline}}}
        };
    }
}
