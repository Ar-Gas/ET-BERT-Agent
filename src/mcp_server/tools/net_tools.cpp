#include "net_tools.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <seastar/core/coroutine.hh> // Seastar 协程支持

namespace aegis::mcp::tools {

    seastar::future<nlohmann::json> NetTools::execute(const nlohmann::json& args) {
        std::string ip = args["ip"];
        int port = args["port"];
        
        // 由于溯源可能是阻塞的 I/O 操作，在 Seastar 中通常需要丢入 backend thread
        // 为了简便且演示逻辑，此处直接同步调用
        int pid = parse_proc_net_tcp(ip, port);
        
        nlohmann::json result;
        if (pid > 0) {
            result = {{"status", "success"}, {"pid", pid}};
        } else {
            result = {{"status", "failed"}, {"error", "Connection not found or process exited."}};
        }
        co_return result;
    }

    int NetTools::parse_proc_net_tcp(const std::string& ip, int port) {
        std::ifstream tcp_file("/proc/net/tcp");
        if (!tcp_file.is_open()) return -1;

        std::string line;
        std::string target_inode = "";
        char hex_port[8];
        snprintf(hex_port, sizeof(hex_port), "%04X", port);
        std::string port_str(hex_port);

        while (std::getline(tcp_file, line)) {
            if (line.find(":" + port_str) != std::string::npos) {
                std::istringstream iss(line);
                std::string sl, local_addr, rem_addr, st, tx_rx, tr, tmwhen, retrnsmt, uid, timeout, inode;
                if (iss >> sl >> local_addr >> rem_addr >> st >> tx_rx >> tr >> tmwhen >> retrnsmt >> uid >> timeout >> inode) {
                    target_inode = inode;
                    break;
                }
            }
        }

        if (target_inode.empty() || target_inode == "0") return -1;

        for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
            if (!entry.is_directory()) continue;
            std::string pid_str = entry.path().filename().string();
            if (!std::isdigit(pid_str[0])) continue;

            std::string fd_dir = entry.path().string() + "/fd";
            if (!std::filesystem::exists(fd_dir)) continue;

            try {
                for (const auto& fd_entry : std::filesystem::directory_iterator(fd_dir)) {
                    if (std::filesystem::is_symlink(fd_entry)) {
                        std::string target = std::filesystem::read_symlink(fd_entry).string();
                        if (target == "socket:[" + target_inode + "]") {
                            return std::stoi(pid_str);
                        }
                    }
                }
            } catch (...) { /* 忽略权限错误 */ }
        }
        return -1;
    }
}
