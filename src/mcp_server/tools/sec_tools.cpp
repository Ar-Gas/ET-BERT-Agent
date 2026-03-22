#include "sec_tools.hpp"
#include <iostream>
#include <arpa/inet.h>
#include <seastar/core/coroutine.hh>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/bpf.h>
#include <cstring>
#include <cerrno>

namespace aegis::mcp::tools {

    // 通过原始 bpf(2) syscall 向 pinned BPF map 写入黑名单 IP
    static bool raw_bpf_map_update(int map_fd, uint32_t key, uint32_t value) {
        union bpf_attr attr{};
        attr.map_fd = static_cast<__u32>(map_fd);
        attr.key    = reinterpret_cast<__u64>(&key);
        attr.value  = reinterpret_cast<__u64>(&value);
        attr.flags  = BPF_ANY;
        return ::syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) == 0;
    }

    // 通过 fork+execv 调用 iptables，无 shell，消除注入风险
    static bool iptables_block(const std::string& ip) {
        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "[SecTools] fork() failed: " << strerror(errno) << "\n";
            return false;
        }
        if (pid == 0) {
            // 子进程
            const char* args[] = {
                "/sbin/iptables", "-w", "-A", "INPUT",
                "-s", ip.c_str(), "-j", "DROP", nullptr
            };
            execv("/sbin/iptables", const_cast<char**>(args));
            _exit(1); // execv 失败时退出
        }
        int status = 0;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }

    seastar::future<nlohmann::json> SecTools::execute(const nlohmann::json& args) {
        std::string ip = args.value("ip", "");

        // 验证 IPv4 格式
        struct sockaddr_in sa{};
        if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) {
            std::cerr << "[SecTools] Invalid IP: " << ip << "\n";
            co_return nlohmann::json{{"status", "failed"}, {"error", "Invalid IPv4 format."}};
        }

        uint32_t target_ip = sa.sin_addr.s_addr;
        uint32_t value     = 1;

        std::cout << "[SecTools] Blocking IP: " << ip << "\n";

        // 优先尝试 eBPF XDP map
        int map_fd = open("/sys/fs/bpf/aegis_blacklist", O_RDWR);
        if (map_fd >= 0) {
            bool ok = raw_bpf_map_update(map_fd, target_ip, value);
            close(map_fd);
            if (ok) {
                co_return nlohmann::json{
                    {"status", "success"}, {"method", "ebpf_xdp"}, {"ip", ip}};
            }
            std::cerr << "[SecTools] eBPF map update failed, falling back to iptables\n";
        }

        // Fallback: iptables via fork+execv
        if (iptables_block(ip)) {
            co_return nlohmann::json{
                {"status", "success"}, {"method", "iptables_fallback"}, {"ip", ip}};
        }

        co_return nlohmann::json{
            {"status", "failed"},
            {"error", "Both eBPF and iptables failed. Need root privileges."}};
    }

}
