#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <mutex>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <csignal>

#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sharded.hh>

#include "mcp/server/mcp_server.hh"
#include "mcp/handlers/mcp_handler.hh"

#include "capture/pcap_sniffer.hpp"
#include "capture/flow_tracker.hpp"
#include "inference/onnx_engine.hpp"

std::mutex cout_mtx;

void write_mcp_message(const std::string& msg) {
    std::lock_guard<std::mutex> lock(cout_mtx);
    std::cout << msg << "\n";
    std::cout.flush();
}

void run_stdio_bridge(uint16_t port) {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
        
        if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) { 
            close(sock); 
            continue; 
        }
        
        std::string req = "POST /message HTTP/1.1\r\n"
                          "Host: 127.0.0.1\r\n"
                          "Content-Type: application/json\r\n"
                          "Connection: close\r\n"
                          "Content-Length: " + std::to_string(line.size()) + "\r\n\r\n" + 
                          line;
                          
        send(sock, req.c_str(), req.size(), 0);
        
        std::string resp;
        char buffer[4096];
        while (true) {
            int bytes = read(sock, buffer, sizeof(buffer));
            if (bytes <= 0) break;
            resp.append(buffer, bytes);
        }
        close(sock);
        
        auto body_pos = resp.find("\r\n\r\n");
        if (body_pos != std::string::npos) {
            write_mcp_message(resp.substr(body_pos + 4));
        }
    }
}

int main(int argc, char** argv) {
    seastar::app_template app;
    return app.run(argc, argv, []() -> seastar::future<> {
        uint16_t listen_port = 8080;
        
        std::cerr << "[Aegis-Agent] Initializing Control Plane (Seastar MCP Server)...\n";
        auto server = std::make_unique<mcp::server::McpServer>(); 
        
        // 核心路由注册。我们的 aegis tools 已经侵入式地注入到了第三方框架的这个方法里。
        mcp::handlers::McpHandler::register_routes(*server); 
        
        co_await server->start(listen_port);
        std::thread(run_stdio_bridge, listen_port).detach();

        std::cerr << "[Aegis-Agent] Starting Data Plane (Pcap & ONNXEngine) on separate thread...\n";

        if (!std::getenv("AEGIS_NO_DATAPLANE")) {
        std::thread data_plane_thread([]() {
            aegis::inference::ONNXEngine ai_engine("models/et_bert_dummy.onnx");
            aegis::capture::FlowTracker  tracker;
            aegis::capture::PcapSniffer  sniffer("ens33");

            int pkt_count = 0;

            sniffer.start_capture([&](const std::string& src_ip, int dst_port, const std::vector<uint8_t>& raw_pkt) {
                // 构建 FlowKey（用 src_ip + dst_port 区分流，src_port/dst_ip 未知置 0）
                struct in_addr addr{};
                inet_pton(AF_INET, src_ip.c_str(), &addr);
                aegis::capture::FlowKey key{};
                key.src_ip   = addr.s_addr;
                key.dst_port = static_cast<uint16_t>(dst_port);
                key.protocol = 6; // TCP

                auto payload = tracker.process_packet(key, raw_pkt);
                if (payload.empty()) return; // 还未拼装完成

                float threat_score = ai_engine.infer(payload);
                if (threat_score > 0.95f) {
                    nlohmann::json notification = {
                        {"jsonrpc", "2.0"},
                        {"method", "notifications/threat_detected"},
                        {"params", {
                            {"type", "High_Threat_Detected"},
                            {"severity", "CRITICAL"},
                            {"confidence", threat_score},
                            {"src_ip", src_ip},
                            {"dst_port", dst_port}
                        }}
                    };
                    write_mcp_message(notification.dump());
                }

                // 每 1000 个包清理一次超过 60s 未活跃的 flow，防止内存泄漏
                if (++pkt_count % 1000 == 0) {
                    tracker.cleanup_stale(60);
                }
            });

            // start_capture() 正常情况下会永久阻塞（pcap_loop 无限循环）。
            // 如果因权限失败而返回，保持线程存活以防止对象析构在非 Seastar 线程上
            // 执行，那会破坏 Seastar 的自定义分配器 per-shard free-list。
            while (true) {
                std::this_thread::sleep_for(std::chrono::hours(1));
            }
        });
        data_plane_thread.detach();
        }

        seastar::promise<> stop_signal;
        // 修复废弃的 handle_signal 警告 (用 engine().handle_signal 是因为 Seastar 版本兼容性)
        seastar::engine().handle_signal(SIGINT, [&] { stop_signal.set_value(); });
        seastar::engine().handle_signal(SIGTERM, [&] { stop_signal.set_value(); });
        co_await stop_signal.get_future();

        std::cerr << "[Aegis-Agent] Shutting down...\n";
        // 直接退出，不调用 server->stop()。
        // 原因：detach 的 stdio_bridge 线程仍在运行，Seastar 拦截了全局 operator new，
        // 调用 server->stop() 会在 reactor 关闭时与该线程的分配操作冲突导致崩溃。
        // std::exit(0) 跳过局部对象析构，安全退出。
        std::exit(0);
    });
}
