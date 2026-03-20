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
        
        std::thread data_plane_thread([]() {
            aegis::inference::ONNXEngine ai_engine("models/et_bert_dummy.onnx");
            aegis::capture::PcapSniffer sniffer("eth0");
            
            sniffer.start_capture([&](const std::vector<uint8_t>& session_payload) {
                float threat_score = ai_engine.infer(session_payload);
                if (threat_score > 0.95f) {
                    nlohmann::json notification = {
                        {"jsonrpc", "2.0"},
                        {"method", "notifications/threat_detected"},
                        {"params", {
                            {"type", "High_Threat_Detected"},
                            {"severity", "CRITICAL"},
                            {"confidence", threat_score}
                        }}
                    };
                    write_mcp_message(notification.dump());
                }
            });
        });
        data_plane_thread.detach();

        seastar::promise<> stop_signal;
        // 修复废弃的 handle_signal 警告 (用 engine().handle_signal 是因为 Seastar 版本兼容性)
        seastar::engine().handle_signal(SIGINT, [&] { stop_signal.set_value(); });
        seastar::engine().handle_signal(SIGTERM, [&] { stop_signal.set_value(); });
        co_await stop_signal.get_future();
        
        std::cerr << "[Aegis-Agent] Shutting down...\n";
        co_await server->stop();
        server.reset();
        std::exit(0); 
    });
}
