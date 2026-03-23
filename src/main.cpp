#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <mutex>
#include <arpa/inet.h>
#include <unistd.h>
#include <csignal>

#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/reactor.hh>
#include <nlohmann/json.hpp>

#include "mcp/mcp.hh"
#include "mcp_server/tools/net_tools.hpp"
#include "mcp_server/tools/os_tools.hpp"
#include "mcp_server/tools/sec_tools.hpp"

#include "capture/pcap_sniffer.hpp"
#include "capture/flow_tracker.hpp"
#include "inference/onnx_engine.hpp"

// data_plane 线程直接写 stdout 发通知，需互斥锁防止与 StdioTransport 交叉
std::mutex cout_mtx;

void write_mcp_message(const std::string& msg) {
    std::lock_guard<std::mutex> lock(cout_mtx);
    std::cout << msg << "\n";
    std::cout.flush();
}

int main(int argc, char** argv) {
    seastar::app_template app;
    return app.run(argc, argv, []() -> seastar::future<> {
        const char* port_env  = std::getenv("AEGIS_MCP_PORT");
        const char* iface_env = std::getenv("AEGIS_INTERFACE");
        const char* model_env = std::getenv("AEGIS_MODEL");
        const char* thresh_env= std::getenv("AEGIS_THRESHOLD");

        uint16_t listen_port = port_env   ? static_cast<uint16_t>(std::stoi(port_env)) : 8080;
        const char* iface    = iface_env  ? iface_env  : "ens33";
        const char* model    = model_env  ? model_env  : "models/et_bert_dummy.onnx";
        float threshold      = thresh_env ? std::stof(thresh_env) : 0.95f;

        std::cerr << "[Aegis-Agent] 初始化控制面 (MCP Server, port=" << listen_port << ")...\n";

        // Builder 模式：一步完成配置 + 工具注册 + transport 选择
        auto server = mcp::McpServerBuilder()
            .name("aegis-mcp-server")
            .version("1.0.0")
            .with_http(listen_port)   // HTTP+SSE transport（供 Python HTTP 客户端使用）
            .with_stdio()             // StdIO transport（替代原手写 stdio_bridge 线程）
            .add_tool<aegis::mcp::tools::NetTools>()
            .add_tool<aegis::mcp::tools::OSTools>()
            .add_tool<aegis::mcp::tools::SecTools>()
            .build();

        co_await server->start();
        std::cerr << "[Aegis-Agent] MCP Server 已启动 (HTTP+SSE port=" << listen_port << ", StdIO)\n";

        if (!std::getenv("AEGIS_NO_DATAPLANE")) {
            std::cerr << "[Aegis-Agent] 启动数据面 (Pcap & ONNXEngine, iface=" << iface << ")...\n";
            std::thread([iface, model, threshold]() {
                aegis::inference::ONNXEngine ai_engine(model);
                aegis::capture::FlowTracker  tracker;
                aegis::capture::PcapSniffer  sniffer(iface);

                int pkt_count = 0;

                sniffer.start_capture([&](const std::string& src_ip, int dst_port,
                                          const std::vector<uint8_t>& raw_pkt) {
                    struct in_addr addr{};
                    inet_pton(AF_INET, src_ip.c_str(), &addr);
                    aegis::capture::FlowKey key{};
                    key.src_ip   = addr.s_addr;
                    key.dst_port = static_cast<uint16_t>(dst_port);
                    key.protocol = 6; // TCP

                    auto payload = tracker.process_packet(key, raw_pkt);
                    if (payload.empty()) return;

                    float threat_score = ai_engine.infer(payload);
                    if (threat_score > threshold) {
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

                // start_capture() 因权限失败返回时，保持线程存活防止非 Seastar 线程上的析构
                while (true) {
                    std::this_thread::sleep_for(std::chrono::hours(1));
                }
            }).detach();
        }

        seastar::promise<> stop_signal;
        seastar::engine().handle_signal(SIGINT,  [&] { stop_signal.set_value(); }); // NOLINT
        seastar::engine().handle_signal(SIGTERM, [&] { stop_signal.set_value(); }); // NOLINT
        co_await stop_signal.get_future();

        std::cerr << "[Aegis-Agent] 正在关闭...\n";
        // StdioTransport 使用 seastar::thread（可正常 join），现可安全调用 stop()
        // data_plane_thread 处于 sleep 状态，不调用 Seastar API，不会冲突
        co_await server->stop();
    });
}
