#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include <pcap.h>

namespace aegis::capture {
    class PcapSniffer {
    public:
        PcapSniffer(const std::string& interface) : interface_(interface) {}
        
        // 放弃 std::functional，直接使用模板接收 Callable 对象
        template <typename Func>
        void start_capture(Func callback) {
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t* handle = pcap_open_live(interface_.c_str(), BUFSIZ, 1, 1000, errbuf);
            if (handle == nullptr) {
                std::cerr << "[PcapSniffer] Failed to open device " << interface_ << ": " << errbuf << "\n";
                return;
            }

            std::cout << "[PcapSniffer] Successfully listening on " << interface_ << " using libpcap.\n";

            pcap_loop(handle, 0, [](u_char* user, const struct pcap_pkthdr* header, const u_char* bytes) {
                auto* cb = reinterpret_cast<Func*>(user);
                std::vector<uint8_t> payload(bytes, bytes + header->caplen);
                (*cb)(payload);
            }, reinterpret_cast<u_char*>(&callback));

            pcap_close(handle);
        }

    private:
        std::string interface_;
    };
}
