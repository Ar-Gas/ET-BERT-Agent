#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

namespace aegis::capture {
    class PcapSniffer {
    public:
        PcapSniffer(const std::string& interface) : interface_(interface) {}
        
        // Callback signature: void(const std::string& src_ip, int dst_port, const std::vector<uint8_t>& payload)
        template <typename Func>
        void start_capture(Func callback) {
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t* handle = pcap_open_live(interface_.c_str(), 65535, 1, 1000, errbuf);
            if (handle == nullptr) {
                std::cerr << "[PcapSniffer] Failed to open device " << interface_ << ": " << errbuf << "\n";
                return;
            }

            std::cout << "[PcapSniffer] Successfully listening on " << interface_ << " using libpcap.\n";

            pcap_loop(handle, 0, [](u_char* user, const struct pcap_pkthdr* header, const u_char* bytes) {
                if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;
                
                struct ether_header* eth = (struct ether_header*)bytes;
                if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;
                
                struct ip* iph = (struct ip*)(bytes + sizeof(struct ether_header));
                if (iph->ip_p != IPPROTO_TCP) return;
                
                int ip_len = iph->ip_hl * 4;
                if (header->caplen < sizeof(struct ether_header) + ip_len + sizeof(struct tcphdr)) return;
                
                struct tcphdr* tcph = (struct tcphdr*)(bytes + sizeof(struct ether_header) + ip_len);
                
                char src_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
                int dst_port = ntohs(tcph->dest);
                
                auto* cb = reinterpret_cast<Func*>(user);
                std::vector<uint8_t> payload(bytes, bytes + header->caplen);
                (*cb)(std::string(src_ip), dst_port, payload);
            }, reinterpret_cast<u_char*>(&callback));

            pcap_close(handle);
        }

    private:
        std::string interface_;
    };
}
