#include "xdp_loader.hpp"
#include <iostream>

#ifdef AEGIS_LIBBPF_AVAILABLE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#endif

namespace aegis::ebpf {

XdpLoader::XdpLoader(const std::string& prog_obj_path, const std::string& iface)
    : prog_obj_path_(prog_obj_path), iface_(iface) {}

XdpLoader::~XdpLoader() {
    if (loaded_) unload();
#ifdef AEGIS_LIBBPF_AVAILABLE
    if (bpf_obj_) {
        bpf_object__close(static_cast<struct bpf_object*>(bpf_obj_));
        bpf_obj_ = nullptr;
    }
#endif
}

bool XdpLoader::load() {
#ifdef AEGIS_LIBBPF_AVAILABLE
    // --- 1. Resolve interface index ---
    ifindex_ = static_cast<int>(if_nametoindex(iface_.c_str()));
    if (ifindex_ == 0) {
        std::cerr << "[XdpLoader] Unknown interface: " << iface_ << "\n";
        return false;
    }

    // --- 2. Open BPF object ---
    struct bpf_object* obj = bpf_object__open_file(prog_obj_path_.c_str(), nullptr);
    if (libbpf_get_error(obj)) {
        std::cerr << "[XdpLoader] Failed to open BPF object: " << prog_obj_path_ << "\n";
        return false;
    }
    bpf_obj_ = obj;

    // --- 3. Load (verify + JIT) ---
    if (bpf_object__load(obj) != 0) {
        std::cerr << "[XdpLoader] BPF load/verify failed.\n";
        return false;
    }

    // --- 4. Find the XDP program by section name ---
    struct bpf_program* prog = bpf_object__find_program_by_name(obj, "xdp_firewall");
    if (!prog) {
        std::cerr << "[XdpLoader] Section 'xdp' not found in BPF object.\n";
        return false;
    }
    prog_fd_ = bpf_program__fd(prog);

    // --- 5. Attach to interface (generic XDP mode, works without driver support) ---
    if (bpf_xdp_attach(ifindex_, prog_fd_, XDP_FLAGS_UPDATE_IF_NOEXIST, nullptr) < 0) {
        std::cerr << "[XdpLoader] Failed to attach XDP program to " << iface_ << "\n";
        return false;
    }

    // --- 6. Pin the map so sec_tools can update it ---
    struct bpf_map* map = bpf_object__find_map_by_name(obj, "aegis_blacklist");
    if (!map) {
        std::cerr << "[XdpLoader] Map 'aegis_blacklist' not found.\n";
        bpf_xdp_detach(ifindex_, XDP_FLAGS_UPDATE_IF_NOEXIST, nullptr);
        return false;
    }
    // Remove stale pin
    ::unlink(MAP_PIN_PATH);
    if (bpf_map__pin(map, MAP_PIN_PATH) != 0) {
        std::cerr << "[XdpLoader] Failed to pin map to " << MAP_PIN_PATH << "\n";
        bpf_xdp_detach(ifindex_, XDP_FLAGS_UPDATE_IF_NOEXIST, nullptr);
        return false;
    }

    loaded_ = true;
    std::cerr << "[XdpLoader] XDP program attached to " << iface_
              << ", map pinned at " << MAP_PIN_PATH << "\n";
    return true;

#else
    std::cerr << "[XdpLoader] libbpf not available. XDP loading disabled "
                 "(iptables fallback will be used).\n";
    return false;
#endif
}

void XdpLoader::unload() {
#ifdef AEGIS_LIBBPF_AVAILABLE
    if (ifindex_ > 0) {
        bpf_xdp_detach(ifindex_, XDP_FLAGS_UPDATE_IF_NOEXIST, nullptr);
        ::unlink(MAP_PIN_PATH);
    }
#endif
    loaded_ = false;
    prog_fd_ = -1;
}

} // namespace aegis::ebpf
