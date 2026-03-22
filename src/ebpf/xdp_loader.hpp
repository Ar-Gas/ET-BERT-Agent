#pragma once
#include <string>

namespace aegis::ebpf {

// Loads a compiled XDP BPF object file, attaches it to a network interface,
// and pins the aegis_blacklist map to /sys/fs/bpf/aegis_blacklist so that
// sec_tools can update it at runtime.
//
// Requires:
//   - libbpf (AEGIS_LIBBPF_AVAILABLE compile-time flag set by CMake)
//   - Root privileges
//   - A compiled xdp_filter.o in the same directory as the binary
//
// When libbpf is not available the class becomes a no-op and is_loaded()
// always returns false.  sec_tools will then fall back to iptables.
class XdpLoader {
public:
    // prog_obj_path : path to the compiled BPF .o file (e.g. "xdp_filter.o")
    // iface         : network interface to attach to (e.g. "ens33")
    XdpLoader(const std::string& prog_obj_path, const std::string& iface);
    ~XdpLoader();

    // Load, attach, and pin. Returns true on success.
    bool load();

    // Detach XDP program from the interface.
    void unload();

    bool is_loaded() const { return loaded_; }

    // Path where the BPF map is pinned (used by sec_tools).
    static constexpr const char* MAP_PIN_PATH = "/sys/fs/bpf/aegis_blacklist";

private:
    std::string prog_obj_path_;
    std::string iface_;
    bool        loaded_ = false;
    int         ifindex_ = -1;

    // Opaque pointers to libbpf objects.  Declared as void* so that this
    // header does not drag in <bpf/libbpf.h> for consumers that only need
    // the interface.
    void* bpf_obj_ = nullptr;    // struct bpf_object*
    int   prog_fd_ = -1;
};

} // namespace aegis::ebpf
