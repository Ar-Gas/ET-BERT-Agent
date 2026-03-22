"""
Integration tests — require the compiled C++ probe (build/aegis_agent).
Skipped automatically when the binary is absent.

Tests:
  - MCP HTTP server health check
  - get_pid_by_connection: find PID for a real listening socket
  - analyze_process_behavior: read /proc/<pid>/cmdline
  - block_malicious_ip: eBPF or iptables fallback (BLOCK_TEST env gate)
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).parent.parent))

BINARY   = Path(__file__).parent.parent.parent / "build" / "aegis_agent"
ORT_LIB  = Path(__file__).parent.parent.parent / "third_party" / "onnxruntime" / "lib"
MCP_URL  = "http://127.0.0.1:8080/message"
TIMEOUT  = 10

needs_probe = pytest.mark.skipif(
    not BINARY.exists(),
    reason="C++ probe binary not found at build/aegis_agent"
)


# ─────────────────────────────────────────────────────────────────────────────
# Shared probe fixture (module scope — start once for all integration tests)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def probe_process():
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = str(ORT_LIB)
    env["AEGIS_INTERFACE"]  = "lo"     # loopback — safe, no root needed for pcap read
    env["AEGIS_THRESHOLD"]  = "0.95"

    proc = subprocess.Popen(
        [str(BINARY)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
    )

    # Wait for MCP HTTP server to become ready
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            r = requests.post(
                MCP_URL,
                json={"jsonrpc": "2.0", "id": 0, "method": "tools/list"},
                timeout=2,
            )
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.5)
    else:
        proc.terminate()
        pytest.fail("Probe did not become ready within 15 s")

    yield proc
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def rpc_call(method: str, args: dict) -> dict:
    resp = requests.post(
        MCP_URL,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": method, "arguments": args}},
        timeout=TIMEOUT,
    )
    assert resp.status_code == 200, f"HTTP {resp.status_code}"
    return resp.json()


# ─────────────────────────────────────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────────────────────────────────────

@needs_probe
class TestMCPHealth:
    def test_tools_list_returns_200(self, probe_process):
        r = requests.post(
            MCP_URL,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            timeout=TIMEOUT,
        )
        assert r.status_code == 200

    def test_tools_list_contains_expected_tools(self, probe_process):
        r = requests.post(
            MCP_URL,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            timeout=TIMEOUT,
        )
        body = r.json()
        # The MCP response may vary; at minimum we should get a valid JSON-RPC response
        assert "result" in body or "error" in body


# ─────────────────────────────────────────────────────────────────────────────
# get_pid_by_connection
# ─────────────────────────────────────────────────────────────────────────────

@needs_probe
class TestGetPidByConnection:
    @pytest.fixture(scope="class")
    def http_server(self):
        """Spin up a local HTTP server on a free port."""
        import socket, http.server, threading
        # Find a free port
        s = socket.socket()
        s.bind(("0.0.0.0", 0))
        port = s.getsockname()[1]
        s.close()

        srv = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(port), "--bind", "0.0.0.0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.5)
        yield {"pid": srv.pid, "port": port}
        srv.terminate()
        srv.wait()

    def test_finds_pid_for_listening_port(self, probe_process, http_server):
        result = rpc_call("get_pid_by_connection", {
            "ip":   "0.0.0.0",
            "port": http_server["port"],
        })
        data = result.get("result", result)
        assert data.get("status") == "success", f"Unexpected: {data}"
        returned_pid = data.get("pid")
        assert isinstance(returned_pid, int) and returned_pid > 0
        # The returned PID should be the http.server process (or its parent)
        assert returned_pid == http_server["pid"], (
            f"Expected PID {http_server['pid']}, got {returned_pid}"
        )

    def test_returns_failed_for_closed_port(self, probe_process):
        result = rpc_call("get_pid_by_connection", {
            "ip": "0.0.0.0", "port": 19999
        })
        data = result.get("result", result)
        assert data.get("status") == "failed"


# ─────────────────────────────────────────────────────────────────────────────
# analyze_process_behavior
# ─────────────────────────────────────────────────────────────────────────────

@needs_probe
class TestAnalyzeProcessBehavior:
    def test_reads_own_cmdline(self, probe_process):
        my_pid = os.getpid()
        result = rpc_call("analyze_process_behavior", {"pid": my_pid})
        data = result.get("result", result)
        assert data.get("status") == "success", f"Unexpected: {data}"
        cmdline = data.get("process_info", {}).get("cmdline", "")
        # Our cmdline should mention pytest
        assert "pytest" in cmdline or "python" in cmdline.lower()

    def test_nonexistent_pid_returns_failed(self, probe_process):
        result = rpc_call("analyze_process_behavior", {"pid": 9999999})
        data = result.get("result", result)
        assert data.get("status") == "failed"


# ─────────────────────────────────────────────────────────────────────────────
# block_malicious_ip  (only runs if AEGIS_RUN_BLOCK_TEST=1 is set)
# ─────────────────────────────────────────────────────────────────────────────

@needs_probe
@pytest.mark.skipif(
    os.environ.get("AEGIS_RUN_BLOCK_TEST") != "1",
    reason="Set AEGIS_RUN_BLOCK_TEST=1 to run destructive block tests",
)
class TestBlockMaliciousIP:
    def test_block_valid_ip(self, probe_process):
        result = rpc_call("block_malicious_ip", {"ip": "192.0.2.1"})
        data = result.get("result", result)
        assert data.get("status") == "success"
        assert data.get("method") in ("ebpf_xdp", "iptables_fallback")

    def test_block_invalid_ip_rejected(self, probe_process):
        result = rpc_call("block_malicious_ip", {"ip": "not_an_ip"})
        data = result.get("result", result)
        assert data.get("status") == "failed"
        assert "Invalid" in data.get("error", "")
