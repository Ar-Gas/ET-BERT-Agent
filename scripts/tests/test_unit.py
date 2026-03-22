"""
Unit tests — pure Python, no C++ probe required.
Tests: AlertDedup, IncidentLogger, WAFLogMonitor, CppProbeWrapper(mock mode)
"""
import json
import sys
import time
import tempfile
import threading
from pathlib import Path

# Make sure the scripts dir is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from multi_agent_soc import (
    AlertDedup,
    IncidentLogger,
    WAFLogMonitor,
    CppProbeWrapper,
)


# ─────────────────────────────────────────────────────────────────────────────
# AlertDedup
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertDedup:
    def test_first_alert_is_not_duplicate(self):
        d = AlertDedup(window_seconds=60)
        assert d.is_duplicate("1.2.3.4") is False

    def test_second_alert_within_window_is_duplicate(self):
        d = AlertDedup(window_seconds=60)
        d.is_duplicate("1.2.3.4")
        assert d.is_duplicate("1.2.3.4") is True

    def test_different_ips_are_independent(self):
        d = AlertDedup(window_seconds=60)
        d.is_duplicate("1.2.3.4")
        assert d.is_duplicate("5.6.7.8") is False

    def test_expired_window_allows_new_alert(self):
        d = AlertDedup(window_seconds=1)
        d.is_duplicate("1.2.3.4")
        time.sleep(1.1)
        assert d.is_duplicate("1.2.3.4") is False

    def test_thread_safety(self):
        """Multiple threads calling is_duplicate must not crash."""
        d = AlertDedup(window_seconds=60)
        errors = []

        def worker(ip):
            try:
                for _ in range(50):
                    d.is_duplicate(ip)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f"10.0.0.{i}",))
                   for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == [], f"Thread errors: {errors}"


# ─────────────────────────────────────────────────────────────────────────────
# IncidentLogger
# ─────────────────────────────────────────────────────────────────────────────

class TestIncidentLogger:
    def test_creates_incident_file(self, tmp_path, monkeypatch):
        import multi_agent_soc as soc
        monkeypatch.setattr(soc, "LOG_DIR", tmp_path)
        logger = IncidentLogger()
        incident = {
            "alert": {"src_ip": "1.2.3.4", "dst_port": 443, "confidence": 0.99},
            "decision": "blocked",
            "blocked": True,
        }
        out = logger.save(incident)
        assert out.exists()
        loaded = json.loads(out.read_text())
        assert loaded["blocked"] is True
        assert loaded["alert"]["src_ip"] == "1.2.3.4"

    def test_filename_contains_ip(self, tmp_path, monkeypatch):
        import multi_agent_soc as soc
        monkeypatch.setattr(soc, "LOG_DIR", tmp_path)
        logger = IncidentLogger()
        out = logger.save({"alert": {"src_ip": "9.8.7.6"}, "blocked": False})
        assert "9_8_7_6" in out.name


# ─────────────────────────────────────────────────────────────────────────────
# WAFLogMonitor
# ─────────────────────────────────────────────────────────────────────────────

class TestWAFLogMonitor:
    def test_reads_new_lines(self, tmp_path):
        log_file = tmp_path / "waf_alerts.log"
        received = []
        event    = threading.Event()

        def on_alert(a):
            received.append(a)
            event.set()

        monitor = WAFLogMonitor(str(log_file), on_alert)
        monitor.start()
        time.sleep(0.2)

        # Write a valid alert line
        log_file.write_text(f"{time.time()},1.2.3.4,/search,0.99,SQL injection\n")

        assert event.wait(timeout=3), "WAFLogMonitor did not fire callback"
        monitor.stop()

        assert len(received) >= 1
        assert received[0]["src_ip"] == "1.2.3.4"
        assert received[0]["confidence"] == pytest.approx(0.99, abs=0.01)
        assert received[0]["source"] == "waf"

    def test_skips_malformed_lines(self, tmp_path):
        log_file = tmp_path / "waf.log"
        log_file.write_text("not,valid\n")
        called = []
        monitor = WAFLogMonitor(str(log_file), called.append)
        monitor.start()
        time.sleep(0.5)
        monitor.stop()
        assert called == []


# ─────────────────────────────────────────────────────────────────────────────
# CppProbeWrapper — mock mode
# ─────────────────────────────────────────────────────────────────────────────

class TestCppProbeWrapperMock:
    @pytest.fixture
    def probe(self):
        return CppProbeWrapper(mock=True)

    def test_get_pid_returns_mock_pid(self, probe):
        result = probe.call_tool("get_pid_by_connection", {"ip": "1.2.3.4", "port": 443})
        assert result.get("status") == "success"
        assert isinstance(result.get("pid"), int)

    def test_analyze_process_returns_cmdline(self, probe):
        result = probe.call_tool("analyze_process_behavior", {"pid": 1234})
        assert result.get("status") == "success"
        assert "cmdline" in result.get("process_info", {})

    def test_block_ip_returns_success(self, probe):
        result = probe.call_tool("block_malicious_ip", {"ip": "1.2.3.4"})
        assert result.get("status") == "success"

    def test_unknown_tool_returns_failed(self, probe):
        result = probe.call_tool("nonexistent_tool", {})
        assert result.get("status") == "failed"
