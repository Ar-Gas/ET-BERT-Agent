"""
WAF Proxy tests — rule engine, ONNX scoring, alert log writing.
Tests run against the WAF logic directly (no server needed).
"""
import sys
import time
import tempfile
import json
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "waf"))


# ─────────────────────────────────────────────────────────────────────────────
# Rule engine
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleEngine:
    """Test _rule_score directly."""

    @pytest.fixture(autouse=True)
    def import_waf(self):
        import waf_proxy as waf
        self.waf = waf

    def test_sql_injection_detected(self):
        score, reason = self.waf._rule_score("GET /?id=1 UNION SELECT * FROM users HTTP/1.1")
        assert score >= 0.95
        assert "SQL" in reason or "union" in reason.lower()

    def test_xss_detected(self):
        score, reason = self.waf._rule_score("POST / HTTP/1.1\n\n<script>alert(1)</script>")
        assert score >= 0.95
        assert "XSS" in reason

    def test_path_traversal_detected(self):
        score, reason = self.waf._rule_score("GET /../../../../etc/passwd HTTP/1.1")
        assert score >= 0.95

    def test_rce_detected(self):
        # _rule_score operates on raw HTTP text (not URL-decoded)
        score, reason = self.waf._rule_score("POST / HTTP/1.1\n\n;cat /etc/passwd")
        assert score >= 0.95

    def test_ssrf_detected(self):
        score, reason = self.waf._rule_score("GET /?url=http://169.254.169.254/latest HTTP/1.1")
        assert score >= 0.95

    def test_normal_request_passes(self):
        score, _ = self.waf._rule_score("GET /api/users?page=1 HTTP/1.1\nHost: example.com")
        assert score < 0.95

    def test_benign_post_passes(self):
        raw = "POST /login HTTP/1.1\nContent-Type: application/json\n\n{\"user\":\"alice\",\"pass\":\"hello123\"}"
        score, _ = self.waf._rule_score(raw)
        assert score < 0.95


# ─────────────────────────────────────────────────────────────────────────────
# Tokenizer  (verify it matches C++ tokenizer)
# ─────────────────────────────────────────────────────────────────────────────

class TestTokenizer:
    @pytest.fixture(autouse=True)
    def import_waf(self):
        import waf_proxy as waf
        self.waf = waf

    def test_output_shape(self):
        ids, mask = self.waf._tokenize("hello world")
        assert ids.shape  == (1, 512)
        assert mask.shape == (1, 512)

    def test_cls_token(self):
        ids, mask = self.waf._tokenize("test")
        assert ids[0, 0] == 101    # [CLS]
        assert mask[0, 0] == 1

    def test_sep_token_after_content(self):
        """SEP should appear right after the encoded payload."""
        text = "AB"  # 2 bytes
        ids, _ = self.waf._tokenize(text)
        # Positions: [CLS]=0, A=1, B=2, [SEP]=3, PAD=4…
        assert ids[0, 3] == 102   # [SEP]
        assert ids[0, 4] == 0     # [PAD]

    def test_byte_offset_encoding(self):
        """Byte values should be shifted by +200."""
        text = "\x00\x01"
        ids, _ = self.waf._tokenize(text)
        assert ids[0, 1] == 200   # 0x00 + 200
        assert ids[0, 2] == 201   # 0x01 + 200

    def test_long_input_truncated_to_510(self):
        """Payload > 510 bytes should be truncated (512 - CLS - SEP)."""
        text = "A" * 1000
        ids, mask = self.waf._tokenize(text)
        # Position 511 should be [SEP] (last token), position 510 = byte
        assert ids[0, 511] == 102   # [SEP] at 511
        assert ids[0, 510] != 0     # last content byte present
        assert mask[0, 511] == 1
        assert mask[0, -1] == 1

    def test_attention_mask_covers_content(self):
        text = "XY"  # 2 bytes → positions 0,1,2,3 = CLS,X,Y,SEP
        _, mask = self.waf._tokenize(text)
        assert all(mask[0, :4] == 1)
        assert all(mask[0, 4:] == 0)


# ─────────────────────────────────────────────────────────────────────────────
# Alert log writer
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertWriter:
    def test_write_alert_creates_entry(self, tmp_path, monkeypatch):
        import waf_proxy as waf
        log_path = tmp_path / "waf_alerts.log"
        monkeypatch.setattr(waf, "WAF_ALERT_LOG", log_path)
        waf._write_alert("1.2.3.4", "/search", 0.99, "SQL injection")
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 1
        parts = lines[0].split(",")
        assert parts[1] == "1.2.3.4"
        assert float(parts[3]) == pytest.approx(0.99, abs=0.001)

    def test_write_alert_appends(self, tmp_path, monkeypatch):
        import waf_proxy as waf
        log_path = tmp_path / "waf_alerts.log"
        monkeypatch.setattr(waf, "WAF_ALERT_LOG", log_path)
        waf._write_alert("1.1.1.1", "/a", 0.99, "reason1")
        waf._write_alert("2.2.2.2", "/b", 0.98, "reason2")
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 2
