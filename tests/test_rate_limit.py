"""Tests for app/rate_limit.py — WSGIRateLimiter and get_client_ip."""

from __future__ import annotations

import pytest

from app.rate_limit import WSGIRateLimiter, get_client_ip


class TestGetClientIP:
    def test_reads_remote_addr(self):
        """get_client_ip reads REMOTE_ADDR; ProxyFix is responsible for correcting it."""
        environ = {"REMOTE_ADDR": "1.2.3.4"}
        assert get_client_ip(environ) == "1.2.3.4"

    def test_ignores_x_forwarded_for(self):
        """XFF is NOT parsed — ProxyFix handles that before get_client_ip is called."""
        environ = {
            "HTTP_X_FORWARDED_FOR": "5.6.7.8",
            "REMOTE_ADDR": "127.0.0.1",
        }
        assert get_client_ip(environ) == "127.0.0.1"

    def test_missing_remote_addr_returns_loopback(self):
        environ = {}
        assert get_client_ip(environ) == "127.0.0.1"

    def test_proxyfix_corrected_addr_is_used(self):
        """Simulate what happens after ProxyFix runs: REMOTE_ADDR is the real client IP."""
        # ProxyFix would have moved the XFF value into REMOTE_ADDR
        environ = {
            "HTTP_X_FORWARDED_FOR": "5.6.7.8",  # stale; ProxyFix already processed it
            "REMOTE_ADDR": "9.9.9.9",            # ProxyFix-corrected real client IP
        }
        assert get_client_ip(environ) == "9.9.9.9"


class TestWSGIRateLimiter:
    def _make_limiter(self, limit_string="3/minute"):
        limiter = WSGIRateLimiter()
        limiter.add_limit("test", limit_string)
        return limiter

    def test_allows_requests_under_limit(self):
        limiter = self._make_limiter("5/minute")
        for _ in range(5):
            assert limiter.check("test", "192.168.1.1") is True

    def test_blocks_requests_over_limit(self):
        limiter = self._make_limiter("3/minute")
        # First 3 should pass
        for _ in range(3):
            limiter.check("test", "10.0.0.1")
        # 4th should be blocked
        assert limiter.check("test", "10.0.0.1") is False

    def test_different_keys_are_independent(self):
        limiter = self._make_limiter("2/minute")
        # Exhaust key A
        limiter.check("test", "key-a")
        limiter.check("test", "key-a")
        # key-a is now blocked
        assert limiter.check("test", "key-a") is False
        # key-b is not affected
        assert limiter.check("test", "key-b") is True

    def test_unknown_limit_name_allows(self):
        limiter = WSGIRateLimiter()
        # No limits registered — should always allow
        assert limiter.check("nonexistent", "any-key") is True

    def test_make_429_response_json(self):
        limiter = WSGIRateLimiter()
        status, headers, body = limiter.make_429_response(json_response=True)
        assert status == "429 Too Many Requests"
        header_dict = {k.lower(): v for k, v in headers}
        assert "application/json" in header_dict.get("content-type", "")
        assert header_dict.get("retry-after") == "60"
        import json
        data = json.loads(b"".join(body))
        assert "error" in data

    def test_make_429_response_html(self):
        limiter = WSGIRateLimiter()
        status, headers, body = limiter.make_429_response(json_response=False)
        assert status == "429 Too Many Requests"
        header_dict = {k.lower(): v for k, v in headers}
        assert "text/html" in header_dict.get("content-type", "")
        assert header_dict.get("retry-after") == "60"
        text = b"".join(body).decode()
        assert "429" in text
