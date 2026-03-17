"""Tests for app/rate_limit.py — WSGIRateLimiter and get_client_ip."""

from __future__ import annotations

import pytest

from app.rate_limit import WSGIRateLimiter, get_client_ip


class TestGetClientIP:
    def test_no_forwarded_for_uses_remote_addr(self):
        environ = {"REMOTE_ADDR": "1.2.3.4"}
        assert get_client_ip(environ) == "1.2.3.4"

    def test_single_forwarded_for(self):
        environ = {
            "HTTP_X_FORWARDED_FOR": "5.6.7.8",
            "REMOTE_ADDR": "127.0.0.1",
        }
        assert get_client_ip(environ) == "5.6.7.8"

    def test_multiple_forwarded_for_uses_last(self):
        """Trust the last (Caddy-appended) entry."""
        environ = {
            "HTTP_X_FORWARDED_FOR": "10.0.0.1, 10.0.0.2, 9.9.9.9",
            "REMOTE_ADDR": "127.0.0.1",
        }
        assert get_client_ip(environ) == "9.9.9.9"

    def test_forwarded_for_with_spaces(self):
        environ = {
            "HTTP_X_FORWARDED_FOR": "1.1.1.1 , 2.2.2.2",
            "REMOTE_ADDR": "127.0.0.1",
        }
        assert get_client_ip(environ) == "2.2.2.2"

    def test_empty_forwarded_for_falls_back_to_remote_addr(self):
        environ = {
            "HTTP_X_FORWARDED_FOR": "",
            "REMOTE_ADDR": "3.3.3.3",
        }
        assert get_client_ip(environ) == "3.3.3.3"

    def test_missing_everything_returns_loopback(self):
        environ = {}
        assert get_client_ip(environ) == "127.0.0.1"


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
        content_types = {k.lower(): v for k, v in headers}
        assert "application/json" in content_types.get("content-type", "")
        import json
        data = json.loads(b"".join(body))
        assert "error" in data

    def test_make_429_response_html(self):
        limiter = WSGIRateLimiter()
        status, headers, body = limiter.make_429_response(json_response=False)
        assert status == "429 Too Many Requests"
        content_types = {k.lower(): v for k, v in headers}
        assert "text/html" in content_types.get("content-type", "")
        text = b"".join(body).decode()
        assert "429" in text
