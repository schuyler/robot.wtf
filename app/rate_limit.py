"""Rate limiting utilities for robot.wtf services."""
import logging
from limits import parse
from limits.storage import MemoryStorage
from limits.strategies import FixedWindowRateLimiter

logger = logging.getLogger(__name__)


def get_client_ip(environ):
    """Extract client IP from WSGI environ, trusting one X-Forwarded-For hop."""
    forwarded = environ.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        # Trust the last entry (appended by Caddy)
        return forwarded.rsplit(",", 1)[-1].strip()
    return environ.get("REMOTE_ADDR", "127.0.0.1")


class WSGIRateLimiter:
    """Rate limiter for use in raw WSGI middleware."""

    def __init__(self):
        self._storage = MemoryStorage()
        self._strategy = FixedWindowRateLimiter(self._storage)
        self._limits = {}

    def add_limit(self, name, limit_string):
        """Register a named limit, e.g. add_limit("api_write", "5/minute")"""
        self._limits[name] = parse(limit_string)

    def check(self, name, key):
        """Check if the request is within limits. Returns True if allowed."""
        limit = self._limits.get(name)
        if not limit:
            return True
        return self._strategy.hit(limit, name, key)

    def make_429_response(self, message="Rate limit exceeded", json_response=True):
        """Return a WSGI 429 response tuple (status, headers, body)."""
        if json_response:
            import json
            body = json.dumps({"error": message})
            content_type = "application/json"
        else:
            body = f"<h1>429 Too Many Requests</h1><p>{message}</p>"
            content_type = "text/html"
        return ("429 Too Many Requests",
                [("Content-Type", content_type)],
                [body.encode()])
