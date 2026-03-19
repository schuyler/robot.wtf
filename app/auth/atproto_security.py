"""ATProto security: SSRF mitigations and hardened HTTP client.

Adapted from bluesky-social/cookbook (CC-0).
"""

import os
from urllib.parse import urlparse
import requests_hardened

_ALLOW_HTTP_PDS = os.environ.get("ALLOW_HTTP_PDS", "").lower() in ("true", "1")
if _ALLOW_HTTP_PDS and os.environ.get("FLASK_ENV") != "testing":
    raise RuntimeError(
        "ALLOW_HTTP_PDS requires FLASK_ENV=testing. "
        "This flag disables SSRF protections and must never be used in production."
    )


def is_safe_url(url):
    """Crude/partial SSRF filter for URLs."""
    parts = urlparse(url)
    # In test mode, allow HTTP to loopback addresses
    if _ALLOW_HTTP_PDS:
        if parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1"):
            return True
    # Production: require HTTPS with valid TLD
    if not (
        parts.scheme == "https"
        and parts.hostname is not None
        and parts.hostname == parts.netloc
        and parts.username is None
        and parts.password is None
        and parts.port is None
    ):
        return False

    segments = parts.hostname.split(".")
    if not (
        len(segments) >= 2
        and segments[-1] not in ["local", "arpa", "internal", "localhost"]
    ):
        return False

    if segments[-1].isdigit():
        return False

    return True


hardened_http = requests_hardened.Manager(
    requests_hardened.Config(
        default_timeout=(2, 10),
        never_redirect=True,
        ip_filter_enable=True,
        ip_filter_allow_loopback_ips=_ALLOW_HTTP_PDS,  # Only allow loopback in test mode
        user_agent_override="RobotWTF-ATProto/1.0",
    )
)
