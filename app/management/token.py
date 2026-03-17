"""MCP bearer token generation for robot.wtf."""

from __future__ import annotations

import hashlib
import secrets


def generate_mcp_token() -> tuple[str, str]:
    """Generate an MCP bearer token and its SHA-256 hash.

    Returns:
        Tuple of (plaintext_token, sha256_hex_hash).
    """
    plaintext = secrets.token_urlsafe(32)
    hashed = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    return plaintext, hashed
