"""MCP bearer token generation for robot.wtf."""

from __future__ import annotations

import secrets

import bcrypt


def generate_mcp_token() -> tuple[str, str]:
    """Generate an MCP bearer token and its bcrypt hash.

    Returns:
        Tuple of (plaintext_token, bcrypt_hash).
    """
    plaintext = secrets.token_urlsafe(32)
    hashed = bcrypt.hashpw(
        plaintext.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
    return plaintext, hashed
