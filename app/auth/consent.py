"""Consent token creation and verification for MCP OAuth flow.

The auth service creates consent tokens to bind user approval to OAuth
authorization requests. The MCP server verifies these tokens when the
user is redirected back after consenting.

Both services share the same platform signing key, so HMAC-based
tokens work without a shared database.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time


# Consent token lifetime defaults
CONSENT_TOKEN_LIFETIME = 10 * 60  # 10 minutes
APPROVAL_TOKEN_LIFETIME = 120  # 2 minutes

# OAuth params preserved through the consent flow
OAUTH_PARAM_NAMES = (
    "client_id", "redirect_uri", "code_challenge", "code_challenge_method",
    "state", "scope", "response_type", "resource",
)


def derive_signing_key(private_key_material: str) -> bytes:
    """Derive an HMAC signing key from platform private key material.

    Uses a prefix to domain-separate the consent key from other uses
    of the same key material.

    Args:
        private_key_material: Full PEM private key string.
    """
    return hashlib.sha256(
        f"consent:{private_key_material}".encode()
    ).digest()


def sign_token(payload: dict, signing_key: bytes) -> str:
    """Create an HMAC-signed JSON token.

    Args:
        payload: Dict to sign. Must include an "exp" field.
        signing_key: HMAC key bytes.

    Returns:
        "{json_payload}|{hex_signature}"
    """
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sig = hmac.new(signing_key, payload_json.encode(), hashlib.sha256).hexdigest()
    return f"{payload_json}|{sig}"


def verify_token(token: str, signing_key: bytes) -> dict | None:
    """Verify and decode a consent token.

    Args:
        token: The signed token string.
        signing_key: HMAC key bytes (must match the key used to sign).

    Returns:
        Decoded payload dict, or None if invalid/expired.
    """
    if "|" not in token:
        return None
    payload_json, sig = token.rsplit("|", 1)
    expected = hmac.new(
        signing_key, payload_json.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(payload_json)
    except json.JSONDecodeError:
        return None
    if payload.get("exp", 0) < time.time():
        return None
    return payload
