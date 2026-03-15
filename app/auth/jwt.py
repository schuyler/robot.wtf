"""Platform JWT creation and validation (RS256) for robot.wtf.

Issues JWTs after ATProto authentication. These JWTs are used for all
subsequent browser/API authentication.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone, timedelta
from typing import Any

import jwt

# Default token lifetime: 24 hours
DEFAULT_TOKEN_LIFETIME = timedelta(hours=24)

# JWT issuer and audience
ISSUER = "robot.wtf"
AUDIENCE = "robot.wtf"

# Default key path
DEFAULT_SIGNING_KEY_PATH = "/srv/data/signing_key.pem"


def _load_keys() -> tuple[str, str]:
    """Load RSA keys from env vars or file path.

    Checks SIGNING_PRIVATE_KEY / SIGNING_PUBLIC_KEY env vars first,
    then falls back to loading from SIGNING_KEY_PATH.

    Returns:
        Tuple of (private_key_pem, public_key_pem).
    """
    private_key = os.environ.get("SIGNING_PRIVATE_KEY")
    public_key = os.environ.get("SIGNING_PUBLIC_KEY")

    if private_key and public_key:
        return private_key, public_key

    key_path = os.environ.get("SIGNING_KEY_PATH", DEFAULT_SIGNING_KEY_PATH)
    with open(key_path) as f:
        private_key = f.read()

    # Derive public key from private key
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
    )

    private_key_obj = load_pem_private_key(private_key.encode(), password=None)
    public_key = private_key_obj.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return private_key, public_key


class PlatformJWT:
    """Create and validate platform JWTs signed with RS256."""

    def __init__(self, private_key: str, public_key: str):
        """Initialize with PEM-encoded RSA keys.

        Args:
            private_key: PEM-encoded RSA private key for signing.
            public_key: PEM-encoded RSA public key for verification.
        """
        self._private_key = private_key
        self._public_key = public_key

    def create_token(
        self,
        user_did: str,
        handle: str,
        display_name: str,
        *,
        lifetime: timedelta | None = None,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Create a signed platform JWT.

        Args:
            user_did: The user's ATProto DID.
            handle: The user's ATProto handle.
            display_name: The user's display name.
            lifetime: Token lifetime. Defaults to 24 hours.
            extra_claims: Additional claims to include.

        Returns:
            Encoded JWT string.
        """
        now = datetime.now(timezone.utc)
        lifetime = lifetime or DEFAULT_TOKEN_LIFETIME

        payload = {
            "sub": user_did,
            "handle": handle,
            "name": display_name,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + lifetime,
        }
        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(payload, self._private_key, algorithm="RS256")

    def validate_token(self, token: str) -> dict[str, Any]:
        """Validate a platform JWT and return claims.

        Args:
            token: Encoded JWT string.

        Returns:
            Decoded claims dict.

        Raises:
            jwt.ExpiredSignatureError: Token has expired.
            jwt.InvalidTokenError: Token is invalid.
        """
        return jwt.decode(
            token,
            self._public_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
        )
