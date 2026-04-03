"""Authentication middleware for robot.wtf.

Validates incoming requests and resolves them to a User record.
Two token flows:

1. Platform JWT (browser/API): Validated against our RS256 public key.
2. Bearer token (MCP): Opaque token checked against SHA-256 hashes.

No WorkOS -- ATProto OAuth is handled separately.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import jwt as pyjwt

from app.auth.jwt import PlatformJWT
from app.models.user import UserModel

logger = logging.getLogger(__name__)


@dataclass
class AuthenticatedUser:
    """User context set by auth middleware for downstream handlers."""

    user_did: str
    handle: str
    display_name: str
    # Full user record from SQLite
    record: dict[str, Any]


class AuthMiddleware:
    """JWT validation and user resolution middleware.

    Usage:
        middleware = AuthMiddleware(platform_jwt=..., user_model=...)
        user = middleware.authenticate(authorization_header)
    """

    def __init__(
        self,
        *,
        platform_jwt: PlatformJWT,
        user_model: UserModel,
    ):
        self._jwt = platform_jwt
        self._users = user_model

    def authenticate(self, authorization: str | None) -> AuthenticatedUser:
        """Validate an Authorization header and resolve to a user.

        Args:
            authorization: The Authorization header value
                (e.g., "Bearer <token>").

        Returns:
            AuthenticatedUser with resolved user context.

        Raises:
            AuthError: If the token is missing, invalid, expired,
                or the user is not found.
        """
        if not authorization:
            raise AuthError("Missing Authorization header", status=401)

        parts = authorization.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise AuthError("Invalid Authorization header format", status=401)

        token = parts[1]
        return self._validate_platform_jwt(token)

    def authenticate_from_cookie(self, cookie_header: str | None) -> AuthenticatedUser | None:
        """Extract and validate a platform JWT from the Cookie header.

        Looks for a cookie named 'platform_token'.

        Args:
            cookie_header: The raw Cookie header string.

        Returns:
            AuthenticatedUser if a valid token is found, None otherwise.
        """
        if not cookie_header:
            return None

        from http.cookies import SimpleCookie
        cookies = SimpleCookie()
        try:
            cookies.load(cookie_header)
        except Exception:
            logger.debug("cookie parsing failed", exc_info=True)
            return None

        token_cookie = cookies.get("platform_token")
        if not token_cookie:
            return None

        try:
            return self._validate_platform_jwt(token_cookie.value)
        except AuthError:
            return None

    def _validate_platform_jwt(self, token: str) -> AuthenticatedUser:
        """Validate a platform JWT and resolve to a user."""
        try:
            claims = self._jwt.validate_token(token)
        except pyjwt.ExpiredSignatureError:
            raise AuthError("Token expired", status=401)
        except pyjwt.InvalidTokenError as e:
            raise AuthError(f"Invalid token: {e}", status=401)

        user_did = claims.get("sub")
        if not user_did:
            raise AuthError("Token missing sub claim", status=401)

        user = self._users.get(user_did)
        if not user:
            raise AuthError("User not found", status=401)

        return AuthenticatedUser(
            user_did=user["did"],
            handle=user.get("handle", claims.get("handle", "")),
            display_name=user.get(
                "display_name", claims.get("name", "")
            ),
            record=user,
        )


class AuthError(Exception):
    """Authentication error with HTTP status code."""

    def __init__(self, message: str, status: int = 401):
        super().__init__(message)
        self.status = status
        self.message = message

    def to_response(self) -> dict[str, Any]:
        """Convert to a JSON-serializable error response."""
        return {
            "statusCode": self.status,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": self.message}),
        }
