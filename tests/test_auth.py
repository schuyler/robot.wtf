"""Unit tests for JWT and ACL enforcement."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from app.auth.jwt import PlatformJWT
from app.auth.middleware import AuthError, AuthMiddleware, AuthenticatedUser
from app.auth.permissions import (
    ADMIN,
    READ,
    UPLOAD,
    WRITE,
    format_permission_header,
    permissions_for_role,
)


@pytest.fixture
def rsa_keys():
    """Generate an RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_pem, public_pem


@pytest.fixture
def platform_jwt(rsa_keys):
    private_pem, public_pem = rsa_keys
    return PlatformJWT(private_pem, public_pem)


# --- JWT ---


class TestPlatformJWT:
    def test_create_and_validate(self, platform_jwt):
        token = platform_jwt.create_token(
            user_did="did:plc:test1",
            handle="alice.bsky.social",
            display_name="Alice",
        )
        assert isinstance(token, str)

        claims = platform_jwt.validate_token(token)
        assert claims["sub"] == "did:plc:test1"
        assert claims["handle"] == "alice.bsky.social"
        assert claims["name"] == "Alice"
        assert claims["iss"] == "robot.wtf"
        assert claims["aud"] == "robot.wtf"

    def test_expired_token(self, platform_jwt):
        from datetime import timedelta

        token = platform_jwt.create_token(
            user_did="did:plc:test2",
            handle="bob.bsky.social",
            display_name="Bob",
            lifetime=timedelta(seconds=-1),
        )
        import jwt

        with pytest.raises(jwt.ExpiredSignatureError):
            platform_jwt.validate_token(token)

    def test_wrong_key(self, platform_jwt):
        token = platform_jwt.create_token(
            user_did="did:plc:test3",
            handle="charlie.bsky.social",
            display_name="Charlie",
        )
        # Create a different key pair
        other_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        other_public = other_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()

        wrong_jwt = PlatformJWT("unused", other_public)
        import jwt

        with pytest.raises(jwt.InvalidSignatureError):
            wrong_jwt.validate_token(token)

    def test_extra_claims(self, platform_jwt):
        token = platform_jwt.create_token(
            user_did="did:plc:test4",
            handle="dave.bsky.social",
            display_name="Dave",
            extra_claims={"custom": "value"},
        )
        claims = platform_jwt.validate_token(token)
        assert claims["custom"] == "value"


# --- Permissions ---


class TestPermissions:
    def test_owner_permissions(self):
        perms = permissions_for_role("owner")
        assert perms == (READ, WRITE, UPLOAD, ADMIN)

    def test_editor_permissions(self):
        perms = permissions_for_role("editor")
        assert perms == (READ, WRITE, UPLOAD)

    def test_viewer_permissions(self):
        perms = permissions_for_role("viewer")
        assert perms == (READ,)

    def test_unknown_role(self):
        with pytest.raises(ValueError, match="Unknown role"):
            permissions_for_role("superadmin")

    def test_format_permission_header(self):
        assert format_permission_header((READ, WRITE)) == "READ,WRITE"
        assert format_permission_header((READ,)) == "READ"


# --- AuthMiddleware ---


class TestAuthMiddleware:
    def test_authenticate_success(self, db, platform_jwt, user_model):
        user_model.create(
            did="did:plc:mw1",
            handle="mw.bsky.social",
            display_name="MW User",
            username="mwuser",
        )
        token = platform_jwt.create_token(
            user_did="did:plc:mw1",
            handle="mw.bsky.social",
            display_name="MW User",
        )
        middleware = AuthMiddleware(
            platform_jwt=platform_jwt, user_model=user_model
        )
        authed = middleware.authenticate(f"Bearer {token}")
        assert authed.user_did == "did:plc:mw1"
        assert authed.handle == "mw.bsky.social"

    def test_authenticate_missing_header(self, platform_jwt, user_model):
        middleware = AuthMiddleware(
            platform_jwt=platform_jwt, user_model=user_model
        )
        with pytest.raises(AuthError) as exc_info:
            middleware.authenticate(None)
        assert exc_info.value.status == 401

    def test_authenticate_bad_format(self, platform_jwt, user_model):
        middleware = AuthMiddleware(
            platform_jwt=platform_jwt, user_model=user_model
        )
        with pytest.raises(AuthError) as exc_info:
            middleware.authenticate("Basic abc123")
        assert exc_info.value.status == 401

    def test_authenticate_user_not_found(self, db, platform_jwt, user_model):
        token = platform_jwt.create_token(
            user_did="did:plc:ghost",
            handle="ghost.bsky.social",
            display_name="Ghost",
        )
        middleware = AuthMiddleware(
            platform_jwt=platform_jwt, user_model=user_model
        )
        with pytest.raises(AuthError) as exc_info:
            middleware.authenticate(f"Bearer {token}")
        assert exc_info.value.status == 401
        assert "not found" in exc_info.value.message.lower()
