"""Tests for the auth server (ATProto OAuth flow).

All ATProto network calls are mocked — these tests exercise the auth
server's routing, cookie handling, signup flow, and JWKS endpoint.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from authlib.jose import JsonWebKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from app.db import init_schema


# --- Fixtures ---


@pytest.fixture
def rsa_keys(tmp_path):
    """Generate RSA key pair and write to a temp file."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()
    key_path = tmp_path / "signing_key.pem"
    key_path.write_text(private_pem)
    return str(key_path), private_pem


@pytest.fixture
def client_jwk(tmp_path):
    """Generate an EC P-256 JWK and write to a temp file."""
    jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)
    jwk_data = json.loads(jwk.as_json(is_private=True))
    jwk_path = tmp_path / "client_jwk.json"
    jwk_path.write_text(json.dumps(jwk_data))
    return str(jwk_path), jwk


@pytest.fixture
def db_path(tmp_path):
    """Create a temp SQLite DB with schema."""
    path = str(tmp_path / "test.db")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    init_schema(conn)
    conn.close()
    return path


@pytest.fixture
def app(db_path, client_jwk, rsa_keys):
    """Create the auth Flask app with test configuration."""
    jwk_path, _ = client_jwk
    key_path, _ = rsa_keys

    # Set env vars before importing
    os.environ["ROBOT_DB_PATH"] = db_path
    os.environ["CLIENT_JWK_PATH"] = jwk_path
    os.environ["SIGNING_KEY_PATH"] = key_path
    os.environ["PLATFORM_DOMAIN"] = "robot.wtf"
    os.environ["FLASK_SECRET_KEY"] = "test-secret"

    from app.auth_server import create_app
    application = create_app(
        db_path=db_path,
        client_jwk_path=jwk_path,
        signing_key_path=key_path,
    )
    application.config["TESTING"] = True
    yield application

    # Clean up env vars
    for key in ["ROBOT_DB_PATH", "CLIENT_JWK_PATH", "SIGNING_KEY_PATH",
                "FLASK_SECRET_KEY"]:
        os.environ.pop(key, None)


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def platform_jwt_instance(rsa_keys):
    """Create a PlatformJWT for generating test tokens."""
    _, private_pem = rsa_keys
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
    priv = load_pem_private_key(private_pem.encode(), password=None)
    pub_pem = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    from app.auth.jwt import PlatformJWT
    return PlatformJWT(private_pem, pub_pem)


# --- Client Metadata ---


class TestClientMetadata:
    def test_client_metadata_returns_correct_structure(self, client):
        resp = client.get("/auth/client-metadata.json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["client_id"] == "https://robot.wtf/auth/client-metadata.json"
        assert data["dpop_bound_access_tokens"] is True
        assert data["application_type"] == "web"
        assert data["redirect_uris"] == ["https://robot.wtf/auth/callback"]
        assert data["grant_types"] == ["authorization_code", "refresh_token"]
        assert data["response_types"] == ["code"]
        assert data["scope"] == "atproto"
        assert data["token_endpoint_auth_method"] == "private_key_jwt"
        assert data["token_endpoint_auth_signing_alg"] == "ES256"
        assert "keys" in data["jwks"]
        assert len(data["jwks"]["keys"]) == 1
        # Public key must not contain private material
        assert "d" not in data["jwks"]["keys"][0]
        assert data["client_name"] == "robot.wtf"

    def test_client_metadata_content_type(self, client):
        resp = client.get("/auth/client-metadata.json")
        assert "application/json" in resp.content_type


# --- Login Page ---


class TestLoginPage:
    def test_login_get_renders_form(self, client):
        resp = client.get("/auth/login")
        assert resp.status_code == 200
        assert b"Bluesky" in resp.data
        assert b"username" in resp.data

    def test_login_post_invalid_handle(self, client):
        resp = client.post("/auth/login", data={"username": "not a handle"})
        assert resp.status_code == 400

    def test_login_post_empty_handle(self, client):
        resp = client.post("/auth/login", data={"username": ""})
        assert resp.status_code == 400


class TestJWTAutoRedirect:
    """GET /auth/login with existing JWT cookie."""

    def test_valid_jwt_redirects_to_app(self, client, platform_jwt_instance):
        """Valid JWT cookie -> redirect to /app/."""
        token = platform_jwt_instance.create_token(
            user_did="did:plc:auto1", handle="auto.bsky.social", display_name="Auto"
        )
        client.set_cookie("platform_token", token)
        resp = client.get("/auth/login")
        assert resp.status_code == 302
        assert resp.headers["Location"] == "https://robot.wtf/app/"

    def test_valid_jwt_redirects_to_return_to(self, client, platform_jwt_instance):
        """Valid JWT + safe return_to -> redirect there."""
        token = platform_jwt_instance.create_token(
            user_did="did:plc:auto2", handle="auto2.bsky.social", display_name="Auto2"
        )
        client.set_cookie("platform_token", token)
        resp = client.get("/auth/login?return_to=/some/page")
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/some/page"

    def test_valid_jwt_unsafe_return_to_falls_back(self, client, platform_jwt_instance):
        """Valid JWT + unsafe return_to -> redirect to /app/."""
        token = platform_jwt_instance.create_token(
            user_did="did:plc:auto3", handle="auto3.bsky.social", display_name="Auto3"
        )
        client.set_cookie("platform_token", token)
        resp = client.get("/auth/login?return_to=https://evil.com/steal")
        assert resp.status_code == 302
        assert resp.headers["Location"] == "https://robot.wtf/app/"

    def test_valid_jwt_clears_stale_session_return_to(self, client, platform_jwt_instance):
        """Valid JWT redirect clears stale session return_to."""
        token = platform_jwt_instance.create_token(
            user_did="did:plc:auto4", handle="auto4.bsky.social", display_name="Auto4"
        )
        client.set_cookie("platform_token", token)
        with client.session_transaction() as sess:
            sess["return_to"] = "/stale/session/path"
        resp = client.get("/auth/login")
        assert resp.status_code == 302
        assert resp.headers["Location"] == "https://robot.wtf/app/"
        with client.session_transaction() as sess:
            assert "return_to" not in sess

    def test_valid_jwt_does_not_write_session(self, client, platform_jwt_instance):
        """Auto-redirect must not write return_to to session."""
        token = platform_jwt_instance.create_token(
            user_did="did:plc:auto5", handle="auto5.bsky.social", display_name="Auto5"
        )
        client.set_cookie("platform_token", token)
        resp = client.get("/auth/login?return_to=/new/path")
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            assert "return_to" not in sess

    def test_expired_jwt_prefills_handle(self, client, platform_jwt_instance):
        """Expired JWT -> render login form with handle pre-filled."""
        from datetime import timedelta
        token = platform_jwt_instance.create_token(
            user_did="did:plc:exp1",
            handle="expired.bsky.social",
            display_name="Expired",
            lifetime=timedelta(seconds=-1),
        )
        client.set_cookie("platform_token", token)
        resp = client.get("/auth/login")
        assert resp.status_code == 200
        assert b"expired.bsky.social" in resp.data

    def test_expired_jwt_caps_prefill_handle_length(self, client, platform_jwt_instance):
        """Expired JWT with overlong handle is capped."""
        from datetime import timedelta
        token = platform_jwt_instance.create_token(
            user_did="did:plc:long1",
            handle="a" * 1000,
            display_name="Long",
            lifetime=timedelta(seconds=-1),
        )
        client.set_cookie("platform_token", token)
        resp = client.get("/auth/login")
        assert resp.status_code == 200
        # Handle should be capped at 253 chars
        assert b"a" * 1000 not in resp.data
        assert b"a" * 253 in resp.data

    def test_garbage_cookie_renders_normal_form(self, client):
        """Non-JWT garbage in cookie -> normal login form."""
        client.set_cookie("platform_token", "not-a-jwt-at-all")
        resp = client.get("/auth/login")
        assert resp.status_code == 200
        assert b"Bluesky" in resp.data

    def test_no_cookie_renders_normal_form(self, client):
        """No cookie -> normal login form (baseline)."""
        resp = client.get("/auth/login")
        assert resp.status_code == 200
        assert b"Bluesky" in resp.data


# --- OAuth Callback ---


class TestOAuthCallback:
    def test_callback_error_redirects(self, client):
        resp = client.get(
            "/auth/callback?error=access_denied&error_description=User+cancelled"
        )
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]

    def test_callback_missing_params(self, client):
        resp = client.get("/auth/callback?state=foo")
        assert resp.status_code == 400

    def test_callback_unknown_state(self, client):
        resp = client.get(
            "/auth/callback?state=unknown&iss=https://bsky.social&code=abc"
        )
        assert resp.status_code == 400

    @patch("app.auth_server.initial_token_request")
    @patch("app.auth_server._fetch_display_name")
    def test_callback_returning_user_sets_cookie(
        self, mock_display, mock_token, app, client, db_path
    ):
        """Simulate a returning user completing OAuth — should get a JWT cookie."""
        mock_display.return_value = "Alice Test"
        mock_token.return_value = (
            {"sub": "did:plc:testcb1", "scope": "atproto", "access_token": "at1", "refresh_token": "rt1"},
            "nonce1",
        )

        # Pre-create user in DB (no username)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (did, handle, display_name, created_at) VALUES (?, ?, ?, ?)",
            ("did:plc:testcb1", "alice.bsky.social", "Alice", now),
        )

        # Create a DPoP JWK for the auth request
        dpop_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)

        # Insert an auth request
        conn.execute(
            """INSERT INTO oauth_auth_requests
               (state, authserver_iss, did, handle, pds_url, pkce_verifier,
                scope, dpop_authserver_nonce, dpop_private_jwk, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                "test-state-1",
                "https://bsky.social",
                "did:plc:testcb1",
                "alice.bsky.social",
                "https://pds.bsky.social",
                "verifier123",
                "atproto",
                "nonce0",
                dpop_jwk.as_json(is_private=True),
                now,
            ],
        )
        conn.commit()
        conn.close()

        resp = client.get(
            "/auth/callback?state=test-state-1&iss=https://bsky.social&code=authcode1"
        )

        assert resp.status_code == 302
        # Should set a platform_token cookie
        cookie_header = resp.headers.get("Set-Cookie", "")
        assert "platform_token=" in cookie_header
        assert "HttpOnly" in cookie_header
        assert "Secure" in cookie_header
        assert resp.headers["Location"].endswith("/app/")

    @patch("app.auth_server.initial_token_request")
    @patch("app.auth_server._fetch_display_name")
    def test_callback_return_to_takes_precedence(
        self, mock_display, mock_token, app, client, db_path
    ):
        """return_to in session should override /app/ default after OAuth callback."""
        mock_display.return_value = "Alice Test"
        mock_token.return_value = (
            {"sub": "did:plc:testcb2", "scope": "atproto", "access_token": "at3", "refresh_token": "rt3"},
            "nonce3",
        )

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (did, handle, display_name, created_at) VALUES (?, ?, ?, ?)",
            ("did:plc:testcb2", "alice2.bsky.social", "Alice2", now),
        )
        dpop_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)
        conn.execute(
            """INSERT INTO oauth_auth_requests
               (state, authserver_iss, did, handle, pds_url, pkce_verifier,
                scope, dpop_authserver_nonce, dpop_private_jwk, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                "test-state-rt",
                "https://bsky.social",
                "did:plc:testcb2",
                "alice2.bsky.social",
                "https://pds.bsky.social",
                "verifier789",
                "atproto",
                "nonce0",
                dpop_jwk.as_json(is_private=True),
                now,
            ],
        )
        conn.commit()
        conn.close()

        with client.session_transaction() as sess:
            sess["return_to"] = "/auth/oauth/consent?client_id=test-client"

        resp = client.get(
            "/auth/callback?state=test-state-rt&iss=https://bsky.social&code=authcode3"
        )

        assert resp.status_code == 302
        assert resp.headers["Location"] == "/auth/oauth/consent?client_id=test-client"
        assert not resp.headers["Location"].endswith("/app/")

    @patch("app.auth_server.initial_token_request")
    @patch("app.auth_server._fetch_display_name")
    def test_callback_new_user_auto_creates_and_sets_cookie(
        self, mock_display, mock_token, app, client, db_path
    ):
        """A first-time user should be auto-created and get a JWT cookie."""
        mock_display.return_value = "New User"
        mock_token.return_value = (
            {"sub": "did:plc:newuser1", "scope": "atproto", "access_token": "at2", "refresh_token": "rt2"},
            "nonce2",
        )

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        now = datetime.now(timezone.utc).isoformat()
        dpop_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)
        conn.execute(
            """INSERT INTO oauth_auth_requests
               (state, authserver_iss, did, handle, pds_url, pkce_verifier,
                scope, dpop_authserver_nonce, dpop_private_jwk, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                "test-state-new",
                "https://bsky.social",
                "did:plc:newuser1",
                "newuser.bsky.social",
                "https://pds.bsky.social",
                "verifier456",
                "atproto",
                "nonce0",
                dpop_jwk.as_json(is_private=True),
                now,
            ],
        )
        conn.commit()
        conn.close()

        resp = client.get(
            "/auth/callback?state=test-state-new&iss=https://bsky.social&code=authcode2"
        )
        assert resp.status_code == 302
        # Should set a platform_token cookie (user auto-created)
        cookie_header = resp.headers.get("Set-Cookie", "")
        assert "platform_token=" in cookie_header
        # Should NOT redirect to signup
        assert "/auth/signup" not in resp.headers["Location"]
        assert resp.headers["Location"].endswith("/app/")

        # Verify user was created in DB
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM users WHERE did = ?", ("did:plc:newuser1",)
        ).fetchone()
        conn.close()
        assert row is not None
        assert row["handle"] == "newuser.bsky.social"



# --- Logout ---


class TestLogout:
    def test_logout_clears_cookie(self, client):
        resp = client.get("/auth/logout")
        assert resp.status_code == 302
        cookie_header = resp.headers.get("Set-Cookie", "")
        # Cookie should be expired/deleted
        assert "platform_token=" in cookie_header


# --- JWKS Endpoint ---


class TestJWKS:
    def test_jwks_returns_key(self, client):
        resp = client.get("/.well-known/jwks.json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "keys" in data
        assert len(data["keys"]) == 1
        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"
        assert "n" in key
        assert "e" in key
        # Must not contain private material
        assert "d" not in key
        assert "p" not in key
        assert "q" not in key

    def test_jwks_content_type(self, client):
        resp = client.get("/.well-known/jwks.json")
        assert "application/json" in resp.content_type


# --- AS Metadata ---


class TestASMetadata:
    def test_as_metadata(self, client):
        resp = client.get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["issuer"] == "https://robot.wtf"
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "jwks_uri" in data


# --- Return-to URL Validation ---


class TestReturnToValidation:
    """_is_safe_return_url accepts relative + wiki subdomain URLs, rejects external."""

    def test_return_to_accepts_relative(self):
        from app.auth_server import _is_safe_return_url
        assert _is_safe_return_url("/app/") is True
        assert _is_safe_return_url("/auth/oauth/consent?client_id=x") is True

    def test_return_to_accepts_wiki_subdomain(self):
        from app.auth_server import _is_safe_return_url
        assert _is_safe_return_url("https://foo.robot.wtf/Page") is True
        assert _is_safe_return_url("https://untangling-collective.robot.wtf/") is True

    def test_return_to_rejects_external_domain(self):
        from app.auth_server import _is_safe_return_url
        assert _is_safe_return_url("https://evil.com/") is False
        assert _is_safe_return_url("http://robot.wtf.evil.com/") is False

    def test_return_to_rejects_bare_platform_domain(self):
        """The bare platform domain (robot.wtf) is not a wiki subdomain."""
        from app.auth_server import _is_safe_return_url
        # robot.wtf itself is not *.robot.wtf
        assert _is_safe_return_url("https://robot.wtf/app/") is False

    def test_return_to_rejects_empty_string(self):
        from app.auth_server import _is_safe_return_url
        assert _is_safe_return_url("") is False

    def test_post_login_redirects_to_wiki(self, app, client, db_path):
        """After login, wiki subdomain return_to in session causes redirect there."""
        from unittest.mock import patch
        import sqlite3
        from datetime import datetime, timezone
        from authlib.jose import JsonWebKey

        with patch("app.auth_server.initial_token_request") as mock_token, \
             patch("app.auth_server._fetch_display_name") as mock_display:
            mock_display.return_value = "Alice"
            mock_token.return_value = (
                {
                    "sub": "did:plc:retto1",
                    "scope": "atproto",
                    "access_token": "at_retto",
                    "refresh_token": "rt_retto",
                },
                "nonce_retto",
            )

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO users (did, handle, display_name, created_at) VALUES (?, ?, ?, ?)",
                ("did:plc:retto1", "alice.bsky.social", "Alice", now),
            )
            dpop_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)
            conn.execute(
                """INSERT INTO oauth_auth_requests
                   (state, authserver_iss, did, handle, pds_url, pkce_verifier,
                    scope, dpop_authserver_nonce, dpop_private_jwk, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    "state-retto",
                    "https://bsky.social",
                    "did:plc:retto1",
                    "alice.bsky.social",
                    "https://pds.bsky.social",
                    "verifier_retto",
                    "atproto",
                    "nonce0",
                    dpop_jwk.as_json(is_private=True),
                    now,
                ],
            )
            conn.commit()
            conn.close()

            with client.session_transaction() as sess:
                sess["return_to"] = "https://gruen.robot.wtf/SomePage"

            resp = client.get(
                "/auth/callback?state=state-retto&iss=https://bsky.social&code=code_retto"
            )
            assert resp.status_code == 302
            assert resp.headers["Location"] == "https://gruen.robot.wtf/SomePage"

    def test_login_page_sets_return_to_unconditionally(self, client):
        """GET /auth/login?return_to=... stores it in session, overwriting stale value."""
        with client.session_transaction() as sess:
            sess["return_to"] = "/old/stale/path"

        resp = client.get("/auth/login?return_to=/new/path")
        assert resp.status_code == 200

        with client.session_transaction() as sess:
            assert sess.get("return_to") == "/new/path"


# --- Default Username Derivation ---


class TestDefaultUsername:
    def test_simple_handle(self):
        from app.models.user import default_username_from_handle
        assert default_username_from_handle("alice.bsky.social") == "alice"

    def test_handle_with_uppercase(self):
        from app.models.user import default_username_from_handle
        assert default_username_from_handle("Alice.bsky.social") == "alice"

    def test_short_prefix(self):
        from app.models.user import default_username_from_handle
        # "ab" is too short, should get padded
        result = default_username_from_handle("ab.bsky.social")
        assert len(result) >= 3

    def test_handle_with_special_chars(self):
        from app.models.user import default_username_from_handle
        result = default_username_from_handle("test_user.bsky.social")
        # underscore stripped, result is "testuser"
        assert "_" not in result
        assert result == "testuser"


# --- FLASK_SECRET_KEY Enforcement ---


class TestFlaskSecretKeyEnforcement:
    """FLASK_SECRET_KEY must be set in production; dev default is rejected."""

    def test_missing_secret_key_raises_in_production(self, db_path, client_jwk, rsa_keys):
        """create_app() without FLASK_SECRET_KEY raises RuntimeError."""
        jwk_path, _ = client_jwk
        key_path, _ = rsa_keys

        # Set paths so module-level import works
        os.environ["CLIENT_JWK_PATH"] = jwk_path
        os.environ["SIGNING_KEY_PATH"] = key_path
        os.environ["ROBOT_DB_PATH"] = db_path
        saved = os.environ.pop("FLASK_SECRET_KEY", None)
        os.environ.pop("FLASK_ENV", None)  # not testing mode
        try:
            from app.auth_server import create_app
            with pytest.raises(RuntimeError, match="FLASK_SECRET_KEY"):
                create_app(
                    db_path=db_path,
                    client_jwk_path=jwk_path,
                    signing_key_path=key_path,
                )
        finally:
            if saved is not None:
                os.environ["FLASK_SECRET_KEY"] = saved

    def test_dev_default_secret_key_raises_in_production(self, db_path, client_jwk, rsa_keys):
        """create_app() with the dev-default key raises RuntimeError."""
        jwk_path, _ = client_jwk
        key_path, _ = rsa_keys

        os.environ["CLIENT_JWK_PATH"] = jwk_path
        os.environ["SIGNING_KEY_PATH"] = key_path
        os.environ["ROBOT_DB_PATH"] = db_path
        saved_key = os.environ.get("FLASK_SECRET_KEY")
        saved_env = os.environ.get("FLASK_ENV")
        os.environ["FLASK_SECRET_KEY"] = "dev-secret-change-me"
        os.environ.pop("FLASK_ENV", None)
        try:
            from app.auth_server import create_app
            with pytest.raises(RuntimeError, match="FLASK_SECRET_KEY"):
                create_app(
                    db_path=db_path,
                    client_jwk_path=jwk_path,
                    signing_key_path=key_path,
                )
        finally:
            if saved_key is not None:
                os.environ["FLASK_SECRET_KEY"] = saved_key
            else:
                os.environ.pop("FLASK_SECRET_KEY", None)
            if saved_env is not None:
                os.environ["FLASK_ENV"] = saved_env

    def test_valid_secret_key_works(self, db_path, client_jwk, rsa_keys):
        """create_app() with a real secret key succeeds."""
        jwk_path, _ = client_jwk
        key_path, _ = rsa_keys
        os.environ["CLIENT_JWK_PATH"] = jwk_path
        os.environ["SIGNING_KEY_PATH"] = key_path
        os.environ["ROBOT_DB_PATH"] = db_path
        os.environ["FLASK_SECRET_KEY"] = "a-proper-secret-key-for-testing-xyz"
        try:
            from app.auth_server import create_app
            application = create_app(
                db_path=db_path,
                client_jwk_path=jwk_path,
                signing_key_path=key_path,
            )
            assert application.secret_key == "a-proper-secret-key-for-testing-xyz"
        finally:
            os.environ.pop("FLASK_SECRET_KEY", None)


# --- Rate Limiting ---


class TestRateLimiting:
    """Auth server route rate limiting.

    Flask-Limiter disables itself when TESTING=True. To exercise rate limits,
    we must set RATELIMIT_ENABLED=True explicitly in the app config.
    """

    @pytest.fixture
    def rate_limit_app(self, db_path, client_jwk, rsa_keys):
        """Auth app with rate limiting enabled (overrides TESTING=True disabling)."""
        jwk_path, _ = client_jwk
        key_path, _ = rsa_keys

        os.environ["ROBOT_DB_PATH"] = db_path
        os.environ["CLIENT_JWK_PATH"] = jwk_path
        os.environ["SIGNING_KEY_PATH"] = key_path
        os.environ["PLATFORM_DOMAIN"] = "robot.wtf"
        os.environ["FLASK_SECRET_KEY"] = "test-secret"

        from app.auth_server import create_app
        application = create_app(
            db_path=db_path,
            client_jwk_path=jwk_path,
            signing_key_path=key_path,
        )
        application.config["TESTING"] = True
        application.config["RATELIMIT_ENABLED"] = True

        yield application

        for key in ["ROBOT_DB_PATH", "CLIENT_JWK_PATH", "SIGNING_KEY_PATH",
                    "FLASK_SECRET_KEY"]:
            os.environ.pop(key, None)

    @pytest.fixture
    def rate_limit_client(self, rate_limit_app):
        return rate_limit_app.test_client()

    def test_login_post_rate_limited(self, rate_limit_client):
        """POST /auth/login should return 429 after exceeding limit (1/minute per IP)."""
        # The limit is 1/minute. First request may succeed (400 for bad handle is fine),
        # but subsequent requests within the same window should get 429.
        data = {"username": "not-a-valid-handle"}
        responses = []
        for _ in range(3):
            resp = rate_limit_client.post(
                "/auth/login",
                data=data,
                environ_base={"REMOTE_ADDR": "1.2.3.4"},
            )
            responses.append(resp.status_code)

        assert 429 in responses, (
            f"Expected at least one 429 after exceeding login rate limit; got: {responses}"
        )

    def test_oauth_consent_post_rate_limited(self, rate_limit_client):
        """POST /auth/oauth/consent should return 429 after exceeding limit (2/minute per IP)."""
        data = {"action": "approve"}
        responses = []
        for _ in range(4):
            resp = rate_limit_client.post(
                "/auth/oauth/consent",
                data=data,
                environ_base={"REMOTE_ADDR": "3.4.5.6"},
            )
            responses.append(resp.status_code)

        assert 429 in responses, (
            f"Expected at least one 429 after exceeding oauth_consent rate limit; got: {responses}"
        )


# --- normalize_handle unit tests ---


class TestNormalizeHandle:
    """Unit tests for normalize_handle()."""

    def setup_method(self):
        from app.auth_server import normalize_handle
        self.normalize_handle = normalize_handle

    def test_bare_handle_appends_bsky_social(self):
        assert self.normalize_handle("alice") == "alice.bsky.social"

    def test_full_handle_unchanged(self):
        assert self.normalize_handle("alice.bsky.social") == "alice.bsky.social"

    def test_custom_domain_unchanged(self):
        assert self.normalize_handle("alice.custom.domain") == "alice.custom.domain"

    def test_did_plc_unchanged(self):
        assert self.normalize_handle("did:plc:xyz") == "did:plc:xyz"

    def test_https_url_unchanged(self):
        assert self.normalize_handle("https://bsky.social") == "https://bsky.social"

    def test_empty_string_unchanged(self):
        assert self.normalize_handle("") == ""

    def test_trailing_dot_unchanged(self):
        # Has a dot, so no suffix appended
        assert self.normalize_handle("alice.") == "alice."


# --- normalize_handle integration tests ---


class TestLoginNormalizeHandle:
    """Integration tests: POST /auth/login triggers normalize_handle."""

    def test_bare_handle_resolves_with_bsky_social(self, client):
        """POST with bare 'alice' should resolve as 'alice.bsky.social'."""
        with patch("app.auth_server.resolve_identity") as mock_resolve:
            mock_resolve.side_effect = Exception("stop after resolve")
            client.post("/auth/login", data={"username": "alice"})
            mock_resolve.assert_called_once_with("alice.bsky.social")

    def test_at_bare_handle_resolves_with_bsky_social(self, client):
        """POST with '@alice' should resolve as 'alice.bsky.social'."""
        with patch("app.auth_server.resolve_identity") as mock_resolve:
            mock_resolve.side_effect = Exception("stop after resolve")
            client.post("/auth/login", data={"username": "@alice"})
            mock_resolve.assert_called_once_with("alice.bsky.social")
