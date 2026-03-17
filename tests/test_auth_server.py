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

        # Pre-create user in DB
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (did, handle, display_name, username, created_at) VALUES (?, ?, ?, ?, ?)",
            ("did:plc:testcb1", "alice.bsky.social", "Alice", "alice", now),
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
            "INSERT INTO users (did, handle, display_name, username, created_at) VALUES (?, ?, ?, ?, ?)",
            ("did:plc:testcb2", "alice2.bsky.social", "Alice2", "alice2", now),
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
    def test_callback_new_user_redirects_to_signup(
        self, mock_display, mock_token, app, client, db_path
    ):
        """A first-time user should be redirected to /auth/signup."""
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
        assert "/auth/signup" in resp.headers["Location"]


# --- Signup Flow ---


class TestSignupFlow:
    def test_signup_get_without_session_redirects(self, client):
        """Accessing signup without pending session should redirect to login."""
        resp = client.get("/auth/signup")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]

    def test_signup_renders_form(self, app, client):
        """With a pending session, signup should render the form."""
        with client.session_transaction() as sess:
            sess["pending_did"] = "did:plc:signup1"
            sess["pending_handle"] = "signup.bsky.social"

        resp = client.get("/auth/signup")
        assert resp.status_code == 200
        assert b"username" in resp.data
        assert b"signup.bsky.social" in resp.data

    @patch("app.auth_server._fetch_display_name")
    def test_signup_creates_user(self, mock_display, app, client, db_path):
        """Posting a valid username should create the user and set a cookie."""
        mock_display.return_value = "Signup User"

        with client.session_transaction() as sess:
            sess["pending_did"] = "did:plc:signup2"
            sess["pending_handle"] = "signup2.bsky.social"

        resp = client.post("/auth/signup", data={"username": "signup2"})
        assert resp.status_code == 302
        cookie_header = resp.headers.get("Set-Cookie", "")
        assert "platform_token=" in cookie_header

        # Verify user was created in DB
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM users WHERE did = ?", ("did:plc:signup2",)
        ).fetchone()
        conn.close()
        assert row is not None
        assert row["username"] == "signup2"
        assert row["handle"] == "signup2.bsky.social"
        assert resp.headers["Location"].endswith("/app/")

    @patch("app.auth_server._fetch_display_name")
    def test_signup_return_to_takes_precedence(self, mock_display, app, client, db_path):
        """return_to in session should override /app/ default after signup."""
        mock_display.return_value = "Signup User RT"

        with client.session_transaction() as sess:
            sess["pending_did"] = "did:plc:signup_rt"
            sess["pending_handle"] = "signuprt.bsky.social"
            sess["return_to"] = "/auth/oauth/consent?client_id=test-client"

        resp = client.post("/auth/signup", data={"username": "signuprt"})
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/auth/oauth/consent?client_id=test-client"
        assert not resp.headers["Location"].endswith("/app/")

    def test_signup_rejects_invalid_username(self, app, client):
        """Invalid usernames should be rejected with a 400."""
        with client.session_transaction() as sess:
            sess["pending_did"] = "did:plc:signup3"
            sess["pending_handle"] = "signup3.bsky.social"

        resp = client.post("/auth/signup", data={"username": "ab"})  # too short
        assert resp.status_code == 400

    def test_signup_rejects_reserved_username(self, app, client):
        """Reserved usernames should be rejected."""
        with client.session_transaction() as sess:
            sess["pending_did"] = "did:plc:signup4"
            sess["pending_handle"] = "signup4.bsky.social"

        resp = client.post("/auth/signup", data={"username": "admin"})
        assert resp.status_code == 400

    @patch("app.auth_server._fetch_display_name")
    def test_signup_rejects_duplicate_username(
        self, mock_display, app, client, db_path
    ):
        """Duplicate usernames should be rejected."""
        mock_display.return_value = "Dup User"

        # Create existing user
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (did, handle, display_name, username, created_at) VALUES (?, ?, ?, ?, ?)",
            ("did:plc:existing", "existing.bsky.social", "Existing", "taken", now),
        )
        conn.commit()
        conn.close()

        with client.session_transaction() as sess:
            sess["pending_did"] = "did:plc:signup5"
            sess["pending_handle"] = "signup5.bsky.social"

        resp = client.post("/auth/signup", data={"username": "taken"})
        assert resp.status_code == 400


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
                "INSERT INTO users (did, handle, display_name, username, created_at) VALUES (?, ?, ?, ?, ?)",
                ("did:plc:retto1", "alice.bsky.social", "Alice", "aliceretto", now),
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
        from app.auth_server import _default_username_from_handle
        assert _default_username_from_handle("alice.bsky.social") == "alice"

    def test_handle_with_uppercase(self):
        from app.auth_server import _default_username_from_handle
        assert _default_username_from_handle("Alice.bsky.social") == "alice"

    def test_short_prefix(self):
        from app.auth_server import _default_username_from_handle
        # "ab" is too short, should get padded
        result = _default_username_from_handle("ab.bsky.social")
        assert len(result) >= 3

    def test_handle_with_special_chars(self):
        from app.auth_server import _default_username_from_handle
        result = _default_username_from_handle("test_user.bsky.social")
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
