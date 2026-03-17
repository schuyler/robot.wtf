"""Tests for the MCP OAuth consent flow (V5).

Covers:
- Consent token signing/verification
- GET /auth/oauth/consent (authenticated, unauthenticated, missing params)
- POST /auth/oauth/consent (approve, deny, expired token, user mismatch)
- return_to flow through login
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from authlib.jose import JsonWebKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from app.auth.consent import (
    APPROVAL_TOKEN_LIFETIME,
    CONSENT_TOKEN_LIFETIME,
    OAUTH_PARAM_NAMES,
    derive_signing_key,
    sign_token,
    verify_token,
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

    for key in ["ROBOT_DB_PATH", "CLIENT_JWK_PATH", "SIGNING_KEY_PATH",
                "FLASK_SECRET_KEY"]:
        os.environ.pop(key, None)


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def signing_key(rsa_keys):
    """Derive consent signing key from RSA key."""
    _, private_pem = rsa_keys
    return derive_signing_key(private_pem)


@pytest.fixture
def platform_token(app, rsa_keys):
    """Create a valid platform JWT for testing."""
    from app.auth.jwt import PlatformJWT, _load_keys
    _, private_pem = rsa_keys
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
        Encoding,
        PublicFormat,
    )
    priv_obj = load_pem_private_key(private_pem.encode(), password=None)
    pub_pem = priv_obj.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()
    jwt_svc = PlatformJWT(private_pem, pub_pem)
    return jwt_svc.create_token(
        user_did="did:plc:test123",
        handle="alice.bsky.social",
        display_name="Alice",
    )


# OAuth params for testing
SAMPLE_OAUTH_PARAMS = {
    "client_id": "test-client-abc",
    "redirect_uri": "https://claude.ai/oauth/callback",
    "code_challenge": "challenge123",
    "code_challenge_method": "S256",
    "state": "random-state-42",
    "scope": "read write",
    "response_type": "code",
}


# --- derive_signing_key Unit Tests ---


class TestDeriveSigningKey:
    def test_different_keys_produce_different_signing_keys(self):
        # Keys share identical first 64 chars (the PEM header) but differ in body.
        # The old [:64] slice would produce the same HMAC key for both.
        header = "-----BEGIN RSA PRIVATE KEY-----\n"  # 32 chars
        padding = "X" * (64 - len(header))             # pad to exactly 64 chars
        key_a = header + padding + "AAAA" + "A" * 100
        key_b = header + padding + "BBBB" + "B" * 100
        assert derive_signing_key(key_a) != derive_signing_key(key_b)

    def test_short_key_still_works(self):
        short = "short"
        result = derive_signing_key(short)
        assert isinstance(result, bytes)
        assert len(result) == 32


# --- Consent Token Unit Tests ---


class TestConsentToken:
    def test_sign_and_verify(self, signing_key):
        payload = {"foo": "bar", "exp": time.time() + 300}
        token = sign_token(payload, signing_key)
        result = verify_token(token, signing_key)
        assert result is not None
        assert result["foo"] == "bar"

    def test_expired_token_rejected(self, signing_key):
        payload = {"foo": "bar", "exp": time.time() - 10}
        token = sign_token(payload, signing_key)
        assert verify_token(token, signing_key) is None

    def test_tampered_payload_rejected(self, signing_key):
        payload = {"foo": "bar", "exp": time.time() + 300}
        token = sign_token(payload, signing_key)
        # Tamper with the payload
        tampered = token.replace('"bar"', '"baz"')
        assert verify_token(tampered, signing_key) is None

    def test_wrong_key_rejected(self, signing_key):
        payload = {"foo": "bar", "exp": time.time() + 300}
        token = sign_token(payload, signing_key)
        wrong_key = derive_signing_key("different-key-material-xxxx" * 3)
        assert verify_token(token, wrong_key) is None

    def test_malformed_token_rejected(self, signing_key):
        assert verify_token("not-a-token", signing_key) is None
        assert verify_token("", signing_key) is None
        assert verify_token("{bad json|abc", signing_key) is None


# --- Consent Page GET Tests ---


class TestConsentGet:
    def _consent_url(self, **extra):
        params = {**SAMPLE_OAUTH_PARAMS, "wiki_slug": "3gw", **extra}
        from urllib.parse import urlencode
        return f"/auth/oauth/consent?{urlencode(params)}"

    def test_missing_client_id_returns_400(self, client):
        resp = client.get("/auth/oauth/consent?redirect_uri=https://x.com&wiki_slug=3gw")
        assert resp.status_code == 400

    def test_missing_wiki_slug_returns_400(self, client, platform_token):
        params = {**SAMPLE_OAUTH_PARAMS}
        from urllib.parse import urlencode
        url = f"/auth/oauth/consent?{urlencode(params)}"
        client.set_cookie("platform_token", platform_token)
        resp = client.get(url)
        assert resp.status_code == 400

    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get(self._consent_url())
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]
        assert "return_to" in resp.headers["Location"]

    def test_authenticated_shows_consent_page(self, client, platform_token, db_path):
        # Insert the wiki owned by the test user so membership check passes
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT OR IGNORE INTO users (did, handle, display_name, username, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            ("did:plc:test123", "alice.bsky.social", "Alice", "alice", now),
        )
        conn.execute(
            "INSERT INTO wikis (slug, owner_did, display_name, repo_path,"
            " mcp_token_hash, is_public, created_at, last_accessed, page_count)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
            ("3gw", "did:plc:test123", "3gw", "/srv/data/wikis/3gw",
             "$2b$12$fakehash000000000000000000000000000000000000000000000",
             0, now, now),
        )
        conn.commit()
        conn.close()
        client.set_cookie("platform_token", platform_token)
        resp = client.get(self._consent_url())
        assert resp.status_code == 200
        assert b"Authorize Access" in resp.data
        assert b"3gw.robot.wtf" in resp.data
        assert b"test-client-abc" in resp.data
        assert b"alice.bsky.social" in resp.data

    def test_expired_jwt_redirects_to_login(self, app, client, rsa_keys):
        """An expired platform JWT should redirect to login."""
        from app.auth.jwt import PlatformJWT
        from datetime import timedelta
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
            Encoding,
            PublicFormat,
        )
        _, private_pem = rsa_keys
        priv_obj = load_pem_private_key(private_pem.encode(), password=None)
        pub_pem = priv_obj.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
        jwt_svc = PlatformJWT(private_pem, pub_pem)
        expired_token = jwt_svc.create_token(
            user_did="did:plc:test123",
            handle="alice.bsky.social",
            display_name="Alice",
            lifetime=timedelta(seconds=-1),
        )
        client.set_cookie("platform_token", expired_token, domain="robot.wtf")
        resp = client.get(self._consent_url())
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]


# --- Consent Page POST Tests ---


class TestConsentPost:
    def _make_consent_token(self, signing_key, user_did="did:plc:test123", csrf_nonce=None, **extra):
        payload = {
            **SAMPLE_OAUTH_PARAMS,
            "wiki_slug": "3gw",
            "user_did": user_did,
            "exp": time.time() + CONSENT_TOKEN_LIFETIME,
            **extra,
        }
        if csrf_nonce is not None:
            payload["csrf_nonce"] = csrf_nonce
        return sign_token(payload, signing_key)

    def test_approve_redirects_to_mcp_callback(self, client, platform_token, signing_key):
        nonce = "test-nonce-approve"
        with client.session_transaction() as sess:
            sess["csrf_nonces"] = [nonce]
        consent_token = self._make_consent_token(signing_key, csrf_nonce=nonce)
        client.set_cookie("platform_token", platform_token)
        resp = client.post(
            "/auth/oauth/consent",
            data={"consent_token": consent_token, "action": "approve"},
        )
        assert resp.status_code == 302
        location = resp.headers["Location"]
        assert "3gw.robot.wtf/authorize/callback" in location
        assert "approval_token=" in location
        assert "client_id=test-client-abc" in location
        assert "code_challenge=challenge123" in location
        assert "state=random-state-42" in location

    def test_deny_redirects_with_error(self, client, platform_token, signing_key):
        nonce = "test-nonce-deny"
        with client.session_transaction() as sess:
            sess["csrf_nonces"] = [nonce]
        consent_token = self._make_consent_token(signing_key, csrf_nonce=nonce)
        client.set_cookie("platform_token", platform_token)
        resp = client.post(
            "/auth/oauth/consent",
            data={"consent_token": consent_token, "action": "deny"},
        )
        assert resp.status_code == 302
        location = resp.headers["Location"]
        assert "claude.ai/oauth/callback" in location
        assert "error=access_denied" in location
        assert "state=random-state-42" in location

    def test_missing_consent_token_returns_400(self, client, platform_token):
        client.set_cookie("platform_token", platform_token)
        resp = client.post(
            "/auth/oauth/consent",
            data={"action": "approve"},
        )
        assert resp.status_code == 400

    def test_expired_consent_token_returns_400(self, client, platform_token, signing_key):
        # Create an already-expired consent token
        payload = {
            **SAMPLE_OAUTH_PARAMS,
            "wiki_slug": "3gw",
            "user_did": "did:plc:test123",
            "exp": time.time() - 10,
        }
        expired_token = sign_token(payload, signing_key)
        client.set_cookie("platform_token", platform_token)
        resp = client.post(
            "/auth/oauth/consent",
            data={"consent_token": expired_token, "action": "approve"},
        )
        assert resp.status_code == 400

    def test_user_mismatch_returns_403(self, client, platform_token, signing_key):
        # Consent token signed for a different user
        consent_token = self._make_consent_token(signing_key, user_did="did:plc:other")
        client.set_cookie("platform_token", platform_token)
        resp = client.post(
            "/auth/oauth/consent",
            data={"consent_token": consent_token, "action": "approve"},
        )
        assert resp.status_code == 403

    def test_unauthenticated_returns_401(self, client, signing_key):
        consent_token = self._make_consent_token(signing_key)
        resp = client.post(
            "/auth/oauth/consent",
            data={"consent_token": consent_token, "action": "approve"},
        )
        assert resp.status_code == 401

    def test_invalid_action_returns_400(self, client, platform_token, signing_key):
        nonce = "test-nonce-invalid-action"
        with client.session_transaction() as sess:
            sess["csrf_nonces"] = [nonce]
        consent_token = self._make_consent_token(signing_key, csrf_nonce=nonce)
        client.set_cookie("platform_token", platform_token)
        resp = client.post(
            "/auth/oauth/consent",
            data={"consent_token": consent_token, "action": "maybe"},
        )
        assert resp.status_code == 400

    def test_csrf_nonce_missing_returns_403(self, client, platform_token, signing_key):
        """POST with a valid consent token that has no csrf_nonce field returns 403."""
        # No csrf_nonce in token, no nonce in session
        consent_token = self._make_consent_token(signing_key)
        client.set_cookie("platform_token", platform_token)
        resp = client.post(
            "/auth/oauth/consent",
            data={"consent_token": consent_token, "action": "approve"},
        )
        assert resp.status_code == 403

    def test_csrf_nonce_mismatch_returns_403(self, client, platform_token, signing_key):
        """POST with consent token csrf_nonce='abc' but session has 'xyz' returns 403."""
        consent_token = self._make_consent_token(signing_key, csrf_nonce="abc")
        client.set_cookie("platform_token", platform_token)
        with client.session_transaction() as sess:
            sess["csrf_nonces"] = ["xyz"]
        resp = client.post(
            "/auth/oauth/consent",
            data={"consent_token": consent_token, "action": "approve"},
        )
        assert resp.status_code == 403

    def test_csrf_nonce_consumed_on_use(self, client, platform_token, signing_key):
        """First POST with matching nonce succeeds; second POST with same token returns 403."""
        nonce = "consume-me-nonce"
        consent_token = self._make_consent_token(signing_key, csrf_nonce=nonce)
        client.set_cookie("platform_token", platform_token)

        # First POST — should succeed
        with client.session_transaction() as sess:
            sess["csrf_nonces"] = [nonce]
        resp = client.post(
            "/auth/oauth/consent",
            data={"consent_token": consent_token, "action": "approve"},
        )
        assert resp.status_code == 302

        # Second POST with same consent token — nonce should be consumed, returns 403
        resp2 = client.post(
            "/auth/oauth/consent",
            data={"consent_token": consent_token, "action": "approve"},
        )
        assert resp2.status_code == 403

    def test_multiple_tabs_nonces(self, client, platform_token, signing_key):
        """Two GETs create two nonces. POST with either nonce succeeds."""
        nonce_a = "tab-a-nonce"
        nonce_b = "tab-b-nonce"
        token_a = self._make_consent_token(signing_key, csrf_nonce=nonce_a)
        token_b = self._make_consent_token(signing_key, csrf_nonce=nonce_b)
        client.set_cookie("platform_token", platform_token)

        # Both nonces in session (simulating two tabs)
        with client.session_transaction() as sess:
            sess["csrf_nonces"] = [nonce_a, nonce_b]

        # POST with token_b (second tab) should succeed
        resp = client.post(
            "/auth/oauth/consent",
            data={"consent_token": token_b, "action": "deny"},
        )
        assert resp.status_code == 302

        # nonce_b is consumed; token_a (first tab) should still work
        resp2 = client.post(
            "/auth/oauth/consent",
            data={"consent_token": token_a, "action": "deny"},
        )
        assert resp2.status_code == 302


# --- Open Redirect Prevention Tests ---


class TestReturnToOpenRedirect:
    """Ensure return_to cannot redirect to an external domain (open redirect)."""

    def test_return_to_rejects_absolute_url(self, client):
        """Login with return_to=https://evil.com — must not redirect there."""
        resp = client.get("/auth/login?return_to=https://evil.com")
        assert resp.status_code == 200  # renders the form, not a redirect

        # Verify evil.com is NOT stored as return_to in session
        with client.session_transaction() as sess:
            assert sess.get("return_to") != "https://evil.com"
            # Either not set at all, or empty string
            stored = sess.get("return_to", "")
            assert not stored or stored.startswith("/")

    def test_return_to_rejects_protocol_relative(self, client):
        """return_to=//evil.com must be rejected (protocol-relative URL)."""
        resp = client.get("/auth/login?return_to=//evil.com")
        assert resp.status_code == 200
        with client.session_transaction() as sess:
            stored = sess.get("return_to", "")
            assert not stored or stored.startswith("/")

    def test_return_to_accepts_relative_path(self, client):
        """Login with return_to=/some/page — must be stored and redirected to."""
        resp = client.get("/auth/login?return_to=/some/page")
        assert resp.status_code == 200
        with client.session_transaction() as sess:
            assert sess.get("return_to") == "/some/page"

    @patch("app.auth_server.initial_token_request")
    @patch("app.auth_server._fetch_display_name")
    def test_callback_does_not_redirect_to_evil(
        self, mock_display, mock_token, app, client, db_path
    ):
        """After login, callback must not follow a malicious return_to."""
        mock_display.return_value = "Alice"
        mock_token.return_value = (
            {"sub": "did:plc:redirecttest", "scope": "atproto",
             "access_token": "at1", "refresh_token": "rt1"},
            "nonce1",
        )

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (did, handle, display_name, username, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            ("did:plc:redirecttest", "alice.bsky.social", "Alice", "alicerd", now),
        )
        dpop_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)
        conn.execute(
            """INSERT INTO oauth_auth_requests
               (state, authserver_iss, did, handle, pds_url, pkce_verifier,
                scope, dpop_authserver_nonce, dpop_private_jwk, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ["state-redirect", "https://bsky.social", "did:plc:redirecttest",
             "alice.bsky.social", "https://pds.bsky.social", "verifier123",
             "atproto", "nonce0", dpop_jwk.as_json(is_private=True), now],
        )
        conn.commit()
        conn.close()

        # Store malicious return_to in session (simulating a tampered session)
        # In practice the fix prevents storing it, but test the callback too
        with client.session_transaction() as sess:
            sess["return_to"] = "https://evil.com/steal"

        resp = client.get(
            "/auth/callback?state=state-redirect&iss=https://bsky.social&code=code1"
        )

        assert resp.status_code == 302
        location = resp.headers["Location"]
        assert "evil.com" not in location


# --- Return-to Flow Tests ---


class TestReturnToFlow:
    def test_login_preserves_return_to(self, client):
        """Login GET with a relative return_to should pass it into template context."""
        resp = client.get("/auth/login?return_to=/auth/oauth/consent?foo=bar")
        assert resp.status_code == 200
        # The hidden input should be in the rendered HTML
        assert b"return_to" in resp.data

    @patch("app.auth_server.initial_token_request")
    @patch("app.auth_server._fetch_display_name")
    def test_callback_uses_return_to(
        self, mock_display, mock_token, app, client, db_path
    ):
        """After login, callback should redirect to return_to if set in session."""
        mock_display.return_value = "Alice Test"
        mock_token.return_value = (
            {"sub": "did:plc:returntest", "scope": "atproto", "access_token": "at1", "refresh_token": "rt1"},
            "nonce1",
        )

        # Pre-create user
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (did, handle, display_name, username, created_at) VALUES (?, ?, ?, ?, ?)",
            ("did:plc:returntest", "alice.bsky.social", "Alice", "aliceret", now),
        )
        dpop_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)
        conn.execute(
            """INSERT INTO oauth_auth_requests
               (state, authserver_iss, did, handle, pds_url, pkce_verifier,
                scope, dpop_authserver_nonce, dpop_private_jwk, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                "test-state-ret",
                "https://bsky.social",
                "did:plc:returntest",
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

        # Set return_to in session — must be a relative URL
        consent_path = "/auth/oauth/consent?client_id=test&wiki_slug=3gw"
        with client.session_transaction() as sess:
            sess["return_to"] = consent_path

        resp = client.get(
            "/auth/callback?state=test-state-ret&iss=https://bsky.social&code=authcode1"
        )

        assert resp.status_code == 302
        assert resp.headers["Location"] == consent_path


# --- Wiki Membership Tests ---


class TestConsentWikiMembership:
    """Wiki membership check on GET /auth/oauth/consent."""

    def _consent_url(self, wiki_slug="test-wiki", **extra):
        params = {**SAMPLE_OAUTH_PARAMS, "wiki_slug": wiki_slug, **extra}
        from urllib.parse import urlencode
        return f"/auth/oauth/consent?{urlencode(params)}"

    def _insert_user(self, db_path, did="did:plc:test123"):
        """Insert a user row so foreign-key constraints are satisfied."""
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT OR IGNORE INTO users (did, handle, display_name, username, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (did, "alice.bsky.social", "Alice", "alice", now),
        )
        conn.commit()
        conn.close()

    def _insert_wiki(self, db_path, slug, owner_did="did:plc:owner", is_public=False):
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT OR IGNORE INTO users (did, handle, display_name, username, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (owner_did, "owner.bsky.social", "Owner", "owner", now),
        )
        conn.execute(
            "INSERT INTO wikis (slug, owner_did, display_name, repo_path,"
            " mcp_token_hash, is_public, created_at, last_accessed, page_count)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (slug, owner_did, slug, f"/srv/data/wikis/{slug}",
             "$2b$12$fakehash000000000000000000000000000000000000000000000",
             int(is_public), now, now),
        )
        conn.commit()
        conn.close()

    def _insert_acl(self, db_path, wiki_slug, grantee_did, role="viewer"):
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO acls (wiki_slug, grantee_did, role, granted_by, granted_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (wiki_slug, grantee_did, role, grantee_did, now),
        )
        conn.commit()
        conn.close()

    def test_consent_get_rejects_nonexistent_wiki(self, client, platform_token, db_path):
        """GET consent for a wiki slug that does not exist returns 403.

        is_public is no longer checked. Any existing wiki is accessible to
        authenticated users; READ_ACCESS in wiki.db gates actual content access.
        """
        # Do NOT insert the wiki — slug is unknown
        client.set_cookie("platform_token", platform_token)
        resp = client.get(self._consent_url(wiki_slug="no-such-wiki"))
        assert resp.status_code == 403

    def test_consent_get_allows_existing_wiki_without_acl(self, client, platform_token, db_path):
        """GET consent succeeds for any existing wiki, even without an explicit ACL.

        READ_ACCESS in wiki.db is the sole gating mechanism for anonymous access.
        Authenticated users can consent to grant OAuth tokens for any existing wiki.
        """
        # Insert the wiki but NOT an ACL entry for did:plc:test123
        self._insert_wiki(db_path, "any-wiki", owner_did="did:plc:someone-else")
        client.set_cookie("platform_token", platform_token)
        resp = client.get(self._consent_url(wiki_slug="any-wiki"))
        assert resp.status_code == 200
        assert b"Authorize Access" in resp.data

    def test_consent_get_allows_authorized_wiki(self, client, platform_token, db_path):
        """GET consent with a wiki the user has an ACL entry for returns 200."""
        self._insert_user(db_path)
        self._insert_wiki(db_path, "my-wiki", owner_did="did:plc:owner")
        self._insert_acl(db_path, "my-wiki", "did:plc:test123", role="viewer")
        client.set_cookie("platform_token", platform_token)
        resp = client.get(self._consent_url(wiki_slug="my-wiki"))
        assert resp.status_code == 200
        assert b"Authorize Access" in resp.data

    def test_consent_get_allows_existing_wiki(self, client, platform_token, db_path):
        """GET consent for any existing wiki returns 200 regardless of is_public.

        is_public is no longer the gating mechanism; READ_ACCESS in wiki.db controls access.
        """
        self._insert_wiki(db_path, "open-wiki", owner_did="did:plc:owner", is_public=False)
        client.set_cookie("platform_token", platform_token)
        resp = client.get(self._consent_url(wiki_slug="open-wiki"))
        assert resp.status_code == 200
        assert b"Authorize Access" in resp.data


# --- Approval Token Tests ---


class TestApprovalToken:
    def test_approval_token_in_redirect_is_valid(self, client, platform_token, signing_key):
        """The approval token in the redirect URL should be verifiable."""
        from urllib.parse import urlparse, parse_qs

        nonce = "test-nonce-approval"
        with client.session_transaction() as sess:
            sess["csrf_nonces"] = [nonce]

        consent_token = sign_token(
            {
                **SAMPLE_OAUTH_PARAMS,
                "wiki_slug": "3gw",
                "user_did": "did:plc:test123",
                "csrf_nonce": nonce,
                "exp": time.time() + 300,
            },
            signing_key,
        )

        client.set_cookie("platform_token", platform_token)
        resp = client.post(
            "/auth/oauth/consent",
            data={"consent_token": consent_token, "action": "approve"},
        )
        assert resp.status_code == 302
        location = resp.headers["Location"]
        parsed = urlparse(location)
        qs = parse_qs(parsed.query)

        approval_token = qs["approval_token"][0]
        payload = verify_token(approval_token, signing_key)
        assert payload is not None
        assert payload["user_did"] == "did:plc:test123"
        assert payload["wiki_slug"] == "3gw"
        assert payload["client_id"] == "test-client-abc"
