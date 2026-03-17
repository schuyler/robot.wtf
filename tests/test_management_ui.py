"""Tests for the Management UI Flask routes at /app/*.

Tests verify:
- Authentication gating (redirect to login without JWT cookie)
- Dashboard rendering with and without wikis
- Wiki creation flow including MCP token display
- Wiki settings, collaborator management, MCP instructions
- Account page and deletion
- /api/me endpoint
"""

from __future__ import annotations

import os
import sqlite3
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest

from app.auth.jwt import PlatformJWT
from app.auth.middleware import AuthMiddleware
from app.db import init_schema
from app.models.user import UserModel
from app.models.wiki import WikiModel


# --- Helpers ---


def _generate_rsa_keys():
    """Generate a test RSA key pair."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

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


# --- Fixtures ---


@pytest.fixture
def rsa_keys():
    return _generate_rsa_keys()


@pytest.fixture
def db():
    """In-memory SQLite database with schema initialized."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    init_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def user_model(db):
    return UserModel(db)


@pytest.fixture
def wiki_model(db):
    return WikiModel(db)


@pytest.fixture
def platform_jwt(rsa_keys):
    private_key, public_key = rsa_keys
    return PlatformJWT(private_key, public_key)


@pytest.fixture
def owner_user(user_model):
    return user_model.create(
        did="did:plc:owner",
        handle="owner.bsky.social",
        display_name="Owner",
        username="owner",
    )


@pytest.fixture
def collab_user(user_model):
    return user_model.create(
        did="did:plc:collab",
        handle="collab.bsky.social",
        display_name="Collab",
        username="collab",
    )


@pytest.fixture
def owner_token(platform_jwt, owner_user):
    """Valid JWT token for the owner user."""
    return platform_jwt.create_token(
        user_did="did:plc:owner",
        handle="owner.bsky.social",
        display_name="Owner",
    )


@pytest.fixture
def collab_token(platform_jwt, collab_user):
    """Valid JWT token for the collab user."""
    return platform_jwt.create_token(
        user_did="did:plc:collab",
        handle="collab.bsky.social",
        display_name="Collab",
    )


@pytest.fixture
def flask_app(rsa_keys, user_model, wiki_model, platform_jwt, tmp_path):
    """Create a configured Flask test app."""
    import os
    os.environ["FLASK_SECRET_KEY"] = "test-secret-management-ui"
    from app.api_server import _create_flask_app

    app = _create_flask_app()
    app.config["TESTING"] = True

    private_key, public_key = rsa_keys
    auth_middleware = AuthMiddleware(
        platform_jwt=platform_jwt,
        user_model=user_model,
    )
    app.config["AUTH_MIDDLEWARE"] = auth_middleware
    app.config["USER_MODEL"] = user_model
    app.config["WIKI_MODEL"] = wiki_model
    app.config["WIKI_BASE"] = str(tmp_path / "wikis")

    return app


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()


# --- Landing page tests ---


class TestLanding:
    def test_landing_unauthenticated_serves_static(self, client):
        """Unauthenticated visitor gets the marketing page."""
        resp = client.get("/")
        assert resp.status_code == 200

    def test_landing_authenticated_redirects_to_app(
        self, client, owner_token, owner_user
    ):
        """Authenticated user visiting / is redirected to /app/."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/app/")


# --- Auth gating tests ---


class TestAuthGating:
    def test_dashboard_redirects_without_cookie(self, client):
        resp = client.get("/app/")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]

    def test_create_redirects_without_cookie(self, client):
        resp = client.get("/app/create")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]

    def test_account_redirects_without_cookie(self, client):
        resp = client.get("/app/account")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]

    def test_wiki_settings_redirects_without_cookie(self, client):
        resp = client.get("/app/wiki/test-wiki")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]


# --- Dashboard tests ---


class TestDashboard:
    def test_dashboard_empty(self, client, owner_token, owner_user):
        """Dashboard with no wikis shows create CTA."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "Create your wiki" in html

    def test_dashboard_with_wiki(
        self, client, owner_token, owner_user, wiki_model
    ):
        """Dashboard with a wiki shows wiki info."""
        wiki_model.create(
            slug="my-wiki",
            owner_did="did:plc:owner",
            display_name="My Wiki",
            repo_path="/tmp/fake/repo",
            mcp_token_hash="$2b$12$fakehash",
        )
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "My Wiki" in html
        assert "my-wiki" in html


# --- Wiki creation tests ---


class TestWikiCreate:
    def test_create_form_renders(self, client, owner_token, owner_user):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/create")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "Create a new wiki" in html
        assert 'name="slug"' in html

    def test_create_form_default_slug(self, client, owner_token, owner_user):
        """Default slug should be the username."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/create")
        html = resp.data.decode()
        assert 'value="owner"' in html

    @patch("app.api_server._init_wiki_repo")
    def test_create_wiki_success(
        self, mock_init, client, owner_token, owner_user, wiki_model
    ):
        """POST /app/create creates wiki and redirects to dashboard."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.post(
            "/app/create",
            data={
                "slug": "test-wiki",
                "display_name": "Test Wiki",
                "purpose": "Testing",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/app/" in resp.headers["Location"]

        # Wiki should exist
        wiki = wiki_model.get("test-wiki")
        assert wiki is not None
        assert wiki["display_name"] == "Test Wiki"

    @patch("app.api_server._init_wiki_repo")
    def test_create_wiki_shows_token(
        self, mock_init, client, owner_token, owner_user
    ):
        """Dashboard after creation should show the bearer token."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        # Create wiki
        resp = client.post(
            "/app/create",
            data={"slug": "token-wiki", "display_name": "Token Wiki"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "bearer token" in html.lower() or "MCP" in html

    def test_create_wiki_invalid_slug(self, client, owner_token, owner_user):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.post(
            "/app/create",
            data={"slug": "ab", "display_name": "Bad Slug"},
            follow_redirects=True,
        )
        html = resp.data.decode()
        assert "Invalid slug" in html or "3 characters" in html

    def test_create_wiki_reserved_slug(self, client, owner_token, owner_user):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.post(
            "/app/create",
            data={"slug": "admin", "display_name": "Admin Wiki"},
            follow_redirects=True,
        )
        html = resp.data.decode()
        assert "reserved" in html.lower()

    def test_create_wiki_missing_display_name(
        self, client, owner_token, owner_user
    ):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.post(
            "/app/create",
            data={"slug": "good-slug"},
            follow_redirects=True,
        )
        html = resp.data.decode()
        assert "Display name is required" in html


# --- Wiki settings tests ---


class TestWikiSettings:
    @patch("app.api_server._init_wiki_repo")
    def _create_wiki(self, client, owner_token, mock_init):
        """Helper to create a wiki via the UI."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        client.post(
            "/app/create",
            data={"slug": "settings-wiki", "display_name": "Settings Wiki"},
        )

    @patch("app.api_server._init_wiki_repo")
    def test_settings_page_renders(
        self, mock_init, client, owner_token, owner_user
    ):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        client.post(
            "/app/create",
            data={"slug": "settings-wiki", "display_name": "Settings Wiki"},
        )
        resp = client.get("/app/wiki/settings-wiki")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "Settings Wiki" in html
        assert "Danger zone" in html

    @patch("app.api_server._init_wiki_repo")
    def test_update_display_name(
        self, mock_init, client, owner_token, owner_user, wiki_model
    ):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        client.post(
            "/app/create",
            data={"slug": "update-wiki", "display_name": "Old Name"},
        )
        resp = client.post(
            "/app/wiki/update-wiki/settings",
            data={"display_name": "New Name"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        wiki = wiki_model.get("update-wiki")
        assert wiki["display_name"] == "New Name"

    @patch("app.api_server._init_wiki_repo")
    def test_settings_update_ignores_is_public(
        self, mock_init, client, owner_token, owner_user, wiki_model
    ):
        """is_public is no longer written from the settings form.

        READ_ACCESS in wiki.db is the sole gating mechanism for anonymous access.
        Posting is_public=1 should not update the database field.
        """
        client.set_cookie("platform_token", owner_token, domain="localhost")
        client.post(
            "/app/create",
            data={"slug": "vis-wiki", "display_name": "Vis Wiki"},
        )
        # Post is_public=1 — should be silently ignored
        resp = client.post(
            "/app/wiki/vis-wiki/settings",
            data={"display_name": "Vis Wiki", "is_public": "1"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        wiki = wiki_model.get("vis-wiki")
        # is_public must not have been set to 1 — it should remain 0 (the schema default)
        assert wiki["is_public"] == 0

    @patch("app.api_server._init_wiki_repo")
    def test_delete_wiki(
        self, mock_init, client, owner_token, owner_user, wiki_model
    ):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        client.post(
            "/app/create",
            data={"slug": "del-wiki", "display_name": "Delete Me"},
        )
        resp = client.post(
            "/app/wiki/del-wiki/delete",
            data={"confirm_slug": "del-wiki"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert wiki_model.get("del-wiki") is None

    @patch("app.api_server._init_wiki_repo")
    def test_delete_wiki_wrong_confirmation(
        self, mock_init, client, owner_token, owner_user, wiki_model
    ):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        client.post(
            "/app/create",
            data={"slug": "safe-wiki", "display_name": "Safe Wiki"},
        )
        resp = client.post(
            "/app/wiki/safe-wiki/delete",
            data={"confirm_slug": "wrong"},
            follow_redirects=True,
        )
        assert wiki_model.get("safe-wiki") is not None

    def test_settings_nonexistent_wiki(self, client, owner_token, owner_user):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/wiki/nonexistent", follow_redirects=False)
        assert resp.status_code == 302

    @patch("app.api_server._init_wiki_repo")
    def test_settings_access_denied(
        self, mock_init, client, owner_token, collab_token, owner_user, collab_user
    ):
        """Non-owner cannot access settings."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        client.post(
            "/app/create",
            data={"slug": "perm-wiki", "display_name": "Perm Wiki"},
        )
        # Switch to collab user
        client.set_cookie("platform_token", collab_token, domain="localhost")
        resp = client.get("/app/wiki/perm-wiki", follow_redirects=False)
        assert resp.status_code == 302  # redirects to dashboard


# --- MCP tests (on dashboard) ---


class TestMCPOnDashboard:
    @patch("app.api_server._init_wiki_repo")
    def test_dashboard_shows_mcp_info(
        self, mock_init, client, owner_token, owner_user
    ):
        """Dashboard shows MCP endpoint and claude mcp add command."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        client.post(
            "/app/create",
            data={"slug": "mcp-wiki", "display_name": "MCP Wiki"},
        )
        resp = client.get("/app/")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "MCP" in html
        assert "mcp-wiki" in html
        assert "claude mcp add" in html

    @patch("app.api_server._init_wiki_repo")
    def test_regenerate_token(
        self, mock_init, client, owner_token, owner_user, wiki_model
    ):
        """Regenerate MCP token changes the hash."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        client.post(
            "/app/create",
            data={"slug": "regen-wiki", "display_name": "Regen Wiki"},
        )
        old_hash = wiki_model.get("regen-wiki")["mcp_token_hash"]

        resp = client.post(
            "/app/wiki/regen-wiki/mcp/regenerate",
            follow_redirects=False,
        )
        assert resp.status_code == 302
        new_hash = wiki_model.get("regen-wiki")["mcp_token_hash"]
        assert new_hash != old_hash


# --- Account tests ---


class TestAccount:
    def test_account_page_renders(self, client, owner_token, owner_user):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/account")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "owner.bsky.social" in html
        assert "did:plc:owner" in html

    @patch("app.api_server._init_wiki_repo")
    def test_account_delete(
        self, mock_init, client, owner_token, owner_user, user_model, wiki_model
    ):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        # Create a wiki first
        client.post(
            "/app/create",
            data={"slug": "doomed-wiki", "display_name": "Doomed Wiki"},
        )
        # Delete account
        resp = client.post(
            "/app/account/delete",
            data={"confirm_username": "owner"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert user_model.get("did:plc:owner") is None
        assert wiki_model.get("doomed-wiki") is None

    def test_account_delete_wrong_confirmation(
        self, client, owner_token, owner_user, user_model
    ):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.post(
            "/app/account/delete",
            data={"confirm_username": "wrong"},
            follow_redirects=True,
        )
        # User should still exist
        assert user_model.get("did:plc:owner") is not None


# --- /api/me tests ---


class TestApiMe:
    def test_api_me_authenticated(self, client, owner_token, owner_user):
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/api/me")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["did"] == "did:plc:owner"
        assert data["handle"] == "owner.bsky.social"
        assert data["username"] == "owner"

    def test_api_me_unauthenticated(self, client):
        resp = client.get("/api/me")
        assert resp.status_code == 401
        data = resp.get_json()
        assert "error" in data
