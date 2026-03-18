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
    )


@pytest.fixture
def collab_user(user_model):
    return user_model.create(
        did="did:plc:collab",
        handle="collab.bsky.social",
        display_name="Collab",
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

    def test_landing_authenticated_serves_landing_page(
        self, client, owner_token, owner_user
    ):
        """Authenticated user visiting / still sees the landing page."""
        client.set_cookie("platform_token", owner_token)
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 200


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
        assert "Create your first wiki" in html

    def test_dashboard_with_wiki_redirects(
        self, client, owner_token, owner_user, wiki_model
    ):
        """Dashboard redirects to first wiki's settings page when wikis exist."""
        wiki_model.create(
            slug="my-wiki",
            owner_did="did:plc:owner",
            display_name="My Wiki",
            repo_path="/tmp/fake/repo",
            mcp_token_hash="a" * 64,
        )
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/app/wiki/my-wiki" in resp.headers["Location"]

    def test_dashboard_with_wiki_follows_to_settings(
        self, client, owner_token, owner_user, wiki_model
    ):
        """Dashboard redirect lands on wiki settings page with wiki info."""
        wiki_model.create(
            slug="my-wiki",
            owner_did="did:plc:owner",
            display_name="My Wiki",
            repo_path="/tmp/fake/repo",
            mcp_token_hash="a" * 64,
        )
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/", follow_redirects=True)
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
        """Default slug should be derived from handle."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/create")
        html = resp.data.decode()
        # handle "owner.bsky.social" -> slug "owner"
        assert 'value="owner"' in html

    @patch("app.api_server._init_wiki_repo")
    def test_create_wiki_success(
        self, mock_init, client, owner_token, owner_user, wiki_model
    ):
        """POST /app/create creates wiki and redirects to wiki settings."""
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
        assert "/app/wiki/test-wiki" in resp.headers["Location"]

        # Wiki should exist
        wiki = wiki_model.get("test-wiki")
        assert wiki is not None
        assert wiki["display_name"] == "Test Wiki"

    @patch("app.api_server._init_wiki_repo")
    def test_create_wiki_shows_token(
        self, mock_init, client, owner_token, owner_user
    ):
        """Wiki settings page after creation should show the bearer token."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        # Create wiki
        resp = client.post(
            "/app/create",
            data={"slug": "token-wiki", "display_name": "Token Wiki"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "Your MCP bearer token" in html or "MCP" in html

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

    def test_create_form_default_slug_from_handle(
        self, client, platform_jwt, user_model
    ):
        """User gets handle-derived slug default."""
        user_model.create(
            did="did:plc:nouser",
            handle="nouser.bsky.social",
            display_name="No User",
        )
        token = platform_jwt.create_token(
            user_did="did:plc:nouser",
            handle="nouser.bsky.social",
            display_name="No User",
        )
        client.set_cookie("platform_token", token, domain="localhost")
        resp = client.get("/app/create")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert 'value="nouser"' in html

    def test_create_form_empty_default_slug_when_handle_is_reserved(
        self, client, platform_jwt, user_model
    ):
        """User with a handle that produces a reserved slug gets empty default."""
        user_model.create(
            did="did:plc:adminuser",
            handle="admin.bsky.social",
            display_name="Admin User",
        )
        token = platform_jwt.create_token(
            user_did="did:plc:adminuser",
            handle="admin.bsky.social",
            display_name="Admin User",
        )
        client.set_cookie("platform_token", token, domain="localhost")
        resp = client.get("/app/create")
        assert resp.status_code == 200
        html = resp.data.decode()
        # slug field should have empty value
        assert 'value=""' in html

    @patch("app.api_server._init_wiki_repo")
    def test_create_wiki_derives_slug_from_handle(
        self, mock_init, client, platform_jwt, user_model, wiki_model
    ):
        """Wiki creation derives default slug from handle."""
        user_model.create(
            did="did:plc:slughook",
            handle="slughook.bsky.social",
            display_name="Slug Hook",
        )
        token = platform_jwt.create_token(
            user_did="did:plc:slughook",
            handle="slughook.bsky.social",
            display_name="Slug Hook",
        )
        client.set_cookie("platform_token", token, domain="localhost")
        resp = client.post(
            "/app/create",
            data={
                "slug": "slughook",
                "display_name": "Slug Hook Wiki",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        wiki = wiki_model.get("slughook")
        assert wiki is not None


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


# --- MCP tests (on wiki_settings) ---


class TestMCPOnWikiSettings:
    @patch("app.api_server._init_wiki_repo")
    def test_wiki_settings_shows_mcp_info(
        self, mock_init, client, owner_token, owner_user
    ):
        """Wiki settings page shows MCP endpoint and claude mcp add command."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        client.post(
            "/app/create",
            data={"slug": "mcp-wiki", "display_name": "MCP Wiki"},
        )
        resp = client.get("/app/wiki/mcp-wiki")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "MCP" in html
        assert "mcp-wiki" in html
        assert "claude mcp add" in html

    @patch("app.api_server._init_wiki_repo")
    def test_wiki_settings_shows_mcp_token_once(
        self, mock_init, client, owner_token, owner_user
    ):
        """Wiki settings page shows bearer token alert after creation, then clears it."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        # Create wiki; token is stored in session
        client.post(
            "/app/create",
            data={"slug": "tok-wiki", "display_name": "Tok Wiki"},
            follow_redirects=False,
        )
        # First visit to wiki_settings should show the token alert
        resp = client.get("/app/wiki/tok-wiki")
        assert resp.status_code == 200
        html = resp.data.decode()
        # The token alert section contains this specific text
        assert "Your MCP bearer token" in html

        # Second visit should NOT show the token alert (popped from session)
        resp2 = client.get("/app/wiki/tok-wiki")
        html2 = resp2.data.decode()
        assert "Your MCP bearer token" not in html2

    @patch("app.api_server._init_wiki_repo")
    def test_regenerate_token(
        self, mock_init, client, owner_token, owner_user, wiki_model
    ):
        """Regenerate MCP token changes the hash and redirects to wiki_settings."""
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
        assert "/app/wiki/regen-wiki" in resp.headers["Location"]
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
        # Delete account — confirm_handle must match the full handle
        resp = client.post(
            "/app/account/delete",
            data={"confirm_handle": "owner.bsky.social"},
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
            data={"confirm_handle": "wrong"},
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
        assert "username" not in data

    def test_api_me_unauthenticated(self, client):
        resp = client.get("/api/me")
        assert resp.status_code == 401
        data = resp.get_json()
        assert "error" in data


# --- Context processor / sidebar tests ---


class TestContextProcessor:
    def test_sidebar_empty_when_unauthenticated(self, client):
        """Unauthenticated requests do not trigger wiki DB queries for sidebar."""
        resp = client.get("/app/")
        # Redirect to login -- sidebar_wikis should not cause an error
        assert resp.status_code == 302

    def test_sidebar_shows_user_wikis(self, client, owner_token, owner_user, wiki_model):
        """Authenticated user sees their wikis in the sidebar."""
        wiki_model.create(
            slug="sidebar-wiki",
            owner_did="did:plc:owner",
            display_name="Sidebar Wiki",
            repo_path="/tmp/fake/repo",
            mcp_token_hash="b" * 64,
        )
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/wiki/sidebar-wiki")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "Sidebar Wiki" in html
        # Sidebar link should appear
        assert "/app/wiki/sidebar-wiki" in html

    def test_sidebar_active_link(self, client, owner_token, owner_user, wiki_model):
        """Current wiki's sidebar link has active class."""
        import re

        wiki_model.create(
            slug="active-wiki",
            owner_did="did:plc:owner",
            display_name="Active Wiki",
            repo_path="/tmp/fake/repo",
            mcp_token_hash="c" * 64,
        )
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/wiki/active-wiki")
        html = resp.data.decode()
        # The sidebar link for this specific wiki should have the 'active' class
        assert re.search(r'href="/app/wiki/active-wiki"[^>]*class="[^"]*\bactive\b', html)

    def test_platform_domain_injected(self, client, owner_token, owner_user, wiki_model):
        """platform_domain is injected by context processor and appears in templates."""
        wiki_model.create(
            slug="domain-wiki",
            owner_did="did:plc:owner",
            display_name="Domain Wiki",
            repo_path="/tmp/fake/repo",
            mcp_token_hash="d" * 64,
        )
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/wiki/domain-wiki")
        html = resp.data.decode()
        # The wiki URL should contain the platform domain
        assert "domain-wiki.robot.wtf" in html


# --- Admin stats tests ---


class TestAdminStats:
    def test_admin_stats_requires_auth(self, client):
        """Unauthenticated request redirects to login."""
        resp = client.get("/app/admin/stats")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]

    def test_admin_stats_forbidden_for_non_admin(self, client, owner_token, owner_user):
        """Authenticated non-admin gets 403."""
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/admin/stats")
        assert resp.status_code == 403

    def test_admin_stats_renders_for_admin(self, flask_app, owner_token, owner_user):
        """Admin user sees the stats page with expected sections."""
        flask_app.config["PLATFORM_ADMIN_DIDS"] = {"did:plc:owner"}
        client = flask_app.test_client()
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/admin/stats")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "System Status" in html
        assert "Services" in html
        assert "Disk Usage" in html
        assert "Platform Counts" in html
        assert "All Wikis" in html
        assert "Journal" in html

    def test_admin_stats_sidebar_visible_for_admin(self, flask_app, owner_token, owner_user, wiki_model):
        """Admin user sees System status link in sidebar."""
        flask_app.config["PLATFORM_ADMIN_DIDS"] = {"did:plc:owner"}
        wiki_model.create(
            slug="admin-sidebar-wiki",
            owner_did="did:plc:owner",
            display_name="Admin Sidebar Wiki",
            repo_path="/tmp/fake/repo",
            mcp_token_hash="e" * 64,
        )
        client = flask_app.test_client()
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/wiki/admin-sidebar-wiki")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "/app/admin/stats" in html
        assert "System status" in html

    def test_admin_stats_sidebar_hidden_for_non_admin(self, client, owner_token, owner_user, wiki_model):
        """Non-admin does not see System status link in sidebar."""
        wiki_model.create(
            slug="nonadmin-sidebar-wiki",
            owner_did="did:plc:owner",
            display_name="Non-Admin Sidebar Wiki",
            repo_path="/tmp/fake/repo",
            mcp_token_hash="f" * 64,
        )
        client.set_cookie("platform_token", owner_token, domain="localhost")
        resp = client.get("/app/wiki/nonadmin-sidebar-wiki")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "/app/admin/stats" not in html


# --- Rate limiting tests ---


class TestRateLimiting:
    """Management UI rate limiting.

    Flask-Limiter disables itself when TESTING=True. To exercise rate limits,
    we must set RATELIMIT_ENABLED=True explicitly in the app config.
    """

    @pytest.fixture
    def rate_limit_app(self, rsa_keys, user_model, wiki_model, platform_jwt, tmp_path):
        """Management UI app with rate limiting enabled."""
        import os
        os.environ["FLASK_SECRET_KEY"] = "test-secret-management-ui"
        from app.api_server import _create_flask_app

        app = _create_flask_app()
        app.config["TESTING"] = True
        app.config["RATELIMIT_ENABLED"] = True

        private_key, public_key = rsa_keys
        from app.auth.middleware import AuthMiddleware
        auth_middleware = AuthMiddleware(
            platform_jwt=platform_jwt,
            user_model=user_model,
        )
        app.config["AUTH_MIDDLEWARE"] = auth_middleware
        app.config["USER_MODEL"] = user_model
        app.config["WIKI_MODEL"] = wiki_model
        app.config["WIKI_BASE"] = str(tmp_path / "wikis")

        yield app

        os.environ.pop("FLASK_SECRET_KEY", None)

    @pytest.fixture
    def rate_limit_client(self, rate_limit_app):
        return rate_limit_app.test_client()

    @pytest.fixture
    def owner_token_rl(self, platform_jwt, owner_user):
        """Valid JWT for owner user (rate-limit fixture scope)."""
        return platform_jwt.create_token(
            user_did="did:plc:owner",
            handle="owner.bsky.social",
            display_name="Owner",
        )

    @pytest.fixture
    def test_wiki_rl(self, wiki_model, tmp_path):
        """A wiki record for rate-limit tests (no repo needed)."""
        return wiki_model.create(
            slug="rl-wiki",
            owner_did="did:plc:owner",
            display_name="RL Wiki",
            repo_path=str(tmp_path / "rl-wiki" / "repo"),
            mcp_token_hash="testhash",
        )

    def test_mcp_regenerate_rate_limited(
        self, rate_limit_client, owner_token_rl, owner_user, test_wiki_rl
    ):
        """POST /app/wiki/<slug>/mcp/regenerate should return 429 after exceeding 2/minute."""
        rate_limit_client.set_cookie("platform_token", owner_token_rl, domain="localhost")
        responses = []
        for _ in range(4):
            resp = rate_limit_client.post(
                "/app/wiki/rl-wiki/mcp/regenerate",
                environ_base={"REMOTE_ADDR": "10.0.0.1"},
                follow_redirects=False,
            )
            responses.append(resp.status_code)

        assert 429 in responses, (
            f"Expected at least one 429 after exceeding mcp_regenerate rate limit; got: {responses}"
        )

    def test_wiki_settings_update_rate_limited(
        self, rate_limit_client, owner_token_rl, owner_user, test_wiki_rl
    ):
        """POST /app/wiki/<slug>/settings should return 429 after exceeding 5/minute."""
        rate_limit_client.set_cookie("platform_token", owner_token_rl, domain="localhost")
        responses = []
        for _ in range(7):
            resp = rate_limit_client.post(
                "/app/wiki/rl-wiki/settings",
                data={"display_name": "Updated"},
                environ_base={"REMOTE_ADDR": "10.0.0.2"},
                follow_redirects=False,
            )
            responses.append(resp.status_code)

        assert 429 in responses, (
            f"Expected at least one 429 after exceeding wiki_settings_update rate limit; got: {responses}"
        )
