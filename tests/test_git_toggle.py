"""Tests for per-wiki git access toggle: GIT_WEB_SERVER preference + management endpoint.

Feature:
- New wikis seed GIT_WEB_SERVER=False in wiki.db (via _init_wiki_db platform_preferences)
- POST /api/wikis/{slug}/git {"enabled": true|false} owner-only endpoint
  - 404 if wiki not found
  - 403 if caller is not the wiki owner
  - 200 + UPSERTs GIT_WEB_SERVER in per-wiki wiki.db
  - Can flip False→True and True→False
- GET /api/wikis/{slug} response includes git_access_enabled field
- After toggling on, otterwiki app.config["GIT_WEB_SERVER"] is True on next request
  (update_app_config reload)
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
import tempfile
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.auth.middleware import AuthenticatedUser, AuthMiddleware, AuthError
from app.db import init_schema
from app.models.user import UserModel
from app.models.wiki import WikiModel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_environ(method, path, body=None, authorization=None):
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "SERVER_NAME": "robot.wtf",
        "SERVER_PORT": "443",
        "HTTP_HOST": "robot.wtf",
    }
    if authorization:
        environ["HTTP_AUTHORIZATION"] = authorization
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        environ["wsgi.input"] = io.BytesIO(payload)
        environ["CONTENT_LENGTH"] = str(len(payload))
        environ["CONTENT_TYPE"] = "application/json"
    else:
        environ["wsgi.input"] = io.BytesIO(b"")
        environ["CONTENT_LENGTH"] = "0"
    return environ


class _ResponseCapture:
    def __init__(self):
        self.status = ""
        self.headers = []

    def __call__(self, status, headers, exc_info=None):
        self.status = status
        self.headers = headers


def _call_api(middleware, method, path, body=None, authorization="Bearer test-token"):
    environ = _make_environ(method, path, body=body, authorization=authorization)
    capture = _ResponseCapture()
    result = middleware(environ, capture)
    status_code = int(capture.status.split(" ", 1)[0])
    response_body = json.loads(b"".join(result))
    return status_code, response_body


# ---------------------------------------------------------------------------
# Fixtures (inline, no conftest dependency beyond what's already there)
# ---------------------------------------------------------------------------


def _make_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    init_schema(conn)
    return conn


def _make_middleware(db, user_model, wiki_model, wiki_base, auth_authenticate=None):
    from app.management.routes import ManagementMiddleware

    def stub_app(environ, start_response):
        start_response("200 OK", [("Content-Type", "application/json")])
        return [b"{}"]

    mock_auth = MagicMock(spec=AuthMiddleware)
    if auth_authenticate:
        mock_auth.authenticate = MagicMock(side_effect=auth_authenticate)

    return ManagementMiddleware(
        stub_app,
        auth_middleware=mock_auth,
        user_model=user_model,
        wiki_model=wiki_model,
        wiki_base=wiki_base,
    ), mock_auth


def _owner_authenticated(user_model, user_did="did:plc:owner"):
    """Return an authenticate side_effect that returns the given user."""
    def authenticate(authorization):
        if not authorization:
            raise AuthError("Missing Authorization header", status=401)
        user = user_model.get(user_did)
        if not user:
            raise AuthError("User not found", status=401)
        return AuthenticatedUser(
            user_did=user["did"],
            handle=user["handle"],
            display_name=user.get("display_name", ""),
            record=user,
        )
    return authenticate


# ---------------------------------------------------------------------------
# Area 3a: _init_wiki_db seeds GIT_WEB_SERVER=False
# ---------------------------------------------------------------------------


class TestInitWikiDbSeedsGitWebServer:
    """New wikis must have GIT_WEB_SERVER=False seeded in their wiki.db."""

    def test_init_wiki_db_seeds_git_web_server_false(self, tmp_path):
        """_init_wiki_db seeds GIT_WEB_SERVER=False in the preferences table."""
        from app.resolver import _init_wiki_db, _initialized_dbs

        db_path = str(tmp_path / "wiki.db")
        _initialized_dbs.discard(db_path)
        _init_wiki_db(db_path)

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT value FROM preferences WHERE name = 'GIT_WEB_SERVER'"
        ).fetchone()
        conn.close()

        assert row is not None, (
            "GIT_WEB_SERVER preference must be seeded by _init_wiki_db"
        )
        # Value should be False-y: 'False' or '0' or similar
        assert row[0].lower() in ("false", "0"), (
            f"GIT_WEB_SERVER must default to False; got {row[0]!r}"
        )

    def test_init_wiki_db_does_not_override_existing_git_web_server(self, tmp_path):
        """If GIT_WEB_SERVER is already set, _init_wiki_db must not overwrite it."""
        from app.resolver import _init_wiki_db, _initialized_dbs

        db_path = str(tmp_path / "wiki_existing.db")

        # Pre-create DB with GIT_WEB_SERVER=True
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE preferences (name VARCHAR(256) PRIMARY KEY, value TEXT)"
        )
        conn.execute(
            "INSERT INTO preferences (name, value) VALUES ('GIT_WEB_SERVER', 'True')"
        )
        conn.commit()
        conn.close()

        _initialized_dbs.discard(db_path)
        _init_wiki_db(db_path)

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT value FROM preferences WHERE name = 'GIT_WEB_SERVER'"
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == "True", (
            "Existing GIT_WEB_SERVER=True must not be overwritten by _init_wiki_db"
        )


# ---------------------------------------------------------------------------
# Area 3b: POST /api/wikis/{slug}/git endpoint
# ---------------------------------------------------------------------------


class TestGitToggleEndpoint:
    """Management API: POST /api/wikis/{slug}/git toggles GIT_WEB_SERVER."""

    def _setup(self, tmp_path):
        """Return (middleware, wiki, wiki_db_path)."""
        db = _make_db()
        user_model = UserModel(db)
        wiki_model = WikiModel(db)
        wiki_base = str(tmp_path / "wikis")

        owner = user_model.create(
            did="did:plc:owner",
            handle="owner.bsky.social",
            display_name="Owner",
        )

        middleware, mock_auth = _make_middleware(
            db, user_model, wiki_model, wiki_base,
            auth_authenticate=_owner_authenticated(user_model),
        )

        # Create a wiki via the API (sets up repo + wiki.db)
        status, body = _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "my-wiki", "display_name": "My Wiki"},
        )
        assert status == 201, f"Wiki creation failed: {body}"

        wiki_dir = os.path.join(wiki_base, "my-wiki")
        wiki_db_path = os.path.join(wiki_dir, "wiki.db")

        return middleware, mock_auth, user_model, wiki_db_path

    def test_enable_git_access_returns_200(self, tmp_path):
        """POST /api/wikis/my-wiki/git {enabled: true} returns 200."""
        middleware, _, _, _ = self._setup(tmp_path)

        status, body = _call_api(
            middleware, "POST", "/api/wikis/my-wiki/git",
            body={"enabled": True},
        )
        assert status == 200, (
            f"Enabling git access must return 200; got {status}: {body}"
        )

    def test_disable_git_access_returns_200(self, tmp_path):
        """POST /api/wikis/my-wiki/git {enabled: false} returns 200."""
        middleware, _, _, _ = self._setup(tmp_path)

        status, body = _call_api(
            middleware, "POST", "/api/wikis/my-wiki/git",
            body={"enabled": False},
        )
        assert status == 200, (
            f"Disabling git access must return 200; got {status}: {body}"
        )

    def test_enable_git_access_upserts_preference_in_wiki_db(self, tmp_path):
        """POST /api/wikis/my-wiki/git {enabled: true} sets GIT_WEB_SERVER='True' in wiki.db."""
        middleware, _, _, wiki_db_path = self._setup(tmp_path)

        _call_api(
            middleware, "POST", "/api/wikis/my-wiki/git",
            body={"enabled": True},
        )

        assert os.path.exists(wiki_db_path), "wiki.db must exist"
        conn = sqlite3.connect(wiki_db_path)
        row = conn.execute(
            "SELECT value FROM preferences WHERE name = 'GIT_WEB_SERVER'"
        ).fetchone()
        conn.close()

        assert row is not None, "GIT_WEB_SERVER must be set in wiki.db after toggle"
        assert row[0].lower() in ("true", "1"), (
            f"GIT_WEB_SERVER must be True after enabling; got {row[0]!r}"
        )

    def test_disable_git_access_upserts_preference_in_wiki_db(self, tmp_path):
        """POST {enabled: false} after {enabled: true} flips GIT_WEB_SERVER back to False."""
        middleware, _, _, wiki_db_path = self._setup(tmp_path)

        # Enable first
        _call_api(
            middleware, "POST", "/api/wikis/my-wiki/git",
            body={"enabled": True},
        )

        # Then disable
        _call_api(
            middleware, "POST", "/api/wikis/my-wiki/git",
            body={"enabled": False},
        )

        conn = sqlite3.connect(wiki_db_path)
        row = conn.execute(
            "SELECT value FROM preferences WHERE name = 'GIT_WEB_SERVER'"
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0].lower() in ("false", "0"), (
            f"GIT_WEB_SERVER must be False after disabling; got {row[0]!r}"
        )

    def test_toggle_nonexistent_wiki_returns_404(self, tmp_path):
        """POST /api/wikis/nonexistent/git returns 404."""
        middleware, _, _, _ = self._setup(tmp_path)

        status, body = _call_api(
            middleware, "POST", "/api/wikis/nonexistent/git",
            body={"enabled": True},
        )
        assert status == 404, (
            f"Toggle on nonexistent wiki must return 404; got {status}: {body}"
        )

    def test_toggle_by_non_owner_returns_403(self, tmp_path):
        """POST /api/wikis/my-wiki/git by a non-owner returns 403."""
        db = _make_db()
        user_model = UserModel(db)
        wiki_model = WikiModel(db)
        wiki_base = str(tmp_path / "wikis")

        owner = user_model.create(
            did="did:plc:owner",
            handle="owner.bsky.social",
            display_name="Owner",
        )
        collab = user_model.create(
            did="did:plc:collab",
            handle="collab.bsky.social",
            display_name="Collab",
        )

        # Create wiki as owner
        middleware_owner, _ = _make_middleware(
            db, user_model, wiki_model, wiki_base,
            auth_authenticate=_owner_authenticated(user_model, "did:plc:owner"),
        )
        status, body = _call_api(
            middleware_owner, "POST", "/api/wikis",
            body={"slug": "guarded-wiki", "display_name": "Guarded"},
        )
        assert status == 201

        # Try to toggle as collab
        middleware_collab, _ = _make_middleware(
            db, user_model, wiki_model, wiki_base,
            auth_authenticate=_owner_authenticated(user_model, "did:plc:collab"),
        )
        status, body = _call_api(
            middleware_collab, "POST", "/api/wikis/guarded-wiki/git",
            body={"enabled": True},
        )
        assert status == 403, (
            f"Non-owner toggle must return 403; got {status}: {body}"
        )


# ---------------------------------------------------------------------------
# Area 3c: GET /api/wikis/{slug} includes git_access_enabled
# ---------------------------------------------------------------------------


class TestGetWikiIncludesGitAccessEnabled:
    """GET /api/wikis/{slug} response body must include git_access_enabled."""

    def _setup(self, tmp_path):
        db = _make_db()
        user_model = UserModel(db)
        wiki_model = WikiModel(db)
        wiki_base = str(tmp_path / "wikis")

        user_model.create(
            did="did:plc:owner",
            handle="owner.bsky.social",
            display_name="Owner",
        )

        middleware, mock_auth = _make_middleware(
            db, user_model, wiki_model, wiki_base,
            auth_authenticate=_owner_authenticated(user_model),
        )

        status, body = _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "info-wiki", "display_name": "Info Wiki"},
        )
        assert status == 201

        return middleware

    def test_get_wiki_includes_git_access_enabled_field(self, tmp_path):
        """GET /api/wikis/info-wiki response includes git_access_enabled key."""
        middleware = self._setup(tmp_path)

        status, body = _call_api(middleware, "GET", "/api/wikis/info-wiki")
        assert status == 200, f"Expected 200; got {status}: {body}"

        wiki = body.get("wiki", body)
        assert "git_access_enabled" in wiki or "git_access_enabled" in body, (
            f"GET /api/wikis/<slug> must include git_access_enabled; "
            f"got response: {body!r}"
        )

    def test_get_wiki_git_access_enabled_false_by_default(self, tmp_path):
        """New wikis have git_access_enabled=False by default."""
        middleware = self._setup(tmp_path)

        status, body = _call_api(middleware, "GET", "/api/wikis/info-wiki")
        assert status == 200

        wiki = body.get("wiki", body)
        enabled = wiki.get("git_access_enabled", body.get("git_access_enabled"))
        assert enabled is False or enabled == "False" or enabled == 0, (
            f"New wiki must have git_access_enabled=False; got {enabled!r}"
        )

    def test_get_wiki_git_access_enabled_true_after_toggle(self, tmp_path):
        """After toggling on, GET response has git_access_enabled=True."""
        middleware = self._setup(tmp_path)

        # Enable
        _call_api(
            middleware, "POST", "/api/wikis/info-wiki/git",
            body={"enabled": True},
        )

        status, body = _call_api(middleware, "GET", "/api/wikis/info-wiki")
        assert status == 200

        wiki = body.get("wiki", body)
        enabled = wiki.get("git_access_enabled", body.get("git_access_enabled"))
        assert enabled is True or enabled == "True" or enabled == 1, (
            f"After enabling, git_access_enabled must be True; got {enabled!r}"
        )


# ---------------------------------------------------------------------------
# Area 3d: app.config["GIT_WEB_SERVER"] reflects toggle on next request
# ---------------------------------------------------------------------------


class TestAppConfigReflectsToggle:
    """After toggling GIT_WEB_SERVER in wiki.db, otterwiki app.config is updated."""

    def test_update_app_config_called_after_toggle(self, tmp_path):
        """POST /api/wikis/{slug}/git triggers update_app_config so config reflects change.

        This verifies that _swap_database (or equivalent) is called to reload
        preferences into otterwiki.server.app.config after the toggle.

        We check indirectly: after enabling git access, reading back GIT_WEB_SERVER
        from the wiki.db directly confirms the DB was written. The resolver-side
        reload is tested in test_git_auth_bridge.py (end-to-end).
        """
        db = _make_db()
        user_model = UserModel(db)
        wiki_model = WikiModel(db)
        wiki_base = str(tmp_path / "wikis")

        user_model.create(
            did="did:plc:owner",
            handle="owner.bsky.social",
            display_name="Owner",
        )

        middleware, _ = _make_middleware(
            db, user_model, wiki_model, wiki_base,
            auth_authenticate=_owner_authenticated(user_model),
        )

        # Create the wiki
        status, body = _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "reload-wiki", "display_name": "Reload Wiki"},
        )
        assert status == 201

        wiki_db_path = os.path.join(wiki_base, "reload-wiki", "wiki.db")

        # Enable git access
        status, body = _call_api(
            middleware, "POST", "/api/wikis/reload-wiki/git",
            body={"enabled": True},
        )
        assert status == 200, (
            f"Toggle must succeed; got {status}: {body}"
        )

        # Verify DB was written (resolver reads from this DB via update_app_config)
        assert os.path.exists(wiki_db_path), "wiki.db must exist"
        conn = sqlite3.connect(wiki_db_path)
        row = conn.execute(
            "SELECT value FROM preferences WHERE name = 'GIT_WEB_SERVER'"
        ).fetchone()
        conn.close()

        assert row is not None, (
            "GIT_WEB_SERVER must be written to wiki.db; config reload won't work otherwise"
        )
        assert row[0].lower() in ("true", "1"), (
            f"Expected True in wiki.db after toggle; got {row[0]!r}"
        )
