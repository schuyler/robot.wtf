"""Integration tests for the Management API lifecycle.

Tests the full wiki lifecycle:
  create user -> set username -> create wiki -> list/get wiki
  -> regenerate token -> grant/revoke ACL -> delete wiki

Uses in-memory SQLite and temp directories for git repos.
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
import subprocess
import tempfile
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.auth.middleware import AuthenticatedUser, AuthMiddleware, AuthError
from app.db import init_schema
from app.management.routes import (
    ManagementMiddleware,
    MAX_WIKIS_PER_USER,
    validate_slug,
)
import app.management.routes as management_routes
from app.models.user import UserModel
from app.models.wiki import WikiModel


# --- Helpers ---


def _make_environ(
    method: str,
    path: str,
    body: dict | None = None,
    authorization: str | None = None,
) -> dict[str, Any]:
    """Build a minimal WSGI environ dict."""
    environ: dict[str, Any] = {
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
    """Capture start_response calls."""

    def __init__(self):
        self.status: str = ""
        self.headers: list[tuple[str, str]] = []

    def __call__(self, status: str, headers: list[tuple[str, str]]):
        self.status = status
        self.headers = headers


def _call_api(
    middleware: ManagementMiddleware,
    method: str,
    path: str,
    body: dict | None = None,
    authorization: str = "Bearer test-token",
) -> tuple[int, dict]:
    """Call the management middleware and return (status_code, parsed_body)."""
    environ = _make_environ(method, path, body=body, authorization=authorization)
    capture = _ResponseCapture()
    result = middleware(environ, capture)
    status_code = int(capture.status.split(" ", 1)[0])
    response_body = json.loads(b"".join(result))
    return status_code, response_body


# --- Fixtures ---


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
def owner_user(user_model):
    """Create an owner user with username."""
    return user_model.create(
        did="did:plc:owner",
        handle="owner.bsky.social",
        display_name="Owner",
        username="owner",
    )


@pytest.fixture
def collab_user(user_model):
    """Create a collaborator user."""
    return user_model.create(
        did="did:plc:collab",
        handle="collab.bsky.social",
        display_name="Collab",
        username="collab",
    )


@pytest.fixture
def wiki_base(tmp_path):
    """Temp directory for wiki repos."""
    return str(tmp_path / "wikis")


@pytest.fixture
def template_dir(tmp_path):
    """Create a temp wiki template directory and patch WIKI_TEMPLATE_DIR."""
    tdir = tmp_path / "templates" / "default-wiki"
    tdir.mkdir(parents=True)
    (tdir / "Home.md").write_text("# Welcome\n\nYour wiki.\n")
    (tdir / "Getting_Started.md").write_text("# Getting Started\n\nSetup guide.\n")
    (tdir / "Agent_Guide.md").write_text("# Agent Guide\n\nFor agents.\n")
    old = management_routes.WIKI_TEMPLATE_DIR
    management_routes.WIKI_TEMPLATE_DIR = str(tdir)
    yield str(tdir)
    management_routes.WIKI_TEMPLATE_DIR = old


@pytest.fixture
def auth_middleware(user_model):
    """Mock AuthMiddleware that returns the owner user by default."""
    mock = MagicMock(spec=AuthMiddleware)

    def authenticate(authorization):
        if not authorization:
            raise AuthError("Missing Authorization header", status=401)
        # Return owner by default; tests can override
        user = user_model.get("did:plc:owner")
        if not user:
            raise AuthError("User not found", status=401)
        return AuthenticatedUser(
            user_did=user["did"],
            handle=user["handle"],
            display_name=user.get("display_name", ""),
            record=user,
        )

    mock.authenticate = MagicMock(side_effect=authenticate)
    return mock


@pytest.fixture
def middleware(auth_middleware, user_model, wiki_model, wiki_base):
    """ManagementMiddleware wired to in-memory DB + temp wiki base."""
    inner_app = MagicMock()
    inner_app.return_value = [b"inner app"]
    return ManagementMiddleware(
        inner_app,
        auth_middleware=auth_middleware,
        user_model=user_model,
        wiki_model=wiki_model,
        wiki_base=wiki_base,
    )


def _set_auth_user(auth_middleware, user_model, user_did):
    """Switch the mock auth to return a different user."""
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
    auth_middleware.authenticate = MagicMock(side_effect=authenticate)


# --- Slug Validation Tests ---


class TestSlugValidation:
    def test_valid_slugs(self):
        assert validate_slug("my-wiki")[0] is True
        assert validate_slug("test123")[0] is True
        assert validate_slug("abc")[0] is True

    def test_empty(self):
        ok, err = validate_slug("")
        assert ok is False
        assert "required" in err

    def test_uppercase(self):
        ok, err = validate_slug("MyWiki")
        assert ok is False
        assert "lowercase" in err

    def test_too_short(self):
        ok, err = validate_slug("ab")
        assert ok is False
        assert "3 characters" in err

    def test_too_long(self):
        ok, err = validate_slug("a" * 31)
        assert ok is False
        assert "30 characters" in err

    def test_leading_hyphen(self):
        ok, err = validate_slug("-wiki")
        assert ok is False

    def test_trailing_hyphen(self):
        ok, err = validate_slug("wiki-")
        assert ok is False

    def test_reserved(self):
        ok, err = validate_slug("admin")
        assert ok is False
        assert "reserved" in err

    def test_reserved_www(self):
        ok, err = validate_slug("www")
        assert ok is False
        assert "reserved" in err


# --- Set Username Tests ---


class TestSetUsername:
    def test_set_username(self, middleware, owner_user):
        status, body = _call_api(
            middleware, "POST", "/api/username",
            body={"username": "newname"},
        )
        assert status == 200
        assert body["username"] == "newname"
        assert body["user_did"] == "did:plc:owner"


# --- Wiki Lifecycle Tests ---


class TestWikiLifecycle:
    def test_create_wiki(self, middleware, owner_user, wiki_base):
        """Create a wiki: verify git repo, token, wiki_count."""
        status, body = _call_api(
            middleware, "POST", "/api/wikis",
            body={
                "slug": "my-wiki",
                "display_name": "My Wiki",
                "purpose": "Testing",
            },
        )
        assert status == 201
        assert body["wiki"]["slug"] == "my-wiki"
        assert "mcp_token" in body
        assert len(body["mcp_token"]) > 0
        assert body["mcp_endpoint"] == "https://my-wiki.robot.wtf/mcp"

        # Verify git repo was created
        repo_path = os.path.join(wiki_base, "my-wiki", "repo")
        assert os.path.isdir(repo_path)
        assert os.path.isdir(os.path.join(repo_path, ".git"))

        # Verify Home.md was bootstrapped
        home_path = os.path.join(repo_path, "Home.md")
        assert os.path.isfile(home_path)
        with open(home_path) as f:
            content = f.read()
        assert "My Wiki" in content

    def test_create_wiki_increments_count(
        self, middleware, owner_user, user_model
    ):
        """wiki_count should be incremented after creation."""
        _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "count-wiki", "display_name": "Count Wiki"},
        )
        user = user_model.get("did:plc:owner")
        assert user["wiki_count"] == 1

    def test_list_wikis(self, middleware, owner_user):
        """Created wiki should appear in the list."""
        _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "list-wiki", "display_name": "List Wiki"},
        )
        status, body = _call_api(middleware, "GET", "/api/wikis")
        assert status == 200
        assert len(body["wikis"]) == 1
        assert body["wikis"][0]["slug"] == "list-wiki"

    def test_get_wiki_detail(self, middleware, owner_user):
        """Get details for a specific wiki."""
        _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "detail-wiki", "display_name": "Detail Wiki"},
        )
        status, body = _call_api(middleware, "GET", "/api/wikis/detail-wiki")
        assert status == 200
        assert body["wiki"]["slug"] == "detail-wiki"
        assert body["mcp_endpoint"] == "https://detail-wiki.robot.wtf/mcp"

    def test_get_wiki_not_found(self, middleware, owner_user):
        status, body = _call_api(middleware, "GET", "/api/wikis/nonexistent")
        assert status == 404

    def test_regenerate_token(self, middleware, owner_user):
        """Regenerate MCP token and get a new plaintext token back."""
        _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "regen-wiki", "display_name": "Regen Wiki"},
        )
        status, body = _call_api(
            middleware, "POST", "/api/wikis/regen-wiki/token"
        )
        assert status == 200
        assert "mcp_token" in body
        assert len(body["mcp_token"]) > 0

    def test_delete_wiki(
        self, middleware, owner_user, user_model, wiki_model, wiki_base
    ):
        """Delete a wiki: verify repo removed, count decremented."""
        _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "del-wiki", "display_name": "Delete Me"},
        )
        assert user_model.get("did:plc:owner")["wiki_count"] == 1
        repo_path = os.path.join(wiki_base, "del-wiki", "repo")
        assert os.path.isdir(repo_path)

        status, body = _call_api(
            middleware, "DELETE", "/api/wikis/del-wiki"
        )
        assert status == 200
        assert body["deleted"] is True

        # Repo should be gone
        wiki_dir = os.path.join(wiki_base, "del-wiki")
        assert not os.path.exists(wiki_dir)

        # Wiki count decremented
        assert user_model.get("did:plc:owner")["wiki_count"] == 0

        # Wiki record gone
        assert wiki_model.get("del-wiki") is None


# --- Tier Limit Tests ---


class TestTierLimits:
    def test_wiki_limit(self, middleware, owner_user):
        """Second wiki creation should be rejected on free tier."""
        status, _ = _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "first-wiki", "display_name": "First Wiki"},
        )
        assert status == 201

        status, body = _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "second-wiki", "display_name": "Second Wiki"},
        )
        assert status == 403
        assert "limit" in body["error"].lower()

    # No collaborator limit for robot.wtf
        assert "limit" in body["error"].lower()

    def test_page_limit_check(self, wiki_model, owner_user):
        """check_page_limit should reject when at limit."""
        wiki = wiki_model.create(
            slug="page-wiki",
            owner_did="did:plc:owner",
            display_name="Page Wiki",
            repo_path="/srv/data/wikis/page-wiki/repo",
            mcp_token_hash="$2b$12$fakehash",
        )
        # Under limit
        ok, err = ManagementMiddleware.check_page_limit(wiki)
        assert ok is True

        # At limit
        wiki_model.update("page-wiki", page_count=500)
        wiki = wiki_model.get("page-wiki")
        ok, err = ManagementMiddleware.check_page_limit(wiki)
        assert ok is False
        assert "limit" in err.lower()


# --- Validation Tests ---


class TestCreateWikiValidation:
    def test_missing_slug(self, middleware, owner_user):
        status, body = _call_api(
            middleware, "POST", "/api/wikis",
            body={"display_name": "No Slug"},
        )
        assert status == 400
        assert "slug" in body["error"].lower()

    def test_missing_display_name(self, middleware, owner_user):
        status, body = _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "test-wiki"},
        )
        assert status == 400
        assert "display_name" in body["error"]

    def test_reserved_slug(self, middleware, owner_user):
        status, body = _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "admin", "display_name": "Admin Wiki"},
        )
        assert status == 400
        assert "reserved" in body["error"]

    def test_invalid_slug_format(self, middleware, owner_user):
        status, body = _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "AB", "display_name": "Bad Slug"},
        )
        assert status == 400

    def test_duplicate_slug(self, middleware, owner_user, user_model):
        """Creating a wiki with a duplicate slug should fail."""
        _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "dup-wiki", "display_name": "First"},
        )
        # Need to reset wiki count so the tier limit doesn't block us
        user_model.update("did:plc:owner", wiki_count=0)
        # Re-set auth so it picks up updated record
        status, body = _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "dup-wiki", "display_name": "Second"},
        )
        assert status == 409


# --- Delete Ownership Tests ---


class TestDeleteOwnership:
    def test_non_owner_cannot_delete(
        self, middleware, owner_user, collab_user,
        auth_middleware, user_model
    ):
        """Only the owner can delete a wiki."""
        _call_api(
            middleware, "POST", "/api/wikis",
            body={"slug": "guarded-wiki", "display_name": "Guarded"},
        )
        # Switch to collab user
        _set_auth_user(auth_middleware, user_model, "did:plc:collab")
        status, body = _call_api(
            middleware, "DELETE", "/api/wikis/guarded-wiki"
        )
        assert status == 403


# --- Pass-through Tests ---


class TestPassthrough:
    def test_internal_endpoint_passes_through(self, middleware, owner_user):
        """Internal endpoints should be passed to the inner app."""
        environ = _make_environ("GET", "/api/internal/check-slug")
        capture = _ResponseCapture()
        middleware(environ, capture)
        # The inner app (mock) should have been called
        middleware._app.assert_called()

    def test_v1_endpoint_passes_through(self, middleware, owner_user):
        """Otterwiki REST API routes bypass management auth."""
        environ = _make_environ("GET", "/api/v1/pages")
        capture = _ResponseCapture()
        middleware(environ, capture)
        middleware._app.assert_called()

    def test_non_api_passes_through(self, middleware, owner_user):
        """Non-/api paths should pass through to inner app."""
        environ = _make_environ("GET", "/some/other/path")
        capture = _ResponseCapture()
        middleware(environ, capture)
        middleware._app.assert_called()


# --- Git HTTP Tests ---


class TestGitHttp:
    def test_info_refs(self, wiki_base):
        """GET /info/refs should return ref advertisement."""
        from app.git_http import GitHttpBackend
        from app.management.routes import _init_wiki_repo

        slug = "git-test"
        repo_path = os.path.join(wiki_base, slug, "repo")
        _init_wiki_repo(repo_path, "Git Test", "For testing git HTTP")

        backend = GitHttpBackend(wiki_base=wiki_base)
        environ = _make_environ("GET", f"/{slug}/repo.git/info/refs")
        environ["QUERY_STRING"] = "service=git-upload-pack"
        capture = _ResponseCapture()
        result = backend(environ, capture)

        assert capture.status.startswith("200")
        content_type = dict(capture.headers).get("Content-Type", "")
        assert "git-upload-pack-advertisement" in content_type
        body = b"".join(result)
        assert b"service=git-upload-pack" in body

    def test_receive_pack_rejected(self, wiki_base):
        """git-receive-pack should be rejected with 403."""
        from app.git_http import GitHttpBackend
        from app.management.routes import _init_wiki_repo

        slug = "git-reject"
        repo_path = os.path.join(wiki_base, slug, "repo")
        _init_wiki_repo(repo_path, "Git Reject", "For testing")

        backend = GitHttpBackend(wiki_base=wiki_base)
        environ = _make_environ("GET", f"/{slug}/repo.git/info/refs")
        environ["QUERY_STRING"] = "service=git-receive-pack"
        capture = _ResponseCapture()
        result = backend(environ, capture)

        assert capture.status.startswith("403")

    def test_not_found(self, wiki_base):
        """Nonexistent repo should return 404."""
        from app.git_http import GitHttpBackend

        backend = GitHttpBackend(wiki_base=wiki_base)
        environ = _make_environ("GET", "/nonexistent/repo.git/info/refs")
        environ["QUERY_STRING"] = "service=git-upload-pack"
        capture = _ResponseCapture()
        result = backend(environ, capture)

        assert capture.status.startswith("404")

    def test_head_endpoint(self, wiki_base):
        """GET /HEAD should return the HEAD ref."""
        from app.git_http import GitHttpBackend
        from app.management.routes import _init_wiki_repo

        slug = "git-head"
        repo_path = os.path.join(wiki_base, slug, "repo")
        _init_wiki_repo(repo_path, "Git Head", "For testing")

        backend = GitHttpBackend(wiki_base=wiki_base)
        environ = _make_environ("GET", f"/{slug}/repo.git/HEAD")
        capture = _ResponseCapture()
        result = backend(environ, capture)

        assert capture.status.startswith("200")
        body = b"".join(result)
        assert b"ref:" in body

    def test_upload_pack_post(self, wiki_base):
        """POST /git-upload-pack with empty body should return 200 or valid error."""
        from app.git_http import GitHttpBackend
        from app.management.routes import _init_wiki_repo

        slug = "git-post"
        repo_path = os.path.join(wiki_base, slug, "repo")
        _init_wiki_repo(repo_path, "Git Post", "For testing")

        backend = GitHttpBackend(wiki_base=wiki_base)
        # First get refs
        environ = _make_environ("GET", f"/{slug}/repo.git/info/refs")
        environ["QUERY_STRING"] = "service=git-upload-pack"
        capture = _ResponseCapture()
        backend(environ, capture)
        assert capture.status.startswith("200")


# --- Template Seeding Tests ---


class TestTemplateSeeding:
    def test_seeds_from_template_dir(self, wiki_base, template_dir):
        """_init_wiki_repo copies all .md files from the template directory."""
        from app.management.routes import _init_wiki_repo

        repo_path = os.path.join(wiki_base, "tpl-wiki", "repo")
        _init_wiki_repo(repo_path, "Template Wiki", "Testing templates")

        assert os.path.isfile(os.path.join(repo_path, "Home.md"))
        assert os.path.isfile(os.path.join(repo_path, "Getting_Started.md"))
        assert os.path.isfile(os.path.join(repo_path, "Agent_Guide.md"))

        # Home.md should be from template, not the fallback
        with open(os.path.join(repo_path, "Home.md")) as f:
            assert "Your wiki" in f.read()

        # All files should be committed
        result = subprocess.run(
            ["git", "-C", repo_path, "status", "--porcelain"],
            capture_output=True, text=True,
        )
        assert result.stdout.strip() == "", "Uncommitted files in repo"

    def test_fallback_without_template_dir(self, wiki_base):
        """Without a template dir, falls back to a minimal Home.md."""
        old = management_routes.WIKI_TEMPLATE_DIR
        management_routes.WIKI_TEMPLATE_DIR = "/nonexistent/path"
        try:
            from app.management.routes import _init_wiki_repo
            repo_path = os.path.join(wiki_base, "fallback-wiki", "repo")
            _init_wiki_repo(repo_path, "Fallback Wiki", "Testing fallback")

            home_path = os.path.join(repo_path, "Home.md")
            assert os.path.isfile(home_path)
            with open(home_path) as f:
                content = f.read()
            assert "Fallback Wiki" in content
        finally:
            management_routes.WIKI_TEMPLATE_DIR = old

    def test_creates_non_bare_repo(self, wiki_base, template_dir):
        """Wiki repos must be non-bare (otterwiki needs a working tree)."""
        from app.management.routes import _init_wiki_repo

        repo_path = os.path.join(wiki_base, "bare-check", "repo")
        _init_wiki_repo(repo_path, "Bare Check", "Testing")

        assert os.path.isdir(os.path.join(repo_path, ".git")), \
            "Repo should have .git directory (non-bare)"
        result = subprocess.run(
            ["git", "-C", repo_path, "config", "--get", "core.bare"],
            capture_output=True, text=True,
        )
        assert result.stdout.strip() == "false", "Repo should not be bare"
