"""Management API -- WSGI middleware for wiki lifecycle operations.

Intercepts ``/api/*`` requests before they reach the otterwiki Flask
app. All other requests are passed through unmodified.

Every management route requires a valid platform JWT in the
Authorization header (except /api/auth/callback).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from typing import Any, Callable

from app.auth.middleware import AuthError, AuthMiddleware, AuthenticatedUser
from app.constants import MAX_PAGES_PER_WIKI
from app.management.token import generate_mcp_token
from app.resolver import _init_wiki_db, _initialized_dbs
from app.models.user import RESERVED_NAMES, UserModel, validate_username
from app.models.wiki import WikiModel

logger = logging.getLogger(__name__)

# --- Tier limits (free tier) ---
MAX_WIKIS_PER_USER = 1
# No collaborator limit for robot.wtf

# Slug validation: lowercase alphanumeric + hyphens, 3-30 chars,
# no leading/trailing hyphens
_SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,28}[a-z0-9]$")

def validate_slug(slug: str) -> tuple[bool, str | None]:
    """Validate a wiki slug for format and reserved names.

    Returns:
        (True, None) if valid, (False, error_message) if invalid.
    """
    if not slug:
        return False, "slug is required"
    if slug != slug.lower():
        return False, "slug must be lowercase"
    if not _SLUG_PATTERN.match(slug):
        if len(slug) < 3:
            return False, "slug must be at least 3 characters"
        if len(slug) > 30:
            return False, "slug must be at most 30 characters"
        if slug.startswith("-") or slug.endswith("-"):
            return False, "slug must not start or end with a hyphen"
        return False, "slug must contain only lowercase letters, digits, and hyphens"
    if slug in RESERVED_NAMES:
        return False, "slug is reserved"
    return True, None


# Route patterns
_USERNAME_ENDPOINT = re.compile(r"^/api/username$")
_AUTH_CALLBACK = re.compile(r"^/api/auth/callback$")
_WIKIS_COLLECTION = re.compile(r"^/api/wikis$")
_WIKI_DETAIL = re.compile(r"^/api/wikis/([a-zA-Z0-9_-]+)$")
_WIKI_TOKEN = re.compile(r"^/api/wikis/([a-zA-Z0-9_-]+)/token$")

# Base path for wiki repos
WIKI_BASE = "/srv/data/wikis"


WIKI_TEMPLATE_DIR = os.environ.get(
    "WIKI_TEMPLATE_DIR", "/srv/app/templates/default-wiki"
)


def _init_wiki_repo(repo_path: str, display_name: str, purpose: str) -> None:
    """Initialize a git repo and seed it from the wiki template.

    Copies all .md files from WIKI_TEMPLATE_DIR into the new repo.
    Falls back to a minimal Home.md if the template dir is missing.

    Args:
        repo_path: Path where the git repo should be created.
        display_name: Wiki display name for the Home page.
        purpose: Description for the Home page.
    """
    os.makedirs(repo_path, exist_ok=True)
    git = os.environ.get("GIT_PYTHON_GIT_EXECUTABLE", "git")

    subprocess.run([git, "init", repo_path], check=True, capture_output=True)
    subprocess.run(
        [git, "-C", repo_path, "config", "user.email", "system@robot.wtf"],
        check=True, capture_output=True,
    )
    subprocess.run(
        [git, "-C", repo_path, "config", "user.name", "robot.wtf"],
        check=True, capture_output=True,
    )

    # Seed from template directory if available
    seeded_files = []
    if os.path.isdir(WIKI_TEMPLATE_DIR):
        for name in os.listdir(WIKI_TEMPLATE_DIR):
            if not name.endswith(".md"):
                continue
            src = os.path.join(WIKI_TEMPLATE_DIR, name)
            dst = os.path.join(repo_path, name)
            shutil.copy2(src, dst)
            seeded_files.append(name)

    # Always ensure Home.md exists
    home_path = os.path.join(repo_path, "Home.md")
    if not os.path.exists(home_path):
        with open(home_path, "w") as f:
            f.write(f"# {display_name}\n\n{purpose}\n")
        if "Home.md" not in seeded_files:
            seeded_files.append("Home.md")

    if not seeded_files:
        seeded_files = ["Home.md"]

    subprocess.run(
        [git, "-C", repo_path, "add"] + seeded_files,
        check=True, capture_output=True,
    )
    subprocess.run(
        [git, "-C", repo_path, "commit", "-m", "Initial commit"],
        check=True, capture_output=True,
    )


def _delete_wiki_repo(wiki_dir: str) -> None:
    """Remove a wiki directory from disk."""
    if os.path.exists(wiki_dir):
        shutil.rmtree(wiki_dir)


class ManagementMiddleware:
    """WSGI middleware that handles ``/api/*`` management routes."""

    def __init__(
        self,
        app: Callable,
        *,
        auth_middleware: AuthMiddleware,
        user_model: UserModel,
        wiki_model: WikiModel,
        acl_model=None,  # kept for backwards compatibility, no longer used
        wiki_base: str | None = None,
    ):
        self._app = app
        self._auth = auth_middleware
        self._users = user_model
        self._wikis = wiki_model
        self._wiki_base = wiki_base or os.environ.get("WIKI_BASE", WIKI_BASE)

    def __call__(self, environ: dict, start_response: Callable) -> Any:
        path = environ.get("PATH_INFO", "")
        if not path.startswith("/api"):
            return self._app(environ, start_response)

        # Internal endpoints bypass auth (e.g. Caddy on-demand TLS check)
        if path.startswith("/api/internal/"):
            return self._app(environ, start_response)

        # Otterwiki REST API plugin routes bypass management auth
        if path.startswith("/api/v1/"):
            return self._app(environ, start_response)

        method = environ.get("REQUEST_METHOD", "GET")

        # Auth callback is unauthenticated
        m = _AUTH_CALLBACK.match(path)
        if m:
            if method == "POST":
                try:
                    status, body = self._auth_callback(environ)
                except AuthError as e:
                    return _json_response(
                        start_response, e.status, {"error": e.message}
                    )
                return _json_response(start_response, status, body)
            return _json_response(
                start_response, 405, {"error": "Method not allowed"}
            )

        authorization = environ.get("HTTP_AUTHORIZATION")

        try:
            user = self._auth.authenticate(authorization)
        except AuthError as e:
            return _json_response(
                start_response, e.status, {"error": e.message}
            )

        try:
            status, body = self._route(method, path, user, environ)
        except AuthError as e:
            return _json_response(
                start_response, e.status, {"error": e.message}
            )

        return _json_response(start_response, status, body)

    def _route(
        self,
        method: str,
        path: str,
        user: AuthenticatedUser,
        environ: dict,
    ) -> tuple[int, dict]:
        """Dispatch to the correct handler based on method + path."""
        m = _USERNAME_ENDPOINT.match(path)
        if m:
            if method == "POST":
                return self._set_username(user, environ)
            return 405, {"error": "Method not allowed"}

        m = _WIKIS_COLLECTION.match(path)
        if m:
            if method == "POST":
                return self._create_wiki(user, environ)
            if method == "GET":
                return self._list_wikis(user)
            return 405, {"error": "Method not allowed"}

        m = _WIKI_TOKEN.match(path)
        if m:
            slug = m.group(1)
            if method == "POST":
                return self._regenerate_token(user, slug)
            return 405, {"error": "Method not allowed"}

        m = _WIKI_DETAIL.match(path)
        if m:
            slug = m.group(1)
            if method == "GET":
                return self._get_wiki(user, slug)
            if method == "DELETE":
                return self._delete_wiki(user, slug)
            return 405, {"error": "Method not allowed"}

        return 404, {"error": "Not found"}

    # --- Username ---

    def _set_username(
        self, user: AuthenticatedUser, environ: dict
    ) -> tuple[int, dict]:
        """Set the authenticated user's username."""
        body = _read_json_body(environ)
        username = body.get("username", "").strip().lower()

        valid, error = validate_username(username)
        if not valid:
            return 400, {"error": error}

        existing = self._users.get_by_username(username)
        if existing and existing["did"] != user.user_did:
            return 409, {"error": "Username is already taken"}

        try:
            updated = self._users.set_username(user.user_did, username)
        except ValueError as e:
            error_msg = str(e)
            if "taken" in error_msg.lower():
                return 409, {"error": error_msg}
            return 400, {"error": error_msg}

        return 200, {
            "username": updated.get("username"),
            "user_did": updated.get("did"),
        }

    # --- Auth ---

    def _auth_callback(self, environ: dict) -> tuple[int, dict]:
        """Handle ATProto auth callback.

        This is a placeholder -- the actual ATProto OAuth flow
        will be implemented when the auth system is built.
        """
        body = _read_json_body(environ)
        # TODO: implement ATProto OAuth callback
        return 501, {"error": "ATProto auth callback not yet implemented"}

    # --- Wiki CRUD ---

    def _create_wiki(
        self, user: AuthenticatedUser, environ: dict
    ) -> tuple[int, dict]:
        body = _read_json_body(environ)
        slug = body.get("slug", "").strip().lower()
        display_name = body.get("display_name", "").strip()
        wiki_purpose = body.get("purpose", "").strip()

        if not display_name:
            return 400, {"error": "display_name is required"}

        # Validate slug format
        valid, error = validate_slug(slug)
        if not valid:
            return 400, {"error": error}

        # Check tier limit: max wikis per user
        wiki_count = int(user.record.get("wiki_count", 0))
        if wiki_count >= MAX_WIKIS_PER_USER:
            return 403, {
                "error": f"Wiki limit reached ({MAX_WIKIS_PER_USER} wiki per user on free tier)"
            }

        # Generate MCP token
        plaintext_token, token_hash = generate_mcp_token()

        # Repo path
        repo_path = os.path.join(self._wiki_base, slug, "repo")

        # Create wiki record
        try:
            wiki = self._wikis.create(
                slug=slug,
                owner_did=user.user_did,
                display_name=display_name,
                repo_path=repo_path,
                mcp_token_hash=token_hash,
            )
        except Exception as e:
            logger.error("Failed to create wiki record: %s", e)
            return 409, {"error": "Wiki already exists"}

        # Init git repo + bootstrap
        try:
            _init_wiki_repo(
                repo_path, display_name, wiki_purpose or f"A wiki about {display_name}"
            )
        except Exception as e:
            logger.error("Failed to init wiki repo: %s", e)
            try:
                self._wikis.delete(slug)
            except Exception:
                pass
            return 500, {"error": "Failed to initialize wiki repository"}

        # Initialize per-wiki database, seeding the owner
        wiki_dir = os.path.dirname(repo_path)
        db_path = os.path.join(wiki_dir, "wiki.db")
        # Use the full handle for email lookup (@{full_handle}); the name can use the short form
        full_handle = user.handle if user.handle else None
        owner_name = user.handle.split(".")[0] if user.handle else None
        try:
            _init_wiki_db(db_path, site_name=display_name, owner_handle=full_handle, owner_name=owner_name)
        except Exception:
            logger.warning("Failed to pre-initialize wiki DB at %s", db_path, exc_info=True)

        # Increment wiki count
        self._users.update(user.user_did, wiki_count=wiki_count + 1)

        return 201, {
            "wiki": wiki,
            "mcp_token": plaintext_token,
            "mcp_endpoint": f"https://{slug}.robot.wtf/mcp",
        }

    def _list_wikis(self, user: AuthenticatedUser) -> tuple[int, dict]:
        wikis = self._wikis.list_by_owner(user.user_did)
        return 200, {"wikis": wikis}

    def _get_wiki(
        self, user: AuthenticatedUser, slug: str
    ) -> tuple[int, dict]:
        wiki = self._wikis.get(slug)
        if not wiki:
            return 404, {"error": "Wiki not found"}

        # Only the owner can view wiki details via the management API
        if wiki["owner_did"] != user.user_did:
            return 403, {"error": "Access denied"}

        return 200, {
            "wiki": wiki,
            "mcp_endpoint": f"https://{slug}.robot.wtf/mcp",
        }

    def _delete_wiki(
        self, user: AuthenticatedUser, slug: str
    ) -> tuple[int, dict]:
        wiki = self._wikis.get(slug)
        if not wiki:
            return 404, {"error": "Wiki not found"}

        # Verify ownership
        if wiki.get("owner_did") != user.user_did:
            return 403, {"error": "Only the owner can delete a wiki"}

        # Remove repo from disk
        repo_path = wiki.get("repo_path", "")
        if repo_path:
            wiki_dir = os.path.dirname(repo_path)
            _delete_wiki_repo(wiki_dir)
            # Clear DB initialization cache
            db_path = os.path.join(wiki_dir, "wiki.db")
            _initialized_dbs.discard(db_path)

        # Delete wiki record
        self._wikis.delete(slug)

        # Decrement wiki count
        wiki_count = int(user.record.get("wiki_count", 0))
        new_count = max(0, wiki_count - 1)
        self._users.update(user.user_did, wiki_count=new_count)

        return 200, {"deleted": True}

    # --- Token management ---

    def _regenerate_token(
        self, user: AuthenticatedUser, slug: str
    ) -> tuple[int, dict]:
        wiki = self._wikis.get(slug)
        if not wiki:
            return 404, {"error": "Wiki not found"}

        if wiki.get("owner_did") != user.user_did:
            return 403, {"error": "Only the owner can regenerate the token"}

        plaintext_token, token_hash = generate_mcp_token()
        self._wikis.update(slug, mcp_token_hash=token_hash)

        return 200, {"mcp_token": plaintext_token}

# --- Helpers ---


def _read_json_body(environ: dict) -> dict:
    """Read and parse JSON from the WSGI request body."""
    try:
        content_length = int(environ.get("CONTENT_LENGTH", 0))
    except (ValueError, TypeError):
        content_length = 0

    if content_length == 0:
        return {}

    body = environ["wsgi.input"].read(content_length)
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return {}


def _json_response(
    start_response: Callable, status_code: int, body: dict
) -> list[bytes]:
    """Build a JSON WSGI response."""
    status_map = {
        200: "200 OK",
        201: "201 Created",
        400: "400 Bad Request",
        401: "401 Unauthorized",
        403: "403 Forbidden",
        404: "404 Not Found",
        405: "405 Method Not Allowed",
        409: "409 Conflict",
        500: "500 Internal Server Error",
        501: "501 Not Implemented",
    }
    status_str = status_map.get(status_code, f"{status_code} Error")
    payload = json.dumps(body).encode("utf-8")
    start_response(
        status_str,
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(payload))),
        ],
    )
    return [payload]
