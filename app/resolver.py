"""Multi-tenant WSGI middleware for robot.wtf.

Resolves incoming requests to a specific wiki based on Host header
(subdomain = wiki slug on robot.wtf). Looks up the wiki by slug,
authenticates, checks ACL, swaps otterwiki storage singletons,
injects proxy headers, and delegates.

On robot.wtf the Host pattern is {slug}.robot.wtf (wiki slug is the
subdomain directly, unlike wikibot.io where subdomain = username and
path = wiki slug).
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any, Callable
from urllib.parse import quote

from app.auth.acl import AclEnforcer
from app.auth.headers import build_proxy_headers
from app.auth.middleware import AuthError, AuthMiddleware
from app.auth.permissions import READ, WRITE, UPLOAD, format_permission_header

logger = logging.getLogger(__name__)

# Cache storage instances by repo path
_storage_cache: dict[str, Any] = {}

# Set of wiki DB paths known to be initialized
_initialized_dbs: set = set()

# Domain suffix for extracting wiki slug from Host header
PLATFORM_DOMAIN = os.environ.get("PLATFORM_DOMAIN", "robot.wtf")

# Per-wiki disk quota
QUOTA_BYTES = 50 * 1024 * 1024  # 50MB

# Base path for wiki data
WIKI_BASE = os.environ.get("WIKI_BASE", "/srv/data/wikis")


def _init_wiki_db(db_path: str, site_name: str = None, is_public: bool = True) -> None:
    """Create otterwiki tables in a per-wiki SQLite database.

    Uses raw SQL to avoid importing otterwiki models.
    Tables: preferences, drafts, user, cache.

    Args:
        db_path: Path to the per-wiki SQLite file.
        site_name: Optional SITE_NAME preference to seed.
        is_public: Whether the wiki is publicly readable. If False and
            READ_ACCESS is not already set, seeds READ_ACCESS=REGISTERED
            to preserve the wiki's private status after is_public removal.
    """
    if db_path in _initialized_dbs:
        return

    import sqlite3
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS preferences (
                name VARCHAR(256) PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS drafts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pagepath VARCHAR(2048),
                revision VARCHAR(64),
                author_email VARCHAR(256),
                content TEXT,
                cursor_line INTEGER,
                cursor_ch INTEGER,
                datetime DATETIME
            );
            CREATE INDEX IF NOT EXISTS ix_drafts_pagepath ON drafts (pagepath);
            CREATE TABLE IF NOT EXISTS "user" (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(128),
                email VARCHAR(128) UNIQUE,
                password_hash VARCHAR(512),
                first_seen DATETIME,
                last_seen DATETIME,
                is_approved BOOLEAN DEFAULT 0,
                is_admin BOOLEAN DEFAULT 0,
                email_confirmed BOOLEAN DEFAULT 0,
                allow_read BOOLEAN DEFAULT 0,
                allow_write BOOLEAN DEFAULT 0,
                allow_upload BOOLEAN DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS cache (
                key VARCHAR(64) PRIMARY KEY,
                value TEXT,
                datetime DATETIME
            );
            CREATE INDEX IF NOT EXISTS ix_cache_key ON cache (key);
        """)
        if site_name:
            conn.execute(
                "INSERT OR IGNORE INTO preferences (name, value) VALUES (?, ?)",
                ("SITE_NAME", site_name),
            )
        # Migration: seed READ_ACCESS=REGISTERED for private wikis that have
        # no READ_ACCESS preference yet, preserving their access policy after
        # the is_public flag was removed as the gating mechanism.
        if not is_public:
            conn.execute(
                "INSERT OR IGNORE INTO preferences (name, value) VALUES (?, ?)",
                ("READ_ACCESS", "REGISTERED"),
            )
        conn.commit()
    finally:
        conn.close()

    os.chmod(db_path, 0o600)
    _initialized_dbs.add(db_path)


def _swap_database(wiki_dir: str, is_public: bool = True, display_name: str = None) -> None:
    """Swap otterwiki's SQLAlchemy engine to the per-wiki SQLite DB.

    Args:
        wiki_dir: Directory containing wiki.db.
        is_public: Passed through to _init_wiki_db to seed READ_ACCESS
            for wikis that were previously marked private via is_public=0.
        display_name: Wiki display name, seeded as SITE_NAME preference on
            first init so the wiki shows its own name from the start.
    """
    db_path = os.path.join(wiki_dir, "wiki.db")

    # Path validation: ensure db_path is under WIKI_BASE
    real_path = os.path.realpath(db_path)
    if not real_path.startswith(os.path.realpath(WIKI_BASE) + os.sep):
        logger.error("wiki.db path escapes WIKI_BASE: %s", db_path)
        return

    try:
        import otterwiki.server
        from sqlalchemy import create_engine
    except ImportError:
        return

    app = otterwiki.server.app
    db = otterwiki.server.db

    uri = f"sqlite:///{db_path}"

    # Fast path: check actual engine URL, not config (FSA ignores config post-init)
    engines = db._app_engines.get(app, {})
    current_engine = engines.get(None)
    if current_engine is not None and str(current_engine.url) == uri:
        return

    # Ensure DB exists with schema (seeds SITE_NAME and READ_ACCESS for private wikis)
    _init_wiki_db(db_path, site_name=display_name, is_public=is_public)

    old_uri = app.config.get("SQLALCHEMY_DATABASE_URI")

    try:
        with app.app_context():
            # Remove current scoped session (needs app context for session scoping)
            db.session.remove()

            # Create new engine FIRST, then dispose old
            new_engine = create_engine(
                uri,
                connect_args={"check_same_thread": False},
            )
            engines[None] = new_engine

            # Now safe to dispose the old engine
            if current_engine is not None:
                current_engine.dispose()

            # Update config (for reference only — FSA ignores this post-init)
            app.config["SQLALCHEMY_DATABASE_URI"] = uri

            # Reload preferences from the new DB
            otterwiki.server.update_app_config()
    except Exception:
        # Restore previous engine if swap failed
        if current_engine is not None:
            # Dispose the new engine to avoid leaking its connection pool
            if engines.get(None) is not current_engine:
                try:
                    engines[None].dispose()
                except Exception:
                    pass
            engines[None] = current_engine
            app.config["SQLALCHEMY_DATABASE_URI"] = old_uri
        logger.exception("Failed to swap database for wiki %s", wiki_dir)
        raise


def _is_jwt(token: str) -> bool:
    """Heuristic: JWTs have two dots (header.payload.signature)."""
    return token.count(".") == 2


def _get_wiki_access_config() -> dict[str, str]:
    """Return per-wiki access preference values from otterwiki app.config.

    Returns a dict with READ_ACCESS, WRITE_ACCESS, ATTACHMENT_ACCESS keys,
    defaulting to 'ANONYMOUS' if otterwiki is not available or preferences
    are not set.
    """
    defaults = {
        "READ_ACCESS": "ANONYMOUS",
        "WRITE_ACCESS": "ANONYMOUS",
        "ATTACHMENT_ACCESS": "ANONYMOUS",
    }
    try:
        import otterwiki.server
        app = otterwiki.server.app
        return {
            "READ_ACCESS": app.config.get("READ_ACCESS", "ANONYMOUS"),
            "WRITE_ACCESS": app.config.get("WRITE_ACCESS", "ANONYMOUS"),
            "ATTACHMENT_ACCESS": app.config.get("ATTACHMENT_ACCESS", "ANONYMOUS"),
        }
    except ImportError:
        logger.warning("otterwiki not installed; wiki access config unavailable, defaulting to ANONYMOUS")
        return defaults


def _apply_wiki_access_restrictions(
    permissions: list[str], is_authenticated: bool, config: dict[str, str] | None = None
) -> list[str]:
    """Restrict proxy header permissions based on per-wiki access preferences.

    Platform ACL grants the ceiling. Per-wiki preferences (READ_ACCESS,
    WRITE_ACCESS, ATTACHMENT_ACCESS) can restrict further but never escalate.

    Access levels: ANONYMOUS (no restriction), REGISTERED (auth required),
    APPROVED (treated as REGISTERED for now — full support needs user tracking).

    ADMIN is never stripped.
    """
    from app.auth.permissions import READ, WRITE, UPLOAD

    if config is None:
        config = _get_wiki_access_config()
    read_access = config.get("READ_ACCESS", "ANONYMOUS")
    write_access = config.get("WRITE_ACCESS", "ANONYMOUS")
    attachment_access = config.get("ATTACHMENT_ACCESS", "ANONYMOUS")

    result = list(permissions)

    # READ_ACCESS restriction: if not ANONYMOUS and user not authenticated,
    # strip READ, WRITE, and UPLOAD (can't write if can't read)
    if read_access != "ANONYMOUS" and not is_authenticated:
        result = [p for p in result if p not in (READ, WRITE, UPLOAD)]
        return result  # No need to check further; everything is already stripped

    # WRITE_ACCESS restriction: if not ANONYMOUS and user not authenticated,
    # strip WRITE and UPLOAD
    if write_access != "ANONYMOUS" and not is_authenticated:
        result = [p for p in result if p not in (WRITE, UPLOAD)]

    # ATTACHMENT_ACCESS restriction: if not ANONYMOUS and user not authenticated,
    # strip UPLOAD
    if attachment_access != "ANONYMOUS" and not is_authenticated:
        result = [p for p in result if p != UPLOAD]

    return result


def _get_or_create_storage(repo_path: str) -> Any:
    """Get a cached storage instance, or create one.

    Also lazy-inits the git repo if it doesn't exist yet.
    """
    if repo_path in _storage_cache:
        return _storage_cache[repo_path]

    _ensure_wiki_repo(repo_path)

    # TODO: otterwiki integration — import GitStorage when otterwiki is available
    try:
        from otterwiki.gitstorage import GitStorage
        storage = GitStorage(repo_path)
    except ImportError:
        logger.warning("otterwiki not available; using repo_path as storage stub")
        storage = repo_path  # Stub: just store the path

    _storage_cache[repo_path] = storage
    return storage


def _ensure_wiki_repo(repo_path: str) -> None:
    """Create directories and git init if the repo doesn't exist."""
    if os.path.exists(os.path.join(repo_path, ".git")) or os.path.exists(
        os.path.join(repo_path, "HEAD")
    ):
        return

    logger.info("Initializing wiki repo at %s", repo_path)
    os.makedirs(repo_path, exist_ok=True)

    git_executable = os.environ.get("GIT_PYTHON_GIT_EXECUTABLE", "git")
    subprocess.run(
        [git_executable, "init", repo_path],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [git_executable, "-C", repo_path, "config", "user.email",
         "system@robot.wtf"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [git_executable, "-C", repo_path, "config", "user.name", "robot.wtf"],
        check=True,
        capture_output=True,
    )


def _parse_host(host: str) -> str | None:
    """Extract wiki slug from Host header.

    Pattern: {slug}.robot.wtf -> slug
    Returns None if host doesn't match the multi-tenant pattern.
    """
    if not host:
        return None

    # Strip port if present
    host = host.split(":")[0].lower()

    suffix = f".{PLATFORM_DOMAIN}"
    if not host.endswith(suffix):
        return None

    subdomain = host[: -len(suffix)]
    if not subdomain:
        return None

    # Reserved subdomains that are not wiki tenants
    reserved = {"www", "api", "mcp", "auth"}
    if subdomain in reserved:
        return None

    return subdomain


def _is_write_request(method: str, path: str) -> bool:
    """Return True if the request would mutate wiki content."""
    if method not in ("POST", "PUT", "PATCH"):
        return False
    # Web UI write paths
    if path.endswith("/save") or "/attachments" in path or "/inline_attachment" in path:
        return True
    # API write paths
    if path.startswith("/api/v1/pages") and method in ("PUT", "PATCH", "POST"):
        return True
    if "/rename" in path:
        return True
    return False


def _error_response(
    start_response: Callable, status_code: int, message: str
) -> list[bytes]:
    """Return a JSON error response."""
    body = json.dumps({"error": message})
    status_map = {
        400: "400 Bad Request",
        401: "401 Unauthorized",
        403: "403 Forbidden",
        404: "404 Not Found",
        500: "500 Internal Server Error",
    }
    status = status_map.get(status_code, f"{status_code} Error")
    start_response(
        status,
        [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
    )
    return [body.encode("utf-8")]


def _is_browser_request(environ: dict[str, Any]) -> bool:
    """Return True if the client accepts HTML (i.e. is a browser)."""
    accept = environ.get("HTTP_ACCEPT", "")
    return "text/html" in accept


def _build_login_url(environ: dict[str, Any]) -> str:
    """Build the login URL with a return_to param containing the original wiki URL."""
    scheme = environ.get("wsgi.url_scheme", "https")
    host = environ.get("HTTP_HOST", "")
    path = environ.get("PATH_INFO", "/")
    query = environ.get("QUERY_STRING", "")
    original_url = f"{scheme}://{host}{path}"
    if query:
        original_url += f"?{query}"
    return f"https://{PLATFORM_DOMAIN}/auth/login?return_to={quote(original_url, safe='')}"


def _redirect_response(
    start_response: Callable, location: str
) -> list[bytes]:
    """Return a 302 redirect response."""
    start_response(
        "302 Found",
        [
            ("Location", location),
            ("Content-Type", "text/html"),
            ("Content-Length", "0"),
        ],
    )
    return [b""]


class TenantResolver:
    """WSGI middleware that resolves requests to a specific wiki tenant.

    For each request:
    1. Extracts wiki slug from Host subdomain
    2. Authenticates (JWT / bearer token / anonymous)
    3. Checks ACL
    4. Swaps otterwiki globals (storage, config)
    5. Injects proxy headers
    6. Delegates to the wrapped WSGI app
    """

    def __init__(
        self,
        app: Any,
        *,
        auth_middleware: AuthMiddleware,
        acl_enforcer: AclEnforcer,
        wiki_model: Any,
        user_model: Any,
    ):
        self._app = app
        self._auth = auth_middleware
        self._acl = acl_enforcer
        self._wikis = wiki_model
        self._users = user_model

    def __call__(
        self, environ: dict[str, Any], start_response: Callable
    ) -> Any:
        host = environ.get("HTTP_HOST", "")
        wiki_slug = _parse_host(host)

        if wiki_slug is None:
            # Non-tenant host — not a wiki subdomain, deny access.
            # The platform domain and reserved subdomains (api, auth, mcp, www)
            # are served by separate processes (api_server, auth_server); if a
            # request somehow reaches the TenantResolver for those hosts it must
            # NOT be granted any permissions, especially not ADMIN.
            return _error_response(start_response, 404, "Not Found")

        # Look up wiki by slug
        wiki = self._wikis.get(wiki_slug)
        if not wiki:
            return _error_response(start_response, 404, "Wiki not found")

        # Enforce disk quota on write requests
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        over_quota = wiki.get("disk_usage_bytes", 0) > QUOTA_BYTES
        if over_quota and _is_write_request(method, path):
            if path.startswith("/api/"):
                return _error_response(
                    start_response, 413, "Wiki quota exceeded (50MB limit)"
                )
            # Web UI writes: continue to auth, then strip write permissions below

        # Authenticate and authorize
        try:
            auth_result = self._resolve_auth(environ, wiki_slug, wiki)
        except AuthError as e:
            if e.status == 403 and _is_browser_request(environ):
                login_url = _build_login_url(environ)
                return _redirect_response(start_response, login_url)
            return _error_response(start_response, e.status, e.message)

        # Strip write permissions for web UI writes when over quota
        if over_quota and _is_write_request(method, path) and not path.startswith("/api/"):
            proxy_headers = auth_result["proxy_headers"]
            perms_key = "x-otterwiki-permissions"
            raw = proxy_headers.get(perms_key, "")
            stripped = [p for p in raw.split(",") if p not in (WRITE, UPLOAD)]
            proxy_headers[perms_key] = format_permission_header(stripped)

        # Build repo path
        repo_path = wiki.get(
            "repo_path",
            os.path.join(WIKI_BASE, wiki_slug, "repo"),
        )

        # Swap otterwiki globals (loads per-wiki preferences into app.config)
        self._swap_storage(repo_path)
        wiki_dir = os.path.dirname(repo_path)
        wiki_is_public = bool(wiki.get("is_public", True))
        _swap_database(wiki_dir, is_public=wiki_is_public, display_name=wiki.get("display_name"))

        # Fetch wiki access config once (after storage swap so preferences are loaded)
        wiki_access_config = _get_wiki_access_config()

        # Apply per-wiki access restrictions based on preferences now loaded
        # into app.config. Bearer tokens (MCP clients) bypass restrictions.
        if not auth_result.get("is_bearer_token"):
            proxy_headers = auth_result["proxy_headers"]
            perms_key = "x-otterwiki-permissions"
            raw = proxy_headers.get(perms_key, "")
            permissions = [p for p in raw.split(",") if p]
            is_authenticated = auth_result.get("is_authenticated", False)
            restricted = _apply_wiki_access_restrictions(permissions, is_authenticated, wiki_access_config)
            proxy_headers[perms_key] = format_permission_header(restricted)

        # If READ_ACCESS requires authentication and anonymous user: deny
        if not auth_result.get("is_authenticated") and not auth_result.get("is_bearer_token"):
            proxy_headers = auth_result["proxy_headers"]
            perms_key = "x-otterwiki-permissions"
            raw = proxy_headers.get(perms_key, "")
            if not raw or all(p not in (READ, WRITE, UPLOAD) for p in raw.split(",")):
                # No meaningful permissions remain after restrictions — check if
                # this is because READ_ACCESS is restricted
                if wiki_access_config.get("READ_ACCESS", "ANONYMOUS") != "ANONYMOUS":
                    if _is_browser_request(environ):
                        login_url = _build_login_url(environ)
                        return _redirect_response(start_response, login_url)
                    return _error_response(start_response, 403, "Authentication required")

        # Inject proxy headers
        proxy_headers = auth_result["proxy_headers"]
        for header_name, header_value in proxy_headers.items():
            wsgi_key = "HTTP_" + header_name.upper().replace("-", "_")
            environ[wsgi_key] = header_value

        # Replace Authorization header with internal API key
        api_key = os.environ.get("OTTERWIKI_API_KEY", "")
        if api_key:
            environ["HTTP_AUTHORIZATION"] = f"Bearer {api_key}"

        return self._app(environ, start_response)

    def _resolve_auth(
        self,
        environ: dict[str, Any],
        wiki_slug: str,
        wiki: dict[str, Any],
    ) -> dict[str, Any]:
        """Resolve authentication and authorization.

        Three paths:
        1. Bearer token (MCP) -- opaque token, no dots
        2. Platform JWT -- three dot-separated segments
        3. Cookie -- platform_token cookie
        4. Anonymous -- no credentials
        """
        authorization = environ.get("HTTP_AUTHORIZATION")

        if authorization:
            parts = authorization.split(" ", 1)
            if len(parts) != 2 or parts[0].lower() != "bearer":
                raise AuthError("Invalid Authorization header format", status=401)

            token = parts[1]
            if _is_jwt(token):
                return self._resolve_jwt(token, wiki_slug)

            # Internal API key bypass (MCP sidecar → REST API on localhost)
            api_key = os.environ.get("OTTERWIKI_API_KEY", "")
            if api_key and token == api_key:
                proxy_headers = build_proxy_headers(
                    email="@system",
                    name="MCP",
                    permissions=("READ", "WRITE", "UPLOAD", "ADMIN"),
                )
                return {
                    "proxy_headers": proxy_headers,
                    "is_authenticated": True,
                    "is_bearer_token": True,
                }

            return self._resolve_bearer_token(token)

        # Try cookie auth
        cookie_header = environ.get("HTTP_COOKIE")
        if cookie_header:
            authed_user = self._auth.authenticate_from_cookie(cookie_header)
            if authed_user:
                try:
                    access = self._acl.check_access(authed_user.user_did, wiki_slug)
                except AuthError as e:
                    if e.status != 403:
                        raise
                    # No explicit ACL entry — fall back to public access if allowed
                    access = self._acl.check_public_access(wiki_slug)
                proxy_headers = build_proxy_headers(
                    email=f"@{authed_user.handle}",
                    name=authed_user.display_name or authed_user.handle,
                    permissions=access["permissions"],
                )
                return {
                    "proxy_headers": proxy_headers,
                    "is_authenticated": True,
                    "is_bearer_token": False,
                }

        # Anonymous access
        return self._resolve_anonymous(wiki_slug)

    def _resolve_jwt(
        self, token: str, wiki_slug: str
    ) -> dict[str, Any]:
        """Authenticate via platform JWT, then check ACL."""
        authed_user = self._auth.authenticate(f"Bearer {token}")
        access = self._acl.check_access(authed_user.user_did, wiki_slug)

        proxy_headers = build_proxy_headers(
            email=f"@{authed_user.handle}",
            name=authed_user.display_name or authed_user.handle,
            permissions=access["permissions"],
        )
        return {
            "proxy_headers": proxy_headers,
            "is_authenticated": True,
            "is_bearer_token": False,
        }

    def _resolve_bearer_token(self, token: str) -> dict[str, Any]:
        """Authenticate via MCP bearer token."""
        access = self._acl.check_bearer_token(token)

        proxy_headers = build_proxy_headers(
            email="mcp@robot.wtf",
            name="MCP Client",
            permissions=access["permissions"],
        )
        return {
            "proxy_headers": proxy_headers,
            "is_authenticated": True,
            "is_bearer_token": True,
        }

    def _resolve_anonymous(self, wiki_slug: str) -> dict[str, Any]:
        """Check if anonymous (public) access is allowed."""
        access = self._acl.check_public_access(wiki_slug)

        proxy_headers = build_proxy_headers(
            email="@anonymous",
            name="Anonymous",
            permissions=access["permissions"],
        )
        return {
            "proxy_headers": proxy_headers,
            "is_authenticated": False,
            "is_bearer_token": False,
        }

    def _swap_storage(self, repo_path: str) -> None:
        """Swap otterwiki module-level singletons for this tenant's wiki.

        TODO: otterwiki integration -- the actual module patching depends on
        otterwiki being installed. When otterwiki is available, this method
        patches storage in every module that imported it by value, recreates
        GitHttpServer, and updates Flask app config. For now, we just update
        the storage cache.
        """
        try:
            import otterwiki.helper
            import otterwiki.pageindex
            import otterwiki.remote
            import otterwiki.server
            import otterwiki.sidebar
            import otterwiki.sitemap
            import otterwiki.tools
            import otterwiki.views
            import otterwiki.wiki

            storage = _get_or_create_storage(repo_path)

            otterwiki.server.storage = storage
            otterwiki.wiki.storage = storage
            otterwiki.helper.storage = storage
            otterwiki.sitemap.storage = storage
            otterwiki.tools.storage = storage
            otterwiki.pageindex.storage = storage
            otterwiki.sidebar.storage = storage

            # Patch plugin state dicts
            try:
                import otterwiki_api
                otterwiki_api._state["storage"] = storage
            except ImportError:
                pass
            try:
                import otterwiki_semantic_search
                otterwiki_semantic_search._state["storage"] = storage
            except ImportError:
                pass

            githttpserver = otterwiki.remote.GitHttpServer(path=repo_path)
            otterwiki.server.githttpserver = githttpserver
            otterwiki.views.githttpserver = githttpserver

            otterwiki.server.app.config["REPOSITORY"] = repo_path
        except ImportError:
            # otterwiki not installed yet -- just cache the storage stub
            _get_or_create_storage(repo_path)
