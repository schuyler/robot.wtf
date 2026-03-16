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

from app.auth.acl import AclEnforcer
from app.auth.headers import build_proxy_headers
from app.auth.middleware import AuthError, AuthMiddleware
from app.auth.permissions import READ, WRITE, UPLOAD, format_permission_header

logger = logging.getLogger(__name__)

# Cache storage instances by repo path
_storage_cache: dict[str, Any] = {}

# Domain suffix for extracting wiki slug from Host header
PLATFORM_DOMAIN = os.environ.get("PLATFORM_DOMAIN", "robot.wtf")

# Per-wiki disk quota
QUOTA_BYTES = 50 * 1024 * 1024  # 50MB

# Base path for wiki data
WIKI_BASE = os.environ.get("WIKI_BASE", "/srv/data/wikis")


def _is_jwt(token: str) -> bool:
    """Heuristic: JWTs have two dots (header.payload.signature)."""
    return token.count(".") == 2


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
            # Non-tenant subdomain — pass through with anonymous headers
            environ["HTTP_X_OTTERWIKI_NAME"] = "Anonymous"
            environ["HTTP_X_OTTERWIKI_EMAIL"] = "@anonymous"
            environ["HTTP_X_OTTERWIKI_PERMISSIONS"] = "READ,WRITE,UPLOAD,ADMIN"
            return self._app(environ, start_response)

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
            return _error_response(start_response, e.status, e.message)

        # Strip write permissions for web UI writes when over quota
        if over_quota and _is_write_request(method, path) and not path.startswith("/api/"):
            proxy_headers = auth_result["proxy_headers"]
            perms_key = "X-Otterwiki-Permissions"
            raw = proxy_headers.get(perms_key, "")
            stripped = [p for p in raw.split(",") if p not in (WRITE, UPLOAD)]
            proxy_headers[perms_key] = format_permission_header(stripped)

        # Build repo path
        repo_path = wiki.get(
            "repo_path",
            os.path.join(WIKI_BASE, wiki_slug, "repo"),
        )

        # Swap otterwiki globals
        self._swap_storage(repo_path)

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
                return {"proxy_headers": proxy_headers}

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
                return {"proxy_headers": proxy_headers}

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
        return {"proxy_headers": proxy_headers}

    def _resolve_bearer_token(self, token: str) -> dict[str, Any]:
        """Authenticate via MCP bearer token."""
        access = self._acl.check_bearer_token(token)

        proxy_headers = build_proxy_headers(
            email="mcp@robot.wtf",
            name="MCP Client",
            permissions=access["permissions"],
        )
        return {"proxy_headers": proxy_headers}

    def _resolve_anonymous(self, wiki_slug: str) -> dict[str, Any]:
        """Check if anonymous (public) access is allowed."""
        access = self._acl.check_public_access(wiki_slug)

        proxy_headers = build_proxy_headers(
            email="@anonymous",
            name="Anonymous",
            permissions=access["permissions"],
        )
        return {"proxy_headers": proxy_headers}

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
