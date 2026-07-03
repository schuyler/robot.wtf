"""Tests for git-over-HTTPS auth bridge in TenantResolver._resolve_auth.

Feature: direct git access at https://{slug}.robot.wtf/.git/...
per-wiki opt-in via GIT_WEB_SERVER preference.

Coverage:
- GIT_WEB_SERVER=False → 404, no WWW-Authenticate, _resolve_bearer_token NOT called
- GIT_WEB_SERVER=True + no/invalid auth → 401 with WWW-Authenticate: Basic realm="{slug}"
- GIT_WEB_SERVER=True + valid Basic(user:token) → editor perms (READ,WRITE,UPLOAD)
- GIT_WEB_SERVER=True + unknown token → 401 + WWW-Authenticate re-prompt
- GIT_WEB_SERVER=True + cross-wiki token → 403 (no re-prompt)
- AuthError.headers optional field forwards extra headers in response
- Regression: non-.git Basic auth still rejected as before
"""

from __future__ import annotations

import base64
import contextlib
import sys
import types
from unittest.mock import MagicMock, patch

from app.auth.middleware import AuthMiddleware, AuthError


# ---------------------------------------------------------------------------
# Helpers shared across all test classes
# ---------------------------------------------------------------------------


def _make_environ(host, path="/", method="GET", authorization=None):
    env = {
        "HTTP_HOST": host,
        "PATH_INFO": path,
        "REQUEST_METHOD": method,
        "wsgi.input": b"",
        "wsgi.errors": "",
    }
    if authorization:
        env["HTTP_AUTHORIZATION"] = authorization
    return env


def _capture_response():
    calls = []

    def start_response(status, headers, exc_info=None):
        calls.append((status, headers))

    return start_response, calls


def _basic_auth(username, password):
    """Return an HTTP Basic Authorization header value."""
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {creds}"


_PUBLIC_CONFIG = {
    "READ_ACCESS": "ANONYMOUS",
    "WRITE_ACCESS": "ANONYMOUS",
    "ATTACHMENT_ACCESS": "ANONYMOUS",
}


def _make_server_mock(git_web_server: bool):
    """Return a minimal otterwiki.server module stub with GIT_WEB_SERVER set.

    Used with patch.dict(sys.modules, ...) so that feature code reading
    otterwiki.server.app.config["GIT_WEB_SERVER"] sees the expected value
    without triggering the real otterwiki.server import (which requires
    SECRET_KEY and a database).
    """
    mock_app = MagicMock()
    mock_app.config = {"GIT_WEB_SERVER": git_web_server}
    mock_mod = types.ModuleType("otterwiki.server")
    mock_mod.app = mock_app
    return mock_mod


def _make_resolver(wiki_slug="test-wiki", owner_did="did:plc:owner",
                   token_wiki=None):
    """Build a minimal TenantResolver for git auth tests.

    token_wiki: if provided, wiki_model.get_by_token returns this dict;
                otherwise returns None (unknown token).
    """
    from app.resolver import TenantResolver

    def stub_app(environ, start_response):
        start_response("200 OK", [])
        return [b"ok"]

    auth_middleware = MagicMock(spec=AuthMiddleware)
    auth_middleware.authenticate_from_cookie.return_value = None

    wiki_model = MagicMock()
    wiki_model.get.return_value = {
        "slug": wiki_slug,
        "owner_did": owner_did,
        "disk_usage_bytes": 0,
        "page_count": 0,
        "is_public": 0,
    }
    wiki_model.get_by_token.return_value = token_wiki

    user_model = MagicMock()

    return TenantResolver(
        stub_app,
        auth_middleware=auth_middleware,
        wiki_model=wiki_model,
        user_model=user_model,
    )


def _run(resolver, path, method="GET", authorization=None, wiki_slug="test-wiki",
         git_web_server=None):
    """Run resolver against a path with standard mocks, capturing the response.

    git_web_server: if not None, patches otterwiki.server.app.config with
    GIT_WEB_SERVER=<value> so that the feature gate sees the intended setting.
    Pass True for enabled-path tests, False for disabled-path tests.
    """
    environ = _make_environ(f"{wiki_slug}.robot.wtf", path=path,
                            method=method, authorization=authorization)
    start_response, calls = _capture_response()

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(resolver, "_swap_storage"))
        stack.enter_context(patch("app.resolver._swap_database"))
        stack.enter_context(
            patch("app.resolver._get_wiki_access_config", return_value=_PUBLIC_CONFIG)
        )
        if git_web_server is not None:
            stack.enter_context(
                patch.dict(sys.modules, {"otterwiki.server": _make_server_mock(git_web_server)})
            )
        resolver(environ, start_response)

    return calls


# ---------------------------------------------------------------------------
# Area 1a: GIT_WEB_SERVER=False (not set / default)
# ---------------------------------------------------------------------------
#
# When GIT_WEB_SERVER is absent or False in the wiki config, .git paths
# must be rejected with 404 before any credential parsing.
#
# Currently the resolver has no .git path detection, so these paths are
# handled by normal auth flow → wrong status code → tests fail.


class TestGitWebServerDisabled:
    """When GIT_WEB_SERVER is absent/False, all .git paths must return 404."""

    def test_git_info_refs_returns_404_when_disabled(self):
        """GET /.git/info/refs returns 404 when GIT_WEB_SERVER is not enabled."""
        resolver = _make_resolver()
        calls = _run(resolver, "/.git/info/refs", git_web_server=False)
        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "404 Not Found", (
            f"Disabled GIT_WEB_SERVER must return 404 for .git path; got {status!r}"
        )

    def test_git_receive_pack_returns_404_when_disabled(self):
        """POST /.git/git-receive-pack returns 404 when GIT_WEB_SERVER is not enabled."""
        resolver = _make_resolver()
        calls = _run(resolver, "/.git/git-receive-pack", method="POST", git_web_server=False)
        assert calls
        status, _ = calls[0]
        assert status == "404 Not Found", (
            f"Disabled GIT_WEB_SERVER must return 404 for receive-pack; got {status!r}"
        )

    def test_git_path_no_www_authenticate_when_disabled(self):
        """404 for disabled GIT_WEB_SERVER must NOT include WWW-Authenticate."""
        resolver = _make_resolver()
        calls = _run(resolver, "/.git/info/refs", git_web_server=False)
        assert calls
        status, headers = calls[0]
        assert status == "404 Not Found", (
            f"Expected 404; got {status!r}"
        )
        header_names = {k.lower() for k, _ in headers}
        assert "www-authenticate" not in header_names, (
            f"Disabled git path must NOT send WWW-Authenticate; headers: {headers!r}"
        )

    def test_git_path_no_token_validation_when_disabled(self):
        """_resolve_bearer_token must NOT be called when GIT_WEB_SERVER is disabled.

        Even if credentials are supplied, no token lookup should occur —
        the request is 404'd immediately.
        """
        resolver = _make_resolver()

        with patch.object(resolver, "_resolve_bearer_token") as mock_resolve, \
             patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=_PUBLIC_CONFIG), \
             patch.dict(sys.modules, {"otterwiki.server": _make_server_mock(False)}):
            environ = _make_environ(
                "test-wiki.robot.wtf", path="/.git/info/refs",
                authorization=_basic_auth("user", "some-token"),
            )
            start_response, calls = _capture_response()
            resolver(environ, start_response)

        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "404 Not Found", (
            f"Disabled git path must 404; got {status!r}"
        )
        mock_resolve.assert_not_called(), (
            "_resolve_bearer_token must NOT be called for disabled GIT_WEB_SERVER"
        )


# ---------------------------------------------------------------------------
# Area 1b: GIT_WEB_SERVER=True — unauthenticated and malformed auth
# ---------------------------------------------------------------------------
#
# When GIT_WEB_SERVER is True on the wiki:
#   - No Authorization header → 401 + WWW-Authenticate: Basic realm="{slug}"
#   - Bearer (not Basic) Authorization → 401 + WWW-Authenticate (prompt for Basic)
#
# Currently the resolver doesn't detect .git paths, so:
#   - No auth → anonymous resolution → 200 (public wiki) or 403 (restricted)
#   Tests will fail: expected 401, got something else.


class TestGitWebServerEnabledNoAuth:
    """GIT_WEB_SERVER=True: missing/non-Basic auth returns 401 with WWW-Authenticate."""

    def test_no_auth_returns_401(self):
        """GET /.git path with no Authorization header → 401."""
        resolver = _make_resolver()
        calls = _run(resolver, "/.git/info/refs", git_web_server=True)
        assert calls
        status, _ = calls[0]
        assert status == "401 Unauthorized", (
            f"No auth on .git path (GIT_WEB_SERVER=True) must → 401; got {status!r}"
        )

    def test_no_auth_includes_www_authenticate(self):
        """401 for no auth on .git path must include WWW-Authenticate: Basic realm='<slug>'."""
        resolver = _make_resolver()
        calls = _run(resolver, "/.git/info/refs", git_web_server=True)
        assert calls
        status, headers = calls[0]
        assert status == "401 Unauthorized", f"Expected 401; got {status!r}"
        header_dict = {k.lower(): v for k, v in headers}
        assert "www-authenticate" in header_dict, (
            f"Missing WWW-Authenticate header for .git 401; got headers: {headers!r}"
        )
        www_auth = header_dict["www-authenticate"]
        assert www_auth.lower().startswith("basic"), (
            f"WWW-Authenticate must use Basic scheme; got: {www_auth!r}"
        )
        assert "test-wiki" in www_auth, (
            f"WWW-Authenticate realm must include the wiki slug 'test-wiki'; "
            f"got: {www_auth!r}"
        )

    def test_bearer_token_on_git_path_returns_401_with_www_authenticate(self):
        """Bearer (not Basic) auth on .git path → 401 with WWW-Authenticate.

        Git clients expect Basic challenge; a raw Bearer token is not a valid
        git HTTP credential format and must be rejected with a Basic prompt.
        """
        resolver = _make_resolver()
        calls = _run(resolver, "/.git/info/refs",
                     authorization="Bearer some-mcp-token", git_web_server=True)
        assert calls
        status, headers = calls[0]
        assert status == "401 Unauthorized", (
            f"Bearer (not Basic) on .git path must → 401; got {status!r}"
        )
        header_dict = {k.lower(): v for k, v in headers}
        assert "www-authenticate" in header_dict, (
            "Must include WWW-Authenticate: Basic to prompt for correct credentials"
        )


# ---------------------------------------------------------------------------
# Area 1c: GIT_WEB_SERVER=True — valid Basic auth → bearer token resolution
# ---------------------------------------------------------------------------
#
# Basic(user:token) where password is a valid MCP bearer token for this wiki:
#   → resolve via _resolve_bearer_token(password, wiki_slug=slug)
#   → return editor perms (READ, WRITE, UPLOAD) — not ADMIN
#
# Currently Basic auth on any path raises AuthError("Invalid ... format", 401)
# before any bearer resolution. Tests will fail.


class TestGitBasicAuthResolution:
    """Valid Basic auth on .git path: password treated as opaque bearer token."""

    def test_valid_basic_auth_grants_editor_perms(self):
        """Basic(user:token) with valid token → READ, WRITE, UPLOAD injected (not ADMIN)."""
        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        token = "valid-mcp-token-abc123"
        resolver = _make_resolver(
            token_wiki={"slug": "test-wiki", "owner_did": "did:plc:owner"}
        )
        resolver._app = capture_app

        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=_PUBLIC_CONFIG), \
             patch.dict(sys.modules, {"otterwiki.server": _make_server_mock(True)}):
            environ = _make_environ(
                "test-wiki.robot.wtf", path="/.git/info/refs",
                authorization=_basic_auth("anyuser", token),
            )
            start_response, calls = _capture_response()
            resolver(environ, start_response)

        perms = injected.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")
        assert "READ" in perms, f"Valid git auth must grant READ; got {perms!r}"
        assert "WRITE" in perms, f"Valid git auth must grant WRITE; got {perms!r}"
        assert "UPLOAD" in perms, f"Valid git auth must grant UPLOAD; got {perms!r}"
        assert "ADMIN" not in perms, (
            f"Git auth must NOT grant ADMIN; got {perms!r}"
        )

    def test_valid_basic_auth_calls_resolve_bearer_with_password(self):
        """_resolve_bearer_token is called with the Basic auth password as the token."""
        from app.auth.headers import build_proxy_headers
        from app.auth.permissions import READ, WRITE, UPLOAD

        token = "my-mcp-token-xyz"
        resolver = _make_resolver(
            token_wiki={"slug": "test-wiki", "owner_did": "did:plc:owner"}
        )

        mock_result = {
            "proxy_headers": build_proxy_headers(
                email="mcp@robot.wtf",
                name="MCP Client",
                permissions=(READ, WRITE, UPLOAD),
            ),
            "is_authenticated": True,
            "is_bearer_token": True,
        }

        with patch.object(resolver, "_resolve_bearer_token",
                          return_value=mock_result) as mock_resolve, \
             patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=_PUBLIC_CONFIG), \
             patch.dict(sys.modules, {"otterwiki.server": _make_server_mock(True)}):
            environ = _make_environ(
                "test-wiki.robot.wtf", path="/.git/info/refs",
                authorization=_basic_auth("anyusername", token),
            )
            start_response, calls = _capture_response()
            resolver(environ, start_response)

        mock_resolve.assert_called_once()
        args, kwargs = mock_resolve.call_args
        called_token = args[0] if args else kwargs.get("token")
        assert called_token == token, (
            f"_resolve_bearer_token must be called with password '{token}'; "
            f"called with: args={args!r}, kwargs={kwargs!r}"
        )
        # wiki_slug cross-check must be passed
        called_slug = kwargs.get("wiki_slug") or (args[1] if len(args) > 1 else None)
        assert called_slug == "test-wiki", (
            f"_resolve_bearer_token must receive wiki_slug='test-wiki'; "
            f"called with: args={args!r}, kwargs={kwargs!r}"
        )

    def test_unknown_token_returns_401_with_www_authenticate(self):
        """Basic auth with an unknown token → 401 with WWW-Authenticate (re-prompt)."""
        # wiki_model.get_by_token returns None → unknown token
        resolver = _make_resolver(token_wiki=None)
        calls = _run(resolver, "/.git/info/refs",
                     authorization=_basic_auth("user", "bad-unknown-token"),
                     git_web_server=True)
        assert calls
        status, headers = calls[0]
        assert status == "401 Unauthorized", (
            f"Unknown token must → 401; got {status!r}"
        )
        header_dict = {k.lower(): v for k, v in headers}
        assert "www-authenticate" in header_dict, (
            "Unknown token re-prompt must include WWW-Authenticate"
        )

    def test_cross_wiki_token_returns_403_no_www_authenticate(self):
        """Token valid but belongs to a different wiki → 403, no WWW-Authenticate.

        No re-prompt: the token is real, but used on the wrong wiki (authorization error,
        not authentication error).
        """
        # Token belongs to 'other-wiki', not 'test-wiki'
        resolver = _make_resolver(
            token_wiki={"slug": "other-wiki", "owner_did": "did:plc:other"}
        )
        calls = _run(resolver, "/.git/info/refs",
                     authorization=_basic_auth("user", "cross-wiki-token"),
                     git_web_server=True)
        assert calls
        status, headers = calls[0]
        assert status == "403 Forbidden", (
            f"Cross-wiki token must → 403; got {status!r}"
        )
        header_dict = {k.lower(): v for k, v in headers}
        assert "www-authenticate" not in header_dict, (
            "403 cross-wiki response must NOT include WWW-Authenticate "
            f"(no re-prompt); headers: {headers!r}"
        )


# ---------------------------------------------------------------------------
# Area 1d: AuthError.headers support
# ---------------------------------------------------------------------------
#
# The design requires AuthError to carry an optional 'headers' dict so that
# WWW-Authenticate (and any future headers) can be forwarded by _error_response
# and the __call__ except-block.
#
# Currently AuthError.__init__ only accepts (message, status). Adding 'headers'
# as a kwarg will raise TypeError until the feature is implemented.


class TestAuthErrorHeaders:
    """AuthError gains an optional 'headers' dict for forwarding extra response headers."""

    def test_auth_error_accepts_headers_kwarg(self):
        """AuthError can be constructed with a 'headers' keyword argument."""
        # This will raise TypeError with the current implementation because
        # AuthError.__init__ does not accept 'headers'.
        err = AuthError(
            "Unauthorized",
            status=401,
            headers={"WWW-Authenticate": "Basic realm=\"test-wiki\""},
        )
        assert hasattr(err, "headers"), (
            "AuthError must expose a 'headers' attribute"
        )
        assert err.headers.get("WWW-Authenticate") == "Basic realm=\"test-wiki\""

    def test_auth_error_headers_forwarded_in_http_response(self):
        """When AuthError.headers is set, those headers appear in the HTTP response.

        The _error_response helper and the __call__ except-block must pass through
        any headers carried in the AuthError.
        """
        from app.resolver import TenantResolver

        resolver = _make_resolver()
        www_auth_header = "Basic realm=\"test-wiki\""

        def _raise_with_headers(environ, wiki_slug, wiki):
            raise AuthError(
                "Unauthorized",
                status=401,
                headers={"WWW-Authenticate": www_auth_header},
            )

        with patch.object(resolver, "_resolve_auth",
                          side_effect=_raise_with_headers), \
             patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=_PUBLIC_CONFIG):
            environ = _make_environ("test-wiki.robot.wtf", path="/.git/info/refs")
            start_response, calls = _capture_response()
            resolver(environ, start_response)

        assert calls
        status, headers = calls[0]
        assert status == "401 Unauthorized"
        header_dict = {k.lower(): v for k, v in headers}
        assert "www-authenticate" in header_dict, (
            f"AuthError.headers must be forwarded into the HTTP response; "
            f"got response headers: {headers!r}"
        )
        assert header_dict["www-authenticate"] == www_auth_header


# ---------------------------------------------------------------------------
# Area 1e: regression guard — non-.git Basic auth still rejected
# ---------------------------------------------------------------------------
#
# Adding git support must not accidentally validate Basic auth on normal wiki paths.
# The existing behavior (reject non-Bearer, non-JWT Authorization) must be preserved.


class TestNonGitBasicAuthRejection:
    """Basic auth on non-.git paths must still be rejected (regression guard)."""

    def test_non_git_basic_auth_rejected(self):
        """Basic(user:token) on a regular wiki page → 401 (invalid auth format).

        The existing code raises AuthError("Invalid ... format") for non-Bearer
        Authorization headers. Adding git support must not break this.
        """
        resolver = _make_resolver()
        environ = _make_environ(
            "test-wiki.robot.wtf", path="/SomePage",
            authorization=_basic_auth("user", "sometoken"),
        )
        start_response, calls = _capture_response()

        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config",
                   return_value={
                       "READ_ACCESS": "APPROVED",
                       "WRITE_ACCESS": "APPROVED",
                       "ATTACHMENT_ACCESS": "APPROVED",
                   }):
            resolver(environ, start_response)

        assert calls
        status, _ = calls[0]
        # Must be rejected — not passed through as a valid credential
        assert status in ("401 Unauthorized", "403 Forbidden"), (
            f"Non-.git Basic auth must be rejected; got {status!r}"
        )
