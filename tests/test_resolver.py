"""Tests for TenantResolver WSGI middleware.

Covers:
- Non-tenant hosts must NOT receive ADMIN permissions (ACL bypass)
- Wiki tenant resolution and passthrough
- Per-wiki access restrictions (READ_ACCESS, WRITE_ACCESS, ATTACHMENT_ACCESS)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def _make_environ(host: str, path: str = "/", accept: str = "") -> dict:
    env = {
        "HTTP_HOST": host,
        "PATH_INFO": path,
        "REQUEST_METHOD": "GET",
        "wsgi.input": b"",
        "wsgi.errors": "",
    }
    if accept:
        env["HTTP_ACCEPT"] = accept
    return env


def _capture_response():
    """Return a start_response callable and a list to capture calls."""
    calls = []

    def start_response(status, headers, exc_info=None):
        calls.append((status, headers))

    return start_response, calls


class TestNonTenantPassthrough:
    """Non-tenant hosts must not grant ADMIN permissions."""

    def _make_resolver(self, stub_app=None):
        from app.resolver import TenantResolver
        from app.auth.acl import AclEnforcer
        from app.auth.middleware import AuthMiddleware

        if stub_app is None:
            def stub_app(environ, start_response):
                start_response("200 OK", [("Content-Type", "text/plain")])
                return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        acl_enforcer = MagicMock(spec=AclEnforcer)
        wiki_model = MagicMock()
        user_model = MagicMock()

        return TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
            acl_enforcer=acl_enforcer,
            wiki_model=wiki_model,
            user_model=user_model,
        )

    def test_non_tenant_host_does_not_grant_admin(self):
        """A request to robot.wtf (no subdomain) must not inject ADMIN permissions."""
        injected_environ = {}

        def capture_app(environ, start_response):
            injected_environ.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        resolver = self._make_resolver(stub_app=capture_app)
        start_response, calls = _capture_response()

        resolver(_make_environ("robot.wtf"), start_response)

        perms = injected_environ.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")
        assert "ADMIN" not in perms, (
            f"Non-tenant host must not receive ADMIN permission; got: {perms!r}"
        )

    def test_reserved_subdomain_does_not_grant_admin(self):
        """Reserved subdomains (api, auth, mcp, www) must not inject ADMIN permissions."""
        for subdomain in ("api", "auth", "mcp", "www"):
            injected_environ = {}

            def capture_app(environ, start_response, _captured=injected_environ):
                _captured.update(environ)
                start_response("200 OK", [])
                return [b"ok"]

            resolver = self._make_resolver(stub_app=capture_app)
            start_response, _ = _capture_response()

            resolver(_make_environ(f"{subdomain}.robot.wtf"), start_response)

            perms = injected_environ.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")
            assert "ADMIN" not in perms, (
                f"{subdomain}.robot.wtf must not receive ADMIN permission; got: {perms!r}"
            )

    def test_non_tenant_returns_404_or_no_admin(self):
        """A non-tenant host either returns 404 or passes through without ADMIN.

        Either outcome is acceptable — what is NOT acceptable is passing
        through with ADMIN permissions.
        """
        injected_environ = {}
        response_statuses = []

        def capture_app(environ, start_response, _captured=injected_environ):
            _captured.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        resolver = self._make_resolver(stub_app=capture_app)

        def record_start_response(status, headers, exc_info=None):
            response_statuses.append(status)

        resolver(_make_environ("robot.wtf"), record_start_response)

        # If the request was passed to the inner app, check no ADMIN
        if injected_environ:
            perms = injected_environ.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")
            assert "ADMIN" not in perms


class TestParseHost:
    """Unit tests for _parse_host."""

    def test_tenant_subdomain_extracted(self):
        from app.resolver import _parse_host
        assert _parse_host("alice.robot.wtf") == "alice"
        assert _parse_host("my-wiki.robot.wtf") == "my-wiki"

    def test_reserved_subdomains_return_none(self):
        from app.resolver import _parse_host
        for sub in ("www", "api", "mcp", "auth"):
            assert _parse_host(f"{sub}.robot.wtf") is None

    def test_bare_domain_returns_none(self):
        from app.resolver import _parse_host
        assert _parse_host("robot.wtf") is None

    def test_unknown_domain_returns_none(self):
        from app.resolver import _parse_host
        assert _parse_host("evil.com") is None
        assert _parse_host("") is None


class TestBrowserRedirect:
    """Browser visitors on private wikis are redirected to login; API gets JSON."""

    def _make_resolver(self, *, public=False):
        from app.resolver import TenantResolver
        from app.auth.acl import AclEnforcer
        from app.auth.middleware import AuthMiddleware, AuthError

        def stub_app(environ, start_response):
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        auth_middleware.authenticate_from_cookie.return_value = None

        acl_enforcer = MagicMock(spec=AclEnforcer)
        if public:
            acl_enforcer.check_public_access.return_value = {"permissions": ["READ"]}
        else:
            acl_enforcer.check_public_access.side_effect = AuthError(
                "Access denied", status=403
            )

        wiki_model = MagicMock()
        wiki_model.get.return_value = {"name": "Test Wiki", "disk_usage_bytes": 0}

        user_model = MagicMock()

        return TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
            acl_enforcer=acl_enforcer,
            wiki_model=wiki_model,
            user_model=user_model,
        )

    def test_browser_gets_redirect_on_403(self):
        resolver = self._make_resolver(public=False)
        start_response, calls = _capture_response()
        environ = _make_environ("gruen.robot.wtf", accept="text/html,application/xhtml+xml,*/*")
        resolver(environ, start_response)
        assert len(calls) == 1
        status, headers = calls[0]
        assert status == "302 Found"
        assert dict(headers)["Location"] == "https://robot.wtf/auth/login"

    def test_api_gets_json_on_403(self):
        resolver = self._make_resolver(public=False)
        start_response, calls = _capture_response()
        environ = _make_environ("gruen.robot.wtf", accept="application/json")
        resolver(environ, start_response)
        assert len(calls) == 1
        status, headers = calls[0]
        assert status == "403 Forbidden"
        assert dict(headers)["Content-Type"] == "application/json"

    def test_sse_client_gets_json_on_403(self):
        resolver = self._make_resolver(public=False)
        start_response, calls = _capture_response()
        environ = _make_environ("gruen.robot.wtf", accept="text/event-stream")
        resolver(environ, start_response)
        assert len(calls) == 1
        status, _ = calls[0]
        assert status == "403 Forbidden"

    def test_no_accept_header_gets_json_on_403(self):
        resolver = self._make_resolver(public=False)
        start_response, calls = _capture_response()
        environ = _make_environ("gruen.robot.wtf")
        resolver(environ, start_response)
        assert len(calls) == 1
        status, _ = calls[0]
        assert status == "403 Forbidden"

    def test_public_wiki_browser_passes_through(self):
        resolver = self._make_resolver(public=True)
        start_response, calls = _capture_response()
        environ = _make_environ("gruen.robot.wtf", accept="text/html,application/xhtml+xml,*/*")
        open_config = {
            "READ_ACCESS": "ANONYMOUS",
            "WRITE_ACCESS": "ANONYMOUS",
            "ATTACHMENT_ACCESS": "ANONYMOUS",
        }
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=open_config):
            resolver(environ, start_response)
        assert len(calls) == 1
        status, _ = calls[0]
        assert status == "200 OK"


class TestWikiAccessRestrictions:
    """Unit tests for _apply_wiki_access_restrictions."""

    def _call(self, permissions, is_authenticated, config_overrides=None):
        """Helper: call _apply_wiki_access_restrictions with a mocked app.config."""
        from app.resolver import _apply_wiki_access_restrictions

        default_config = {
            "READ_ACCESS": "ANONYMOUS",
            "WRITE_ACCESS": "ANONYMOUS",
            "ATTACHMENT_ACCESS": "ANONYMOUS",
        }
        if config_overrides:
            default_config.update(config_overrides)

        with patch("app.resolver._get_wiki_access_config", return_value=default_config):
            return _apply_wiki_access_restrictions(list(permissions), is_authenticated)

    def test_anonymous_allowed_read_access_anonymous(self):
        """READ_ACCESS=ANONYMOUS, unauthenticated user: READ permission preserved."""
        result = self._call(["READ", "WRITE"], is_authenticated=False,
                            config_overrides={"READ_ACCESS": "ANONYMOUS"})
        assert "READ" in result

    def test_registered_strips_read_for_unauthenticated(self):
        """READ_ACCESS=REGISTERED, unauthenticated: READ, WRITE, UPLOAD all stripped."""
        result = self._call(["READ", "WRITE", "UPLOAD"], is_authenticated=False,
                            config_overrides={"READ_ACCESS": "REGISTERED"})
        assert "READ" not in result
        assert "WRITE" not in result
        assert "UPLOAD" not in result

    def test_registered_keeps_read_for_authenticated(self):
        """READ_ACCESS=REGISTERED, authenticated: permissions unchanged."""
        perms = ["READ", "WRITE", "UPLOAD"]
        result = self._call(perms, is_authenticated=True,
                            config_overrides={"READ_ACCESS": "REGISTERED"})
        assert "READ" in result
        assert "WRITE" in result
        assert "UPLOAD" in result

    def test_write_restricted_unauthenticated_strips_write_upload(self):
        """WRITE_ACCESS=REGISTERED, unauthenticated: WRITE and UPLOAD stripped but READ kept."""
        result = self._call(["READ", "WRITE", "UPLOAD"], is_authenticated=False,
                            config_overrides={"WRITE_ACCESS": "REGISTERED"})
        assert "READ" in result
        assert "WRITE" not in result
        assert "UPLOAD" not in result

    def test_attachment_restricted_unauthenticated_strips_upload_only(self):
        """ATTACHMENT_ACCESS=REGISTERED, unauthenticated: UPLOAD stripped, READ and WRITE kept."""
        result = self._call(["READ", "WRITE", "UPLOAD"], is_authenticated=False,
                            config_overrides={"ATTACHMENT_ACCESS": "REGISTERED"})
        assert "READ" in result
        assert "WRITE" in result
        assert "UPLOAD" not in result

    def test_admin_never_stripped(self):
        """ADMIN permission is never removed regardless of access settings."""
        result = self._call(["READ", "WRITE", "UPLOAD", "ADMIN"], is_authenticated=False,
                            config_overrides={
                                "READ_ACCESS": "REGISTERED",
                                "WRITE_ACCESS": "REGISTERED",
                                "ATTACHMENT_ACCESS": "REGISTERED",
                            })
        assert "ADMIN" in result

    def test_approved_treated_as_registered(self):
        """APPROVED access level behaves like REGISTERED: strips access for unauthenticated."""
        result = self._call(["READ", "WRITE", "UPLOAD"], is_authenticated=False,
                            config_overrides={"READ_ACCESS": "APPROVED"})
        assert "READ" not in result
        assert "WRITE" not in result
        assert "UPLOAD" not in result

    def test_approved_keeps_perms_for_authenticated(self):
        """APPROVED access level: authenticated users keep their permissions."""
        result = self._call(["READ", "WRITE", "UPLOAD"], is_authenticated=True,
                            config_overrides={"READ_ACCESS": "APPROVED"})
        assert "READ" in result


class TestBearerTokenBypassesRestrictions:
    """MCP bearer tokens bypass per-wiki access restrictions."""

    def _make_resolver(self):
        from app.resolver import TenantResolver
        from app.auth.acl import AclEnforcer
        from app.auth.middleware import AuthMiddleware

        def stub_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        acl_enforcer = MagicMock(spec=AclEnforcer)
        acl_enforcer.check_bearer_token.return_value = {
            "permissions": ["READ", "WRITE", "UPLOAD"],
        }

        wiki_model = MagicMock()
        wiki_model.get.return_value = {"name": "Test Wiki", "disk_usage_bytes": 0}
        user_model = MagicMock()

        return TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
            acl_enforcer=acl_enforcer,
            wiki_model=wiki_model,
            user_model=user_model,
        )

    def test_bearer_token_bypasses_restrictions(self):
        """MCP bearer tokens get full access regardless of wiki access preferences."""
        resolver = self._make_resolver()
        injected_environ = {}

        def capture_app(environ, start_response):
            injected_environ.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        resolver._app = capture_app
        start_response, calls = _capture_response()
        environ = _make_environ("gruen.robot.wtf")
        environ["HTTP_AUTHORIZATION"] = "Bearer opaque-mcp-token"

        restrictive_config = {
            "READ_ACCESS": "REGISTERED",
            "WRITE_ACCESS": "REGISTERED",
            "ATTACHMENT_ACCESS": "REGISTERED",
        }

        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=restrictive_config):
            resolver(environ, start_response)

        perms = injected_environ.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")
        # Bearer token must not have permissions stripped
        assert "WRITE" in perms and "READ" in perms, (
            f"Bearer token permissions were incorrectly stripped: {perms!r}"
        )
