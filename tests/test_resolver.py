"""Tests for TenantResolver WSGI middleware.

Covers:
- Non-tenant hosts must NOT receive ADMIN permissions (ACL bypass)
- Wiki tenant resolution and passthrough
"""

from __future__ import annotations

from unittest.mock import MagicMock


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
        from unittest.mock import patch
        resolver = self._make_resolver(public=True)
        start_response, calls = _capture_response()
        environ = _make_environ("gruen.robot.wtf", accept="text/html,application/xhtml+xml,*/*")
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"):
            resolver(environ, start_response)
        assert len(calls) == 1
        status, _ = calls[0]
        assert status == "200 OK"
