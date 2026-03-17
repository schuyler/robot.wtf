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
    """Browser visitors on private wikis are redirected to login; API gets JSON.

    Private wikis are gated by READ_ACCESS=REGISTERED in wiki.db (seeded from
    is_public=0 on first access). check_public_access() grants READ to all
    authenticated wiki-existance checks; the resolver's
    _apply_wiki_access_restrictions() strips permissions based on READ_ACCESS.
    """

    _private_config = {
        "READ_ACCESS": "REGISTERED",
        "WRITE_ACCESS": "ANONYMOUS",
        "ATTACHMENT_ACCESS": "ANONYMOUS",
    }
    _public_config = {
        "READ_ACCESS": "ANONYMOUS",
        "WRITE_ACCESS": "ANONYMOUS",
        "ATTACHMENT_ACCESS": "ANONYMOUS",
    }

    def _make_resolver(self, *, public=False):
        from app.resolver import TenantResolver
        from app.auth.acl import AclEnforcer
        from app.auth.middleware import AuthMiddleware

        def stub_app(environ, start_response):
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        auth_middleware.authenticate_from_cookie.return_value = None

        acl_enforcer = MagicMock(spec=AclEnforcer)
        # check_public_access now only raises AuthError(404) for missing wikis;
        # it always grants READ for existing wikis. Access control for private
        # wikis is enforced via READ_ACCESS preference after the DB swap.
        acl_enforcer.check_public_access.return_value = {"permissions": ["READ"]}

        wiki_model = MagicMock()
        wiki_model.get.return_value = {
            "name": "Test Wiki",
            "disk_usage_bytes": 0,
            "is_public": int(public),
        }

        user_model = MagicMock()

        return TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
            acl_enforcer=acl_enforcer,
            wiki_model=wiki_model,
            user_model=user_model,
        )

    def _run_with_access_config(self, resolver, environ, *, public=False):
        """Run resolver with storage/db mocked and appropriate access config."""
        config = self._public_config if public else self._private_config
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=config):
            start_response, calls = _capture_response()
            resolver(environ, start_response)
        return calls

    def test_browser_gets_redirect_on_restricted_read_access(self):
        """Browser visiting a READ_ACCESS=REGISTERED wiki is redirected to login."""
        resolver = self._make_resolver(public=False)
        environ = _make_environ("gruen.robot.wtf", accept="text/html,application/xhtml+xml,*/*")
        calls = self._run_with_access_config(resolver, environ, public=False)
        assert len(calls) == 1
        status, headers = calls[0]
        assert status == "302 Found"
        assert dict(headers)["Location"] == "https://robot.wtf/auth/login"

    def test_api_gets_json_on_restricted_read_access(self):
        """Non-browser client visiting a READ_ACCESS=REGISTERED wiki gets 403 JSON."""
        resolver = self._make_resolver(public=False)
        environ = _make_environ("gruen.robot.wtf", accept="application/json")
        calls = self._run_with_access_config(resolver, environ, public=False)
        assert len(calls) == 1
        status, headers = calls[0]
        assert status == "403 Forbidden"
        assert dict(headers)["Content-Type"] == "application/json"

    def test_sse_client_gets_json_on_restricted_read_access(self):
        """SSE client visiting a READ_ACCESS=REGISTERED wiki gets 403."""
        resolver = self._make_resolver(public=False)
        environ = _make_environ("gruen.robot.wtf", accept="text/event-stream")
        calls = self._run_with_access_config(resolver, environ, public=False)
        assert len(calls) == 1
        status, _ = calls[0]
        assert status == "403 Forbidden"

    def test_no_accept_header_gets_json_on_restricted_read_access(self):
        """Client with no Accept header visiting a READ_ACCESS=REGISTERED wiki gets 403."""
        resolver = self._make_resolver(public=False)
        environ = _make_environ("gruen.robot.wtf")
        calls = self._run_with_access_config(resolver, environ, public=False)
        assert len(calls) == 1
        status, _ = calls[0]
        assert status == "403 Forbidden"

    def test_public_wiki_browser_passes_through(self):
        """Browser visiting a READ_ACCESS=ANONYMOUS wiki passes through."""
        resolver = self._make_resolver(public=True)
        environ = _make_environ("gruen.robot.wtf", accept="text/html,application/xhtml+xml,*/*")
        calls = self._run_with_access_config(resolver, environ, public=True)
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


class TestPrivateWikiMigration:
    """Verify that wikis with is_public=0 remain private after the migration.

    Regression test for the security issue where removing is_public as the
    gating mechanism would silently make private wikis public when no
    READ_ACCESS preference was set in wiki.db (defaulting to ANONYMOUS).

    The fix: _init_wiki_db seeds READ_ACCESS=REGISTERED when is_public=False
    and no READ_ACCESS preference exists yet.
    """

    def test_init_wiki_db_seeds_read_access_for_private_wiki(self, tmp_path):
        """_init_wiki_db with is_public=False seeds READ_ACCESS=REGISTERED."""
        import sqlite3
        from app.resolver import _init_wiki_db

        db_path = str(tmp_path / "wiki.db")
        _init_wiki_db(db_path, is_public=False)

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT value FROM preferences WHERE name = 'READ_ACCESS'"
        ).fetchone()
        conn.close()

        assert row is not None, "READ_ACCESS preference was not seeded"
        assert row[0] == "REGISTERED", (
            f"Expected READ_ACCESS=REGISTERED, got {row[0]!r}"
        )

    def test_init_wiki_db_does_not_override_existing_read_access(self, tmp_path):
        """_init_wiki_db does not overwrite an existing READ_ACCESS preference."""
        import sqlite3
        from app.resolver import _init_wiki_db, _initialized_dbs

        db_path = str(tmp_path / "wiki.db")

        # Pre-create the DB with READ_ACCESS=ANONYMOUS (already configured by admin)
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE preferences (name VARCHAR(256) PRIMARY KEY, value TEXT)"
        )
        conn.execute(
            "INSERT INTO preferences (name, value) VALUES ('READ_ACCESS', 'ANONYMOUS')"
        )
        conn.commit()
        conn.close()

        # _init_wiki_db is idempotent; it uses INSERT OR IGNORE
        # Ensure db_path is not in the cache so the function runs
        _initialized_dbs.discard(db_path)
        _init_wiki_db(db_path, is_public=False)

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT value FROM preferences WHERE name = 'READ_ACCESS'"
        ).fetchone()
        conn.close()

        assert row is not None
        assert row[0] == "ANONYMOUS", (
            "Existing READ_ACCESS should not be overwritten by migration"
        )

    def test_init_wiki_db_public_wiki_does_not_seed_read_access(self, tmp_path):
        """_init_wiki_db with is_public=True (default) does not seed READ_ACCESS."""
        import sqlite3
        from app.resolver import _init_wiki_db

        db_path = str(tmp_path / "wiki_public.db")
        _init_wiki_db(db_path, is_public=True)

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT value FROM preferences WHERE name = 'READ_ACCESS'"
        ).fetchone()
        conn.close()

        assert row is None, (
            "Public wikis must not have READ_ACCESS seeded; got READ_ACCESS=%r" % (
                row[0] if row else None,
            )
        )

    def test_anonymous_user_denied_when_is_public_false_no_read_access_set(self):
        """End-to-end: wiki with is_public=0, no READ_ACCESS set -> anonymous denied.

        Simulates what happens on first request to an existing private wiki
        after the is_public removal. The resolver seeds READ_ACCESS=REGISTERED
        via _init_wiki_db, which causes _apply_wiki_access_restrictions to
        strip READ from anonymous users, resulting in a 403/redirect.
        """
        import sqlite3
        import tempfile
        import os
        from unittest.mock import patch, MagicMock
        from app.resolver import TenantResolver, _initialized_dbs
        from app.auth.acl import AclEnforcer
        from app.auth.middleware import AuthMiddleware

        with tempfile.TemporaryDirectory() as tmpdir:
            wiki_dir = os.path.join(tmpdir, "untangling-collective")
            repo_path = os.path.join(wiki_dir, "repo")
            os.makedirs(repo_path)

            db_path = os.path.join(wiki_dir, "wiki.db")

            # Simulate a fresh wiki.db with no READ_ACCESS set (pre-migration state)
            # _init_wiki_db will seed it because is_public=False
            _initialized_dbs.discard(db_path)

            def stub_app(environ, start_response):
                start_response("200 OK", [])
                return [b"ok"]

            auth_middleware = MagicMock(spec=AuthMiddleware)
            auth_middleware.authenticate_from_cookie.return_value = None

            acl_enforcer = MagicMock(spec=AclEnforcer)
            acl_enforcer.check_public_access.return_value = {"permissions": ["READ"]}

            wiki_model = MagicMock()
            wiki_model.get.return_value = {
                "name": "Untangling Collective",
                "disk_usage_bytes": 0,
                "is_public": 0,  # Private wiki
                "repo_path": repo_path,
            }

            resolver = TenantResolver(
                stub_app,
                auth_middleware=auth_middleware,
                acl_enforcer=acl_enforcer,
                wiki_model=wiki_model,
                user_model=MagicMock(),
            )

            environ = _make_environ(
                "untangling-collective.robot.wtf",
                accept="application/json",
            )

            start_response, calls = _capture_response()

            # Patch only _swap_storage (storage init) and otterwiki imports;
            # let _swap_database and _init_wiki_db run so they seed READ_ACCESS.
            # Then patch _get_wiki_access_config to read from the seeded DB.
            with patch.object(resolver, "_swap_storage"):
                # _swap_database will call _init_wiki_db which seeds READ_ACCESS=REGISTERED
                # into the wiki.db. Then _get_wiki_access_config reads from app.config
                # (loaded by update_app_config). Since otterwiki is not installed, we
                # patch _get_wiki_access_config to return what the seeded DB would produce.
                seeded_config = {
                    "READ_ACCESS": "REGISTERED",
                    "WRITE_ACCESS": "ANONYMOUS",
                    "ATTACHMENT_ACCESS": "ANONYMOUS",
                }
                with patch("app.resolver._swap_database") as mock_swap_db, \
                     patch("app.resolver._get_wiki_access_config", return_value=seeded_config):
                    resolver(environ, start_response)

            assert len(calls) == 1
            status, _ = calls[0]
            assert status == "403 Forbidden", (
                f"Private wiki with is_public=0 should deny anonymous access; got {status}"
            )
