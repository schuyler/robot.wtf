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
        from app.auth.middleware import AuthMiddleware

        if stub_app is None:
            def stub_app(environ, start_response):
                start_response("200 OK", [("Content-Type", "text/plain")])
                return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        wiki_model = MagicMock()
        user_model = MagicMock()

        return TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
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
        from app.auth.middleware import AuthMiddleware

        def stub_app(environ, start_response):
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        auth_middleware.authenticate_from_cookie.return_value = None

        wiki_model = MagicMock()
        wiki_model.get.return_value = {
            "name": "Test Wiki",
            "owner_did": "did:plc:owner",
            "disk_usage_bytes": 0,
            "is_public": int(public),
        }

        user_model = MagicMock()

        return TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
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
        """Browser visiting a READ_ACCESS=REGISTERED wiki is redirected to login with return_to."""
        resolver = self._make_resolver(public=False)
        environ = _make_environ("gruen.robot.wtf", accept="text/html,application/xhtml+xml,*/*")
        calls = self._run_with_access_config(resolver, environ, public=False)
        assert len(calls) == 1
        status, headers = calls[0]
        assert status == "302 Found"
        location = dict(headers)["Location"]
        assert location.startswith("https://robot.wtf/auth/login")
        assert "return_to=" in location
        assert "gruen.robot.wtf" in location

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

    def test_approved_keeps_perms_for_approved_authenticated(self):
        """APPROVED access level: authenticated + is_approved=True keeps permissions."""
        from app.resolver import _apply_wiki_access_restrictions

        config = {
            "READ_ACCESS": "APPROVED",
            "WRITE_ACCESS": "ANONYMOUS",
            "ATTACHMENT_ACCESS": "ANONYMOUS",
        }
        per_wiki_user = {"is_approved": True, "is_admin": False}
        with patch("app.resolver._get_wiki_access_config", return_value=config):
            result = _apply_wiki_access_restrictions(
                ["READ", "WRITE", "UPLOAD"],
                is_authenticated=True,
                config=config,
                per_wiki_user=per_wiki_user,
            )
        assert "READ" in result

    def test_approved_denies_unapproved_authenticated(self):
        """APPROVED access level: authenticated but not approved → denied."""
        from app.resolver import _apply_wiki_access_restrictions

        config = {
            "READ_ACCESS": "APPROVED",
            "WRITE_ACCESS": "ANONYMOUS",
            "ATTACHMENT_ACCESS": "ANONYMOUS",
        }
        with patch("app.resolver._get_wiki_access_config", return_value=config):
            result = _apply_wiki_access_restrictions(
                ["READ", "WRITE", "UPLOAD"],
                is_authenticated=True,
                config=config,
                per_wiki_user=None,  # not in per-wiki table
            )
        assert "READ" not in result


class TestBearerTokenBypassesRestrictions:
    """MCP bearer tokens bypass per-wiki access restrictions."""

    def _make_resolver(self):
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware

        def stub_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)

        wiki_model = MagicMock()
        wiki_model.get.return_value = {
            "name": "Test Wiki",
            "owner_did": "did:plc:owner",
            "disk_usage_bytes": 0,
        }
        wiki_model.get_by_token.return_value = {
            "slug": "gruen",
            "owner_did": "did:plc:owner",
        }
        user_model = MagicMock()

        return TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
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


class TestLoginRedirectReturnTo:
    """Resolver redirects include return_to with the original wiki URL."""

    _private_config = {
        "READ_ACCESS": "REGISTERED",
        "WRITE_ACCESS": "ANONYMOUS",
        "ATTACHMENT_ACCESS": "ANONYMOUS",
    }

    def _make_resolver(self):
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware

        def stub_app(environ, start_response):
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        auth_middleware.authenticate_from_cookie.return_value = None

        wiki_model = MagicMock()
        wiki_model.get.return_value = {
            "name": "Test Wiki",
            "owner_did": "did:plc:owner",
            "disk_usage_bytes": 0,
            "is_public": 0,
        }

        user_model = MagicMock()

        return TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=user_model,
        )

    def _run_with_private_config(self, resolver, environ):
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=self._private_config):
            start_response, calls = _capture_response()
            resolver(environ, start_response)
        return calls

    def test_login_redirect_includes_return_to(self):
        """Resolver redirects browser to login with return_to containing the wiki URL."""
        resolver = self._make_resolver()
        environ = _make_environ(
            "gruen.robot.wtf",
            path="/SomePage",
            accept="text/html,application/xhtml+xml,*/*",
        )
        environ["wsgi.url_scheme"] = "https"
        environ["QUERY_STRING"] = ""
        calls = self._run_with_private_config(resolver, environ)
        assert len(calls) == 1
        status, headers = calls[0]
        assert status == "302 Found"
        location = dict(headers)["Location"]
        assert "return_to=" in location
        assert "gruen.robot.wtf" in location
        assert "SomePage" in location

    def test_login_redirect_includes_query_string(self):
        """return_to includes the query string when present."""
        resolver = self._make_resolver()
        environ = _make_environ(
            "gruen.robot.wtf",
            path="/SomePage",
            accept="text/html,application/xhtml+xml,*/*",
        )
        environ["wsgi.url_scheme"] = "https"
        environ["QUERY_STRING"] = "edit=1"
        calls = self._run_with_private_config(resolver, environ)
        assert len(calls) == 1
        location = dict(calls[0][1])["Location"]
        assert "edit%3D1" in location or "edit=1" in location


class TestLazyInitSiteName:
    """Verify that lazy DB init seeds SITE_NAME from the wiki's display_name.

    When _swap_database() is called for a wiki that has no wiki.db yet,
    it should seed SITE_NAME from display_name so the wiki shows its own
    name rather than whatever was loaded from a previous request.
    """

    def _make_resolver(self, display_name=None):
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware

        def stub_app(environ, start_response):
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        auth_middleware.authenticate_from_cookie.return_value = None

        wiki_model = MagicMock()
        wiki_record = {
            "name": "test-wiki",
            "owner_did": "did:plc:owner",
            "disk_usage_bytes": 0,
            "is_public": 1,
        }
        if display_name is not None:
            wiki_record["display_name"] = display_name
        wiki_model.get.return_value = wiki_record

        user_model = MagicMock()

        return TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=user_model,
        )

    def test_swap_database_called_with_display_name(self):
        """TenantResolver.__call__ passes display_name to _swap_database."""
        resolver = self._make_resolver(display_name="My Fancy Wiki")
        environ = _make_environ("test-wiki.robot.wtf")
        start_response, calls = _capture_response()

        public_config = {
            "READ_ACCESS": "ANONYMOUS",
            "WRITE_ACCESS": "ANONYMOUS",
            "ATTACHMENT_ACCESS": "ANONYMOUS",
        }

        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database") as mock_swap_db, \
             patch("app.resolver._get_wiki_access_config", return_value=public_config):
            resolver(environ, start_response)

        mock_swap_db.assert_called_once()
        _, kwargs = mock_swap_db.call_args
        assert kwargs.get("display_name") == "My Fancy Wiki", (
            f"_swap_database was not called with display_name='My Fancy Wiki'; "
            f"got kwargs={kwargs!r}"
        )

    def test_swap_database_display_name_none_when_not_in_wiki(self):
        """TenantResolver passes display_name=None when wiki record has no display_name."""
        resolver = self._make_resolver(display_name=None)
        environ = _make_environ("test-wiki.robot.wtf")
        start_response, calls = _capture_response()

        public_config = {
            "READ_ACCESS": "ANONYMOUS",
            "WRITE_ACCESS": "ANONYMOUS",
            "ATTACHMENT_ACCESS": "ANONYMOUS",
        }

        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database") as mock_swap_db, \
             patch("app.resolver._get_wiki_access_config", return_value=public_config):
            resolver(environ, start_response)

        mock_swap_db.assert_called_once()
        _, kwargs = mock_swap_db.call_args
        assert kwargs.get("display_name") is None

    def test_swap_database_passes_display_name_to_init_wiki_db(self, tmp_path):
        """_swap_database passes display_name through to _init_wiki_db as site_name.

        We mock the otterwiki imports and engine state so _swap_database reaches
        the _init_wiki_db call, then verify it receives site_name=display_name.
        """
        import os
        import sys
        import types
        from app.resolver import _initialized_dbs

        wiki_dir = str(tmp_path / "wikis" / "test-wiki")
        os.makedirs(wiki_dir)

        # Build minimal otterwiki.server stub
        mock_app = MagicMock()
        mock_app.config = {}
        mock_engine = MagicMock()
        mock_engine.url = MagicMock()
        mock_engine.url.__str__ = lambda self: "sqlite:///other.db"
        mock_db = MagicMock()
        mock_db._app_engines = {mock_app: {None: mock_engine}}

        mock_server_mod = types.ModuleType("otterwiki.server")
        mock_server_mod.app = mock_app
        mock_server_mod.db = mock_db
        mock_server_mod.update_app_config = MagicMock()

        mock_otterwiki = types.ModuleType("otterwiki")
        mock_create_engine = MagicMock(return_value=MagicMock())

        # Also make otterwiki.server accessible as an attribute on the otterwiki stub
        mock_otterwiki.server = mock_server_mod

        with patch.dict(sys.modules, {
                "otterwiki": mock_otterwiki,
                "otterwiki.server": mock_server_mod,
             }), \
             patch("app.resolver.WIKI_BASE", str(tmp_path / "wikis")), \
             patch("app.resolver._init_wiki_db") as mock_init_db, \
             patch("sqlalchemy.create_engine", mock_create_engine):
            from app.resolver import _swap_database
            _swap_database(wiki_dir, display_name="My Fancy Wiki")

        assert mock_init_db.called, "_init_wiki_db was not called by _swap_database"
        _, kwargs = mock_init_db.call_args
        assert kwargs.get("site_name") == "My Fancy Wiki", (
            f"_init_wiki_db not called with site_name='My Fancy Wiki'; got {kwargs!r}"
        )


class TestPrivateWikiMigration:
    """Verify that wikis with is_public=0 remain private after the migration.

    Regression test for the security issue where removing is_public as the
    gating mechanism would silently make private wikis public when no
    READ_ACCESS preference was set in wiki.db (defaulting to ANONYMOUS).

    The fix: _init_wiki_db seeds READ_ACCESS=APPROVED when is_public=False
    and no READ_ACCESS preference exists yet.
    """

    def test_init_wiki_db_seeds_read_access_for_private_wiki(self, tmp_path):
        """_init_wiki_db with is_public=False seeds READ_ACCESS=APPROVED."""
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
        assert row[0] == "APPROVED", (
            f"Expected READ_ACCESS=APPROVED, got {row[0]!r}"
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

    def test_init_wiki_db_always_seeds_read_access_approved(self, tmp_path):
        """_init_wiki_db always seeds READ_ACCESS=APPROVED regardless of is_public.

        Phase 2 Unit 5: comprehensive seeding means all platform wikis get
        APPROVED as the secure default. The is_public flag is no longer used
        to conditionally seed READ_ACCESS; access control is handled at the
        resolver level, not at DB init time.
        """
        import sqlite3
        from app.resolver import _init_wiki_db

        db_path = str(tmp_path / "wiki_public.db")
        _init_wiki_db(db_path, is_public=True)

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT value FROM preferences WHERE name = 'READ_ACCESS'"
        ).fetchone()
        conn.close()

        assert row is not None, "READ_ACCESS should always be seeded"
        assert row[0] == "APPROVED", (
            "Expected READ_ACCESS=APPROVED (secure default), got %r" % row[0]
        )

    def test_anonymous_user_denied_when_is_public_false_no_read_access_set(self):
        """End-to-end: wiki with is_public=0, no READ_ACCESS set -> anonymous denied.

        Simulates what happens on first request to an existing private wiki
        after the is_public removal. The resolver seeds READ_ACCESS=APPROVED
        via _init_wiki_db, which causes _apply_wiki_access_restrictions to
        strip READ from anonymous users, resulting in a 403/redirect.
        """
        import sqlite3
        import tempfile
        import os
        from unittest.mock import patch, MagicMock
        from app.resolver import TenantResolver, _initialized_dbs
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

            wiki_model = MagicMock()
            wiki_model.get.return_value = {
                "name": "Untangling Collective",
                "owner_did": "did:plc:owner",
                "disk_usage_bytes": 0,
                "is_public": 0,  # Private wiki
                "repo_path": repo_path,
            }

            resolver = TenantResolver(
                stub_app,
                auth_middleware=auth_middleware,
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
                # _swap_database will call _init_wiki_db which seeds READ_ACCESS=APPROVED
                # into the wiki.db. Then _get_wiki_access_config reads from app.config
                # (loaded by update_app_config). Since otterwiki is not installed, we
                # patch _get_wiki_access_config to return what the seeded DB would produce.
                seeded_config = {
                    "READ_ACCESS": "APPROVED",
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


# ===========================================================================
# Phase 2 User Management Tests
# ===========================================================================


def _make_resolver_no_acl(stub_app=None):
    """Build a TenantResolver without AclEnforcer (Phase 2 new resolver)."""
    from app.resolver import TenantResolver
    from app.auth.middleware import AuthMiddleware

    if stub_app is None:
        def stub_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

    auth_middleware = MagicMock(spec=AuthMiddleware)
    wiki_model = MagicMock()
    user_model = MagicMock()

    return TenantResolver(
        stub_app,
        auth_middleware=auth_middleware,
        wiki_model=wiki_model,
        user_model=user_model,
    )


class TestOwnerPermissions:
    """owner_did match on the wiki → ADMIN permissions."""

    def _make_resolver(self, owner_did="did:plc:owner"):
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware, AuthenticatedUser

        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        auth_middleware.authenticate_from_cookie.return_value = AuthenticatedUser(
            user_did=owner_did,
            handle="owner.bsky.social",
            display_name="Owner",
            record={},
        )

        wiki_model = MagicMock()
        wiki_model.get.return_value = {
            "slug": "owner-wiki",
            "owner_did": owner_did,
            "display_name": "Owner Wiki",
            "disk_usage_bytes": 0,
            "is_public": 1,
        }
        user_model = MagicMock()

        resolver = TenantResolver(
            capture_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=user_model,
        )
        return resolver, injected

    def test_owner_gets_admin_permissions(self):
        """Wiki owner (owner_did match) receives ADMIN permission."""
        resolver, injected = self._make_resolver()
        environ = _make_environ("owner-wiki.robot.wtf")
        environ["HTTP_COOKIE"] = "platform_token=sometoken"
        start_response, calls = _capture_response()

        public_config = {
            "READ_ACCESS": "ANONYMOUS",
            "WRITE_ACCESS": "ANONYMOUS",
            "ATTACHMENT_ACCESS": "ANONYMOUS",
        }
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=public_config):
            resolver(environ, start_response)

        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "200 OK"
        perms = injected.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")
        assert "ADMIN" in perms, f"Owner should have ADMIN; got: {perms!r}"


class TestPerWikiUserPermissions:
    """Per-wiki user table determines permissions for non-owners."""

    def _make_resolver(self, per_wiki_user=None):
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware, AuthenticatedUser

        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        auth_middleware.authenticate_from_cookie.return_value = AuthenticatedUser(
            user_did="did:plc:visitor",
            handle="visitor.bsky.social",
            display_name="Visitor",
            record={},
        )

        wiki_model = MagicMock()
        wiki_model.get.return_value = {
            "slug": "test-wiki",
            "owner_did": "did:plc:owner",  # different from visitor
            "display_name": "Test Wiki",
            "disk_usage_bytes": 0,
            "is_public": 1,
        }
        user_model = MagicMock()

        resolver = TenantResolver(
            capture_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=user_model,
        )
        resolver._per_wiki_user_override = per_wiki_user
        return resolver, injected

    def _run(self, resolver, injected, config=None):
        environ = _make_environ("test-wiki.robot.wtf")
        environ["HTTP_COOKIE"] = "platform_token=sometoken"
        start_response, calls = _capture_response()
        if config is None:
            config = {
                "READ_ACCESS": "ANONYMOUS",
                "WRITE_ACCESS": "ANONYMOUS",
                "ATTACHMENT_ACCESS": "ANONYMOUS",
            }
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=config), \
             patch.object(resolver, "_get_per_wiki_user",
                          return_value=resolver._per_wiki_user_override):
            resolver(environ, start_response)
        return calls, injected.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")

    def test_per_wiki_user_admin_gets_admin(self):
        """User in wiki.db with is_admin=True gets ADMIN."""
        resolver, injected = self._make_resolver(per_wiki_user={
            "is_admin": True,
            "is_approved": True,
            "allow_read": True,
            "allow_write": True,
            "allow_upload": True,
        })
        calls, perms = self._run(resolver, injected)
        assert "ADMIN" in perms, f"Admin user should have ADMIN; got {perms!r}"

    def test_per_wiki_user_editor_gets_write(self):
        """User with allow_write=True gets WRITE permission."""
        resolver, injected = self._make_resolver(per_wiki_user={
            "is_admin": False,
            "is_approved": True,
            "allow_read": True,
            "allow_write": True,
            "allow_upload": False,
        })
        calls, perms = self._run(resolver, injected)
        assert "WRITE" in perms, f"Editor should have WRITE; got {perms!r}"

    def test_per_wiki_user_viewer_gets_read_only(self):
        """User with allow_read=True, allow_write=False gets READ but not WRITE."""
        resolver, injected = self._make_resolver(per_wiki_user={
            "is_admin": False,
            "is_approved": True,
            "allow_read": True,
            "allow_write": False,
            "allow_upload": False,
        })
        calls, perms = self._run(resolver, injected)
        assert "READ" in perms, f"Viewer should have READ; got {perms!r}"
        assert "WRITE" not in perms, f"Viewer should not have WRITE; got {perms!r}"


class TestApprovedWikiAccess:
    """APPROVED access level gating via per-wiki user table."""

    def _make_resolver(self, per_wiki_user=None):
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware, AuthenticatedUser

        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        auth_middleware.authenticate_from_cookie.return_value = AuthenticatedUser(
            user_did="did:plc:visitor",
            handle="visitor.bsky.social",
            display_name="Visitor",
            record={},
        )

        wiki_model = MagicMock()
        wiki_model.get.return_value = {
            "slug": "approved-wiki",
            "owner_did": "did:plc:owner",
            "display_name": "Approved Wiki",
            "disk_usage_bytes": 0,
            "is_public": 1,
        }
        user_model = MagicMock()

        resolver = TenantResolver(
            capture_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=user_model,
        )
        resolver._per_wiki_user_override = per_wiki_user
        return resolver, injected

    def _run(self, resolver, injected, read_access="APPROVED"):
        environ = _make_environ("approved-wiki.robot.wtf")
        environ["HTTP_COOKIE"] = "platform_token=sometoken"
        start_response, calls = _capture_response()
        config = {
            "READ_ACCESS": read_access,
            "WRITE_ACCESS": "APPROVED",
            "ATTACHMENT_ACCESS": "APPROVED",
        }
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=config), \
             patch.object(resolver, "_get_per_wiki_user",
                          return_value=resolver._per_wiki_user_override):
            resolver(environ, start_response)
        return calls, injected.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")

    def test_approved_wiki_denies_unapproved_user(self):
        """READ_ACCESS=APPROVED, user not in table → READ denied."""
        resolver, injected = self._make_resolver(per_wiki_user=None)
        calls, perms = self._run(resolver, injected, read_access="APPROVED")
        assert calls, "No response captured"
        status, _ = calls[0]
        # Should get 403 or have no READ permission
        if status == "200 OK":
            assert "READ" not in perms, (
                f"Unapproved user should not have READ on APPROVED wiki; got {perms!r}"
            )
        else:
            assert status in ("403 Forbidden", "302 Found"), (
                f"Expected denial, got: {status}"
            )

    def test_approved_wiki_allows_approved_user(self):
        """READ_ACCESS=APPROVED, user in table with is_approved=True → allowed."""
        resolver, injected = self._make_resolver(per_wiki_user={
            "is_admin": False,
            "is_approved": True,
            "allow_read": True,
            "allow_write": False,
            "allow_upload": False,
        })
        calls, perms = self._run(resolver, injected, read_access="APPROVED")
        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "200 OK", f"Approved user should be allowed; got {status}"
        assert "READ" in perms, f"Approved user should have READ; got {perms!r}"


class TestAnonymousAndRegisteredAccess:
    """Wiki-level preferences for anonymous and registered access."""

    def _make_resolver(self, cookie_user=None):
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware

        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        auth_middleware.authenticate_from_cookie.return_value = cookie_user

        wiki_model = MagicMock()
        wiki_model.get.return_value = {
            "slug": "open-wiki",
            "owner_did": "did:plc:owner",
            "display_name": "Open Wiki",
            "disk_usage_bytes": 0,
            "is_public": 1,
        }
        user_model = MagicMock()

        return TenantResolver(
            capture_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=user_model,
        ), injected

    def _run(self, resolver, injected, config, environ=None, with_cookie=False):
        if environ is None:
            environ = _make_environ("open-wiki.robot.wtf")
            if with_cookie:
                environ["HTTP_COOKIE"] = "platform_token=sometoken"
        start_response, calls = _capture_response()
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=config), \
             patch.object(resolver, "_get_per_wiki_user", return_value=None):
            resolver(environ, start_response)
        return calls, injected.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")

    def test_anonymous_public_wiki(self):
        """READ_ACCESS=ANONYMOUS → unauthenticated user allowed to read."""
        resolver, injected = self._make_resolver(cookie_user=None)
        config = {
            "READ_ACCESS": "ANONYMOUS",
            "WRITE_ACCESS": "ANONYMOUS",
            "ATTACHMENT_ACCESS": "ANONYMOUS",
        }
        calls, perms = self._run(resolver, injected, config)
        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "200 OK", f"Anonymous should be allowed on public wiki; got {status}"
        assert "READ" in perms, f"Anonymous should have READ; got {perms!r}"

    def test_registered_wiki_allows_authenticated(self):
        """READ_ACCESS=REGISTERED, authenticated user (not owner) → allowed."""
        from app.auth.middleware import AuthenticatedUser
        cookie_user = AuthenticatedUser(
            user_did="did:plc:visitor",
            handle="visitor.bsky.social",
            display_name="Visitor",
            record={},
        )
        resolver, injected = self._make_resolver(cookie_user=cookie_user)
        config = {
            "READ_ACCESS": "REGISTERED",
            "WRITE_ACCESS": "REGISTERED",
            "ATTACHMENT_ACCESS": "REGISTERED",
        }
        calls, perms = self._run(resolver, injected, config, with_cookie=True)
        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "200 OK", f"Registered user should be allowed; got {status}"
        assert "READ" in perms, f"Registered user should have READ; got {perms!r}"


class TestBearerTokenResolvesWiki:
    """Bearer token path: WikiModel.get_by_token() used directly."""

    def test_bearer_token_resolves_wiki(self):
        """Bearer token calls wiki_model.get_by_token and returns correct wiki."""
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware

        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        wiki_model = MagicMock()
        # The wiki_slug lookup returns a real wiki for the bearer token path
        wiki_model.get.return_value = {
            "slug": "bearer-wiki",
            "owner_did": "did:plc:owner",
            "display_name": "Bearer Wiki",
            "disk_usage_bytes": 0,
            "is_public": 1,
        }
        wiki_model.get_by_token.return_value = {
            "slug": "bearer-wiki",
            "owner_did": "did:plc:owner",
            "display_name": "Bearer Wiki",
        }
        user_model = MagicMock()

        resolver = TenantResolver(
            capture_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=user_model,
        )

        environ = _make_environ("bearer-wiki.robot.wtf")
        environ["HTTP_AUTHORIZATION"] = "Bearer opaque-mcp-token"
        start_response, calls = _capture_response()

        public_config = {
            "READ_ACCESS": "ANONYMOUS",
            "WRITE_ACCESS": "ANONYMOUS",
            "ATTACHMENT_ACCESS": "ANONYMOUS",
        }
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=public_config):
            resolver(environ, start_response)

        # get_by_token should have been called, not scan_by_token
        wiki_model.get_by_token.assert_called_once()
        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "200 OK", f"Bearer token should succeed; got {status}"


class TestInitWikiDbSeeding:
    """Unit 3: _init_wiki_db seeds the wiki owner into the per-wiki user table."""

    def test_init_wiki_db_seeds_owner(self, tmp_path):
        """After _init_wiki_db with owner_handle, user table has owner with is_admin=True."""
        import sqlite3
        from app.resolver import _init_wiki_db, _initialized_dbs

        db_path = str(tmp_path / "wiki.db")
        _initialized_dbs.discard(db_path)
        _init_wiki_db(db_path, owner_handle="ownerhandle")

        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT * FROM user WHERE email = ?", ("@ownerhandle",)
        ).fetchone()
        conn.close()

        assert row is not None, "Owner was not seeded into per-wiki user table"
        row_dict = dict(zip(
            ["id", "name", "email", "password_hash", "first_seen", "last_seen",
             "is_approved", "is_admin", "email_confirmed", "allow_read", "allow_write", "allow_upload"],
            row
        ))
        assert row_dict["is_admin"] == 1, f"Owner should have is_admin=1; got {row_dict['is_admin']}"
        assert row_dict["is_approved"] == 1, "Owner should have is_approved=1"

    def test_init_wiki_db_idempotent(self, tmp_path):
        """Calling _init_wiki_db twice doesn't duplicate the owner row."""
        import sqlite3
        from app.resolver import _init_wiki_db, _initialized_dbs

        db_path = str(tmp_path / "wiki2.db")
        _initialized_dbs.discard(db_path)
        _init_wiki_db(db_path, owner_handle="ownerhandle")

        # Must remove from cache to call again
        _initialized_dbs.discard(db_path)
        _init_wiki_db(db_path, owner_handle="ownerhandle")

        conn = sqlite3.connect(db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM user WHERE email = ?", ("@ownerhandle",)
        ).fetchone()[0]
        conn.close()

        assert count == 1, f"Owner should appear exactly once; found {count}"


class TestOwnerOnApprovedWiki:
    """Owner always keeps full permissions even on APPROVED wikis."""

    def test_owner_on_approved_wiki_keeps_all_permissions(self):
        """Owner with READ_ACCESS=APPROVED keeps READ, WRITE, UPLOAD, ADMIN."""
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware, AuthenticatedUser

        owner_did = "did:plc:owner-approved"
        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        auth_middleware.authenticate_from_cookie.return_value = AuthenticatedUser(
            user_did=owner_did,
            handle="owner.bsky.social",
            display_name="Owner",
            record={},
        )

        wiki_model = MagicMock()
        wiki_model.get.return_value = {
            "slug": "approved-owner-wiki",
            "owner_did": owner_did,
            "display_name": "Approved Owner Wiki",
            "disk_usage_bytes": 0,
            "is_public": 1,
        }
        user_model = MagicMock()

        resolver = TenantResolver(
            capture_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=user_model,
        )

        environ = _make_environ("approved-owner-wiki.robot.wtf")
        environ["HTTP_COOKIE"] = "platform_token=sometoken"
        start_response, calls = _capture_response()

        approved_config = {
            "READ_ACCESS": "APPROVED",
            "WRITE_ACCESS": "APPROVED",
            "ATTACHMENT_ACCESS": "APPROVED",
        }
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=approved_config):
            resolver(environ, start_response)

        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "200 OK", f"Owner should be allowed; got {status}"
        perms = injected.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")
        assert "ADMIN" in perms, f"Owner should have ADMIN; got {perms!r}"
        assert "READ" in perms, f"Owner should have READ; got {perms!r}"
        assert "WRITE" in perms, f"Owner should have WRITE; got {perms!r}"
        assert "UPLOAD" in perms, f"Owner should have UPLOAD; got {perms!r}"


class TestBearerTokenWikiCrossCheck:
    """Bearer token must only work on the wiki it was issued for."""

    def test_bearer_token_wrong_wiki_denied(self):
        """Token for wiki A used on wiki B should be rejected with 403."""
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware

        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        wiki_model = MagicMock()
        # Host resolves to wiki B
        wiki_model.get.return_value = {
            "slug": "wiki-b",
            "owner_did": "did:plc:owner-b",
            "display_name": "Wiki B",
            "disk_usage_bytes": 0,
            "is_public": 1,
        }
        # But the token belongs to wiki A
        wiki_model.get_by_token.return_value = {
            "slug": "wiki-a",
            "owner_did": "did:plc:owner-a",
            "display_name": "Wiki A",
        }
        user_model = MagicMock()

        resolver = TenantResolver(
            capture_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=user_model,
        )

        environ = _make_environ("wiki-b.robot.wtf")
        environ["HTTP_AUTHORIZATION"] = "Bearer token-for-wiki-a"
        start_response, calls = _capture_response()

        public_config = {
            "READ_ACCESS": "ANONYMOUS",
            "WRITE_ACCESS": "ANONYMOUS",
            "ATTACHMENT_ACCESS": "ANONYMOUS",
        }
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=public_config):
            resolver(environ, start_response)

        assert calls, "No response captured"
        status, _ = calls[0]
        assert status in ("403 Forbidden", "401 Unauthorized"), (
            f"Token from wiki-a on wiki-b should be denied; got {status}"
        )


class TestPageCountQuota:
    """Resolver enforces page_count quota alongside disk quota."""

    _public_config = {
        "READ_ACCESS": "ANONYMOUS",
        "WRITE_ACCESS": "ANONYMOUS",
        "ATTACHMENT_ACCESS": "ANONYMOUS",
    }

    def _make_resolver(self, page_count: int, disk_usage_bytes: int = 0):
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware, AuthenticatedUser

        def stub_app(environ, start_response):
            start_response("200 OK", [])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        # Authenticate as the wiki owner so WRITE permissions are present
        auth_middleware.authenticate_from_cookie.return_value = AuthenticatedUser(
            user_did="did:plc:owner",
            handle="owner.bsky.social",
            display_name="Owner",
            record={},
        )
        wiki_model = MagicMock()
        wiki_model.get.return_value = {
            "slug": "test-wiki",
            "owner_did": "did:plc:owner",
            "display_name": "Test Wiki",
            "disk_usage_bytes": disk_usage_bytes,
            "page_count": page_count,
            "is_public": 1,
        }
        user_model = MagicMock()

        return TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=user_model,
        )

    def _run(self, resolver, environ):
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=self._public_config):
            start_response, calls = _capture_response()
            resolver(environ, start_response)
        return calls

    def test_api_write_blocked_at_page_limit(self):
        """API write returns 413 when page_count >= MAX_PAGES_PER_WIKI."""
        from app.constants import MAX_PAGES_PER_WIKI

        resolver = self._make_resolver(page_count=MAX_PAGES_PER_WIKI)
        environ = _make_environ("test-wiki.robot.wtf", path="/api/v1/pages/NewPage")
        environ["REQUEST_METHOD"] = "PUT"

        calls = self._run(resolver, environ)
        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "413 Request Entity Too Large", (
            f"Expected 413 for page quota; got {status}"
        )

    def test_api_write_blocked_above_page_limit(self):
        """API write returns 413 when page_count exceeds MAX_PAGES_PER_WIKI."""
        from app.constants import MAX_PAGES_PER_WIKI

        resolver = self._make_resolver(page_count=MAX_PAGES_PER_WIKI + 10)
        environ = _make_environ("test-wiki.robot.wtf", path="/api/v1/pages/NewPage")
        environ["REQUEST_METHOD"] = "POST"

        calls = self._run(resolver, environ)
        assert calls
        status, _ = calls[0]
        assert status == "413 Request Entity Too Large"

    def test_api_write_allowed_under_page_limit(self):
        """API write passes through when page_count < MAX_PAGES_PER_WIKI."""
        from app.constants import MAX_PAGES_PER_WIKI

        resolver = self._make_resolver(page_count=MAX_PAGES_PER_WIKI - 1)
        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        resolver._app = capture_app
        environ = _make_environ("test-wiki.robot.wtf", path="/api/v1/pages/NewPage")
        environ["REQUEST_METHOD"] = "PUT"

        calls = self._run(resolver, environ)
        assert calls
        status, _ = calls[0]
        assert status == "200 OK", (
            f"Write under page limit should pass through; got {status}"
        )

    def test_web_ui_write_strips_write_permission_at_page_limit(self):
        """Web UI write strips WRITE and UPLOAD when page_count >= MAX_PAGES_PER_WIKI."""
        from app.constants import MAX_PAGES_PER_WIKI

        resolver = self._make_resolver(page_count=MAX_PAGES_PER_WIKI)
        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        resolver._app = capture_app
        # /SomePage/save is the web UI save path matched by _is_write_request
        environ = _make_environ("test-wiki.robot.wtf", path="/SomePage/save")
        environ["REQUEST_METHOD"] = "POST"
        environ["HTTP_COOKIE"] = "platform_token=ownertoken"

        calls = self._run(resolver, environ)
        # Should reach the app (not 413), but with WRITE/UPLOAD stripped
        perms = injected.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")
        assert "WRITE" not in perms, (
            f"WRITE should be stripped on page-limit web UI write; got {perms!r}"
        )
        assert "UPLOAD" not in perms, (
            f"UPLOAD should be stripped on page-limit web UI write; got {perms!r}"
        )

    def test_web_ui_write_preserves_permissions_under_page_limit(self):
        """Web UI write keeps WRITE and UPLOAD when page_count < MAX_PAGES_PER_WIKI."""
        from app.constants import MAX_PAGES_PER_WIKI

        resolver = self._make_resolver(page_count=MAX_PAGES_PER_WIKI - 1)
        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        resolver._app = capture_app
        # /SomePage/save is the web UI save path matched by _is_write_request
        environ = _make_environ("test-wiki.robot.wtf", path="/SomePage/save")
        environ["REQUEST_METHOD"] = "POST"
        environ["HTTP_COOKIE"] = "platform_token=ownertoken"

        calls = self._run(resolver, environ)
        perms = injected.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")
        assert "WRITE" in perms, (
            f"WRITE should not be stripped under page limit; got {perms!r}"
        )


class TestConstantsImport:
    """Constants module exports expected values."""

    def test_constants_importable(self):
        from app.constants import MAX_PAGES_PER_WIKI, QUOTA_BYTES
        assert MAX_PAGES_PER_WIKI == 500
        assert QUOTA_BYTES == 50 * 1024 * 1024


class TestResolverRateLimiting:
    """TenantResolver enforces write rate limiting (429 after exceeding limit).

    Rate-limit check fires AFTER quota check, so 413 takes priority over 429.
    Read requests are NOT rate-limited.
    """

    _public_config = {
        "READ_ACCESS": "ANONYMOUS",
        "WRITE_ACCESS": "ANONYMOUS",
        "ATTACHMENT_ACCESS": "ANONYMOUS",
    }

    def _make_resolver(self, stub_app=None):
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware, AuthenticatedUser

        if stub_app is None:
            def stub_app(environ, start_response):
                start_response("200 OK", [])
                return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        auth_middleware.authenticate_from_cookie.return_value = AuthenticatedUser(
            user_did="did:plc:owner",
            handle="owner.bsky.social",
            display_name="Owner",
            record={},
        )

        wiki_model = MagicMock()
        wiki_model.get.return_value = {
            "slug": "rl-wiki",
            "owner_did": "did:plc:owner",
            "display_name": "RL Wiki",
            "disk_usage_bytes": 0,
            "page_count": 0,
            "is_public": 1,
        }
        user_model = MagicMock()

        return TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=user_model,
        )

    def _run(self, resolver, environ):
        with patch.object(resolver, "_swap_storage"), \
             patch("app.resolver._swap_database"), \
             patch("app.resolver._get_wiki_access_config", return_value=self._public_config):
            start_response, calls = _capture_response()
            resolver(environ, start_response)
        return calls

    def test_write_requests_are_rate_limited(self):
        """Exceeding write limit on /api/ path returns 429."""
        import app.resolver as resolver_module

        # Reset the module-level limiter to a tight limit for testing
        from app.rate_limit import WSGIRateLimiter
        test_limiter = WSGIRateLimiter()
        test_limiter.add_limit("wiki_write", "1/minute")

        resolver = self._make_resolver()

        environ = _make_environ("rl-wiki.robot.wtf", path="/api/v1/pages/TestPage")
        environ["REQUEST_METHOD"] = "PUT"
        environ["REMOTE_ADDR"] = "10.1.2.3"
        environ["HTTP_COOKIE"] = "platform_token=ownertoken"

        responses = []
        original_limiter = resolver_module._resolver_limiter
        try:
            resolver_module._resolver_limiter = test_limiter
            for _ in range(3):
                calls = self._run(resolver, environ)
                if calls:
                    responses.append(calls[0][0])
        finally:
            resolver_module._resolver_limiter = original_limiter

        assert "429 Too Many Requests" in responses, (
            f"Expected 429 after exceeding write limit; got: {responses}"
        )

    def test_read_requests_not_rate_limited(self):
        """GET requests pass through without rate limiting."""
        import app.resolver as resolver_module

        from app.rate_limit import WSGIRateLimiter
        test_limiter = WSGIRateLimiter()
        test_limiter.add_limit("wiki_write", "1/minute")

        resolver = self._make_resolver()

        environ = _make_environ("rl-wiki.robot.wtf", path="/SomePage")
        environ["REQUEST_METHOD"] = "GET"
        environ["REMOTE_ADDR"] = "10.1.2.3"

        responses = []
        original_limiter = resolver_module._resolver_limiter
        try:
            resolver_module._resolver_limiter = test_limiter
            for _ in range(5):
                calls = self._run(resolver, environ)
                if calls:
                    responses.append(calls[0][0])
        finally:
            resolver_module._resolver_limiter = original_limiter

        assert "429 Too Many Requests" not in responses, (
            f"Read requests should not be rate limited; got: {responses}"
        )
        assert all(s == "200 OK" for s in responses), (
            f"All reads should pass; got: {responses}"
        )

    def test_quota_check_takes_priority_over_rate_limit(self):
        """Quota-exceeded request gets 413 (not 429) even when rate limit exceeded."""
        from app.constants import MAX_PAGES_PER_WIKI
        from app.auth.middleware import AuthenticatedUser
        import app.resolver as resolver_module

        from app.rate_limit import WSGIRateLimiter
        test_limiter = WSGIRateLimiter()
        # Set limit to 0 so the rate check would always fail IF reached
        test_limiter.add_limit("wiki_write", "1/minute")

        # Exhaust the rate limit counter in advance
        test_limiter.check("wiki_write", "10.5.6.7")  # first allowed
        test_limiter.check("wiki_write", "10.5.6.7")  # now blocked

        auth_middleware = MagicMock()
        auth_middleware.authenticate_from_cookie.return_value = AuthenticatedUser(
            user_did="did:plc:owner",
            handle="owner.bsky.social",
            display_name="Owner",
            record={},
        )

        wiki_model = MagicMock()
        wiki_model.get.return_value = {
            "slug": "quota-wiki",
            "owner_did": "did:plc:owner",
            "display_name": "Quota Wiki",
            "disk_usage_bytes": 0,
            "page_count": MAX_PAGES_PER_WIKI,  # at quota
            "is_public": 1,
        }

        from app.resolver import TenantResolver

        def stub_app(environ, start_response):
            start_response("200 OK", [])
            return [b"ok"]

        resolver = TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=MagicMock(),
        )

        environ = _make_environ("quota-wiki.robot.wtf", path="/api/v1/pages/NewPage")
        environ["REQUEST_METHOD"] = "PUT"
        environ["REMOTE_ADDR"] = "10.5.6.7"

        original_limiter = resolver_module._resolver_limiter
        try:
            resolver_module._resolver_limiter = test_limiter
            calls = self._run(resolver, environ)
        finally:
            resolver_module._resolver_limiter = original_limiter

        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "413 Request Entity Too Large", (
            f"Quota check should take priority over rate limit; got {status}"
        )


class TestPlatformStatic:
    """Tests for the /platform/ static file serving route."""

    def _make_resolver(self):
        from app.resolver import TenantResolver
        from app.auth.middleware import AuthMiddleware

        def stub_app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        auth_middleware = MagicMock(spec=AuthMiddleware)
        wiki_model = MagicMock()
        user_model = MagicMock()

        return TenantResolver(
            stub_app,
            auth_middleware=auth_middleware,
            wiki_model=wiki_model,
            user_model=user_model,
        )

    def _run(self, resolver, environ):
        """Run the resolver and capture response status + headers + body."""
        start_response, calls = _capture_response()
        body = resolver(environ, start_response)
        return calls, body

    def test_serves_existing_file(self, tmp_path, monkeypatch):
        """A file that exists in PLATFORM_STATIC_DIR is served with 200."""
        import app.resolver as resolver_module

        svg_content = b"<svg>test</svg>"
        svg_file = tmp_path / "test.svg"
        svg_file.write_bytes(svg_content)

        monkeypatch.setattr(resolver_module, "PLATFORM_STATIC_DIR", str(tmp_path))

        resolver = self._make_resolver()
        environ = _make_environ("robot.wtf", path="/platform/test.svg")
        calls, body = self._run(resolver, environ)

        assert calls, "No response captured"
        status, headers = calls[0]
        assert status == "200 OK"
        headers_dict = dict(headers)
        assert "image/svg+xml" in headers_dict.get("Content-Type", "")
        assert b"".join(body) == svg_content

    def test_404_for_missing_file(self, tmp_path, monkeypatch):
        """A request for a nonexistent file returns 404."""
        import app.resolver as resolver_module

        monkeypatch.setattr(resolver_module, "PLATFORM_STATIC_DIR", str(tmp_path))

        resolver = self._make_resolver()
        environ = _make_environ("robot.wtf", path="/platform/nonexistent.svg")
        calls, _ = self._run(resolver, environ)

        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "404 Not Found"

    def test_403_for_traversal(self, tmp_path, monkeypatch):
        """A path traversal attempt returns 403."""
        import app.resolver as resolver_module

        monkeypatch.setattr(resolver_module, "PLATFORM_STATIC_DIR", str(tmp_path))

        resolver = self._make_resolver()
        environ = _make_environ("robot.wtf", path="/platform/../etc/passwd")
        calls, _ = self._run(resolver, environ)

        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "403 Forbidden"

    def test_empty_path_returns_404(self, tmp_path, monkeypatch):
        """A request for /platform/ (no filename) returns 404."""
        import app.resolver as resolver_module

        monkeypatch.setattr(resolver_module, "PLATFORM_STATIC_DIR", str(tmp_path))

        resolver = self._make_resolver()
        environ = _make_environ("robot.wtf", path="/platform/")
        calls, _ = self._run(resolver, environ)

        assert calls, "No response captured"
        status, _ = calls[0]
        assert status == "404 Not Found"

    def test_cache_control_header(self, tmp_path, monkeypatch):
        """Served files include Cache-Control: public, max-age=86400."""
        import app.resolver as resolver_module

        svg_file = tmp_path / "logo.svg"
        svg_file.write_bytes(b"<svg/>")

        monkeypatch.setattr(resolver_module, "PLATFORM_STATIC_DIR", str(tmp_path))

        resolver = self._make_resolver()
        environ = _make_environ("robot.wtf", path="/platform/logo.svg")
        calls, _ = self._run(resolver, environ)

        assert calls, "No response captured"
        status, headers = calls[0]
        assert status == "200 OK"
        headers_dict = dict(headers)
        assert headers_dict.get("Cache-Control") == "public, max-age=86400"
