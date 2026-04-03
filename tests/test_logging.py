"""Tests for logging behavior in silent exception handlers.

Red phase: all tests must FAIL against current code.

Changes being tested:
1. wsgi.py: basicConfig should be called so root logger has handlers
2. resolver.py _swap_database inner dispose: except Exception: pass → log DEBUG
3. atproto_identity.py resolve_did did:plc: silent return None → log WARNING
4. atproto_identity.py resolve_did did:web: silent return None → log WARNING
5. middleware.py authenticate_from_cookie cookies.load: silent return None → log DEBUG
6. atproto_identity.py resolve_handle DNS TXT: print(...) → log DEBUG
7. atproto_identity.py resolve_handle HTTP: print(...) → log WARNING
"""

from __future__ import annotations

import logging
import sys
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Change 1: wsgi.py basicConfig
# ---------------------------------------------------------------------------

class TestWsgiBasicConfig:
    """Root logger should have at least one handler after wsgi module loads."""

    def test_root_logger_has_handler_after_wsgi_import(self):
        """wsgi.basicConfig() must be called so root logger has a handler.

        FAILS until wsgi.py calls logging.basicConfig().
        """
        # Preserve and clear existing root handlers so we test a clean slate.
        original_handlers = logging.root.handlers[:]
        logging.root.handlers = []

        # Pop the cached wsgi module so the import runs fresh.
        wsgi_module = sys.modules.pop("app.wsgi", None)
        # We also need to prevent the top-level application = _build_app() call
        # from failing. Stub out every import that wsgi.py needs at module scope.
        stub_otterwiki = MagicMock()
        stub_otterwiki.server.app = MagicMock()
        fake_modules = {
            "otterwiki": stub_otterwiki,
            "otterwiki.server": stub_otterwiki.server,
        }

        try:
            with patch.dict(sys.modules, fake_modules), \
                 patch("app.auth.jwt._load_keys", return_value=(MagicMock(), MagicMock())), \
                 patch("app.db.get_connection", return_value=MagicMock()), \
                 patch("app.resolver.TenantResolver", MagicMock()), \
                 patch("app.management.routes.ManagementMiddleware", MagicMock()), \
                 patch("app.auth.middleware.AuthMiddleware", MagicMock()):
                import app.wsgi  # noqa: F401
        finally:
            # Restore module cache
            if wsgi_module is not None:
                sys.modules["app.wsgi"] = wsgi_module
            else:
                sys.modules.pop("app.wsgi", None)

        handlers_after_import = logging.root.handlers[:]

        # Restore original handlers before asserting
        logging.root.handlers = original_handlers

        assert len(handlers_after_import) > 0, (
            "Root logger has no handlers after importing wsgi — "
            "expected wsgi.py to call logging.basicConfig()"
        )


# ---------------------------------------------------------------------------
# Change 2: resolver.py _swap_database inner engine dispose
# ---------------------------------------------------------------------------

class TestSwapDatabaseDisposeLogging:
    """Inner engine dispose exception must log at DEBUG, not silently pass."""

    def test_dispose_exception_logs_debug(self, caplog):
        """When the new engine's dispose() raises, it should log at DEBUG.

        FAILS until the inner except is changed from pass to logger.debug(...).
        """
        import pytest
        from app.resolver import _swap_database

        # We need to exercise the inner except block:
        # outer try raises → cleanup runs → engines[None].dispose() raises
        bad_engine = MagicMock()
        bad_engine.dispose.side_effect = RuntimeError("dispose failed")

        mock_app = MagicMock()
        mock_app.config = {
            "SQLALCHEMY_DATABASE_URI": "sqlite:///old.db",
        }
        mock_db = MagicMock()
        mock_db.session = MagicMock()

        # Build a fake engines dict where new engine is the bad one
        # and current_engine is something different
        old_engine = MagicMock()
        engines = {None: old_engine}
        mock_db._app_engines = {mock_app: engines}

        # Mock otterwiki.server module with update_app_config raising so the
        # outer except is triggered, which causes cleanup to run dispose().
        mock_server = MagicMock()
        mock_server.app = mock_app
        mock_server.db = mock_db
        mock_server.update_app_config = MagicMock(side_effect=RuntimeError("fail"))

        # otterwiki package mock: needs .server attribute for otterwiki.server access
        mock_otterwiki = MagicMock()
        mock_otterwiki.server = mock_server

        with patch("app.resolver.WIKI_BASE", "/srv/data/wikis"), \
             patch("os.path.realpath", side_effect=lambda p: p), \
             patch("app.resolver._init_wiki_db"), \
             patch.dict(sys.modules, {
                 "otterwiki": mock_otterwiki,
                 "otterwiki.server": mock_server,
             }), \
             patch("sqlalchemy.create_engine", return_value=bad_engine), \
             caplog.at_level(logging.DEBUG, logger="app.resolver"), \
             pytest.raises(Exception):
            _swap_database(
                wiki_dir="/srv/data/wikis/test-wiki",
                display_name="Test Wiki",
                is_public=True,
            )

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and "dispose" in r.getMessage().lower()
        ]
        assert debug_msgs, (
            "Expected a DEBUG log message about engine dispose failure, "
            "but none was found — inner except still has bare pass"
        )


# ---------------------------------------------------------------------------
# Changes 3 & 4: atproto_identity.py resolve_did
# ---------------------------------------------------------------------------

class TestResolveDidLogging:
    """resolve_did() HTTP exceptions must log at WARNING before returning None."""

    def test_resolve_did_plc_exception_logs_warning(self, caplog):
        """did:plc HTTP exception must log at WARNING.

        FAILS until atproto_identity.py adds logging for the plc except block.
        """
        import requests_hardened.manager as hm

        mock_sess = MagicMock()
        mock_sess.__enter__ = MagicMock(return_value=mock_sess)
        mock_sess.__exit__ = MagicMock(return_value=False)
        mock_sess.get.side_effect = RuntimeError("connection refused")

        with patch.object(hm.Manager, "get_session", return_value=mock_sess):
            with caplog.at_level(logging.WARNING, logger="app.auth.atproto_identity"):
                from app.auth import atproto_identity
                result = atproto_identity.resolve_did("did:plc:abc123")

        assert result is None
        warning_msgs = [
            r for r in caplog.records
            if r.levelno == logging.WARNING
        ]
        assert warning_msgs, (
            "Expected a WARNING log for did:plc HTTP exception in resolve_did, "
            "but none was found — except block is still silent"
        )

    def test_resolve_did_web_exception_logs_warning(self, caplog):
        """did:web HTTP exception must log at WARNING.

        FAILS until atproto_identity.py adds logging for the did:web except block.
        """
        import requests_hardened.manager as hm

        mock_sess = MagicMock()
        mock_sess.__enter__ = MagicMock(return_value=mock_sess)
        mock_sess.__exit__ = MagicMock(return_value=False)
        mock_sess.get.side_effect = RuntimeError("connection refused")

        with patch.object(hm.Manager, "get_session", return_value=mock_sess):
            with caplog.at_level(logging.WARNING, logger="app.auth.atproto_identity"):
                from app.auth import atproto_identity
                result = atproto_identity.resolve_did("did:web:example.com")

        assert result is None
        warning_msgs = [
            r for r in caplog.records
            if r.levelno == logging.WARNING
        ]
        assert warning_msgs, (
            "Expected a WARNING log for did:web HTTP exception in resolve_did, "
            "but none was found — except block is still silent"
        )


# ---------------------------------------------------------------------------
# Change 5: middleware.py authenticate_from_cookie cookies.load
# ---------------------------------------------------------------------------

class TestAuthenticateFromCookieLogging:
    """authenticate_from_cookie cookies.load exception must log at DEBUG."""

    def _make_middleware(self):
        from app.auth.middleware import AuthMiddleware
        from app.auth.jwt import PlatformJWT

        platform_jwt = MagicMock(spec=PlatformJWT)
        user_model = MagicMock()
        return AuthMiddleware(platform_jwt=platform_jwt, user_model=user_model)

    def test_cookies_load_exception_logs_debug(self, caplog):
        """When SimpleCookie.load() raises, a DEBUG message must be emitted.

        FAILS until the except block logs before returning None.
        """
        middleware = self._make_middleware()

        with patch("http.cookies.SimpleCookie") as mock_cookie_class:
            mock_cookie = MagicMock()
            mock_cookie.load.side_effect = Exception("malformed cookie")
            mock_cookie_class.return_value = mock_cookie

            with caplog.at_level(logging.DEBUG, logger="app.auth.middleware"):
                result = middleware.authenticate_from_cookie("bad-cookie-value")

        assert result is None
        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG
        ]
        assert debug_msgs, (
            "Expected a DEBUG log for cookies.load() exception in "
            "authenticate_from_cookie, but none was found — except block is still silent"
        )


# ---------------------------------------------------------------------------
# Changes 6 & 7: atproto_identity.py resolve_handle
# ---------------------------------------------------------------------------

class TestResolveHandleLogging:
    """resolve_handle() must use logger instead of print statements."""

    def test_dns_txt_exception_logs_debug_not_print(self, caplog):
        """DNS TXT resolution exception must log at DEBUG, not print.

        FAILS until the print() in the DNS except block is replaced with
        logger.debug().
        """
        import requests_hardened.manager as hm
        from app.auth import atproto_identity

        mock_sess = MagicMock()
        mock_sess.__enter__ = MagicMock(return_value=mock_sess)
        mock_sess.__exit__ = MagicMock(return_value=False)
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_sess.get.return_value = mock_resp

        with patch("app.auth.atproto_identity.dns.resolver.resolve") as mock_resolve, \
             patch.object(hm.Manager, "get_session", return_value=mock_sess):
            mock_resolve.side_effect = Exception("DNS error")

            with caplog.at_level(logging.DEBUG, logger="app.auth.atproto_identity"):
                atproto_identity.resolve_handle("alice.bsky.social")

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG
        ]
        assert debug_msgs, (
            "Expected a DEBUG log for DNS TXT exception in resolve_handle, "
            "but none was found — still using print() or no logging at all"
        )

    def test_http_exception_logs_warning_not_print(self, caplog):
        """HTTP well-known resolution exception must log at WARNING, not print.

        FAILS until the print() in the HTTP except block is replaced with
        logger.warning().
        """
        import requests_hardened.manager as hm
        from app.auth import atproto_identity

        mock_sess = MagicMock()
        mock_sess.__enter__ = MagicMock(return_value=mock_sess)
        mock_sess.__exit__ = MagicMock(return_value=False)
        mock_sess.get.side_effect = RuntimeError("HTTP error")

        with patch("app.auth.atproto_identity.dns.resolver.resolve") as mock_dns, \
             patch.object(hm.Manager, "get_session", return_value=mock_sess):
            mock_dns.side_effect = Exception("DNS not found")

            with caplog.at_level(logging.WARNING, logger="app.auth.atproto_identity"):
                result = atproto_identity.resolve_handle("alice.bsky.social")

        assert result is None
        warning_msgs = [
            r for r in caplog.records
            if r.levelno == logging.WARNING
        ]
        assert warning_msgs, (
            "Expected a WARNING log for HTTP exception in resolve_handle, "
            "but none was found — still using print() or no logging at all"
        )


# ---------------------------------------------------------------------------
# Handler A & B: atproto_oauth.py is_use_dpop_nonce_error_response
# ---------------------------------------------------------------------------

class TestDpopNonceLogging:
    """Silent except blocks in is_use_dpop_nonce_error_response must log DEBUG."""

    def test_www_authenticate_parse_exception_logs_debug(self, caplog):
        """WWW-Authenticate parse failure must log at DEBUG.

        FAILS until atproto_oauth.py adds logger.debug() in the first except block.
        """
        from app.auth.atproto_oauth import is_use_dpop_nonce_error_response

        mock_resp = MagicMock(spec=["status_code", "headers", "json"])
        mock_resp.status_code = 401
        mock_resp.headers = {"WWW-Authenticate": "DPoP realm=\"example\""}
        mock_resp.json.return_value = {}

        with patch(
            "app.auth.atproto_oauth.parse_www_authenticate",
            side_effect=ValueError("bad header"),
        ), caplog.at_level(logging.DEBUG, logger="app.auth.atproto_oauth"):
            result = is_use_dpop_nonce_error_response(mock_resp)

        assert result is False
        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and "dpop nonce" in r.getMessage().lower()
        ]
        assert debug_msgs, (
            "Expected a DEBUG log for WWW-Authenticate parse failure in "
            "is_use_dpop_nonce_error_response, but none found — first except block "
            "is still bare pass"
        )

    def test_json_body_parse_exception_logs_debug(self, caplog):
        """JSON body parse failure must log at DEBUG.

        FAILS until atproto_oauth.py adds logger.debug() in the second except block.
        """
        from app.auth.atproto_oauth import is_use_dpop_nonce_error_response

        mock_resp = MagicMock(spec=["status_code", "headers", "json"])
        mock_resp.status_code = 401
        # No WWW-Authenticate header so first branch is skipped
        mock_resp.headers = {}
        mock_resp.json.side_effect = ValueError("not json")

        with caplog.at_level(logging.DEBUG, logger="app.auth.atproto_oauth"):
            result = is_use_dpop_nonce_error_response(mock_resp)

        assert result is False
        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and "json" in r.getMessage().lower()
        ]
        assert debug_msgs, (
            "Expected a DEBUG log for JSON body parse failure in "
            "is_use_dpop_nonce_error_response, but none found — second except block "
            "is still bare pass"
        )


# ---------------------------------------------------------------------------
# Handler C: management/routes.py _create_wiki cleanup path
# ---------------------------------------------------------------------------

class TestCreateWikiCleanupLogging:
    """Cleanup delete failure during _create_wiki rollback must log DEBUG."""

    def test_cleanup_delete_exception_logs_debug(self, caplog):
        """When self._wikis.delete() raises during rollback, must log at DEBUG.

        FAILS until management/routes.py adds logger.debug() in the cleanup
        except block inside _create_wiki.
        """
        import io
        import json as _json
        from app.management.routes import ManagementMiddleware

        middleware = MagicMock(spec=ManagementMiddleware)
        middleware._wikis = MagicMock()
        middleware._wikis.create.return_value = MagicMock()
        middleware._wikis.delete.side_effect = RuntimeError("delete failed")
        middleware._wiki_base = "/srv/wikis"
        middleware._admin_dids = set()

        # Build a minimal user mock
        user = MagicMock()
        user.handle = "alice.bsky.social"
        user.user_did = "did:plc:abc123"
        user.record = {"wiki_count": 0}

        body_bytes = _json.dumps({
            "slug": "test-wiki",
            "display_name": "Test Wiki",
        }).encode()
        environ = {
            "wsgi.input": io.BytesIO(body_bytes),
            "CONTENT_LENGTH": str(len(body_bytes)),
        }

        with patch(
            "app.management.routes._init_wiki_repo",
            side_effect=RuntimeError("repo init failed"),
        ), patch(
            "app.management.routes.validate_slug",
            return_value=(True, None),
        ), patch(
            "app.management.routes.generate_mcp_token",
            return_value=("token", "hash"),
        ), patch(
            "app.management.routes.os.path.join",
            return_value="/srv/wikis/test-wiki/repo",
        ), caplog.at_level(logging.DEBUG, logger="app.management.routes"):
            status, resp_body = ManagementMiddleware._create_wiki(
                middleware,
                user=user,
                environ=environ,
            )

        assert status == 500
        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and "cleanup" in r.getMessage().lower()
        ]
        assert debug_msgs, (
            "Expected a DEBUG log for cleanup delete failure in _create_wiki, "
            "but none found — except block is still bare pass"
        )


# ===========================================================================
# platform_server.py handlers (15 silent handlers, all expected → DEBUG)
# ===========================================================================
#
# Shared fixtures for these tests live below; all tests use
# caplog.at_level(logging.DEBUG, logger="app.platform_server").
#
# Test classes:
#   TestPlatformLoginJwtHandlers    — handlers 1 & 2  (lines 321, 323)
#   TestPlatformLoginPdsHandlers    — handler  3       (line  357)
#   TestPlatformDashboardJwt        — handler  4       (line  573)
#   TestPlatformConsentPostJwt      — handler  5       (line  628)
#   TestPlatformLogoutSession       — handler  6       (line  695)
#   TestPlatformWikiCreateSlug      — handler  7       (line  821)
#   TestPlatformWikiCreateRollback  — handler  8       (line  835)
#   TestPlatformAdminStats          — handlers 9-14   (lines 1057-1099)
#   TestPlatformStartupKeyLoading   — handler  15      (line 1256)
# ===========================================================================

import json as _json
import os as _os
import sqlite3 as _sqlite3

import pytest as _pytest
from authlib.jose import JsonWebKey as _JsonWebKey
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding as _Encoding,
    NoEncryption as _NoEncryption,
    PrivateFormat as _PrivateFormat,
    PublicFormat as _PublicFormat,
)

from app.db import init_schema as _init_schema


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _make_rsa_keys():
    priv = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        _Encoding.PEM, _PrivateFormat.PKCS8, _NoEncryption()
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        _Encoding.PEM, _PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv_pem, pub_pem


@_pytest.fixture(scope="module")
def _platform_rsa_keys():
    return _make_rsa_keys()


@_pytest.fixture
def _platform_db(tmp_path):
    path = str(tmp_path / "platform_test.db")
    conn = _sqlite3.connect(path)
    conn.row_factory = _sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    _init_schema(conn)
    conn.close()
    return path


@_pytest.fixture
def _client_jwk_path(tmp_path):
    jwk = _JsonWebKey.generate_key("EC", "P-256", is_private=True)
    data = _json.loads(jwk.as_json(is_private=True))
    path = str(tmp_path / "client_jwk.json")
    with open(path, "w") as fh:
        _json.dump(data, fh)
    return path


@_pytest.fixture
def _signing_key_path(tmp_path, _platform_rsa_keys):
    priv_pem, _ = _platform_rsa_keys
    path = str(tmp_path / "signing_key.pem")
    with open(path, "w") as fh:
        fh.write(priv_pem)
    return path


@_pytest.fixture
def _flask_app(_platform_db, _client_jwk_path, _signing_key_path):
    """Full platform Flask app wired with test keys and in-memory DB.

    Sets env vars before importing app.platform_server so the module-level
    create_app() call (line 1353) does not raise RuntimeError about the
    missing FLASK_SECRET_KEY.  Inlines the platform_globals_patch logic so
    we do not depend on that fixture (which imports the module before we
    have set the vars).
    """
    # Set env vars FIRST — platform_server.py runs create_app() at import time.
    _os.environ["FLASK_SECRET_KEY"] = "test-secret-platform-logging"
    _os.environ["FLASK_ENV"] = "testing"
    _os.environ["ROBOT_DB_PATH"] = _platform_db
    _os.environ["CLIENT_JWK_PATH"] = _client_jwk_path
    _os.environ["SIGNING_KEY_PATH"] = _signing_key_path

    import app.platform_server as _ps
    import app.auth.atproto_security as _ats

    # Inline platform_globals_patch: override module-level globals to
    # production-like values so route assertions are deterministic.
    _saved = {
        "PLATFORM_DOMAIN": _ps.PLATFORM_DOMAIN,
        "_SCHEME": _ps._SCHEME,
        "CLIENT_ID": _ps.CLIENT_ID,
        "REDIRECT_URI": _ps.REDIRECT_URI,
        "COOKIE_DOMAIN": _ps.COOKIE_DOMAIN,
        "_ALLOW_HTTP_PDS": _ats._ALLOW_HTTP_PDS,
    }
    _ps.PLATFORM_DOMAIN = "robot.wtf"
    _ps._SCHEME = "https"
    _ps.CLIENT_ID = "https://robot.wtf/auth/client-metadata.json"
    _ps.REDIRECT_URI = "https://robot.wtf/auth/callback"
    _ps.COOKIE_DOMAIN = ".robot.wtf"
    _ats._ALLOW_HTTP_PDS = False

    from app.platform_server import create_app
    app = create_app(
        db_path=_platform_db,
        client_jwk_path=_client_jwk_path,
        signing_key_path=_signing_key_path,
    )
    app.config["TESTING"] = True
    yield app

    # Restore globals
    _ps.PLATFORM_DOMAIN = _saved["PLATFORM_DOMAIN"]
    _ps._SCHEME = _saved["_SCHEME"]
    _ps.CLIENT_ID = _saved["CLIENT_ID"]
    _ps.REDIRECT_URI = _saved["REDIRECT_URI"]
    _ps.COOKIE_DOMAIN = _saved["COOKIE_DOMAIN"]
    _ats._ALLOW_HTTP_PDS = _saved["_ALLOW_HTTP_PDS"]

    for key in ["FLASK_SECRET_KEY", "FLASK_ENV", "ROBOT_DB_PATH",
                "CLIENT_JWK_PATH", "SIGNING_KEY_PATH"]:
        _os.environ.pop(key, None)


@_pytest.fixture
def _tc(_flask_app):
    return _flask_app.test_client()


def _make_platform_token(app, priv_pem, pub_pem,
                         user_did="did:plc:test123",
                         handle="alice.bsky.social",
                         display_name="Alice"):
    from app.auth.jwt import PlatformJWT
    svc = PlatformJWT(priv_pem, pub_pem)
    return svc.create_token(user_did=user_did, handle=handle, display_name=display_name)


# ---------------------------------------------------------------------------
# Handlers 1 & 2 — Login GET: inner JWT decode (line 321) and outer (line 323)
# ---------------------------------------------------------------------------

class TestPlatformLoginJwtHandlers:
    """Handlers 1 & 2: silent except blocks in the GET /auth/login cookie check.

    Line 321: inner except when decoding an expired token to extract the handle.
    Line 323: outer except for non-expiry JWT errors.

    Both should log DEBUG. Currently they are bare pass.
    """

    def test_inner_jwt_decode_exception_logs_debug(self, _tc, _flask_app, _platform_rsa_keys, caplog):
        """Handler 1 (line 321): inner JWT decode error must log DEBUG.

        FAILS until platform_server.py line 321 except block adds logger.debug().
        """
        import jwt as pyjwt
        priv_pem, pub_pem = _platform_rsa_keys

        # Create a token that looks expired so ExpiredSignatureError fires,
        # then cause the inner decode to raise by patching pyjwt.decode to raise
        # on the second call (the options={"verify_exp": False} path).
        call_count = {"n": 0}
        real_decode = pyjwt.decode

        def _patched_decode(token, *args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise pyjwt.ExpiredSignatureError("expired")
            raise RuntimeError("inner decode exploded")

        _tc.set_cookie("platform_token", "some.fake.token")
        with patch("app.platform_server.pyjwt.decode", side_effect=_patched_decode), \
             caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.get("/auth/login")

        # The route should still render (200 or redirect) — we only care about the log.
        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 1 (line 321): expected DEBUG log when inner JWT decode "
            "raises during expired-token handle extraction, but none found — "
            "except block is still bare pass"
        )

    def test_outer_jwt_exception_logs_debug(self, _tc, _flask_app, _platform_rsa_keys, caplog):
        """Handler 2 (line 323): outer JWT validation error must log DEBUG.

        FAILS until platform_server.py line 323 except block adds logger.debug().
        """
        import jwt as pyjwt

        def _patched_decode(token, *args, **kwargs):
            raise pyjwt.InvalidTokenError("totally invalid")

        # platform_jwt.validate_token ultimately calls pyjwt.decode;
        # patch it at the platform_server import so the outer except fires.
        _tc.set_cookie("platform_token", "some.fake.token")
        with patch("app.platform_server.pyjwt.decode", side_effect=_patched_decode), \
             caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.get("/auth/login")

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 2 (line 323): expected DEBUG log when outer JWT validation "
            "raises a non-expiry exception in GET /auth/login, but none found — "
            "except block is still bare pass"
        )


# ---------------------------------------------------------------------------
# Handler 3 — Login POST: PDS authserver resolution fallback (line 357)
# ---------------------------------------------------------------------------

class TestPlatformLoginPdsHandlers:
    """Handler 3 (line 357): silent fallback when resolve_pds_authserver raises.

    Should log DEBUG. Currently bare pass.
    """

    def test_pds_authserver_resolution_fallback_logs_debug(self, _tc, caplog):
        """Handler 3 (line 357): resolve_pds_authserver exception must log DEBUG.

        FAILS until platform_server.py line 357 except block adds logger.debug().
        """
        with patch("app.platform_server.resolve_pds_authserver",
                   side_effect=RuntimeError("connection refused")), \
             patch("app.platform_server.is_safe_url", return_value=True), \
             caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.post(
                "/auth/login",
                data={"username": "https://pds.example.com"},
                follow_redirects=False,
            )

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 3 (line 357): expected DEBUG log when resolve_pds_authserver "
            "raises and the fallback fires, but none found — except block is still "
            "bare pass"
        )


# ---------------------------------------------------------------------------
# Handler 4 — Dashboard: JWT validation → redirect (line 573)
# ---------------------------------------------------------------------------

class TestPlatformDashboardJwt:
    """Handler 4 (line 573): silent JWT exception in GET /auth/oauth/consent.

    The consent GET handler silently redirects to login when JWT validation
    raises. Should log DEBUG.
    """

    def test_consent_get_jwt_exception_logs_debug(self, _tc, caplog):
        """Handler 4 (line 573): JWT exception in consent GET must log DEBUG.

        FAILS until platform_server.py line 573 except block adds logger.debug().
        """
        # platform_jwt is a closure variable inside _register_auth_routes, not a
        # module-level attribute. Send an invalid cookie so validate_token raises,
        # which triggers the logger.debug at line 577.
        _tc.set_cookie("platform_token", "invalid.jwt.token")
        with caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.get(
                "/auth/oauth/consent",
                query_string={
                    "client_id": "https://example.com/client",
                    "redirect_uri": "https://example.com/cb",
                    "wiki_slug": "test-wiki",
                },
            )

        # Should redirect to login (302) rather than 500.
        assert resp.status_code in (302, 400, 401), (
            f"Unexpected status {resp.status_code} — route did not handle the bad JWT"
        )
        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 4 (line 573): expected DEBUG log when platform JWT validation "
            "raises in GET /auth/oauth/consent, but none found — except is bare pass"
        )


# ---------------------------------------------------------------------------
# Handler 5 — Consent POST: JWT validation → abort(401) (line 628)
# ---------------------------------------------------------------------------

class TestPlatformConsentPostJwt:
    """Handler 5 (line 628): silent JWT exception in POST /auth/oauth/consent.

    Should log DEBUG before abort(401).
    """

    def test_consent_post_jwt_exception_logs_debug(self, _tc, _flask_app, _platform_rsa_keys, caplog):
        """Handler 5 (line 628): JWT exception in consent POST must log DEBUG.

        FAILS until platform_server.py line 628 except block adds logger.debug().
        """
        from app.auth.consent import derive_signing_key, sign_token
        import time

        priv_pem, pub_pem = _platform_rsa_keys
        consent_key = derive_signing_key(priv_pem)

        # Build a valid consent token so the route gets past payload validation.
        consent_payload = {
            "client_id": "https://example.com/client",
            "redirect_uri": "https://example.com/cb",
            "wiki_slug": "test-wiki",
            "user_did": "did:plc:test123",
            "csrf_nonce": "test-nonce-123",
            "exp": time.time() + 300,
        }
        consent_token = sign_token(consent_payload, consent_key)

        with _tc.session_transaction() as sess:
            sess["csrf_nonces"] = ["test-nonce-123"]

        _tc.set_cookie("platform_token", "invalid.jwt.token")
        with caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.post(
                "/auth/oauth/consent",
                data={
                    "consent_token": consent_token,
                    "action": "approve",
                },
            )

        assert resp.status_code == 401, (
            f"Expected 401 from invalid JWT, got {resp.status_code}"
        )
        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 5 (line 628): expected DEBUG log when platform JWT validation "
            "raises in POST /auth/oauth/consent, but none found — except is bare pass"
        )


# ---------------------------------------------------------------------------
# Handler 6 — Logout: session cleanup (line 695)
# ---------------------------------------------------------------------------

class TestPlatformLogoutSession:
    """Handler 6 (line 695): silent except when JWT validation raises during logout.

    The outer try in oauth_logout() swallows any exception from validate_token.
    Should log DEBUG.
    """

    def test_logout_jwt_exception_logs_debug(self, _tc, caplog):
        """Handler 6 (line 695): JWT exception during logout must log DEBUG.

        FAILS until platform_server.py line 695 except block adds logger.debug().
        """
        _tc.set_cookie("platform_token", "invalid.jwt.token")
        with caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.get("/auth/logout")

        # Logout always redirects regardless.
        assert resp.status_code in (302, 200), (
            f"Unexpected status {resp.status_code} from /auth/logout"
        )
        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 6 (line 695): expected DEBUG log when JWT validation raises "
            "in oauth_logout, but none found — except block is still bare pass"
        )


# ---------------------------------------------------------------------------
# Handlers 7 & 8 — Wiki create: slug collision (821) and rollback (835)
# ---------------------------------------------------------------------------

class TestPlatformWikiCreateSlug:
    """Handler 7 (line 821): silent except when wiki_model.create() raises (slug exists).

    Should log DEBUG before flashing and redirecting.
    """

    def test_wiki_create_slug_collision_logs_debug(self, _tc, _flask_app, _platform_rsa_keys, caplog):
        """Handler 7 (line 821): wiki_model.create() exception must log DEBUG.

        FAILS until platform_server.py line 821 except block adds logger.debug().
        """
        from app.models.user import UserModel
        from app.models.wiki import WikiModel
        from app.auth.middleware import AuthMiddleware
        from app.auth.jwt import PlatformJWT

        priv_pem, pub_pem = _platform_rsa_keys
        jwt_svc = PlatformJWT(priv_pem, pub_pem)
        token = jwt_svc.create_token(
            user_did="did:plc:test123",
            handle="alice.bsky.social",
            display_name="Alice",
        )

        mock_user = MagicMock()
        mock_user.user_did = "did:plc:test123"
        mock_user.handle = "alice.bsky.social"
        mock_user.record = {"wiki_count": 0}

        mock_wiki_model = MagicMock(spec=WikiModel)
        mock_wiki_model.get.return_value = None  # slug not taken via get()
        mock_wiki_model.create.side_effect = Exception("UNIQUE constraint failed")
        mock_wiki_model.list_by_owner.return_value = []

        mock_auth = MagicMock(spec=AuthMiddleware)
        mock_auth.authenticate_from_cookie.return_value = mock_user

        _flask_app.config["AUTH_MIDDLEWARE"] = mock_auth
        _flask_app.config["WIKI_MODEL"] = mock_wiki_model
        _flask_app.config["USER_MODEL"] = MagicMock(spec=UserModel)

        with caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.post(
                "/app/create",
                data={
                    "slug": "new-wiki",
                    "display_name": "New Wiki",
                },
                headers={"Cookie": f"platform_token={token}"},
                follow_redirects=False,
            )

        assert resp.status_code in (302, 200), (
            f"Unexpected status {resp.status_code} from wiki create"
        )
        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 7 (line 821): expected DEBUG log when wiki_model.create() "
            "raises (slug collision) in wiki_create POST, but none found — "
            "except block is still bare pass"
        )


class TestPlatformWikiCreateRollback:
    """Handler 8 (line 835): silent except when wiki_model.delete() raises during rollback.

    Should log DEBUG.
    """

    def test_wiki_create_rollback_delete_logs_debug(self, _tc, _flask_app, _platform_rsa_keys, caplog):
        """Handler 8 (line 835): wiki_model.delete() exception during rollback must log DEBUG.

        FAILS until platform_server.py line 835 except block adds logger.debug().
        """
        from app.models.user import UserModel
        from app.models.wiki import WikiModel
        from app.auth.middleware import AuthMiddleware
        from app.auth.jwt import PlatformJWT

        priv_pem, pub_pem = _platform_rsa_keys
        jwt_svc = PlatformJWT(priv_pem, pub_pem)
        token = jwt_svc.create_token(
            user_did="did:plc:test123",
            handle="alice.bsky.social",
            display_name="Alice",
        )

        mock_user = MagicMock()
        mock_user.user_did = "did:plc:test123"
        mock_user.handle = "alice.bsky.social"
        mock_user.record = {"wiki_count": 0}

        mock_wiki_model = MagicMock(spec=WikiModel)
        mock_wiki_model.get.return_value = None
        mock_wiki_model.create.return_value = MagicMock()
        mock_wiki_model.delete.side_effect = RuntimeError("delete failed during rollback")
        mock_wiki_model.list_by_owner.return_value = []

        mock_auth = MagicMock(spec=AuthMiddleware)
        mock_auth.authenticate_from_cookie.return_value = mock_user

        _flask_app.config["AUTH_MIDDLEWARE"] = mock_auth
        _flask_app.config["WIKI_MODEL"] = mock_wiki_model
        _flask_app.config["USER_MODEL"] = MagicMock(spec=UserModel)

        with patch("app.platform_server._init_wiki_repo",
                   side_effect=RuntimeError("repo init failed")), \
             caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.post(
                "/app/create",
                data={
                    "slug": "new-wiki",
                    "display_name": "New Wiki",
                },
                headers={"Cookie": f"platform_token={token}"},
                follow_redirects=False,
            )

        assert resp.status_code in (302, 200), (
            f"Unexpected status {resp.status_code} from wiki create rollback"
        )
        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 8 (line 835): expected DEBUG log when wiki_model.delete() "
            "raises during rollback in wiki_create POST, but none found — "
            "except block is still bare pass"
        )


# ---------------------------------------------------------------------------
# Handlers 9-14 — Admin stats: 6 silent handlers (lines 1057-1099)
# ---------------------------------------------------------------------------

class TestPlatformAdminStats:
    """Handlers 9-14: six silent except blocks in the /app/admin/stats route.

    Line 1057: subprocess.run for systemctl
    Line 1066: shutil.disk_usage
    Line 1074: wiki_model.count()
    Line 1078: user_model.count()
    Line 1083: wiki_model.list_all()
    Line 1099: subprocess.run for journalctl

    All should log DEBUG. Currently all are bare pass/fallback with no logging.
    """

    def _make_admin_app_and_token(self, flask_app, rsa_keys):
        from app.models.user import UserModel
        from app.models.wiki import WikiModel
        from app.auth.middleware import AuthMiddleware
        from app.auth.jwt import PlatformJWT

        priv_pem, pub_pem = rsa_keys
        jwt_svc = PlatformJWT(priv_pem, pub_pem)
        admin_did = "did:plc:admin123"
        token = jwt_svc.create_token(
            user_did=admin_did,
            handle="admin.bsky.social",
            display_name="Admin",
        )

        mock_user = MagicMock()
        mock_user.user_did = admin_did
        mock_user.handle = "admin.bsky.social"
        mock_user.record = {}

        mock_auth = MagicMock(spec=AuthMiddleware)
        mock_auth.authenticate_from_cookie.return_value = mock_user

        mock_wiki_model = MagicMock(spec=WikiModel)
        mock_user_model = MagicMock(spec=UserModel)
        mock_wiki_model.list_by_owner.return_value = []

        flask_app.config["AUTH_MIDDLEWARE"] = mock_auth
        flask_app.config["WIKI_MODEL"] = mock_wiki_model
        flask_app.config["USER_MODEL"] = mock_user_model
        flask_app.config["PLATFORM_ADMIN_DIDS"] = {admin_did}

        return token, mock_wiki_model, mock_user_model

    def test_systemctl_exception_logs_debug(self, _tc, _flask_app, _platform_rsa_keys, caplog):
        """Handler 9 (line 1057): subprocess.run for systemctl must log DEBUG on failure.

        FAILS until platform_server.py line 1057 except block adds logger.debug().
        """
        token, mock_wm, mock_um = self._make_admin_app_and_token(
            _flask_app, _platform_rsa_keys
        )
        mock_wm.count.return_value = 0
        mock_um.count.return_value = 0
        mock_wm.list_all.return_value = []

        with patch("app.platform_server.subprocess.run",
                   side_effect=OSError("systemctl not found")), \
             patch("app.platform_server.shutil.disk_usage",
                   return_value=MagicMock(total=1, used=0, free=1)), \
             caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.get(
                "/app/admin/stats",
                headers={"Cookie": f"platform_token={token}"},
            )

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 9 (line 1057): expected DEBUG log when systemctl subprocess "
            "raises in admin_stats, but none found — except block is still bare pass"
        )

    def test_disk_usage_exception_logs_debug(self, _tc, _flask_app, _platform_rsa_keys, caplog):
        """Handler 10 (line 1066): shutil.disk_usage must log DEBUG on failure.

        FAILS until platform_server.py line 1066 except block adds logger.debug().
        """
        import subprocess

        token, mock_wm, mock_um = self._make_admin_app_and_token(
            _flask_app, _platform_rsa_keys
        )
        mock_wm.count.return_value = 0
        mock_um.count.return_value = 0
        mock_wm.list_all.return_value = []

        mock_proc = MagicMock()
        mock_proc.stdout = "active\nactive\nactive\n"

        with patch("app.platform_server.subprocess.run", return_value=mock_proc), \
             patch("app.platform_server.shutil.disk_usage",
                   side_effect=OSError("no such path /srv")), \
             caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.get(
                "/app/admin/stats",
                headers={"Cookie": f"platform_token={token}"},
            )

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 10 (line 1066): expected DEBUG log when shutil.disk_usage "
            "raises in admin_stats, but none found — except block is still bare pass"
        )

    def test_wiki_count_exception_logs_debug(self, _tc, _flask_app, _platform_rsa_keys, caplog):
        """Handler 11 (line 1074): wiki_model.count() must log DEBUG on failure.

        FAILS until platform_server.py line 1074 except block adds logger.debug().
        """
        token, mock_wm, mock_um = self._make_admin_app_and_token(
            _flask_app, _platform_rsa_keys
        )
        mock_wm.count.side_effect = RuntimeError("DB error")
        mock_um.count.return_value = 0
        mock_wm.list_all.return_value = []

        mock_proc = MagicMock()
        mock_proc.stdout = "active\nactive\nactive\n"

        with patch("app.platform_server.subprocess.run", return_value=mock_proc), \
             patch("app.platform_server.shutil.disk_usage",
                   return_value=MagicMock(total=1, used=0, free=1)), \
             caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.get(
                "/app/admin/stats",
                headers={"Cookie": f"platform_token={token}"},
            )

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 11 (line 1074): expected DEBUG log when wiki_model.count() "
            "raises in admin_stats, but none found — except block is still bare pass"
        )

    def test_user_count_exception_logs_debug(self, _tc, _flask_app, _platform_rsa_keys, caplog):
        """Handler 12 (line 1078): user_model.count() must log DEBUG on failure.

        FAILS until platform_server.py line 1078 except block adds logger.debug().
        """
        token, mock_wm, mock_um = self._make_admin_app_and_token(
            _flask_app, _platform_rsa_keys
        )
        mock_wm.count.return_value = 5
        mock_um.count.side_effect = RuntimeError("DB error")
        mock_wm.list_all.return_value = []

        mock_proc = MagicMock()
        mock_proc.stdout = "active\nactive\nactive\n"

        with patch("app.platform_server.subprocess.run", return_value=mock_proc), \
             patch("app.platform_server.shutil.disk_usage",
                   return_value=MagicMock(total=1, used=0, free=1)), \
             caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.get(
                "/app/admin/stats",
                headers={"Cookie": f"platform_token={token}"},
            )

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 12 (line 1078): expected DEBUG log when user_model.count() "
            "raises in admin_stats, but none found — except block is still bare pass"
        )

    def test_list_all_wikis_exception_logs_debug(self, _tc, _flask_app, _platform_rsa_keys, caplog):
        """Handler 13 (line 1083): wiki_model.list_all() must log DEBUG on failure.

        FAILS until platform_server.py line 1083 except block adds logger.debug().
        """
        token, mock_wm, mock_um = self._make_admin_app_and_token(
            _flask_app, _platform_rsa_keys
        )
        mock_wm.count.return_value = 5
        mock_um.count.return_value = 3
        mock_wm.list_all.side_effect = RuntimeError("DB error")

        mock_proc = MagicMock()
        mock_proc.stdout = "active\nactive\nactive\n"

        with patch("app.platform_server.subprocess.run", return_value=mock_proc), \
             patch("app.platform_server.shutil.disk_usage",
                   return_value=MagicMock(total=1, used=0, free=1)), \
             caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.get(
                "/app/admin/stats",
                headers={"Cookie": f"platform_token={token}"},
            )

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 13 (line 1083): expected DEBUG log when wiki_model.list_all() "
            "raises in admin_stats, but none found — except block is still bare pass"
        )

    def test_journal_exception_logs_debug(self, _tc, _flask_app, _platform_rsa_keys, caplog):
        """Handler 14 (line 1099): journalctl subprocess must log DEBUG on failure.

        FAILS until platform_server.py line 1099 except block adds logger.debug().
        """
        token, mock_wm, mock_um = self._make_admin_app_and_token(
            _flask_app, _platform_rsa_keys
        )
        mock_wm.count.return_value = 5
        mock_um.count.return_value = 3
        mock_wm.list_all.return_value = []

        mock_proc = MagicMock()
        mock_proc.stdout = "active\nactive\nactive\n"

        call_count = {"n": 0}

        def _subprocess_side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return mock_proc  # first call: systemctl succeeds
            raise OSError("journalctl not available")  # second call: journal fails

        with patch("app.platform_server.subprocess.run",
                   side_effect=_subprocess_side_effect), \
             patch("app.platform_server.shutil.disk_usage",
                   return_value=MagicMock(total=1, used=0, free=1)), \
             caplog.at_level(logging.DEBUG, logger="app.platform_server"):
            resp = _tc.get(
                "/app/admin/stats",
                headers={"Cookie": f"platform_token={token}"},
            )

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 14 (line 1099): expected DEBUG log when journalctl subprocess "
            "raises in admin_stats, but none found — except block is still bare pass"
        )


# ---------------------------------------------------------------------------
# Handler 15 — App startup: key loading (line 1256)
# ---------------------------------------------------------------------------

class TestPlatformStartupKeyLoading:
    """Handler 15 (line 1256): silent except when key loading fails at app startup.

    create_app() silently continues (without auth routes) when _load_keys() or
    _load_client_jwk() raises. Should log DEBUG.

    IMPORTANT: This handler is in create_app() itself, not a route. We test by
    calling create_app() with missing key files and checking for a DEBUG log.
    """

    def test_key_loading_failure_logs_debug(self, tmp_path, caplog):
        """Handler 15 (line 1256): key-loading exception must log DEBUG.

        FAILS until platform_server.py line 1256 except block adds logger.debug().
        """
        import os

        # Set up a valid DB and Flask secret so create_app() can proceed,
        # but deliberately omit the key files so _load_keys() raises.
        db_path = str(tmp_path / "startup_test.db")
        conn = _sqlite3.connect(db_path)
        conn.row_factory = _sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        _init_schema(conn)
        conn.close()

        os.environ["FLASK_SECRET_KEY"] = "test-secret-startup"
        os.environ["FLASK_ENV"] = "testing"
        os.environ["ROBOT_DB_PATH"] = db_path
        # Deliberately point CLIENT_JWK_PATH and SIGNING_KEY_PATH at nonexistent files.
        os.environ["CLIENT_JWK_PATH"] = str(tmp_path / "nonexistent_client.json")
        os.environ["SIGNING_KEY_PATH"] = str(tmp_path / "nonexistent_key.pem")

        try:
            from app.platform_server import create_app
            with caplog.at_level(logging.DEBUG, logger="app.platform_server"):
                app = create_app(
                    db_path=db_path,
                    client_jwk_path=str(tmp_path / "nonexistent_client.json"),
                    signing_key_path=str(tmp_path / "nonexistent_key.pem"),
                )
        finally:
            for key in ["FLASK_SECRET_KEY", "FLASK_ENV", "ROBOT_DB_PATH",
                        "CLIENT_JWK_PATH", "SIGNING_KEY_PATH"]:
                os.environ.pop(key, None)

        debug_msgs = [
            r for r in caplog.records
            if r.levelno == logging.DEBUG and r.name == "app.platform_server"
        ]
        assert debug_msgs, (
            "Handler 15 (line 1256): expected DEBUG log when key loading fails "
            "at create_app() startup, but none found — except block is still bare pass"
        )
