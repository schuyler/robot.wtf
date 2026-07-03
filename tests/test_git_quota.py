"""Tests for disk-quota and rate-limit enforcement on git-receive-pack.

Feature: git push (receive-pack) is treated as a write request so that:
- _is_write_request returns True for POST /.git/git-receive-pack
- Over-quota wikis have WRITE/UPLOAD stripped before the request reaches the git backend
- The rate limiter (5/minute per IP) fires on receive-pack POSTs
- After a successful push, WikiModel.update is called to refresh quota state

Non-changes verified (regression guards that should pass now and after):
- git-upload-pack (clone/fetch) is NOT a write request
- info/refs GET is NOT a write request
"""

from __future__ import annotations

import contextlib
import sys
import types
from unittest.mock import MagicMock, patch

from app.auth.middleware import AuthMiddleware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_environ(host, path="/", method="GET", authorization=None,
                  remote_addr=None):
    env = {
        "HTTP_HOST": host,
        "PATH_INFO": path,
        "REQUEST_METHOD": method,
        "wsgi.input": b"",
        "wsgi.errors": "",
    }
    if authorization:
        env["HTTP_AUTHORIZATION"] = authorization
    if remote_addr:
        env["REMOTE_ADDR"] = remote_addr
    return env


def _capture_response():
    calls = []

    def start_response(status, headers, exc_info=None):
        calls.append((status, headers))

    return start_response, calls


_PUBLIC_CONFIG = {
    "READ_ACCESS": "ANONYMOUS",
    "WRITE_ACCESS": "ANONYMOUS",
    "ATTACHMENT_ACCESS": "ANONYMOUS",
}


def _make_server_mock(git_web_server: bool):
    """Return a minimal otterwiki.server module stub with GIT_WEB_SERVER set.

    Used with patch.dict(sys.modules, ...) so that feature code reading
    otterwiki.server.app.config["GIT_WEB_SERVER"] sees the expected value
    without triggering the real otterwiki.server import (requires SECRET_KEY).
    """
    mock_app = MagicMock()
    mock_app.config = {"GIT_WEB_SERVER": git_web_server}
    mock_mod = types.ModuleType("otterwiki.server")
    mock_mod.app = mock_app
    return mock_mod


def _make_resolver(disk_usage_bytes=0, page_count=0, token_wiki=None,
                   wiki_slug="test-wiki"):
    """Build a resolver with configurable quota state.

    Uses MCP bearer token auth so the test doesn't depend on the git
    Basic-auth bridge being implemented.
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
        "owner_did": "did:plc:owner",
        "disk_usage_bytes": disk_usage_bytes,
        "page_count": page_count,
        "is_public": 0,
        "repo_path": f"/srv/data/wikis/{wiki_slug}/repo",
    }
    if token_wiki is not None:
        wiki_model.get_by_token.return_value = token_wiki
    else:
        wiki_model.get_by_token.return_value = None

    user_model = MagicMock()

    return TenantResolver(
        stub_app,
        auth_middleware=auth_middleware,
        wiki_model=wiki_model,
        user_model=user_model,
    )


def _run(resolver, environ, git_web_server=None):
    """Run resolver with standard mocks.

    git_web_server: if not None, patches otterwiki.server.app.config with
    GIT_WEB_SERVER=<value> so the feature gate sees the intended setting.
    """
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
        start_response, calls = _capture_response()
        resolver(environ, start_response)
    return calls


# ---------------------------------------------------------------------------
# Area 2a: _is_write_request recognises git-receive-pack
# ---------------------------------------------------------------------------


class TestIsWriteRequestGitPaths:
    """_is_write_request must return True for POST /.git/git-receive-pack only."""

    def test_receive_pack_post_is_write(self):
        """POST /.git/git-receive-pack → _is_write_request returns True."""
        from app.resolver import _is_write_request

        assert _is_write_request("POST", "/.git/git-receive-pack") is True, (
            "_is_write_request must return True for POST /.git/git-receive-pack"
        )

    def test_receive_pack_post_without_dot_git_prefix(self):
        """POST /git-receive-pack (some git clients omit .git) → True."""
        from app.resolver import _is_write_request

        assert _is_write_request("POST", "/git-receive-pack") is True, (
            "_is_write_request must return True for POST /git-receive-pack"
        )

    def test_upload_pack_post_is_not_write(self):
        """POST /.git/git-upload-pack (clone/fetch) → False.

        Upload-pack is a read operation. Must NOT be rate-limited as a write.
        """
        from app.resolver import _is_write_request

        assert _is_write_request("POST", "/.git/git-upload-pack") is False, (
            "git-upload-pack is a read (clone/fetch); must NOT be treated as write"
        )

    def test_info_refs_get_is_not_write(self):
        """GET /.git/info/refs → False (read)."""
        from app.resolver import _is_write_request

        assert _is_write_request("GET", "/.git/info/refs") is False

    def test_receive_pack_get_is_not_write(self):
        """GET /.git/git-receive-pack → False (wrong method)."""
        from app.resolver import _is_write_request

        assert _is_write_request("GET", "/.git/git-receive-pack") is False


# ---------------------------------------------------------------------------
# Area 2b: over-quota wiki has WRITE/UPLOAD stripped on receive-pack
# ---------------------------------------------------------------------------
#
# The perm-strip block at ~line 711 runs when:
#   over_quota AND _is_write_request(method, path) AND not path.startswith('/api/')
#
# Currently _is_write_request returns False for /.git/ paths, so the quota
# perm-strip never fires on git paths. Once _is_write_request is extended,
# WRITE/UPLOAD will be stripped for over-quota wikis.


class TestGitReceivePackQuotaEnforcement:
    """Over-quota wiki: WRITE/UPLOAD stripped on git-receive-pack POST."""

    def test_over_disk_quota_strips_write_upload_on_receive_pack(self):
        """POST /.git/git-receive-pack on over-disk-quota wiki: WRITE/UPLOAD stripped.

        We use MCP bearer token auth (not git Basic auth) so the test focuses
        purely on the quota perm-strip behaviour, independent of the git auth bridge.
        Currently _is_write_request("POST", "/.git/git-receive-pack") returns False,
        so the strip doesn't fire → WRITE/UPLOAD remain → test fails.
        """
        from app.constants import QUOTA_BYTES

        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        resolver = _make_resolver(
            disk_usage_bytes=QUOTA_BYTES + 1,  # over disk quota
            token_wiki={"slug": "test-wiki", "owner_did": "did:plc:owner"},
        )
        resolver._app = capture_app

        environ = _make_environ(
            "test-wiki.robot.wtf",
            path="/.git/git-receive-pack",
            method="POST",
            authorization="Bearer valid-mcp-token",
        )

        # GIT_WEB_SERVER=True ensures the .git path passes the feature gate and
        # reaches capture_app (and quota enforcement) rather than being 404'd.
        _run(resolver, environ, git_web_server=True)

        # capture_app must have been called — if it wasn't, the quota strip never
        # had a chance to fire (e.g. the .git path was 404'd by the feature gate).
        assert injected, (
            "capture_app was not reached; the .git path was blocked before quota "
            "enforcement ran — check that GIT_WEB_SERVER=True reaches the inner app"
        )
        perms = injected.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")
        assert "WRITE" not in perms, (
            f"Over-quota receive-pack must have WRITE stripped; got {perms!r}"
        )
        assert "UPLOAD" not in perms, (
            f"Over-quota receive-pack must have UPLOAD stripped; got {perms!r}"
        )

    def test_under_quota_receive_pack_preserves_write_upload(self):
        """POST /.git/git-receive-pack on under-quota wiki: WRITE/UPLOAD preserved.

        This is a regression guard: under-quota pushes must always succeed.
        This test should pass both before and after the feature is implemented.
        """
        injected = {}

        def capture_app(environ, start_response):
            injected.update(environ)
            start_response("200 OK", [])
            return [b"ok"]

        resolver = _make_resolver(
            disk_usage_bytes=0,  # well under quota
            token_wiki={"slug": "test-wiki", "owner_did": "did:plc:owner"},
        )
        resolver._app = capture_app

        environ = _make_environ(
            "test-wiki.robot.wtf",
            path="/.git/git-receive-pack",
            method="POST",
            authorization="Bearer valid-mcp-token",
        )

        # GIT_WEB_SERVER=True ensures the .git path passes the feature gate and
        # reaches capture_app rather than being 404'd.
        _run(resolver, environ, git_web_server=True)

        # Hard assertion: capture_app must have been called.
        # An empty injected dict means the request never reached the inner app —
        # which would make the permission assertions vacuously pass.
        assert injected, (
            "capture_app was not reached; the .git path was blocked before the "
            "inner app ran — under-quota receive-pack must reach the git backend"
        )
        perms = injected.get("HTTP_X_OTTERWIKI_PERMISSIONS", "")
        assert perms, (
            f"No permissions were injected for under-quota receive-pack; got {perms!r}"
        )
        assert "WRITE" in perms, (
            f"Under-quota receive-pack must preserve WRITE; got {perms!r}"
        )
        assert "UPLOAD" in perms, (
            f"Under-quota receive-pack must preserve UPLOAD; got {perms!r}"
        )


# ---------------------------------------------------------------------------
# Area 2c: rate limiter fires on receive-pack (6th request → 429)
# ---------------------------------------------------------------------------
#
# The rate limiter at ~line 674 checks _is_write_request. Currently that returns
# False for /.git/git-receive-pack, so the limiter is never consulted.
# Once extended, the 6th POST from the same IP within a minute gets 429.


class TestGitReceivePackRateLimit:
    """6th POST /.git/git-receive-pack from same IP within 1 minute → 429."""

    def test_sixth_receive_pack_returns_429(self):
        """After 5 allowed receive-pack POSTs, the 6th returns 429 Too Many Requests."""
        import app.resolver as resolver_module
        from app.rate_limit import WSGIRateLimiter

        resolver = _make_resolver(
            token_wiki={"slug": "test-wiki", "owner_did": "did:plc:owner"}
        )

        # Use a tight 5/min limiter (same as the real default)
        test_limiter = WSGIRateLimiter()
        test_limiter.add_limit("wiki_write", "5/minute")

        responses = []
        original_limiter = resolver_module._resolver_limiter
        try:
            resolver_module._resolver_limiter = test_limiter
            for _i in range(6):
                environ = _make_environ(
                    "test-wiki.robot.wtf",
                    path="/.git/git-receive-pack",
                    method="POST",
                    authorization="Bearer valid-mcp-token",
                    remote_addr="10.1.2.3",
                )
                calls = _run(resolver, environ)
                if calls:
                    responses.append(calls[0][0])
        finally:
            resolver_module._resolver_limiter = original_limiter

        assert "429 Too Many Requests" in responses, (
            f"6th receive-pack from same IP must → 429; got responses: {responses}"
        )

    def test_receive_pack_429_is_plain_text_not_json(self):
        """429 for /.git paths must be plain text, not JSON.

        The rate limiter emits json_response=True only for /api/ paths. Since
        /.git/ does not start with /api/, the 429 body must be plain text.
        """
        import app.resolver as resolver_module
        from app.rate_limit import WSGIRateLimiter

        resolver = _make_resolver(
            token_wiki={"slug": "test-wiki", "owner_did": "did:plc:owner"}
        )

        test_limiter = WSGIRateLimiter()
        test_limiter.add_limit("wiki_write", "1/minute")
        # Exhaust the limit for this IP
        test_limiter.check("wiki_write", "10.9.8.7")

        original_limiter = resolver_module._resolver_limiter
        try:
            resolver_module._resolver_limiter = test_limiter
            environ = _make_environ(
                "test-wiki.robot.wtf",
                path="/.git/git-receive-pack",
                method="POST",
                authorization="Bearer valid-mcp-token",
                remote_addr="10.9.8.7",
            )
            calls = _run(resolver, environ)
        finally:
            resolver_module._resolver_limiter = original_limiter

        assert calls, "No response captured"
        status, headers = calls[0]
        assert status == "429 Too Many Requests", (
            f"Expected 429; got {status!r}"
        )
        header_dict = {k.lower(): v for k, v in headers}
        content_type = header_dict.get("content-type", "")
        assert "application/json" not in content_type, (
            f"/.git 429 must be plain text, not JSON; got Content-Type: {content_type!r}"
        )

    def test_upload_pack_not_rate_limited(self):
        """POST /.git/git-upload-pack (clone/fetch) is NOT rate-limited.

        Even with the write rate limit exhausted, upload-pack must pass through.
        This is a regression guard: upload-pack is a read operation.
        """
        import app.resolver as resolver_module
        from app.rate_limit import WSGIRateLimiter

        resolver = _make_resolver(
            token_wiki={"slug": "test-wiki", "owner_did": "did:plc:owner"}
        )

        test_limiter = WSGIRateLimiter()
        test_limiter.add_limit("wiki_write", "1/minute")
        # Exhaust the write limit
        test_limiter.check("wiki_write", "10.5.5.5")

        responses = []
        original_limiter = resolver_module._resolver_limiter
        try:
            resolver_module._resolver_limiter = test_limiter
            for _ in range(3):
                environ = _make_environ(
                    "test-wiki.robot.wtf",
                    path="/.git/git-upload-pack",
                    method="POST",
                    authorization="Bearer valid-mcp-token",
                    remote_addr="10.5.5.5",
                )
                calls = _run(resolver, environ)
                if calls:
                    responses.append(calls[0][0])
        finally:
            resolver_module._resolver_limiter = original_limiter

        assert "429 Too Many Requests" not in responses, (
            f"upload-pack (read) must NOT be rate-limited; got: {responses}"
        )


# ---------------------------------------------------------------------------
# Area 2d: WikiModel.update called after successful receive-pack
# ---------------------------------------------------------------------------
#
# After a successful git push, the resolver (or a post-request callback) must
# call WikiModel.update(slug, disk_usage_bytes=..., page_count=...) immediately
# so quota state is refreshed without waiting for the 15-minute cron.


class TestRecomputeWikiUsageAfterPush:
    """After successful git-receive-pack, WikiModel.update refreshes quota state."""

    def test_wiki_model_update_called_with_disk_usage_and_page_count(self):
        """WikiModel.update(slug, disk_usage_bytes=N, page_count=M) is invoked after push.

        We use a stub inner app that simulates a successful receive-pack response.
        Since _recompute_wiki_usage (or equivalent) does not exist yet, this test
        will fail with 'WikiModel.update must be called ... after successful receive-pack'.
        """
        update_calls = []

        def capture_app(environ, start_response):
            start_response(
                "200 OK",
                [("Content-Type", "application/x-git-receive-pack-result")],
            )
            return [b""]

        resolver = _make_resolver(
            disk_usage_bytes=0,
            token_wiki={"slug": "test-wiki", "owner_did": "did:plc:owner"},
        )
        resolver._app = capture_app

        # Capture update calls via side_effect
        resolver._wikis.update.side_effect = lambda slug, **kw: update_calls.append(
            (slug, kw)
        )

        environ = _make_environ(
            "test-wiki.robot.wtf",
            path="/.git/git-receive-pack",
            method="POST",
            authorization="Bearer valid-mcp-token",
        )

        _run(resolver, environ)

        # Filter for quota-refresh calls (must include disk_usage_bytes or page_count)
        quota_calls = [
            (slug, kw)
            for slug, kw in update_calls
            if "disk_usage_bytes" in kw or "page_count" in kw
        ]
        assert quota_calls, (
            "WikiModel.update must be called with disk_usage_bytes/page_count "
            f"after successful receive-pack; all update calls: {update_calls!r}"
        )
        slug, kw = quota_calls[0]
        assert slug == "test-wiki", (
            f"WikiModel.update called with wrong slug: {slug!r}"
        )
        assert "disk_usage_bytes" in kw, (
            f"WikiModel.update must include disk_usage_bytes; got: {kw!r}"
        )
        assert "page_count" in kw, (
            f"WikiModel.update must include page_count; got: {kw!r}"
        )
