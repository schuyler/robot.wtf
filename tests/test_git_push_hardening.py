"""Tests for git push hardening: symlink checkout and push body size.

- _disable_repo_symlinks: a pushed symlink must land in the working tree as a
  plain file, never as a link otterwiki would follow when reading pages.
- _PushSizeLimitedStream / resolver: a push body larger than the remaining
  disk quota is rejected with 413, whether or not Content-Length is sent.
"""

from __future__ import annotations

import base64
import contextlib
import io
import os
import subprocess
import sys
import types
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.exceptions import RequestEntityTooLarge

from app.auth.middleware import AuthMiddleware
from app.constants import QUOTA_BYTES


# ---------------------------------------------------------------------------
# _disable_repo_symlinks — end-to-end with real git
# ---------------------------------------------------------------------------


def _git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd, check=True, capture_output=True,
    )


@pytest.fixture
def pushed_symlink(tmp_path):
    """Return a function that pushes `leak.md -> secret` into a non-bare repo
    configured like otterwiki's (receive.denyCurrentBranch=updateInstead)."""
    secret = tmp_path / "secret.pem"
    secret.write_text("TOP SECRET")

    server = tmp_path / "server"
    server.mkdir()
    _git(server, "init", "-q")
    (server / "home.md").write_text("hi")
    _git(server, "add", ".")
    _git(server, "commit", "-qm", "init")
    _git(server, "config", "receive.denyCurrentBranch", "updateInstead")

    def push():
        client = tmp_path / "client"
        _git(tmp_path, "clone", "-q", str(server), str(client))
        os.symlink(secret, client / "leak.md")
        _git(client, "add", "leak.md")
        _git(client, "commit", "-qm", "leak")
        _git(client, "push", "-q", "origin", "HEAD")
        return server / "leak.md"

    return server, push


class TestDisableRepoSymlinks:
    def test_without_fix_symlink_is_checked_out(self, pushed_symlink):
        """Regression guard for the premise: updateInstead creates a real link."""
        _, push = pushed_symlink
        leak = push()
        assert leak.is_symlink()
        assert leak.read_text() == "TOP SECRET"

    def test_with_fix_symlink_is_plain_file(self, pushed_symlink):
        from app.resolver import _disable_repo_symlinks

        server, push = pushed_symlink
        _disable_repo_symlinks(str(server))
        leak = push()
        assert not leak.is_symlink()
        assert "TOP SECRET" not in leak.read_text()

    def test_raises_when_repo_missing(self, tmp_path):
        from app.resolver import _disable_repo_symlinks

        with pytest.raises(subprocess.CalledProcessError):
            _disable_repo_symlinks(str(tmp_path / "nope"))

    def test_already_set_needs_no_lock(self, pushed_symlink):
        """Once set, a concurrent writer holding config.lock can't fail the push."""
        from app.resolver import _disable_repo_symlinks

        server, _ = pushed_symlink
        _disable_repo_symlinks(str(server))
        (server / ".git" / "config.lock").touch()
        _disable_repo_symlinks(str(server))  # must not raise

    def test_lock_held_and_unset_raises_after_retries(self, pushed_symlink):
        from app.resolver import _disable_repo_symlinks

        server, _ = pushed_symlink
        (server / ".git" / "config.lock").touch()
        with patch("app.resolver.time.sleep"):
            with pytest.raises(subprocess.CalledProcessError):
                _disable_repo_symlinks(str(server))

    def test_transient_lock_is_retried(self, pushed_symlink):
        """A lock released between attempts lets the write succeed."""
        from app.resolver import _disable_repo_symlinks

        server, _ = pushed_symlink
        lock = server / ".git" / "config.lock"
        lock.touch()
        with patch("app.resolver.time.sleep", side_effect=lambda _: lock.unlink()):
            _disable_repo_symlinks(str(server))
        out = subprocess.run(
            ["git", "config", "--file", str(server / ".git" / "config"), "core.symlinks"],
            capture_output=True, text=True, check=True,
        )
        assert out.stdout.strip() == "false"


# ---------------------------------------------------------------------------
# _PushSizeLimitedStream
# ---------------------------------------------------------------------------


class TestPushSizeLimitedStream:
    def _stream(self, data, limit):
        from app.resolver import _PushSizeLimitedStream
        return _PushSizeLimitedStream(io.BytesIO(data), limit)

    def test_read_all_within_limit(self):
        assert self._stream(b"x" * 100, 100).read() == b"x" * 100

    def test_read_all_over_limit_raises(self):
        with pytest.raises(RequestEntityTooLarge):
            self._stream(b"x" * 101, 100).read()

    def test_unbounded_read_rejects_before_buffering_everything(self):
        """A huge body is rejected after roughly limit + one chunk is read."""
        from app.resolver import _PushSizeLimitedStream

        src = io.BytesIO(b"x" * (10 * 1024 * 1024))
        stream = _PushSizeLimitedStream(src, 1024)
        with pytest.raises(RequestEntityTooLarge):
            stream.read()
        assert src.tell() <= 1024 + _PushSizeLimitedStream._CHUNK

    def test_sized_reads_accumulate(self):
        stream = self._stream(b"x" * 150, 100)
        assert stream.read(60) == b"x" * 60
        with pytest.raises(RequestEntityTooLarge):
            stream.read(60)

    def test_readline_counts(self):
        stream = self._stream(b"a" * 80 + b"\n" + b"b" * 80 + b"\n", 100)
        stream.readline()
        with pytest.raises(RequestEntityTooLarge):
            stream.readline()


# ---------------------------------------------------------------------------
# Resolver wiring
# ---------------------------------------------------------------------------


def _otterwiki_modules(git_web_server=True):
    """Stub otterwiki and otterwiki.server so the git gate runs without otterwiki."""
    pkg = types.ModuleType("otterwiki")
    pkg.__path__ = []
    server = types.ModuleType("otterwiki.server")
    server.app = MagicMock()
    server.app.config = {"GIT_WEB_SERVER": git_web_server}
    pkg.server = server
    return {"otterwiki": pkg, "otterwiki.server": server}


def _make_resolver(disk_usage_bytes=0, app=None):
    from app.resolver import TenantResolver

    seen = {}

    def stub_app(environ, start_response):
        seen["environ"] = environ
        start_response("200 OK", [])
        return [b"ok"]

    wiki = {
        "slug": "test-wiki",
        "owner_did": "did:plc:owner",
        "disk_usage_bytes": disk_usage_bytes,
        "page_count": 0,
        "is_public": 0,
        "repo_path": "/srv/data/wikis/test-wiki/repo",
    }
    wiki_model = MagicMock()
    wiki_model.get.return_value = wiki
    wiki_model.get_by_token.return_value = wiki

    auth = MagicMock(spec=AuthMiddleware)
    auth.authenticate_from_cookie.return_value = None

    resolver = TenantResolver(
        app or stub_app,
        auth_middleware=auth,
        wiki_model=wiki_model,
        user_model=MagicMock(),
    )
    return resolver, seen


def _push_environ(content_length=None, body=b""):
    creds = base64.b64encode(b"x-token:tok").decode()
    env = {
        "HTTP_HOST": "test-wiki.robot.wtf",
        "PATH_INFO": "/.git/git-receive-pack",
        "REQUEST_METHOD": "POST",
        "HTTP_AUTHORIZATION": f"Basic {creds}",
        "REMOTE_ADDR": "10.9.8.7",
        "wsgi.input": io.BytesIO(body),
        "wsgi.errors": "",
    }
    if content_length is not None:
        env["CONTENT_LENGTH"] = str(content_length)
    return env


def _run(resolver, environ, disable_symlinks=None):
    calls = []

    def start_response(status, headers, exc_info=None):
        calls.append((status, headers))

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(resolver, "_swap_storage"))
        stack.enter_context(patch.object(resolver, "_recompute_wiki_usage"))
        stack.enter_context(patch("app.resolver._swap_database"))
        stack.enter_context(patch("app.resolver._resolver_limiter"))
        stack.enter_context(patch(
            "app.resolver._get_wiki_access_config",
            return_value={"READ_ACCESS": "ANONYMOUS", "WRITE_ACCESS": "ANONYMOUS"},
        ))
        stack.enter_context(patch.dict(sys.modules, _otterwiki_modules()))
        mock_disable = stack.enter_context(
            patch("app.resolver._disable_repo_symlinks", side_effect=disable_symlinks)
        )
        resolver(environ, start_response)
    return calls[0][0], mock_disable


class TestResolverPushHardening:
    def test_content_length_over_remaining_quota_returns_413(self):
        resolver, seen = _make_resolver(disk_usage_bytes=QUOTA_BYTES - 1000)
        status, _ = _run(resolver, _push_environ(content_length=1001))
        assert status.startswith("413")
        assert "environ" not in seen

    def test_push_within_quota_reaches_app_with_limited_stream(self):
        from app.resolver import _PushSizeLimitedStream

        resolver, seen = _make_resolver(disk_usage_bytes=QUOTA_BYTES - 1000)
        status, mock_disable = _run(resolver, _push_environ(content_length=10, body=b"x" * 10))
        assert status == "200 OK"
        stream = seen["environ"]["wsgi.input"]
        assert isinstance(stream, _PushSizeLimitedStream)
        assert stream._limit == 1000
        mock_disable.assert_called_once_with("/srv/data/wikis/test-wiki/repo")

    def test_chunked_push_body_is_capped(self):
        """No Content-Length (chunked): the app's read raises 413 past the limit."""
        captured = {}

        def reading_app(environ, start_response):
            try:
                environ["wsgi.input"].read()
            except RequestEntityTooLarge:
                captured["rejected"] = True
            start_response("200 OK", [])
            return [b""]

        resolver, _ = _make_resolver(disk_usage_bytes=QUOTA_BYTES - 100, app=reading_app)
        _run(resolver, _push_environ(body=b"x" * 101))
        assert captured.get("rejected")

    def test_symlink_config_failure_refuses_push(self):
        resolver, seen = _make_resolver()
        status, _ = _run(
            resolver, _push_environ(content_length=0),
            disable_symlinks=subprocess.CalledProcessError(1, "git"),
        )
        assert status.startswith("500")
        assert "environ" not in seen

    def test_non_push_requests_untouched(self):
        resolver, seen = _make_resolver()
        env = _push_environ()
        env["PATH_INFO"] = "/.git/git-upload-pack"
        original = env["wsgi.input"]
        status, mock_disable = _run(resolver, env)
        assert status == "200 OK"
        assert seen["environ"]["wsgi.input"] is original
        mock_disable.assert_not_called()
