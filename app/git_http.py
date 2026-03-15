"""Git smart HTTP server (read-only) for robot.wtf.

Provides read-only git clone access to wiki repos via the git smart HTTP
protocol. Only git-upload-pack is supported (clone/fetch). git-receive-pack
(push) is rejected with 403.

Routes:
  GET  /{slug}.robot.wtf/repo.git/info/refs?service=git-upload-pack
  POST /{slug}.robot.wtf/repo.git/git-upload-pack

These are mounted in the TenantResolver or as a separate WSGI app fronted
by Caddy.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Base path for wiki repos (same as management routes)
WIKI_BASE = "/srv/data/wikis"


def _error_response(
    start_response: Callable, status_code: int, message: str
) -> list[bytes]:
    """Return a plain text error response."""
    status_map = {
        400: "400 Bad Request",
        403: "403 Forbidden",
        404: "404 Not Found",
        500: "500 Internal Server Error",
    }
    status = status_map.get(status_code, f"{status_code} Error")
    body = message.encode("utf-8")
    start_response(
        status,
        [("Content-Type", "text/plain"), ("Content-Length", str(len(body)))],
    )
    return [body]


class GitHttpBackend:
    """WSGI application that serves read-only git smart HTTP protocol.

    This handles the two endpoints needed for git clone:
    1. GET /info/refs?service=git-upload-pack  (ref advertisement)
    2. POST /git-upload-pack  (pack negotiation)

    The wiki slug and repo path must be resolved before calling this app.
    Set environ["GIT_HTTP_REPO_PATH"] to the repo directory.
    """

    def __init__(self, wiki_base: str | None = None):
        self._wiki_base = wiki_base or os.environ.get("WIKI_BASE", WIKI_BASE)

    def __call__(
        self, environ: dict[str, Any], start_response: Callable
    ) -> Any:
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "GET")

        # Extract slug from path: /repo.git/info/refs or /repo.git/git-upload-pack
        # The slug is resolved from Host header by Caddy/TenantResolver and
        # injected as GIT_HTTP_WIKI_SLUG, or we parse from the path.
        repo_path = environ.get("GIT_HTTP_REPO_PATH")

        if not repo_path:
            # Try to extract slug from path pattern: /{slug}/repo.git/...
            m = re.match(r"^/([a-z0-9][a-z0-9-]*[a-z0-9])/repo\.git(/.*)?$", path)
            if not m:
                return _error_response(start_response, 404, "Not found")
            slug = m.group(1)
            repo_path = os.path.join(self._wiki_base, slug, "repo")
            # Rewrite PATH_INFO to just the git part
            path = m.group(2) or "/"

        if not os.path.isdir(repo_path):
            return _error_response(start_response, 404, "Repository not found")

        # Reject git-receive-pack (push) — read-only
        if "git-receive-pack" in path or "git-receive-pack" in environ.get(
            "QUERY_STRING", ""
        ):
            return _error_response(
                start_response, 403, "Push access denied (read-only)"
            )

        # Route: GET /info/refs?service=git-upload-pack
        if method == "GET" and path.rstrip("/").endswith("/info/refs"):
            query = environ.get("QUERY_STRING", "")
            if "service=git-upload-pack" not in query:
                return _error_response(
                    start_response, 400, "Only git-upload-pack is supported"
                )
            return self._info_refs(repo_path, start_response)

        # Route: POST /git-upload-pack
        if method == "POST" and path.rstrip("/").endswith("/git-upload-pack"):
            return self._upload_pack(repo_path, environ, start_response)

        # Route: GET /HEAD (for dumb HTTP clients)
        if method == "GET" and path.rstrip("/").endswith("/HEAD"):
            return self._serve_head(repo_path, start_response)

        return _error_response(start_response, 404, "Not found")

    def _info_refs(
        self, repo_path: str, start_response: Callable
    ) -> list[bytes]:
        """Handle GET /info/refs?service=git-upload-pack."""
        git = os.environ.get("GIT_PYTHON_GIT_EXECUTABLE", "git")
        try:
            result = subprocess.run(
                [git, "upload-pack", "--stateless-rpc", "--advertise-refs", repo_path],
                capture_output=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("git upload-pack --advertise-refs failed: %s", e)
            return _error_response(start_response, 500, "Git backend error")

        if result.returncode != 0:
            logger.error(
                "git upload-pack --advertise-refs failed (rc=%d): %s",
                result.returncode,
                result.stderr.decode("utf-8", errors="replace"),
            )
            return _error_response(start_response, 500, "Git backend error")

        # Smart HTTP preamble: service advertisement
        service = b"# service=git-upload-pack\n"
        pkt_line = _pkt_line(service)
        flush = b"0000"
        body = pkt_line + flush + result.stdout

        start_response(
            "200 OK",
            [
                (
                    "Content-Type",
                    "application/x-git-upload-pack-advertisement",
                ),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-cache"),
            ],
        )
        return [body]

    def _upload_pack(
        self,
        repo_path: str,
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes]:
        """Handle POST /git-upload-pack."""
        try:
            content_length = int(environ.get("CONTENT_LENGTH", 0))
        except (ValueError, TypeError):
            content_length = 0

        input_data = b""
        if content_length > 0:
            input_data = environ["wsgi.input"].read(content_length)

        git = os.environ.get("GIT_PYTHON_GIT_EXECUTABLE", "git")
        try:
            result = subprocess.run(
                [git, "upload-pack", "--stateless-rpc", repo_path],
                input=input_data,
                capture_output=True,
                timeout=60,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("git upload-pack failed: %s", e)
            return _error_response(start_response, 500, "Git backend error")

        if result.returncode != 0:
            logger.error(
                "git upload-pack failed (rc=%d): %s",
                result.returncode,
                result.stderr.decode("utf-8", errors="replace"),
            )
            return _error_response(start_response, 500, "Git backend error")

        start_response(
            "200 OK",
            [
                ("Content-Type", "application/x-git-upload-pack-result"),
                ("Content-Length", str(len(result.stdout))),
                ("Cache-Control", "no-cache"),
            ],
        )
        return [result.stdout]

    def _serve_head(
        self, repo_path: str, start_response: Callable
    ) -> list[bytes]:
        """Serve the HEAD file for dumb HTTP clients."""
        head_path = os.path.join(repo_path, ".git", "HEAD")
        if not os.path.exists(head_path):
            # Try bare repo layout
            head_path = os.path.join(repo_path, "HEAD")

        if not os.path.exists(head_path):
            return _error_response(start_response, 404, "HEAD not found")

        with open(head_path, "rb") as f:
            body = f.read()

        start_response(
            "200 OK",
            [
                ("Content-Type", "text/plain"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]


def _pkt_line(data: bytes) -> bytes:
    """Encode data as a git pkt-line (4-digit hex length prefix)."""
    length = len(data) + 4
    return f"{length:04x}".encode("ascii") + data
