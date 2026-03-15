"""Platform API service entry point (port 8002).

A lightweight Flask app that:
- Mounts ManagementMiddleware for /api/* routes
- Serves static files from /srv/static/ (landing page, SPA)
- Provides /api/internal/check-slug for Caddy on-demand TLS validation
"""

from __future__ import annotations

import logging
import os

from flask import Flask, send_from_directory

from app.auth.acl import AclEnforcer
from app.auth.jwt import PlatformJWT, _load_keys
from app.auth.middleware import AuthMiddleware
from app.db import get_connection
from app.management.routes import ManagementMiddleware
from app.models.acl import AclModel
from app.models.user import UserModel
from app.models.wiki import WikiModel

logger = logging.getLogger(__name__)

STATIC_DIR = os.environ.get("ROBOT_STATIC_DIR", "/srv/static")


def _create_flask_app() -> Flask:
    """Create the inner Flask app for non-API routes."""
    app = Flask(__name__, static_folder=None)

    @app.route("/api/internal/check-slug")
    def check_slug():
        """Validate a subdomain for Caddy on-demand TLS.

        Caddy sends ?domain=foo.robot.wtf — we extract the slug and
        check if a wiki with that slug exists in SQLite.
        Returns 200 if valid, 404 if not.
        """
        from flask import request

        domain = request.args.get("domain", "")
        platform_domain = os.environ.get("PLATFORM_DOMAIN", "robot.wtf")
        suffix = f".{platform_domain}"

        if not domain.endswith(suffix):
            return "", 404

        slug = domain[: -len(suffix)]
        if not slug:
            return "", 404

        conn = get_connection()
        wiki_model = WikiModel(conn)
        wiki = wiki_model.get(slug)
        conn.close()

        if wiki:
            return "", 200
        return "", 404

    @app.route("/")
    def landing():
        """Serve the landing page."""
        index_path = os.path.join(STATIC_DIR, "index.html")
        if os.path.exists(index_path):
            return send_from_directory(STATIC_DIR, "index.html")
        return "robot.wtf", 200

    @app.route("/app/", defaults={"path": ""})
    @app.route("/app/<path:path>")
    def spa(path: str):
        """Serve the SPA. All /app/* routes serve index.html for client-side routing."""
        index_path = os.path.join(STATIC_DIR, "app", "index.html")
        if os.path.exists(index_path):
            return send_from_directory(os.path.join(STATIC_DIR, "app"), "index.html")
        return "SPA not deployed", 404

    @app.route("/static/<path:path>")
    def static_files(path: str):
        """Serve static assets."""
        return send_from_directory(STATIC_DIR, path)

    return app


def _build_app():
    """Build the WSGI application with ManagementMiddleware."""
    flask_app = _create_flask_app()

    conn = get_connection()
    user_model = UserModel(conn)
    wiki_model = WikiModel(conn)
    acl_model = AclModel(conn)

    private_key, public_key = _load_keys()
    platform_jwt = PlatformJWT(private_key, public_key)
    auth_middleware = AuthMiddleware(
        platform_jwt=platform_jwt,
        user_model=user_model,
    )

    # Wrap Flask app with ManagementMiddleware
    wsgi_app = ManagementMiddleware(
        flask_app,
        auth_middleware=auth_middleware,
        user_model=user_model,
        wiki_model=wiki_model,
        acl_model=acl_model,
    )

    return wsgi_app


application = _build_app()


if __name__ == "__main__":
    # For local development / testing
    os.environ.setdefault("GUNICORN_BIND", "0.0.0.0:8002")
    app = _create_flask_app()
    app.run(host="0.0.0.0", port=8002, debug=True)
