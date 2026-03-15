"""Gunicorn WSGI entry point for Otterwiki on robot.wtf.

Imports the Otterwiki Flask app, wraps it in TenantResolver (when
MULTI_TENANT=true) and ManagementMiddleware. Equivalent to wikibot-io's
lambda_init.py but without the Lambda/Mangum wrapper.
"""

from __future__ import annotations

import logging
import os

from app.auth.acl import AclEnforcer
from app.auth.jwt import PlatformJWT, _load_keys
from app.auth.middleware import AuthMiddleware
from app.db import get_connection
from app.management.routes import ManagementMiddleware
from app.models.acl import AclModel
from app.models.user import UserModel
from app.models.wiki import WikiModel
from app.resolver import TenantResolver

logger = logging.getLogger(__name__)

# Try to import the real Otterwiki Flask app; fall back to a stub
try:
    from otterwiki.server import app as otterwiki_app

    _real_otterwiki = True
except ImportError:
    from flask import Flask

    otterwiki_app = Flask(__name__)

    @otterwiki_app.route("/", defaults={"path": ""})
    @otterwiki_app.route("/<path:path>")
    def _stub(path: str):  # type: ignore[no-untyped-def]
        return "Otterwiki not installed", 503

    _real_otterwiki = False
    logger.warning("otterwiki not installed — using stub Flask app")


def _build_app():
    """Build the WSGI application with middleware stack."""
    # Database connection
    conn = get_connection()

    # Models
    user_model = UserModel(conn)
    wiki_model = WikiModel(conn)
    acl_model = AclModel(conn)

    # Auth
    private_key, public_key = _load_keys()
    platform_jwt = PlatformJWT(private_key, public_key)
    auth_middleware = AuthMiddleware(
        platform_jwt=platform_jwt,
        user_model=user_model,
    )
    acl_enforcer = AclEnforcer(acl_model=acl_model, wiki_model=wiki_model)

    # Start with the Otterwiki WSGI app
    wsgi_app = otterwiki_app

    # Wrap with ManagementMiddleware (/api/* routes)
    wsgi_app = ManagementMiddleware(
        wsgi_app,
        auth_middleware=auth_middleware,
        user_model=user_model,
        wiki_model=wiki_model,
        acl_model=acl_model,
    )

    # Wrap with TenantResolver if multi-tenant
    if os.environ.get("MULTI_TENANT", "").lower() in ("true", "1", "yes"):
        wsgi_app = TenantResolver(
            wsgi_app,
            auth_middleware=auth_middleware,
            acl_enforcer=acl_enforcer,
            wiki_model=wiki_model,
            user_model=user_model,
        )

    return wsgi_app


# The WSGI application that Gunicorn will serve
application = _build_app()
