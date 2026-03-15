"""Auth service entry point (port 8003).

Placeholder Flask app with stub routes for the ATProto OAuth flow.
Real implementation comes in V3.

Routes:
- /auth/login — initiate ATProto OAuth
- /auth/callback — handle OAuth callback
- /auth/logout — clear session
- /auth/client-metadata.json — OAuth client metadata
- /.well-known/oauth-authorization-server — AS metadata stub
- /.well-known/jwks.json — public key set stub
"""

from __future__ import annotations

import json
import logging
import os

from flask import Flask, jsonify, request

logger = logging.getLogger(__name__)

PLATFORM_DOMAIN = os.environ.get("PLATFORM_DOMAIN", "robot.wtf")


def create_app() -> Flask:
    """Create the auth service Flask app."""
    app = Flask(__name__)

    @app.route("/auth/login")
    def auth_login():
        """Initiate ATProto OAuth login."""
        return jsonify({"error": "ATProto OAuth not yet implemented"}), 501

    @app.route("/auth/callback")
    def auth_callback():
        """Handle ATProto OAuth callback."""
        return jsonify({"error": "ATProto OAuth not yet implemented"}), 501

    @app.route("/auth/logout", methods=["GET", "POST"])
    def auth_logout():
        """Clear session / logout."""
        return jsonify({"error": "ATProto OAuth not yet implemented"}), 501

    @app.route("/auth/client-metadata.json")
    def client_metadata():
        """OAuth client metadata document."""
        metadata = {
            "client_id": f"https://auth.{PLATFORM_DOMAIN}/auth/client-metadata.json",
            "client_name": "robot.wtf",
            "client_uri": f"https://{PLATFORM_DOMAIN}",
            "redirect_uris": [f"https://auth.{PLATFORM_DOMAIN}/auth/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": "atproto",
            "dpop_bound_access_tokens": True,
        }
        return jsonify(metadata)

    @app.route("/.well-known/oauth-authorization-server")
    def as_metadata():
        """OAuth Authorization Server metadata stub."""
        metadata = {
            "issuer": f"https://auth.{PLATFORM_DOMAIN}",
            "authorization_endpoint": f"https://auth.{PLATFORM_DOMAIN}/auth/login",
            "token_endpoint": f"https://auth.{PLATFORM_DOMAIN}/auth/token",
            "jwks_uri": f"https://auth.{PLATFORM_DOMAIN}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
        }
        return jsonify(metadata)

    @app.route("/.well-known/jwks.json")
    def jwks():
        """JSON Web Key Set stub.

        Real implementation will expose the platform's RS256 public key.
        """
        return jsonify({"keys": []})

    return app


# Gunicorn entry point
application = create_app()


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8003, debug=True)
