"""Platform service entry point (port 8002).

Merged auth service and management/API service into a single Flask app.
Runs behind Caddy at https://robot.wtf/{auth,app,api}/*.

Routes:
- GET  /auth/client-metadata.json — ATProto OAuth client metadata
- GET  /auth/login — login page
- POST /auth/login — initiate OAuth flow
- GET  /auth/callback — OAuth callback -> platform JWT cookie
- GET  /auth/logout — clear cookie
- GET  /auth/oauth/consent — MCP OAuth consent page
- POST /auth/oauth/consent — approve/deny MCP OAuth consent
- GET  /.well-known/oauth-authorization-server — AS metadata stub
- GET  /.well-known/jwks.json — RS256 public key
- GET/POST /app/* — management UI routes
- GET/POST /api/* — management API routes (via ManagementMiddleware)
- GET  / — landing page
- GET  /static/<path> — static assets
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import pathlib
import re
import secrets
import shutil
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import urlencode, quote

from authlib.jose import JsonWebKey
from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)

import jwt as pyjwt

from app.auth.atproto_identity import (
    is_valid_did,
    is_valid_handle,
    resolve_identity,
    pds_endpoint,
)
from app.auth.atproto_oauth import (
    resolve_pds_authserver,
    initial_token_request,
    send_par_auth_request,
    fetch_authserver_meta,
    revoke_token_request,
)
from app.auth.atproto_security import is_safe_url
from app.auth.consent import (
    APPROVAL_TOKEN_LIFETIME,
    CONSENT_TOKEN_LIFETIME,
    OAUTH_PARAM_NAMES,
    derive_signing_key,
    sign_token as sign_consent_token,
    verify_token as verify_consent_token,
)
from app.auth.jwt import PlatformJWT, _load_keys
from app.auth.middleware import AuthError, AuthMiddleware
from app.db import get_connection, init_schema
from app.management.routes import (
    ManagementMiddleware,
    _delete_wiki_repo,
    _init_wiki_repo,
    validate_slug,
)
from app.resolver import _init_wiki_db, _initialized_dbs
from app.management.token import generate_mcp_token
from app.models.user import UserModel, default_username_from_handle
from app.models.wiki import WikiModel

logger = logging.getLogger(__name__)

PLATFORM_DOMAIN = os.environ.get("PLATFORM_DOMAIN", "robot.wtf")
COOKIE_DOMAIN = os.environ.get("COOKIE_DOMAIN", f".{PLATFORM_DOMAIN}")
COOKIE_NAME = "platform_token"
COOKIE_MAX_AGE = 24 * 60 * 60  # 24 hours

# Identity-only scope — we just need to prove the user owns a DID
OAUTH_SCOPE = "atproto"

# Fixed client_id — the URL where client metadata is served
CLIENT_ID = f"https://{PLATFORM_DOMAIN}/auth/client-metadata.json"
REDIRECT_URI = f"https://{PLATFORM_DOMAIN}/auth/callback"

STATIC_DIR = os.environ.get("ROBOT_STATIC_DIR", "/srv/static")
WIKI_BASE = os.environ.get("WIKI_BASE", "/srv/data/wikis")


# ---------------------------------------------------------------------------
# Helper functions (kept importable for test compatibility)
# ---------------------------------------------------------------------------

def normalize_handle(username: str) -> str:
    """If username has no dots and looks like a bare Bluesky handle, append .bsky.social."""
    if "." not in username and ":" not in username and "/" not in username and username:
        return username + ".bsky.social"
    return username


def _is_safe_return_url(url: str) -> bool:
    """Accept relative URLs and URLs on *.PLATFORM_DOMAIN."""
    if not url:
        return False
    if url.startswith("/"):
        return True
    # Accept https://<slug>.robot.wtf/... — slug must be at least one char
    pattern = rf"^https://[a-z0-9][a-z0-9-]*\.{re.escape(PLATFORM_DOMAIN)}/"
    return bool(re.match(pattern, url))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_client_jwk():
    """Load the ATProto client JWK (EC P-256) from file."""
    jwk_path = os.environ.get("CLIENT_JWK_PATH", "/srv/data/client_jwk.json")
    with open(jwk_path) as f:
        secret_jwk = JsonWebKey.import_key(json.load(f))
    pub_jwk = json.loads(secret_jwk.as_json(is_private=False))
    assert "d" not in pub_jwk, "Public key must not contain private material"
    return secret_jwk, pub_jwk


def _get_db():
    """Get or create a DB connection for this request."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = get_connection()
    return db


def _get_user_model():
    """Get a UserModel for the current request."""
    return UserModel(_get_db())


def _fetch_display_name(did: str) -> str | None:
    """Best-effort fetch of display name from Bluesky public API."""
    try:
        import requests
        resp = requests.get(
            "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
            params={"actor": did},
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json().get("displayName")
    except Exception as e:
        logger.debug("Failed to fetch display name for %s: %s", did, e)
    return None


def _authenticate_cookie(app):
    """Authenticate the current request from the platform_token cookie.

    Returns AuthenticatedUser if valid, or None.
    """
    auth = app.config["AUTH_MIDDLEWARE"]
    cookie_header = request.headers.get("Cookie")
    return auth.authenticate_from_cookie(cookie_header)


def _get_user_or_redirect():
    """Return g.user set by load_user(), or a redirect response if unauthenticated."""
    user = getattr(g, "user", None)
    if user is None:
        return redirect(f"/auth/login?return_to={request.url}")
    return user


def _require_platform_admin():
    """Return authenticated user if platform admin, redirect or 403 otherwise."""
    result = _get_user_or_redirect()
    if not hasattr(result, "user_did"):
        return result  # login redirect
    if result.user_did not in current_app.config.get("PLATFORM_ADMIN_DIDS", set()):
        abort(403)
    return result


def _is_owner(wiki, user_did):
    """Return True if user_did is the wiki owner."""
    return wiki is not None and wiki.get("owner_did") == user_did


# ---------------------------------------------------------------------------
# Route registration functions
# ---------------------------------------------------------------------------

def _register_auth_routes(app, limiter, client_secret_jwk, client_pub_jwk, platform_jwt, public_key_pem, consent_key):
    """Register all /auth/* and /.well-known/* routes."""

    # Derive JWKS from public key for the /.well-known/jwks.json endpoint
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    import base64

    pub_key_obj = load_pem_public_key(
        public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
    )
    pub_numbers = pub_key_obj.public_numbers()

    def _int_to_b64url(n: int, length: int | None = None) -> str:
        byte_len = length or ((n.bit_length() + 7) // 8)
        return base64.urlsafe_b64encode(
            n.to_bytes(byte_len, "big")
        ).rstrip(b"=").decode()

    rs256_jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": _int_to_b64url(pub_numbers.n),
        "e": _int_to_b64url(pub_numbers.e),
    }

    def _extract_oauth_params() -> dict:
        """Extract OAuth params from request args, preserving all values."""
        params = {}
        for name in OAUTH_PARAM_NAMES:
            val = request.args.get(name)
            if val:
                params[name] = val
        return params

    def _build_authorize_callback_url(oauth_params: dict, approval_token: str, wiki_slug: str) -> str:
        """Build the URL to redirect back to MCP /authorize/callback."""
        base = f"https://{wiki_slug}.{PLATFORM_DOMAIN}/authorize/callback"
        query = urlencode({
            **oauth_params,
            "approval_token": approval_token,
        })
        return f"{base}?{query}"

    @app.route("/auth/client-metadata.json")
    def oauth_client_metadata():
        """Serve ATProto OAuth client metadata (the client_id URL points here)."""
        return jsonify({
            "client_id": CLIENT_ID,
            "dpop_bound_access_tokens": True,
            "application_type": "web",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": OAUTH_SCOPE,
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": {
                "keys": [client_pub_jwk],
            },
            "client_name": "robot.wtf",
            "client_uri": f"https://{PLATFORM_DOMAIN}",
        })

    @app.route("/auth/login", methods=("GET", "POST"))
    @limiter.limit("1/minute", methods=["POST"])
    def oauth_login():
        """Login page (GET) or initiate OAuth flow (POST)."""
        return_to = request.args.get("return_to") or request.form.get("return_to", "")
        if return_to and not _is_safe_return_url(return_to):
            return_to = ""

        if request.method != "POST":
            cookie_token = request.cookies.get(COOKIE_NAME)
            prefill_handle = ""
            if cookie_token:
                try:
                    platform_jwt.validate_token(cookie_token)
                    for key in ("return_to", "csrf_nonces"):
                        session.pop(key, None)
                    redirect_target = return_to or f"https://{PLATFORM_DOMAIN}/app/"
                    return redirect(redirect_target)
                except pyjwt.ExpiredSignatureError:
                    try:
                        expired_claims = pyjwt.decode(
                            cookie_token,
                            options={
                                "verify_signature": False,
                                "verify_exp": False,
                                "verify_iss": False,
                                "verify_aud": False,
                            },
                            algorithms=["RS256"],
                        )
                        raw_handle = expired_claims.get("handle", "")
                        prefill_handle = re.sub(r"[^\x20-\x7e]", "", raw_handle)[:253]
                    except Exception:
                        pass
                except Exception:
                    pass

            if return_to:
                session["return_to"] = return_to
            return render_template("auth/login.html", return_to=return_to, prefill_handle=prefill_handle)

        # POST branch
        if return_to:
            session["return_to"] = return_to

        username = request.form.get("username", "").strip()
        username = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", username)
        if username.startswith("@"):
            username = username[1:]
        username = normalize_handle(username)

        if is_valid_handle(username) or is_valid_did(username):
            login_hint = username
            try:
                did, handle, did_doc = resolve_identity(username)
            except Exception as e:
                flash(f"Failed to resolve identity: {e}", "error")
                return render_template("auth/login.html"), 400

            pds_url = pds_endpoint(did_doc)
            logger.info("account PDS: %s", pds_url)
            authserver_url = resolve_pds_authserver(pds_url)
        elif username.startswith("https://") and is_safe_url(username):
            did, handle, pds_url = None, None, None
            login_hint = None
            initial_url = username
            try:
                authserver_url = resolve_pds_authserver(initial_url)
            except Exception:
                authserver_url = initial_url.rstrip("/")
        else:
            flash("Not a valid handle, DID, or auth server URL", "error")
            return render_template("auth/login.html"), 400

        logger.info("account Authorization Server: %s", authserver_url)
        if not is_safe_url(authserver_url):
            flash("Invalid authorization server URL", "error")
            return render_template("auth/login.html"), 400

        try:
            authserver_meta = fetch_authserver_meta(authserver_url)
        except Exception as err:
            logger.warning("failed to fetch auth server metadata: %s", err)
            flash("Failed to fetch Auth Server OAuth metadata", "error")
            return render_template("auth/login.html"), 400

        dpop_private_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)

        pkce_verifier, state, dpop_authserver_nonce, resp = send_par_auth_request(
            authserver_url,
            authserver_meta,
            login_hint,
            CLIENT_ID,
            REDIRECT_URI,
            OAUTH_SCOPE,
            client_secret_jwk,
            dpop_private_jwk,
        )
        if resp.status_code == 400:
            logger.warning("PAR HTTP 400: %s", resp.json())
        resp.raise_for_status()
        par_request_uri = resp.json()["request_uri"]

        db = _get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """INSERT INTO oauth_auth_requests
               (state, authserver_iss, did, handle, pds_url, pkce_verifier,
                scope, dpop_authserver_nonce, dpop_private_jwk, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                state,
                authserver_meta["issuer"],
                did,
                handle,
                pds_url,
                pkce_verifier,
                OAUTH_SCOPE,
                dpop_authserver_nonce,
                dpop_private_jwk.as_json(is_private=True),
                now,
            ],
        )
        db.commit()

        auth_url = authserver_meta["authorization_endpoint"]
        if not is_safe_url(auth_url):
            flash("Invalid authorization endpoint", "error")
            return render_template("auth/login.html"), 400
        qparam = urlencode({"client_id": CLIENT_ID, "request_uri": par_request_uri})
        return redirect(f"{auth_url}?{qparam}")

    @app.route("/auth/callback")
    @limiter.limit("5/minute")
    def oauth_callback():
        """OAuth callback — exchange code for tokens, issue platform JWT cookie."""
        if error := request.args.get("error"):
            error_description = request.args.get("error_description", "")
            flash(f"Authorization failed: {error}: {error_description}", "error")
            return redirect("/auth/login")

        state = request.args.get("state")
        authserver_iss = request.args.get("iss")
        authorization_code = request.args.get("code")

        if not state or not authserver_iss or not authorization_code:
            abort(400, "Missing required OAuth callback parameters")

        db = _get_db()
        row = db.execute(
            "SELECT * FROM oauth_auth_requests WHERE state = ?",
            [state],
        ).fetchone()

        if row is None:
            abort(400, "OAuth request not found")

        db.execute("DELETE FROM oauth_auth_requests WHERE state = ?", [state])
        db.commit()

        if row["authserver_iss"] != authserver_iss:
            abort(400, "Issuer mismatch")
        if row["state"] != state:
            abort(400, "State mismatch")

        tokens, dpop_authserver_nonce = initial_token_request(
            dict(row),
            authorization_code,
            CLIENT_ID,
            REDIRECT_URI,
            client_secret_jwk,
        )

        if row["did"]:
            did, handle, pds_url = row["did"], row["handle"], row["pds_url"]
            if tokens["sub"] != did:
                abort(400, "Token subject mismatch")
        else:
            did = tokens["sub"]
            if not is_valid_did(did):
                abort(400, "Invalid DID in token response")
            did, handle, did_doc = resolve_identity(did)
            pds_url = pds_endpoint(did_doc)
            authserver_url = resolve_pds_authserver(pds_url)
            if authserver_url != authserver_iss:
                abort(400, "Auth server mismatch")

        if row["scope"] != tokens.get("scope"):
            abort(400, "Scope mismatch")

        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """INSERT OR REPLACE INTO oauth_sessions
               (did, handle, pds_url, authserver_iss, access_token,
                refresh_token, dpop_authserver_nonce, dpop_private_jwk, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                did,
                handle,
                pds_url,
                authserver_iss,
                tokens.get("access_token"),
                tokens.get("refresh_token"),
                dpop_authserver_nonce,
                row["dpop_private_jwk"],
                now,
            ],
        )
        db.commit()

        user_model = _get_user_model()
        user = user_model.get(did)

        if user is None:
            display_name = _fetch_display_name(did) or handle
            try:
                user = user_model.create(
                    did=did,
                    handle=handle,
                    display_name=display_name,
                )
            except sqlite3.IntegrityError:
                db.execute(
                    """INSERT OR IGNORE INTO users
                       (did, handle, display_name, created_at, wiki_count)
                       VALUES (?, ?, ?, ?, 0)""",
                    (did, handle, display_name,
                     datetime.now(timezone.utc).isoformat()),
                )
                db.commit()
                user = user_model.get(did)

        if user["handle"] != handle:
            user_model.update(did, handle=handle)

        display_name = _fetch_display_name(did) or user.get("display_name") or handle

        token = platform_jwt.create_token(
            user_did=did,
            handle=handle,
            display_name=display_name,
        )

        return_to = session.pop("return_to", None)
        if return_to and not _is_safe_return_url(return_to):
            return_to = None
        redirect_target = return_to or f"https://{PLATFORM_DOMAIN}/app/"

        resp = make_response(redirect(redirect_target))
        resp.set_cookie(
            COOKIE_NAME,
            token,
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            secure=True,
            samesite="Lax",
            domain=COOKIE_DOMAIN,
        )
        return resp

    @app.route("/auth/oauth/consent", methods=("GET", "POST"))
    @limiter.limit("2/minute", methods=["POST"])
    def oauth_consent():
        """MCP OAuth consent page."""
        if request.method == "POST":
            return _handle_consent_post()
        return _handle_consent_get()

    def _handle_consent_get():
        oauth_params = _extract_oauth_params()
        if not oauth_params.get("client_id") or not oauth_params.get("redirect_uri"):
            abort(400, "Missing required OAuth parameters (client_id, redirect_uri)")

        wiki_slug = request.args.get("wiki_slug", "")
        if not wiki_slug:
            abort(400, "Missing wiki_slug parameter")

        cookie_token = request.cookies.get(COOKIE_NAME)
        if not cookie_token:
            return_path = request.full_path.rstrip("?")
            return redirect(f"/auth/login?return_to={quote(return_path, safe='/?=&')}")

        try:
            claims = platform_jwt.validate_token(cookie_token)
        except Exception:
            return_path = request.full_path.rstrip("?")
            return redirect(f"/auth/login?return_to={quote(return_path, safe='/?=&')}")

        user_did = claims.get("sub")
        handle = claims.get("handle", "")
        display_name = claims.get("name", handle)

        db = _get_db()
        wiki = WikiModel(db).get(wiki_slug)
        if not wiki:
            abort(403, "Wiki not found")

        client_name = oauth_params.get("client_id", "Unknown client")
        nonce = secrets.token_hex(16)
        consent_payload = {
            **oauth_params,
            "wiki_slug": wiki_slug,
            "user_did": user_did,
            "csrf_nonce": nonce,
            "exp": time.time() + CONSENT_TOKEN_LIFETIME,
        }
        nonces = session.get("csrf_nonces", [])
        nonces.append(nonce)
        session["csrf_nonces"] = nonces[-5:]
        consent_token = sign_consent_token(consent_payload, consent_key)

        wiki_name = f"{wiki_slug}.{PLATFORM_DOMAIN}"
        scopes = oauth_params.get("scope", "").split() if oauth_params.get("scope") else []

        return render_template(
            "auth/consent.html",
            client_name=client_name,
            wiki_name=wiki_name,
            handle=handle,
            scopes=scopes,
            consent_token=consent_token,
        )

    def _handle_consent_post():
        consent_token_raw = request.form.get("consent_token", "")
        action = request.form.get("action", "")

        if not consent_token_raw:
            abort(400, "Missing consent token")

        payload = verify_consent_token(consent_token_raw, consent_key)
        if payload is None:
            abort(400, "Invalid or expired consent token")

        cookie_token = request.cookies.get(COOKIE_NAME)
        if not cookie_token:
            abort(401, "Not authenticated")
        try:
            claims = platform_jwt.validate_token(cookie_token)
        except Exception:
            abort(401, "Invalid platform token")

        if claims.get("sub") != payload.get("user_did"):
            abort(403, "User mismatch")

        csrf_nonce = payload.get("csrf_nonce")
        if not csrf_nonce:
            abort(403, "Missing CSRF nonce")
        session_nonces = session.get("csrf_nonces", [])
        if csrf_nonce not in session_nonces:
            abort(403, "Invalid CSRF nonce")
        session_nonces.remove(csrf_nonce)
        session["csrf_nonces"] = session_nonces

        oauth_params = {k: payload[k] for k in OAUTH_PARAM_NAMES if k in payload}
        wiki_slug = payload.get("wiki_slug", "")
        user_did = payload.get("user_did", "")

        if action == "deny":
            redirect_uri = oauth_params.get("redirect_uri", "")
            state = oauth_params.get("state", "")
            if redirect_uri:
                error_params = {"error": "access_denied"}
                if state:
                    error_params["state"] = state
                sep = "&" if "?" in redirect_uri else "?"
                return redirect(f"{redirect_uri}{sep}{urlencode(error_params)}")
            abort(400, "No redirect_uri to return error to")

        if action == "approve":
            approval_payload = {
                "user_did": user_did,
                "wiki_slug": wiki_slug,
                "client_id": oauth_params.get("client_id", ""),
                "exp": time.time() + APPROVAL_TOKEN_LIFETIME,
            }
            approval_token = sign_consent_token(approval_payload, consent_key)
            callback_url = _build_authorize_callback_url(oauth_params, approval_token, wiki_slug)
            return redirect(callback_url)

        abort(400, "Invalid action")

    @app.route("/auth/logout")
    def oauth_logout():
        """Clear platform JWT cookie and revoke ATProto tokens."""
        cookie_token = request.cookies.get(COOKIE_NAME)
        if cookie_token:
            try:
                claims = platform_jwt.validate_token(cookie_token)
                did = claims.get("sub")
                if did:
                    db = _get_db()
                    oauth_row = db.execute(
                        "SELECT * FROM oauth_sessions WHERE did = ?", [did]
                    ).fetchone()
                    if oauth_row:
                        try:
                            revoke_token_request(
                                dict(oauth_row), CLIENT_ID, client_secret_jwk
                            )
                        except Exception as e:
                            logger.warning("Token revocation failed: %s", e)
                        db.execute(
                            "DELETE FROM oauth_sessions WHERE did = ?", [did]
                        )
                        db.commit()
            except Exception:
                pass

        session.clear()
        resp = make_response(redirect(f"https://{PLATFORM_DOMAIN}/"))
        resp.delete_cookie(
            COOKIE_NAME,
            domain=COOKIE_DOMAIN,
        )
        return resp

    @app.route("/.well-known/oauth-authorization-server")
    def as_metadata():
        """OAuth Authorization Server metadata stub."""
        return jsonify({
            "issuer": f"https://{PLATFORM_DOMAIN}",
            "authorization_endpoint": f"https://{PLATFORM_DOMAIN}/auth/login",
            "token_endpoint": f"https://{PLATFORM_DOMAIN}/auth/token",
            "jwks_uri": f"https://{PLATFORM_DOMAIN}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
        })

    @app.route("/.well-known/jwks.json")
    def jwks():
        """JSON Web Key Set — exposes the platform's RS256 public key."""
        return jsonify({"keys": [rs256_jwk]})


def _register_management_ui_routes(app, limiter):
    """Register all /app/* management UI routes."""

    @app.before_request
    def load_user():
        """Authenticate user from cookie and store on g for /app/* routes."""
        if request.path.startswith("/app/"):
            g.user = _authenticate_cookie(app)
        else:
            g.user = None

    @app.context_processor
    def inject_sidebar_data():
        """Inject sidebar_wikis, platform_domain, and is_platform_admin into all templates."""
        user = getattr(g, "user", None)
        if user is None:
            return {"sidebar_wikis": [], "platform_domain": PLATFORM_DOMAIN, "is_platform_admin": False}
        wiki_model = app.config["WIKI_MODEL"]
        wikis = wiki_model.list_by_owner(user.user_did)
        is_platform_admin = user.user_did in app.config.get("PLATFORM_ADMIN_DIDS", set())
        return {"sidebar_wikis": wikis, "platform_domain": PLATFORM_DOMAIN, "is_platform_admin": is_platform_admin}

    @app.route("/app/")
    def dashboard():
        """Dashboard: redirect to first wiki, or show empty-state create CTA."""
        result = _get_user_or_redirect()
        if not hasattr(result, "user_did"):
            return result
        user = result

        wiki_model = app.config["WIKI_MODEL"]
        wikis = wiki_model.list_by_owner(user.user_did)

        if wikis:
            return redirect(url_for("wiki_settings", slug=wikis[0]["slug"]))

        return redirect(url_for("wiki_create"))

    @app.route("/app/create", methods=["GET", "POST"])
    @limiter.limit("1/minute", methods=["POST"])
    def wiki_create():
        """Create wiki form (GET) or process creation (POST)."""
        result = _get_user_or_redirect()
        if not hasattr(result, "user_did"):
            return result
        user = result

        user_model = app.config["USER_MODEL"]
        wiki_model = app.config["WIKI_MODEL"]

        if request.method == "GET":
            default_slug = default_username_from_handle(user.handle or "")
            return render_template(
                "management/wiki_create.html",
                user=user,
                default_slug=default_slug,
                platform_domain=PLATFORM_DOMAIN,
            )

        slug = request.form.get("slug", "").strip().lower()
        display_name = request.form.get("display_name", "").strip()
        purpose = request.form.get("purpose", "").strip()
        purpose = purpose[:200]

        if not display_name:
            flash("Display name is required.", "danger")
            return redirect(url_for("wiki_create"))

        valid, error = validate_slug(slug)
        if not valid:
            flash(f"Invalid slug: {error}", "danger")
            return redirect(url_for("wiki_create"))

        is_admin = user.user_did in app.config.get("PLATFORM_ADMIN_DIDS", set())
        wiki_count = int(user.record.get("wiki_count", 0))
        if wiki_count >= 1 and not is_admin:
            flash("You can only have one wiki on the free tier.", "danger")
            return redirect(url_for("dashboard"))

        if wiki_model.get(slug):
            flash("That slug is already taken.", "danger")
            return redirect(url_for("wiki_create"))

        plaintext_token, token_hash = generate_mcp_token()

        wiki_base = app.config.get("WIKI_BASE", WIKI_BASE)
        repo_path = os.path.join(wiki_base, slug, "repo")

        try:
            wiki_model.create(
                slug=slug,
                owner_did=user.user_did,
                display_name=display_name,
                repo_path=repo_path,
                mcp_token_hash=token_hash,
            )
        except Exception:
            flash("A wiki with that slug already exists.", "danger")
            return redirect(url_for("wiki_create"))

        try:
            _init_wiki_repo(
                repo_path,
                display_name,
                purpose or f"A wiki about {display_name}",
            )
        except Exception as e:
            logger.error("Failed to init wiki repo: %s", e)
            try:
                wiki_model.delete(slug)
            except Exception:
                pass
            flash("Failed to initialize wiki repository.", "danger")
            return redirect(url_for("wiki_create"))

        wiki_dir = os.path.join(wiki_base, slug)
        db_path = os.path.join(wiki_dir, "wiki.db")
        owner_handle = user.handle.split(".")[0] if user.handle else None
        try:
            _init_wiki_db(db_path, site_name=display_name, site_description=purpose or None, owner_handle=owner_handle)
        except Exception:
            logger.warning("Failed to pre-initialize wiki DB at %s", db_path, exc_info=True)

        user_model.update(user.user_did, wiki_count=wiki_count + 1)

        flash("Wiki created! Your MCP bearer token is below.", "success")
        session["mcp_token"] = plaintext_token
        return redirect(url_for("wiki_settings", slug=slug))

    @app.route("/app/wiki/<slug>")
    def wiki_settings(slug):
        """Wiki settings page."""
        result = _get_user_or_redirect()
        if not hasattr(result, "user_did"):
            return result
        user = result

        wiki_model = app.config["WIKI_MODEL"]
        wiki = wiki_model.get(slug)
        if not wiki:
            flash("Wiki not found.", "danger")
            return redirect(url_for("dashboard"))

        if not _is_owner(wiki, user.user_did):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        mcp_token = session.pop("mcp_token", None)

        return render_template(
            "management/wiki_settings.html",
            user=user,
            wiki=wiki,
            platform_domain=PLATFORM_DOMAIN,
            mcp_token=mcp_token,
        )

    @app.route("/app/wiki/<slug>/settings", methods=["POST"])
    @limiter.limit("5/minute")
    def wiki_settings_update(slug):
        """Update wiki settings (display name)."""
        result = _get_user_or_redirect()
        if not hasattr(result, "user_did"):
            return result
        user = result

        wiki_model = app.config["WIKI_MODEL"]
        wiki = wiki_model.get(slug)
        if not wiki:
            flash("Wiki not found.", "danger")
            return redirect(url_for("dashboard"))

        if not _is_owner(wiki, user.user_did):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        display_name = request.form.get("display_name", "").strip()
        updates = {}
        if display_name:
            updates["display_name"] = display_name

        wiki_model.update(slug, **updates)
        flash("Settings updated.", "success")
        return redirect(url_for("wiki_settings", slug=slug))

    @app.route("/app/wiki/<slug>/delete", methods=["POST"])
    @limiter.limit("2/minute")
    def wiki_delete(slug):
        """Delete a wiki."""
        result = _get_user_or_redirect()
        if not hasattr(result, "user_did"):
            return result
        user = result

        user_model = app.config["USER_MODEL"]
        wiki_model = app.config["WIKI_MODEL"]
        wiki = wiki_model.get(slug)
        if not wiki:
            flash("Wiki not found.", "danger")
            return redirect(url_for("dashboard"))

        if not _is_owner(wiki, user.user_did):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        confirm = request.form.get("confirm_slug", "").strip()
        if confirm != slug:
            flash("Slug confirmation did not match.", "danger")
            return redirect(url_for("dashboard"))

        repo_path = wiki.get("repo_path", "")
        if repo_path:
            wiki_dir = os.path.dirname(repo_path)
            _delete_wiki_repo(wiki_dir)
            db_path = os.path.join(wiki_dir, "wiki.db")
            _initialized_dbs.discard(db_path)

        wiki_model.delete(slug)

        wiki_count = int(user.record.get("wiki_count", 0))
        user_model.update(user.user_did, wiki_count=max(0, wiki_count - 1))

        flash(f"Wiki '{slug}' has been deleted.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/app/wiki/<slug>/mcp/regenerate", methods=["POST"])
    @limiter.limit("2/minute")
    def mcp_regenerate(slug):
        """Regenerate MCP bearer token."""
        result = _get_user_or_redirect()
        if not hasattr(result, "user_did"):
            return result
        user = result

        wiki_model = app.config["WIKI_MODEL"]
        wiki = wiki_model.get(slug)
        if not wiki:
            flash("Wiki not found.", "danger")
            return redirect(url_for("dashboard"))

        if not _is_owner(wiki, user.user_did):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        plaintext_token, token_hash = generate_mcp_token()
        wiki_model.update(slug, mcp_token_hash=token_hash)

        session["mcp_token"] = plaintext_token
        flash(
            "Token regenerated. Copy it now -- it will not be shown again.",
            "warning",
        )
        return redirect(url_for("wiki_settings", slug=slug))

    @app.route("/app/account")
    def account():
        """Account settings page."""
        result = _get_user_or_redirect()
        if not hasattr(result, "user_did"):
            return result
        user = result

        user_model = app.config["USER_MODEL"]
        record = user_model.get(user.user_did)

        return render_template(
            "management/account.html",
            user=user,
            user_record=record,
        )

    @app.route("/app/account/delete", methods=["POST"])
    @limiter.limit("1/minute")
    def account_delete():
        """Delete the current user's account."""
        result = _get_user_or_redirect()
        if not hasattr(result, "user_did"):
            return result
        user = result

        user_model = app.config["USER_MODEL"]
        wiki_model = app.config["WIKI_MODEL"]
        record = user_model.get(user.user_did)
        if not record:
            flash("User not found.", "danger")
            return redirect(url_for("dashboard"))

        confirm = request.form.get("confirm_handle", "").strip()
        expected = record.get("handle", "")
        if confirm != expected:
            flash("Confirmation did not match.", "danger")
            return redirect(url_for("account"))

        wikis = wiki_model.list_by_owner(user.user_did)
        for wiki in wikis:
            wiki_slug = wiki["slug"]
            repo_path = wiki.get("repo_path", "")
            if repo_path:
                wiki_dir = os.path.dirname(repo_path)
                _delete_wiki_repo(wiki_dir)
                db_path = os.path.join(wiki_dir, "wiki.db")
                _initialized_dbs.discard(db_path)
            wiki_model.delete(wiki_slug)

        user_model.delete(user.user_did)

        flash("Account deleted.", "success")
        resp = make_response(redirect("/"))
        resp.delete_cookie(
            "platform_token",
            domain=f".{PLATFORM_DOMAIN}",
            path="/",
        )
        return resp

    @app.route("/app/admin/stats")
    def admin_stats():
        """Platform admin monitoring dashboard."""
        result = _require_platform_admin()
        if not hasattr(result, "user_did"):
            return result
        user = result

        services = ["robot-otterwiki", "robot-mcp", "robot-platform"]
        try:
            out = subprocess.run(
                ["systemctl", "is-active"] + services,
                capture_output=True, text=True, timeout=10,
            )
            statuses = out.stdout.strip().split("\n")
            service_status = dict(zip(services, statuses))
        except Exception:
            service_status = {svc: "unknown" for svc in services}

        try:
            disk = shutil.disk_usage("/srv")
            disk_total_gb = disk.total / (1024 ** 3)
            disk_used_gb = disk.used / (1024 ** 3)
            disk_free_gb = disk.free / (1024 ** 3)
            disk_pct = int(disk.used / disk.total * 100) if disk.total else 0
        except Exception:
            disk_total_gb = disk_used_gb = disk_free_gb = 0.0
            disk_pct = 0

        wiki_model = app.config["WIKI_MODEL"]
        user_model = app.config["USER_MODEL"]
        try:
            wiki_count = wiki_model.count()
        except Exception:
            wiki_count = 0
        try:
            user_count = user_model.count()
        except Exception:
            user_count = 0

        try:
            all_wikis = wiki_model.list_all()
        except Exception:
            all_wikis = []

        try:
            proc = subprocess.run(
                [
                    "journalctl",
                    "-u", "robot-otterwiki",
                    "-u", "robot-platform",
                    "-u", "robot-mcp",
                    "-n", "50",
                    "--no-pager",
                ],
                capture_output=True, text=True, timeout=10,
            )
            journal = proc.stdout
        except Exception:
            journal = "(journal unavailable)"

        return render_template(
            "management/admin_stats.html",
            user=user,
            service_status=service_status,
            disk_total_gb=disk_total_gb,
            disk_used_gb=disk_used_gb,
            disk_free_gb=disk_free_gb,
            disk_pct=disk_pct,
            wiki_count=wiki_count,
            user_count=user_count,
            all_wikis=all_wikis,
            journal=journal,
        )


def _register_management_api_routes(app, limiter):
    """Register non-/app/* API and static routes."""

    # Resolve otterwiki static dir at startup time
    _spec = importlib.util.find_spec("otterwiki")
    if _spec is None or _spec.origin is None:
        raise RuntimeError("otterwiki package not found")
    OTTERWIKI_STATIC = str(pathlib.Path(_spec.origin).parent / "static")

    @app.route("/app/static/<path:path>")
    @limiter.exempt
    def otterwiki_static(path: str):
        """Serve otterwiki static assets for management UI."""
        return send_from_directory(OTTERWIKI_STATIC, path)

    @app.route("/api/internal/check-slug")
    @limiter.exempt
    def check_slug():
        """Validate a subdomain for Caddy on-demand TLS."""
        domain = request.args.get("domain", "")
        platform_domain = os.environ.get("PLATFORM_DOMAIN", PLATFORM_DOMAIN)
        suffix = f".{platform_domain}"

        if not domain.endswith(suffix):
            return "", 404

        slug = domain[: -len(suffix)]
        if not slug:
            return "", 404

        conn = get_connection()
        wm = WikiModel(conn)
        wiki = wm.get(slug)
        conn.close()

        if wiki:
            return "", 200
        return "", 404

    @app.route("/")
    @limiter.exempt
    def landing():
        """Serve the landing page."""
        index_path = os.path.join(STATIC_DIR, "index.html")
        if os.path.exists(index_path):
            return send_from_directory(STATIC_DIR, "index.html")
        return "robot.wtf", 200

    @app.route("/static/<path:path>")
    @limiter.exempt
    def static_files(path: str):
        """Serve static assets."""
        return send_from_directory(STATIC_DIR, path)

    @app.route("/api/me")
    def api_me():
        """Return current user info from JWT cookie."""
        user = _authenticate_cookie(app)
        if user is None:
            return jsonify({"error": "Not authenticated"}), 401
        user_model = app.config["USER_MODEL"]
        record = user_model.get(user.user_did)
        if not record:
            return jsonify({"error": "User not found"}), 404
        return jsonify({
            "did": record["did"],
            "handle": record["handle"],
            "display_name": record.get("display_name"),
        })


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(
    *,
    db_path: str | None = None,
    client_jwk_path: str | None = None,
    signing_key_path: str | None = None,
) -> Flask:
    """Create the platform Flask app (combined auth + management).

    Args:
        db_path: Override DB path (for testing).
        client_jwk_path: Override client JWK path (for testing).
        signing_key_path: Override signing key path (for testing).
    """
    app = Flask(__name__, template_folder="templates", static_folder=None)

    # Override env vars if provided (for testing)
    if client_jwk_path:
        os.environ["CLIENT_JWK_PATH"] = client_jwk_path
    if signing_key_path:
        os.environ["SIGNING_KEY_PATH"] = signing_key_path
    if db_path:
        os.environ["ROBOT_DB_PATH"] = db_path

    # Secret key for Flask session — must be set in production
    secret_key = os.environ.get("FLASK_SECRET_KEY", "")
    if not secret_key or secret_key.startswith("dev-secret"):
        if os.environ.get("FLASK_ENV") != "testing":
            raise RuntimeError(
                "FLASK_SECRET_KEY must be set to a strong random value in production"
            )
        secret_key = "test-secret-for-testing-only"
    app.secret_key = secret_key
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = True

    # Rate limiting
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["60/minute"],
        storage_uri="memory://",
    )

    # Try to load auth keys; if unavailable, skip auth route registration.
    # Management-only tests call create_app() without keys set in the env.
    _auth_keys_loaded = False
    client_secret_jwk = client_pub_jwk = None
    private_key = public_key = None
    platform_jwt = None
    consent_key = None
    try:
        client_secret_jwk, client_pub_jwk = _load_client_jwk()
        private_key, public_key = _load_keys()
        platform_jwt = PlatformJWT(private_key, public_key)
        consent_key = derive_signing_key(private_key)
        _auth_keys_loaded = True
    except Exception:
        pass

    # Set up models and auth middleware (requires DB + keys)
    conn = None
    user_model = None
    wiki_model = None
    auth_middleware = None
    if _auth_keys_loaded:
        conn = get_connection()
        user_model = UserModel(conn)
        wiki_model = WikiModel(conn)
        auth_middleware = AuthMiddleware(
            platform_jwt=platform_jwt,
            user_model=user_model,
        )
        app.config["AUTH_MIDDLEWARE"] = auth_middleware
        app.config["USER_MODEL"] = user_model
        app.config["WIKI_MODEL"] = wiki_model

    app.config["WIKI_BASE"] = WIKI_BASE
    app.config["PLATFORM_ADMIN_DIDS"] = set(
        d.strip() for d in os.environ.get("PLATFORM_ADMIN_DIDS", "").split(",") if d.strip()
    )

    # Request lifecycle: close DB connection
    @app.teardown_appcontext
    def close_connection(exception):
        db = getattr(g, "_database", None)
        if db is not None:
            db.close()

    # Error handlers
    @app.errorhandler(429)
    def ratelimit_handler(e):
        if request.accept_mimetypes.best == "application/json":
            resp = jsonify(error="Rate limit exceeded")
            resp.status_code = 429
            resp.headers["Retry-After"] = "60"
            return resp
        resp = make_response(
            render_template_string(
                "<h1>Too Many Requests</h1><p>Please slow down and try again later.</p>"
            ),
            429,
        )
        resp.headers["Retry-After"] = "60"
        return resp

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("auth/error.html", status_code=500, err=e), 500

    @app.errorhandler(400)
    def bad_request_error(e):
        return render_template("auth/error.html", status_code=400, err=e), 400

    # Register routes
    if _auth_keys_loaded:
        _register_auth_routes(
            app, limiter, client_secret_jwk, client_pub_jwk,
            platform_jwt, public_key, consent_key
        )
    _register_management_ui_routes(app, limiter)
    _register_management_api_routes(app, limiter)

    # Wrap Flask with ManagementMiddleware, then ProxyFix (outermost).
    # ManagementMiddleware requires auth_middleware/user_model/wiki_model;
    # when keys were not loaded those will come from injected test config.
    _auth_mw = auth_middleware or app.config.get("AUTH_MIDDLEWARE")
    _user_model = user_model or app.config.get("USER_MODEL")
    _wiki_model = wiki_model or app.config.get("WIKI_MODEL")

    from werkzeug.middleware.proxy_fix import ProxyFix

    if _auth_mw and _user_model and _wiki_model:
        # Wrap the Flask internal wsgi_app (not the Flask app itself) to avoid
        # recursion: ManagementMiddleware delegates to app.wsgi_app (original),
        # and ProxyFix sits outermost.
        app.wsgi_app = ProxyFix(
            ManagementMiddleware(
                app.wsgi_app,
                auth_middleware=_auth_mw,
                user_model=_user_model,
                wiki_model=_wiki_model,
                admin_dids=app.config["PLATFORM_ADMIN_DIDS"],
            ),
            x_for=1, x_proto=1, x_host=1,
        )
    else:
        # Apply ProxyFix unconditionally so REMOTE_ADDR is correct for rate limiting.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    return app


# Gunicorn entry point — let failures propagate so Gunicorn fails fast.
application = create_app()


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8002, debug=True)
