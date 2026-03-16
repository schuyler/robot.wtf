"""Auth service entry point (port 8003).

Production ATProto OAuth flow for robot.wtf. Runs behind Caddy at
https://robot.wtf/auth/*.

Routes:
- GET  /auth/client-metadata.json — ATProto OAuth client metadata
- GET  /auth/login — login page
- POST /auth/login — initiate OAuth flow
- GET  /auth/callback — OAuth callback -> platform JWT cookie
- GET  /auth/logout — clear cookie
- GET  /auth/signup — username form (first-time users)
- POST /auth/signup — create user record
- GET  /auth/oauth/consent — MCP OAuth consent page
- POST /auth/oauth/consent — approve/deny MCP OAuth consent
- GET  /.well-known/oauth-authorization-server — AS metadata stub
- GET  /.well-known/jwks.json — RS256 public key
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from urllib.parse import urlencode, quote

from authlib.jose import JsonWebKey
from flask import (
    Flask,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    abort,
    g,
)

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
from app.auth.acl import AclEnforcer
from app.auth.jwt import PlatformJWT, _load_keys
from app.auth.middleware import AuthError
from app.db import get_connection, init_schema
from app.models.acl import AclModel
from app.models.user import UserModel, validate_username
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


def _default_username_from_handle(handle: str) -> str:
    """Derive a default username from a Bluesky handle.

    Takes the first segment (before the first dot), lowercases it,
    strips non-alphanumeric/hyphen chars.
    """
    prefix = handle.split(".")[0].lower()
    # Keep only lowercase alphanumeric and hyphens
    prefix = re.sub(r"[^a-z0-9-]", "", prefix)
    # Strip leading/trailing hyphens
    prefix = prefix.strip("-")
    # Ensure minimum length
    if len(prefix) < 3:
        prefix = prefix + "user"
    # Truncate to 30 chars
    return prefix[:30]


def create_app(
    *,
    db_path: str | None = None,
    client_jwk_path: str | None = None,
    signing_key_path: str | None = None,
) -> Flask:
    """Create the auth service Flask app.

    Args:
        db_path: Override DB path (for testing).
        client_jwk_path: Override client JWK path (for testing).
        signing_key_path: Override signing key path (for testing).
    """
    app = Flask(__name__, template_folder="auth/templates")

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

    # Override env vars if provided (for testing)
    if client_jwk_path:
        os.environ["CLIENT_JWK_PATH"] = client_jwk_path
    if signing_key_path:
        os.environ["SIGNING_KEY_PATH"] = signing_key_path
    if db_path:
        os.environ["ROBOT_DB_PATH"] = db_path

    # Load keys at startup
    client_secret_jwk, client_pub_jwk = _load_client_jwk()
    private_key, public_key = _load_keys()
    platform_jwt = PlatformJWT(private_key, public_key)

    # Derive JWKS from public key for the /.well-known/jwks.json endpoint
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    import base64

    pub_key_obj = load_pem_public_key(public_key.encode())
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

    # --- Request lifecycle ---

    @app.teardown_appcontext
    def close_connection(exception):
        db = getattr(g, "_database", None)
        if db is not None:
            db.close()

    # --- Routes ---

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
    def oauth_login():
        """Login page (GET) or initiate OAuth flow (POST)."""
        # Preserve return_to across the login flow — only accept relative URLs
        return_to = request.args.get("return_to") or request.form.get("return_to", "")
        if return_to and not return_to.startswith("/"):
            return_to = ""  # reject absolute URLs (open redirect prevention)
        if return_to:
            session["return_to"] = return_to

        if request.method != "POST":
            return render_template("login.html", return_to=return_to)

        username = request.form.get("username", "").strip()

        # Strip unicode control chars
        username = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", username)

        # Strip @ prefix
        if is_valid_handle(username.removeprefix("@")):
            username = username.removeprefix("@")

        if is_valid_handle(username) or is_valid_did(username):
            login_hint = username

            try:
                did, handle, did_doc = resolve_identity(username)
            except Exception as e:
                flash(f"Failed to resolve identity: {e}", "error")
                return render_template("login.html"), 400

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
            return render_template("login.html"), 400

        logger.info("account Authorization Server: %s", authserver_url)
        if not is_safe_url(authserver_url):
            flash("Invalid authorization server URL", "error")
            return render_template("login.html"), 400

        try:
            authserver_meta = fetch_authserver_meta(authserver_url)
        except Exception as err:
            logger.warning("failed to fetch auth server metadata: %s", err)
            flash("Failed to fetch Auth Server OAuth metadata", "error")
            return render_template("login.html"), 400

        # Generate DPoP private signing key for this session
        dpop_private_jwk = JsonWebKey.generate_key("EC", "P-256", is_private=True)

        # Submit PAR
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

        # Save auth request to DB
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

        # Redirect user to Authorization Server
        auth_url = authserver_meta["authorization_endpoint"]
        if not is_safe_url(auth_url):
            flash("Invalid authorization endpoint", "error")
            return render_template("login.html"), 400
        qparam = urlencode({"client_id": CLIENT_ID, "request_uri": par_request_uri})
        return redirect(f"{auth_url}?{qparam}")

    @app.route("/auth/callback")
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

        # Delete row to prevent replay
        db.execute("DELETE FROM oauth_auth_requests WHERE state = ?", [state])
        db.commit()

        # Verify issuer matches
        if row["authserver_iss"] != authserver_iss:
            abort(400, "Issuer mismatch")
        if row["state"] != state:
            abort(400, "State mismatch")

        # Exchange code for tokens
        tokens, dpop_authserver_nonce = initial_token_request(
            dict(row),
            authorization_code,
            CLIENT_ID,
            REDIRECT_URI,
            client_secret_jwk,
        )

        # Verify the account
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

        # Verify scope
        if row["scope"] != tokens.get("scope"):
            abort(400, "Scope mismatch")

        # Save ATProto OAuth session
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

        # Check if user exists in the users table
        user_model = _get_user_model()
        user = user_model.get(did)

        if user is None:
            # First-time user — redirect to signup
            # Store DID and handle in session for the signup flow
            session["pending_did"] = did
            session["pending_handle"] = handle
            return redirect("/auth/signup")

        # Returning user — update handle if changed
        if user["handle"] != handle:
            user_model.update(did, handle=handle)

        # Fetch display name (best-effort update)
        display_name = _fetch_display_name(did) or user.get("display_name") or handle

        # Issue platform JWT
        token = platform_jwt.create_token(
            user_did=did,
            handle=handle,
            display_name=display_name,
        )

        # Check for a return_to URL (e.g., from MCP consent flow)
        return_to = session.pop("return_to", None)
        # Reject absolute URLs stored in session (defense in depth)
        if return_to and not return_to.startswith("/"):
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

    @app.route("/auth/signup", methods=("GET", "POST"))
    def signup():
        """Signup form for first-time users."""
        pending_did = session.get("pending_did")
        pending_handle = session.get("pending_handle")

        if not pending_did or not pending_handle:
            return redirect("/auth/login")

        default_username = _default_username_from_handle(pending_handle)

        if request.method != "POST":
            return render_template(
                "signup.html",
                handle=pending_handle,
                default_username=default_username,
            )

        username = request.form.get("username", "").strip().lower()

        # Validate username
        valid, error_msg = validate_username(username)
        if not valid:
            flash(error_msg, "error")
            return render_template(
                "signup.html",
                handle=pending_handle,
                default_username=username,
            ), 400

        # Check uniqueness
        user_model = _get_user_model()
        existing = user_model.get_by_username(username)
        if existing:
            flash("Username is already taken", "error")
            return render_template(
                "signup.html",
                handle=pending_handle,
                default_username=username,
            ), 400

        # Fetch display name
        display_name = _fetch_display_name(pending_did) or pending_handle

        # Create user
        try:
            user = user_model.create(
                did=pending_did,
                handle=pending_handle,
                display_name=display_name,
                username=username,
            )
        except Exception as e:
            logger.error("Failed to create user: %s", e)
            flash("Failed to create account. Please try again.", "error")
            return render_template(
                "signup.html",
                handle=pending_handle,
                default_username=username,
            ), 500

        # Clear pending session
        session.pop("pending_did", None)
        session.pop("pending_handle", None)

        # Issue platform JWT
        token = platform_jwt.create_token(
            user_did=pending_did,
            handle=pending_handle,
            display_name=display_name,
        )

        # Check for a return_to URL (e.g., from MCP consent flow)
        return_to = session.pop("return_to", None)
        # Reject absolute URLs stored in session (defense in depth)
        if return_to and not return_to.startswith("/"):
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

    # --- MCP OAuth Consent ---

    consent_key = derive_signing_key(private_key)

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
        # The MCP server's authorize callback is on the wiki subdomain
        base = f"https://{wiki_slug}.{PLATFORM_DOMAIN}/authorize/callback"
        query = urlencode({
            **oauth_params,
            "approval_token": approval_token,
        })
        return f"{base}?{query}"

    @app.route("/auth/oauth/consent", methods=("GET", "POST"))
    def oauth_consent():
        """MCP OAuth consent page.

        GET: Show the consent form (or redirect to login if no platform JWT).
        POST: Process approve/deny.
        """
        if request.method == "POST":
            return _handle_consent_post()
        return _handle_consent_get()

    def _handle_consent_get():
        """Show consent page or redirect to login."""
        oauth_params = _extract_oauth_params()

        # Require at minimum client_id and redirect_uri
        if not oauth_params.get("client_id") or not oauth_params.get("redirect_uri"):
            abort(400, "Missing required OAuth parameters (client_id, redirect_uri)")

        # Extract wiki slug from a 'wiki_slug' param or the Referer
        wiki_slug = request.args.get("wiki_slug", "")
        if not wiki_slug:
            abort(400, "Missing wiki_slug parameter")

        # Check for platform JWT cookie
        cookie_token = request.cookies.get(COOKIE_NAME)
        if not cookie_token:
            # Redirect to login with a relative return URL (path + query)
            return_path = request.full_path.rstrip("?")
            return redirect(f"/auth/login?return_to={quote(return_path, safe='/?=&')}")

        # Validate platform JWT
        try:
            claims = platform_jwt.validate_token(cookie_token)
        except Exception:
            # Invalid/expired token — redirect to login
            return_path = request.full_path.rstrip("?")
            return redirect(f"/auth/login?return_to={quote(return_path, safe='/?=&')}")

        user_did = claims.get("sub")
        handle = claims.get("handle", "")
        display_name = claims.get("name", handle)

        # Check wiki membership: user must have access to the wiki (via ACL,
        # owner_did, or public flag) before the consent form is shown.
        db = _get_db()
        enforcer = AclEnforcer(
            acl_model=AclModel(db),
            wiki_model=WikiModel(db),
        )
        # First try public access; then try user-specific access
        wiki_accessible = False
        try:
            enforcer.check_public_access(wiki_slug)
            wiki_accessible = True
        except AuthError:
            pass
        if not wiki_accessible:
            try:
                enforcer.check_access(user_did, wiki_slug)
                wiki_accessible = True
            except AuthError:
                pass
        if not wiki_accessible:
            abort(403, "You do not have access to this wiki")

        # Look up client name from the MCP OAuth DB (best-effort)
        client_name = oauth_params.get("client_id", "Unknown client")

        # Create a consent token that binds the OAuth params + user + expiry
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
        session["csrf_nonces"] = nonces[-5:]  # keep last 5 for multi-tab
        consent_token = sign_consent_token(consent_payload, consent_key)

        # Determine wiki display name
        wiki_name = f"{wiki_slug}.{PLATFORM_DOMAIN}"

        # Extract scopes for display
        scopes = oauth_params.get("scope", "").split() if oauth_params.get("scope") else []

        return render_template(
            "consent.html",
            client_name=client_name,
            wiki_name=wiki_name,
            handle=handle,
            scopes=scopes,
            consent_token=consent_token,
        )

    def _handle_consent_post():
        """Process consent approval or denial."""
        consent_token_raw = request.form.get("consent_token", "")
        action = request.form.get("action", "")

        if not consent_token_raw:
            abort(400, "Missing consent token")

        # Verify consent token
        payload = verify_consent_token(consent_token_raw, consent_key)
        if payload is None:
            abort(400, "Invalid or expired consent token")

        # Re-verify platform JWT cookie to ensure the same user
        cookie_token = request.cookies.get(COOKIE_NAME)
        if not cookie_token:
            abort(401, "Not authenticated")
        try:
            claims = platform_jwt.validate_token(cookie_token)
        except Exception:
            abort(401, "Invalid platform token")

        if claims.get("sub") != payload.get("user_did"):
            abort(403, "User mismatch")

        # Verify CSRF nonce
        csrf_nonce = payload.get("csrf_nonce")
        if not csrf_nonce:
            abort(403, "Missing CSRF nonce")
        session_nonces = session.get("csrf_nonces", [])
        if csrf_nonce not in session_nonces:
            abort(403, "Invalid CSRF nonce")
        session_nonces.remove(csrf_nonce)
        session["csrf_nonces"] = session_nonces

        # Extract original OAuth params from the consent token
        oauth_params = {k: payload[k] for k in OAUTH_PARAM_NAMES if k in payload}
        wiki_slug = payload.get("wiki_slug", "")
        user_did = payload.get("user_did", "")

        if action == "deny":
            # Redirect to Claude.ai's redirect_uri with error
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
            # Create an approval token — a short-lived signed token that the MCP
            # server's /authorize/callback will accept as proof of consent
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
        # Try to revoke ATProto tokens if we have a session
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
        """OAuth Authorization Server metadata stub.

        robot.wtf is not an AS — this is a minimal stub for discovery.
        """
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

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("error.html", status_code=500, err=e), 500

    @app.errorhandler(400)
    def bad_request_error(e):
        return render_template("error.html", status_code=400, err=e), 400

    return app


# Gunicorn entry point — guard so tests can import without a live environment
try:
    application = create_app()
except Exception:
    application = None  # Tests create their own app via create_app()


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8003, debug=True)
