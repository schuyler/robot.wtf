"""ATProto OAuth spike — adapted from bluesky-social/cookbook (CC-0).

Identity-only auth flow for robot.wtf. Runs on port 8003 behind Caddy
at https://robot.wtf/auth/*.

Key differences from the cookbook demo:
- Scope is "atproto" (identity-only, no repo access)
- Fixed client_id at https://robot.wtf/auth/client-metadata.json
- All routes prefixed with /auth/
- JWK loaded from /srv/data/client_jwk.json
- On successful login, displays DID + handle + display name
- No Bluesky posting feature
"""

import json
import os
import re
import sqlite3
import functools
from urllib.parse import urlencode
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    jsonify,
    request,
    g,
    session,
    abort,
)
from authlib.jose import JsonWebKey

from atproto_identity import (
    is_valid_did,
    is_valid_handle,
    resolve_identity,
    pds_endpoint,
)
from atproto_oauth import (
    refresh_token_request,
    revoke_token_request,
    resolve_pds_authserver,
    initial_token_request,
    send_par_auth_request,
    fetch_authserver_meta,
)
from atproto_security import is_safe_url

app = Flask(__name__)

# Configuration — set SECRET_KEY via env or .env file
app.config.from_prefixed_env()

# Load client JWK from file (generated on VPS at /srv/data/client_jwk.json)
JWK_PATH = os.environ.get("CLIENT_JWK_PATH", "/srv/data/client_jwk.json")
with open(JWK_PATH) as f:
    CLIENT_SECRET_JWK = JsonWebKey.import_key(json.load(f))
CLIENT_PUB_JWK = json.loads(CLIENT_SECRET_JWK.as_json(is_private=False))
assert "d" not in CLIENT_PUB_JWK  # sanity: public key must not contain private material

# Identity-only scope — we just need to prove the user owns a DID
OAUTH_SCOPE = "atproto"

# Fixed client_id — the URL where client metadata is served
CLIENT_ID = "https://robot.wtf/auth/client-metadata.json"
REDIRECT_URI = "https://robot.wtf/auth/callback"

# --- Database helpers (SQLite, same pattern as cookbook) ---


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db_path = app.config.get("DATABASE_URL", "/srv/data/atproto_spike.sqlite")
        db = g._database = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.commit()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def init_db():
    print("initializing database...")
    with app.app_context():
        db = get_db()
        with app.open_resource("schema.sql", mode="r") as f:
            db.cursor().executescript(f.read())
        db.commit()


init_db()

# --- Session management ---


@app.before_request
def load_logged_in_user():
    user_did = session.get("user_did")
    if user_did is None:
        g.user = None
    else:
        g.user = (
            get_db()
            .execute("SELECT * FROM oauth_session WHERE did = ?", (user_did,))
            .fetchone()
        )


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect("/auth/login")
        return view(**kwargs)

    return wrapped_view


# --- Routes ---


@app.route("/auth/")
def homepage():
    if g.user:
        return redirect("/auth/profile")
    return redirect("/auth/login")


@app.route("/auth/client-metadata.json")
def oauth_client_metadata():
    """Serve ATProto OAuth client metadata (the client_id URL points here)."""
    return jsonify(
        {
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
                "keys": [CLIENT_PUB_JWK],
            },
            "client_name": "robot.wtf ATProto Spike",
            "client_uri": "https://robot.wtf",
        }
    )


@app.route("/auth/login", methods=("GET", "POST"))
def oauth_login():
    """Login page (GET) or initiate OAuth flow (POST)."""
    if request.method != "POST":
        return render_template("login.html")

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
        print(f"account PDS: {pds_url}")
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

    print(f"account Authorization Server: {authserver_url}")
    assert is_safe_url(authserver_url)
    try:
        authserver_meta = fetch_authserver_meta(authserver_url)
    except Exception as err:
        print(f"failed to fetch auth server metadata: {err}")
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
        CLIENT_SECRET_JWK,
        dpop_private_jwk,
    )
    if resp.status_code == 400:
        print(f"PAR HTTP 400: {resp.json()}")
    resp.raise_for_status()
    par_request_uri = resp.json()["request_uri"]

    print(f"saving oauth_auth_request to DB  state={state}")
    query_db(
        "INSERT INTO oauth_auth_request (state, authserver_iss, did, handle, pds_url, pkce_verifier, scope, dpop_authserver_nonce, dpop_private_jwk) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);",
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
        ],
    )

    # Redirect user to Authorization Server
    auth_url = authserver_meta["authorization_endpoint"]
    assert is_safe_url(auth_url)
    qparam = urlencode({"client_id": CLIENT_ID, "request_uri": par_request_uri})
    return redirect(f"{auth_url}?{qparam}")


@app.route("/auth/callback")
def oauth_callback():
    """OAuth callback — exchange code for token, fetch profile, show result."""
    if error := request.args.get("error"):
        error_description = request.args.get("error_description", "")
        flash(f"Authorization failed: {error}: {error_description}", "error")
        return redirect("/auth/login")

    state = request.args["state"]
    authserver_iss = request.args["iss"]
    authorization_code = request.args["code"]

    row = query_db(
        "SELECT * FROM oauth_auth_request WHERE state = ?;",
        [state],
        one=True,
    )
    if row is None:
        abort(400, "OAuth request not found")

    # Delete row to prevent replay
    query_db("DELETE FROM oauth_auth_request WHERE state = ?;", [state])

    # Verify issuer matches
    assert row["authserver_iss"] == authserver_iss
    assert row["state"] == state

    # Exchange code for tokens
    tokens, dpop_authserver_nonce = initial_token_request(
        row,
        authorization_code,
        CLIENT_ID,
        REDIRECT_URI,
        CLIENT_SECRET_JWK,
    )

    # Verify the account
    if row["did"]:
        did, handle, pds_url = row["did"], row["handle"], row["pds_url"]
        assert tokens["sub"] == did
    else:
        did = tokens["sub"]
        assert is_valid_did(did)
        did, handle, did_doc = resolve_identity(did)
        pds_url = pds_endpoint(did_doc)
        authserver_url = resolve_pds_authserver(pds_url)
        assert authserver_url == authserver_iss

    # Verify scope
    assert row["scope"] == tokens["scope"]

    # Save session
    print(f"saving oauth_session to DB  {did}")
    query_db(
        "INSERT OR REPLACE INTO oauth_session (did, handle, pds_url, authserver_iss, access_token, refresh_token, dpop_authserver_nonce, dpop_private_jwk) VALUES(?, ?, ?, ?, ?, ?, ?, ?);",
        [
            did,
            handle,
            pds_url,
            authserver_iss,
            tokens["access_token"],
            tokens["refresh_token"],
            dpop_authserver_nonce,
            row["dpop_private_jwk"],
        ],
    )

    session["user_did"] = did
    session["user_handle"] = handle

    return redirect("/auth/profile")


@app.route("/auth/profile")
@login_required
def profile():
    """Display the authenticated user's DID, handle, and display name."""
    did = g.user["did"]
    handle = g.user["handle"]

    # Try to fetch display name from Bluesky API (best-effort)
    display_name = None
    try:
        import requests

        resp = requests.get(
            "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
            params={"actor": did},
            timeout=5,
        )
        if resp.status_code == 200:
            profile_data = resp.json()
            display_name = profile_data.get("displayName")
    except Exception as e:
        print(f"Failed to fetch profile: {e}")

    return render_template(
        "profile.html",
        did=did,
        handle=handle,
        display_name=display_name,
    )


@app.route("/auth/logout")
@login_required
def oauth_logout():
    """Clear session and revoke tokens."""
    try:
        revoke_token_request(g.user, CLIENT_ID, CLIENT_SECRET_JWK)
    except Exception as e:
        print("Error during token revocation:", e)

    query_db("DELETE FROM oauth_session WHERE did = ?;", [g.user["did"]])
    session.clear()
    return redirect("/auth/login")


@app.errorhandler(500)
def internal_server_error(e):
    return render_template("error.html", status_code=500, err=e), 500


@app.errorhandler(400)
def bad_request_error(e):
    return render_template("error.html", status_code=400, err=e), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8003, debug=True)
