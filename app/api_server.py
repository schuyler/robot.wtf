"""Platform API service entry point (port 8002).

A lightweight Flask app that:
- Mounts ManagementMiddleware for /api/* routes
- Serves management UI at /app/* (server-rendered Flask templates)
- Serves static files from /srv/static/ (landing page)
- Provides /api/internal/check-slug for Caddy on-demand TLS validation
- Provides /api/me for current user info
"""

from __future__ import annotations

import logging
import os

from flask import (
    Flask,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

from app.auth.acl import AclEnforcer
from app.auth.jwt import PlatformJWT, _load_keys
from app.auth.middleware import AuthMiddleware
from app.db import get_connection
from app.management.routes import (
    ManagementMiddleware,
    _delete_wiki_repo,
    _init_wiki_repo,
    validate_slug,
)
from app.resolver import _init_wiki_db, _initialized_dbs
from app.management.token import generate_mcp_token
from app.models.acl import AclModel
from app.models.user import UserModel
from app.models.wiki import WikiModel

logger = logging.getLogger(__name__)

STATIC_DIR = os.environ.get("ROBOT_STATIC_DIR", "/srv/static")
PLATFORM_DOMAIN = os.environ.get("PLATFORM_DOMAIN", "robot.wtf")
WIKI_BASE = os.environ.get("WIKI_BASE", "/srv/data/wikis")


def _authenticate_cookie(app):
    """Authenticate the current request from the platform_token cookie.

    Returns AuthenticatedUser if valid, or None.
    """
    auth = app.config["AUTH_MIDDLEWARE"]
    cookie_header = request.headers.get("Cookie")
    return auth.authenticate_from_cookie(cookie_header)


def _require_login(app):
    """Authenticate or redirect to login.

    Returns AuthenticatedUser on success, or a redirect Response.
    """
    user = _authenticate_cookie(app)
    if user is None:
        return redirect(f"/auth/login?return_to={request.url}")
    return user


def _is_owner(wiki, acl, user_did):
    """Return True if user_did is the wiki owner.

    Checks wiki.owner_did first (canonical), then falls back to an
    explicit ACL row with role='owner' for backwards compatibility.
    """
    if wiki and wiki.get("owner_did") == user_did:
        return True
    if acl and acl.get("role") == "owner":
        return True
    return False


def _create_flask_app() -> Flask:
    """Create the inner Flask app for non-API routes and management UI."""
    template_dir = os.path.join(
        os.path.dirname(__file__), "management", "templates"
    )
    app = Flask(__name__, template_folder=template_dir, static_folder=None)
    # Secret key for Flask session — must be set in production
    secret_key = os.environ.get("FLASK_SECRET_KEY", "")
    if not secret_key or secret_key.startswith("dev-secret"):
        if os.environ.get("FLASK_ENV") != "testing":
            raise RuntimeError(
                "FLASK_SECRET_KEY must be set to a strong random value in production"
            )
        secret_key = "test-secret-for-testing-only"
    app.secret_key = secret_key

    # --- Static / Landing ---

    @app.route("/api/internal/check-slug")
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
    def landing():
        """Serve the landing page. Authenticated users are redirected to /app/."""
        user = _authenticate_cookie(app)
        if user is not None:
            return redirect("/app/")
        index_path = os.path.join(STATIC_DIR, "index.html")
        if os.path.exists(index_path):
            return send_from_directory(STATIC_DIR, "index.html")
        return "robot.wtf", 200

    @app.route("/static/<path:path>")
    def static_files(path: str):
        """Serve static assets."""
        return send_from_directory(STATIC_DIR, path)

    # --- /api/me ---

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
            "username": record.get("username"),
            "display_name": record.get("display_name"),
        })

    # --- Management UI Routes ---

    @app.route("/app/")
    def dashboard():
        """Dashboard: list user's wikis or show create CTA."""
        result = _require_login(app)
        if not hasattr(result, "user_did"):
            return result  # redirect
        user = result

        wiki_model = app.config["WIKI_MODEL"]
        wikis = wiki_model.list_by_owner(user.user_did)

        return render_template(
            "dashboard.html",
            user=user,
            wikis=wikis,
            platform_domain=PLATFORM_DOMAIN,
        )

    @app.route("/app/create", methods=["GET", "POST"])
    def wiki_create():
        """Create wiki form (GET) or process creation (POST)."""
        result = _require_login(app)
        if not hasattr(result, "user_did"):
            return result
        user = result

        user_model = app.config["USER_MODEL"]
        wiki_model = app.config["WIKI_MODEL"]
        acl_model = app.config["ACL_MODEL"]

        if request.method == "GET":
            default_slug = user.record.get("username", "")
            return render_template(
                "wiki_create.html",
                user=user,
                default_slug=default_slug,
                platform_domain=PLATFORM_DOMAIN,
            )

        # POST: create the wiki
        slug = request.form.get("slug", "").strip().lower()
        display_name = request.form.get("display_name", "").strip()
        purpose = request.form.get("purpose", "").strip()

        if not display_name:
            flash("Display name is required.", "danger")
            return redirect(url_for("wiki_create"))

        valid, error = validate_slug(slug)
        if not valid:
            flash(f"Invalid slug: {error}", "danger")
            return redirect(url_for("wiki_create"))

        # Check tier limit
        wiki_count = int(user.record.get("wiki_count", 0))
        if wiki_count >= 1:
            flash("You can only have one wiki on the free tier.", "danger")
            return redirect(url_for("dashboard"))

        # Check slug availability
        if wiki_model.get(slug):
            flash("That slug is already taken.", "danger")
            return redirect(url_for("wiki_create"))

        # Generate token
        plaintext_token, token_hash = generate_mcp_token()

        # Repo path
        wiki_base = app.config.get("WIKI_BASE", WIKI_BASE)
        repo_path = os.path.join(wiki_base, slug, "repo")

        # Create wiki record
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

        # Create owner ACL
        acl_model.create(
            wiki_slug=slug,
            grantee_did=user.user_did,
            role="owner",
            granted_by=user.user_did,
        )

        # Init git repo
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
                acl_model.delete(slug, user.user_did)
            except Exception:
                pass
            flash("Failed to initialize wiki repository.", "danger")
            return redirect(url_for("wiki_create"))

        # Initialize per-wiki database
        wiki_dir = os.path.join(wiki_base, slug)
        db_path = os.path.join(wiki_dir, "wiki.db")
        _init_wiki_db(db_path, site_name=display_name)

        # Increment wiki count
        user_model.update(user.user_did, wiki_count=wiki_count + 1)

        # Store token in session for the MCP page to display
        flash("Wiki created! Your MCP bearer token is below.", "success")
        session["mcp_token"] = plaintext_token
        return redirect(url_for("mcp_instructions", slug=slug))

    @app.route("/app/wiki/<slug>")
    def wiki_settings(slug):
        """Wiki settings page."""
        result = _require_login(app)
        if not hasattr(result, "user_did"):
            return result
        user = result

        wiki_model = app.config["WIKI_MODEL"]
        acl_model = app.config["ACL_MODEL"]
        wiki = wiki_model.get(slug)
        if not wiki:
            flash("Wiki not found.", "danger")
            return redirect(url_for("dashboard"))

        acl = acl_model.get(slug, user.user_did)
        if not _is_owner(wiki, acl, user.user_did):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        return render_template(
            "wiki_settings.html",
            user=user,
            wiki=wiki,
            platform_domain=PLATFORM_DOMAIN,
        )

    @app.route("/app/wiki/<slug>/settings", methods=["POST"])
    def wiki_settings_update(slug):
        """Update wiki settings (display name, visibility)."""
        result = _require_login(app)
        if not hasattr(result, "user_did"):
            return result
        user = result

        wiki_model = app.config["WIKI_MODEL"]
        acl_model = app.config["ACL_MODEL"]
        wiki = wiki_model.get(slug)
        if not wiki:
            flash("Wiki not found.", "danger")
            return redirect(url_for("dashboard"))

        acl = acl_model.get(slug, user.user_did)
        if not _is_owner(wiki, acl, user.user_did):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        display_name = request.form.get("display_name", "").strip()
        is_public = request.form.get("is_public") == "1"

        updates = {}
        if display_name:
            updates["display_name"] = display_name
        updates["is_public"] = int(is_public)

        wiki_model.update(slug, **updates)
        flash("Settings updated.", "success")
        return redirect(url_for("wiki_settings", slug=slug))

    @app.route("/app/wiki/<slug>/delete", methods=["POST"])
    def wiki_delete(slug):
        """Delete a wiki."""
        result = _require_login(app)
        if not hasattr(result, "user_did"):
            return result
        user = result

        user_model = app.config["USER_MODEL"]
        wiki_model = app.config["WIKI_MODEL"]
        acl_model = app.config["ACL_MODEL"]
        wiki = wiki_model.get(slug)
        if not wiki:
            flash("Wiki not found.", "danger")
            return redirect(url_for("dashboard"))

        acl = acl_model.get(slug, user.user_did)
        if not _is_owner(wiki, acl, user.user_did):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        confirm = request.form.get("confirm_slug", "").strip()
        if confirm != slug:
            flash("Slug confirmation did not match.", "danger")
            return redirect(url_for("wiki_settings", slug=slug))

        # Delete repo
        repo_path = wiki.get("repo_path", "")
        if repo_path:
            wiki_dir = os.path.dirname(repo_path)
            _delete_wiki_repo(wiki_dir)
            # Clear DB initialization cache
            db_path = os.path.join(wiki_dir, "wiki.db")
            _initialized_dbs.discard(db_path)

        # Delete ACLs
        for acl_entry in acl_model.list_by_wiki(slug):
            acl_model.delete(slug, acl_entry["grantee_did"])

        # Delete wiki record
        wiki_model.delete(slug)

        # Decrement wiki count
        wiki_count = int(user.record.get("wiki_count", 0))
        user_model.update(user.user_did, wiki_count=max(0, wiki_count - 1))

        flash(f"Wiki '{slug}' has been deleted.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/app/wiki/<slug>/collaborators")
    def collaborators(slug):
        """Collaborator management page."""
        result = _require_login(app)
        if not hasattr(result, "user_did"):
            return result
        user = result

        user_model = app.config["USER_MODEL"]
        wiki_model = app.config["WIKI_MODEL"]
        acl_model = app.config["ACL_MODEL"]
        wiki = wiki_model.get(slug)
        if not wiki:
            flash("Wiki not found.", "danger")
            return redirect(url_for("dashboard"))

        acl = acl_model.get(slug, user.user_did)
        if not _is_owner(wiki, acl, user.user_did):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        acls = acl_model.list_by_wiki(slug)
        # Enrich ACLs with user handles
        for acl_entry in acls:
            grantee = user_model.get(acl_entry["grantee_did"])
            if grantee:
                acl_entry["user_handle"] = grantee.get("handle", "")

        return render_template(
            "collaborators.html",
            user=user,
            wiki=wiki,
            acls=acls,
            platform_domain=PLATFORM_DOMAIN,
        )

    @app.route("/app/wiki/<slug>/collaborators/add", methods=["POST"])
    def collaborator_add(slug):
        """Add a collaborator."""
        result = _require_login(app)
        if not hasattr(result, "user_did"):
            return result
        user = result

        user_model = app.config["USER_MODEL"]
        wiki_model = app.config["WIKI_MODEL"]
        acl_model = app.config["ACL_MODEL"]
        wiki = wiki_model.get(slug)
        if not wiki:
            flash("Wiki not found.", "danger")
            return redirect(url_for("dashboard"))

        acl = acl_model.get(slug, user.user_did)
        if not _is_owner(wiki, acl, user.user_did):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        grantee_handle = request.form.get("grantee_handle", "").strip()
        role = request.form.get("role", "").strip()

        if role not in ("editor", "viewer"):
            flash("Invalid role.", "danger")
            return redirect(url_for("collaborators", slug=slug))

        if not grantee_handle:
            flash("Bluesky handle or DID is required.", "danger")
            return redirect(url_for("collaborators", slug=slug))

        # Look up user by DID or handle
        if grantee_handle.startswith("did:"):
            grantee = user_model.get(grantee_handle)
        else:
            # Try by username first, then by handle field
            grantee = user_model.get_by_username(grantee_handle)
            if not grantee:
                conn = user_model._conn
                row = conn.execute(
                    "SELECT * FROM users WHERE handle = ?",
                    (grantee_handle,),
                ).fetchone()
                grantee = dict(row) if row else None

        if not grantee:
            flash(
                f"User '{grantee_handle}' not found. They must sign up first.",
                "danger",
            )
            return redirect(url_for("collaborators", slug=slug))

        acl_model.create(
            wiki_slug=slug,
            grantee_did=grantee["did"],
            role=role,
            granted_by=user.user_did,
        )

        flash(
            f"Added {grantee.get('handle', grantee['did'])} as {role}.",
            "success",
        )
        return redirect(url_for("collaborators", slug=slug))

    @app.route("/app/wiki/<slug>/collaborators/revoke", methods=["POST"])
    def collaborator_revoke(slug):
        """Revoke a collaborator's access."""
        result = _require_login(app)
        if not hasattr(result, "user_did"):
            return result
        user = result

        wiki_model = app.config["WIKI_MODEL"]
        acl_model = app.config["ACL_MODEL"]
        wiki = wiki_model.get(slug)
        if not wiki:
            flash("Wiki not found.", "danger")
            return redirect(url_for("dashboard"))

        acl = acl_model.get(slug, user.user_did)
        if not _is_owner(wiki, acl, user.user_did):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        grantee_did = request.form.get("grantee_did", "").strip()
        if grantee_did == user.user_did:
            flash("Cannot revoke owner access.", "danger")
            return redirect(url_for("collaborators", slug=slug))

        acl_model.delete(slug, grantee_did)
        flash("Collaborator access revoked.", "success")
        return redirect(url_for("collaborators", slug=slug))

    @app.route("/app/wiki/<slug>/mcp")
    def mcp_instructions(slug):
        """MCP setup instructions page."""
        result = _require_login(app)
        if not hasattr(result, "user_did"):
            return result
        user = result

        wiki_model = app.config["WIKI_MODEL"]
        acl_model = app.config["ACL_MODEL"]
        wiki = wiki_model.get(slug)
        if not wiki:
            flash("Wiki not found.", "danger")
            return redirect(url_for("dashboard"))

        acl = acl_model.get(slug, user.user_did)
        if not _is_owner(wiki, acl, user.user_did):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        # Check for one-time token display
        mcp_token = session.pop("mcp_token", None)

        return render_template(
            "mcp_instructions.html",
            user=user,
            wiki=wiki,
            mcp_token=mcp_token,
            platform_domain=PLATFORM_DOMAIN,
        )

    @app.route("/app/wiki/<slug>/mcp/regenerate", methods=["POST"])
    def mcp_regenerate(slug):
        """Regenerate MCP bearer token."""
        result = _require_login(app)
        if not hasattr(result, "user_did"):
            return result
        user = result

        wiki_model = app.config["WIKI_MODEL"]
        acl_model = app.config["ACL_MODEL"]
        wiki = wiki_model.get(slug)
        if not wiki:
            flash("Wiki not found.", "danger")
            return redirect(url_for("dashboard"))

        acl = acl_model.get(slug, user.user_did)
        if not _is_owner(wiki, acl, user.user_did):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

        plaintext_token, token_hash = generate_mcp_token()
        wiki_model.update(slug, mcp_token_hash=token_hash)

        session["mcp_token"] = plaintext_token
        flash(
            "Token regenerated. Copy it now -- it will not be shown again.",
            "warning",
        )
        return redirect(url_for("mcp_instructions", slug=slug))

    @app.route("/app/account")
    def account():
        """Account settings page."""
        result = _require_login(app)
        if not hasattr(result, "user_did"):
            return result
        user = result

        user_model = app.config["USER_MODEL"]
        record = user_model.get(user.user_did)

        return render_template(
            "account.html",
            user=user,
            user_record=record,
        )

    @app.route("/app/account/delete", methods=["POST"])
    def account_delete():
        """Delete the current user's account."""
        result = _require_login(app)
        if not hasattr(result, "user_did"):
            return result
        user = result

        user_model = app.config["USER_MODEL"]
        wiki_model = app.config["WIKI_MODEL"]
        acl_model = app.config["ACL_MODEL"]
        record = user_model.get(user.user_did)
        if not record:
            flash("User not found.", "danger")
            return redirect(url_for("dashboard"))

        confirm = request.form.get("confirm_username", "").strip()
        expected = record.get("username") or record.get("handle", "")
        if confirm != expected:
            flash("Confirmation did not match.", "danger")
            return redirect(url_for("account"))

        # Delete all owned wikis
        wikis = wiki_model.list_by_owner(user.user_did)
        for wiki in wikis:
            wiki_slug = wiki["slug"]
            repo_path = wiki.get("repo_path", "")
            if repo_path:
                wiki_dir = os.path.dirname(repo_path)
                _delete_wiki_repo(wiki_dir)
                # Clear DB initialization cache
                db_path = os.path.join(wiki_dir, "wiki.db")
                _initialized_dbs.discard(db_path)
            for acl_entry in acl_model.list_by_wiki(wiki_slug):
                acl_model.delete(wiki_slug, acl_entry["grantee_did"])
            wiki_model.delete(wiki_slug)

        # Delete user record
        user_model.delete(user.user_did)

        flash("Account deleted.", "success")
        resp = make_response(redirect("/"))
        resp.delete_cookie(
            "platform_token",
            domain=f".{PLATFORM_DOMAIN}",
            path="/",
        )
        return resp

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

    # Store models and auth in Flask app config for route handlers
    flask_app.config["AUTH_MIDDLEWARE"] = auth_middleware
    flask_app.config["USER_MODEL"] = user_model
    flask_app.config["WIKI_MODEL"] = wiki_model
    flask_app.config["ACL_MODEL"] = acl_model
    flask_app.config["WIKI_BASE"] = WIKI_BASE

    # Wrap Flask app with ManagementMiddleware
    wsgi_app = ManagementMiddleware(
        flask_app,
        auth_middleware=auth_middleware,
        user_model=user_model,
        wiki_model=wiki_model,
        acl_model=acl_model,
    )

    return wsgi_app


def get_application():
    """Lazy-build the WSGI application (for gunicorn / production)."""
    return _build_app()


# Module-level WSGI entry point -- gunicorn expects `application`.
# Guard with try/except so tests can import _create_flask_app without
# needing a live database or signing key.
try:
    application = _build_app()
except Exception:
    application = None  # Tests create their own Flask app via _create_flask_app


if __name__ == "__main__":
    # For local development / testing
    os.environ.setdefault("GUNICORN_BIND", "0.0.0.0:8002")
    app = _create_flask_app()
    app.run(host="0.0.0.0", port=8002, debug=True)
