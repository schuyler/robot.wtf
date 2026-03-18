"""Platform API service entry point (port 8002).

A lightweight Flask app that:
- Mounts ManagementMiddleware for /api/* routes
- Serves management UI at /app/* (server-rendered Flask templates)
- Serves static files from /srv/static/ (landing page)
- Provides /api/internal/check-slug for Caddy on-demand TLS validation
- Provides /api/me for current user info
"""

from __future__ import annotations

import importlib.util
import logging
import os
import pathlib
import shutil
import subprocess

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
from app.models.user import UserModel, default_username_from_handle
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


def _get_user_or_redirect():
    """Return g.user set by load_user(), or a redirect response if unauthenticated.

    Avoids double JWT verification — g.user is already populated by before_request.
    """
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


def _create_flask_app() -> Flask:
    """Create the inner Flask app for non-API routes and management UI."""
    template_dir = os.path.join(
        os.path.dirname(__file__), "management", "templates"
    )
    app = Flask(__name__, template_folder=template_dir, static_folder=None)

    # Resolve otterwiki static dir at startup time
    _spec = importlib.util.find_spec("otterwiki")
    if _spec is None or _spec.origin is None:
        raise RuntimeError("otterwiki package not found")
    OTTERWIKI_STATIC = str(pathlib.Path(_spec.origin).parent / "static")

    # Secret key for Flask session — must be set in production
    secret_key = os.environ.get("FLASK_SECRET_KEY", "")
    if not secret_key or secret_key.startswith("dev-secret"):
        if os.environ.get("FLASK_ENV") != "testing":
            raise RuntimeError(
                "FLASK_SECRET_KEY must be set to a strong random value in production"
            )
        secret_key = "test-secret-for-testing-only"
    app.secret_key = secret_key

    # Rate limiting
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["60/minute"],
        storage_uri="memory://",
    )

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

    # --- Otterwiki static assets ---

    @app.route("/app/static/<path:path>")
    @limiter.exempt
    def otterwiki_static(path: str):
        """Serve otterwiki static assets for management UI."""
        return send_from_directory(OTTERWIKI_STATIC, path)

    # --- Auth via before_request + context processor ---

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

    # --- Static / Landing ---

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
        """Dashboard: redirect to first wiki, or show empty-state create CTA."""
        result = _get_user_or_redirect()
        if not hasattr(result, "user_did"):
            return result  # redirect
        user = result

        wiki_model = app.config["WIKI_MODEL"]
        wikis = wiki_model.list_by_owner(user.user_did)

        if wikis:
            return redirect(url_for("wiki_settings", slug=wikis[0]["slug"]))

        return render_template(
            "dashboard.html",
            user=user,
        )

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
            default_slug = user.record.get("username") or default_username_from_handle(user.handle or "")
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
            except Exception:
                pass
            flash("Failed to initialize wiki repository.", "danger")
            return redirect(url_for("wiki_create"))

        # Initialize per-wiki database, seeding the owner
        wiki_dir = os.path.join(wiki_base, slug)
        db_path = os.path.join(wiki_dir, "wiki.db")
        owner_handle = user.handle.split(".")[0] if user.handle else None
        try:
            _init_wiki_db(db_path, site_name=display_name, owner_handle=owner_handle)
        except Exception:
            logger.warning("Failed to pre-initialize wiki DB at %s", db_path, exc_info=True)

        # Increment wiki count
        user_model.update(user.user_did, wiki_count=wiki_count + 1)

        # Store token in session for wiki_settings to display
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
            "wiki_settings.html",
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

        # Delete repo
        repo_path = wiki.get("repo_path", "")
        if repo_path:
            wiki_dir = os.path.dirname(repo_path)
            _delete_wiki_repo(wiki_dir)
            # Clear DB initialization cache
            db_path = os.path.join(wiki_dir, "wiki.db")
            _initialized_dbs.discard(db_path)

        # Delete wiki record
        wiki_model.delete(slug)

        # Decrement wiki count
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
            "account.html",
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

    @app.route("/app/admin/stats")
    def admin_stats():
        """Platform admin monitoring dashboard."""
        result = _require_platform_admin()
        if not hasattr(result, "user_did"):
            return result
        user = result

        # Service status
        services = ["robot-otterwiki", "robot-api", "robot-auth", "robot-mcp"]
        service_status = {}
        for svc in services:
            try:
                proc = subprocess.run(
                    ["systemctl", "is-active", svc],
                    capture_output=True, text=True, timeout=5,
                )
                service_status[svc] = proc.stdout.strip()
            except Exception:
                service_status[svc] = "unknown"

        # Disk usage
        try:
            disk = shutil.disk_usage("/srv")
            disk_total_gb = disk.total / (1024 ** 3)
            disk_used_gb = disk.used / (1024 ** 3)
            disk_free_gb = disk.free / (1024 ** 3)
            disk_pct = int(disk.used / disk.total * 100) if disk.total else 0
        except Exception:
            disk_total_gb = disk_used_gb = disk_free_gb = 0.0
            disk_pct = 0

        # Platform counts
        wiki_model = app.config["WIKI_MODEL"]
        user_model = app.config["USER_MODEL"]
        try:
            wiki_count = wiki_model._conn.execute("SELECT COUNT(*) FROM wikis").fetchone()[0]
        except Exception:
            wiki_count = 0
        try:
            user_count = wiki_model._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        except Exception:
            user_count = 0

        # All wikis list
        try:
            all_wikis = wiki_model._conn.execute(
                "SELECT slug, owner_did, display_name, created_at, last_accessed FROM wikis ORDER BY created_at DESC"
            ).fetchall()
            all_wikis = [dict(r) for r in all_wikis]
        except Exception:
            all_wikis = []

        # Journal tail
        try:
            proc = subprocess.run(
                [
                    "journalctl",
                    "-u", "robot-otterwiki",
                    "-u", "robot-api",
                    "-u", "robot-auth",
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
            "admin_stats.html",
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

    return app


def _build_app():
    """Build the WSGI application with ManagementMiddleware."""
    flask_app = _create_flask_app()

    conn = get_connection()
    user_model = UserModel(conn)
    wiki_model = WikiModel(conn)

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
    flask_app.config["WIKI_BASE"] = WIKI_BASE
    flask_app.config["PLATFORM_ADMIN_DIDS"] = set(
        d.strip() for d in os.environ.get("PLATFORM_ADMIN_DIDS", "").split(",") if d.strip()
    )

    # Wrap Flask app with ManagementMiddleware
    wsgi_app = ManagementMiddleware(
        flask_app,
        auth_middleware=auth_middleware,
        user_model=user_model,
        wiki_model=wiki_model,
    )

    # Trust one X-Forwarded-For hop (set by Caddy) at the outermost WSGI layer
    # so all middleware (including ManagementMiddleware) sees the corrected REMOTE_ADDR
    from werkzeug.middleware.proxy_fix import ProxyFix
    wsgi_app = ProxyFix(wsgi_app, x_for=1, x_proto=1, x_host=1)

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
