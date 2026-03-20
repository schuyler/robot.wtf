"""E2E test fixtures — PDS, platform server, Playwright browser context."""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import tempfile
import threading
import time

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from authlib.jose import JsonWebKey


# ---------------------------------------------------------------------------
# PDS fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def pds():
    """Start the mock PDS in a daemon thread. Yield its base URL."""
    from tests.e2e.mock_pds import start_mock_pds

    url, server = start_mock_pds(port=0)  # port=0 → OS picks a free port

    # Point PLC resolution at the mock PDS before yielding
    os.environ["PLC_DIRECTORY_URL"] = url

    yield url

    server.shutdown()


# ---------------------------------------------------------------------------
# Test account
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def test_account(pds):
    """Create a test account on the mock PDS. Returns dict with handle/did/password."""
    handle = "e2etest.test"
    password = "e2e-test-password-123"

    resp = requests.post(
        f"{pds}/xrpc/com.atproto.server.createAccount",
        json={
            "handle": handle,
            "email": "e2e@test.com",
            "password": password,
        },
    )
    if resp.status_code in (200, 201):
        data = resp.json()
        return {
            "handle": data["handle"],
            "did": data["did"],
            "password": password,
        }

    # Account already exists — re-use via createSession
    resp = requests.post(
        f"{pds}/xrpc/com.atproto.server.createSession",
        json={"identifier": handle, "password": password},
    )
    resp.raise_for_status()
    data = resp.json()
    return {
        "handle": data["handle"],
        "did": data["did"],
        "password": password,
    }


# ---------------------------------------------------------------------------
# App environment (env vars, keys, DB)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def app_env(pds, tmp_path_factory):
    """Set up temp directories and env vars for the platform server."""
    tmp = tmp_path_factory.mktemp("e2e")

    # --- RSA signing key (platform JWT) ---
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signing_key_path = str(tmp / "signing_key.pem")
    with open(signing_key_path, "wb") as f:
        f.write(rsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))

    # --- EC P-256 client JWK (ATProto OAuth) ---
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    jwk = JsonWebKey.import_key(ec_pem)
    jwk_dict = json.loads(jwk.as_json(is_private=True))
    jwk_dict["kid"] = "e2e-test-key"
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "ES256"
    client_jwk_path = str(tmp / "client_jwk.json")
    with open(client_jwk_path, "w") as f:
        json.dump(jwk_dict, f)

    # --- Platform DB ---
    db_path = str(tmp / "robot.db")
    from app.db import get_connection, init_schema
    conn = get_connection(db_path)
    init_schema(conn)
    conn.close()

    # --- Wiki storage base ---
    wiki_base = str(tmp / "wikis")
    os.makedirs(wiki_base, exist_ok=True)

    # Pick a free port for the platform server
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    platform_port = sock.getsockname()[1]
    sock.close()

    # Save originals so we can restore them after the session
    _saved = {}
    env_updates = {
        "WIKI_BASE": wiki_base,
        "FLASK_ENV": "testing",
        "ALLOW_HTTP_PDS": "true",
        "FLASK_SECRET_KEY": "e2e-test-secret",
        "PLATFORM_DOMAIN": f"127.0.0.1:{platform_port}",
        "PLC_DIRECTORY_URL": pds,
        "SIGNING_KEY_PATH": signing_key_path,
        "CLIENT_JWK_PATH": client_jwk_path,
        "ROBOT_DB_PATH": db_path,
    }
    for k, v in env_updates.items():
        _saved[k] = os.environ.get(k)
        os.environ[k] = v

    yield {
        "signing_key_path": signing_key_path,
        "client_jwk_path": client_jwk_path,
        "db_path": db_path,
        "wiki_base": wiki_base,
        "platform_port": platform_port,
    }

    # Restore env
    for k, old_val in _saved.items():
        if old_val is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = old_val


# ---------------------------------------------------------------------------
# Platform server
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def platform_server(app_env, pds):
    """Start the consolidated platform server in a daemon thread."""
    from werkzeug.serving import make_server
    # Import create_app AFTER env vars are set
    from app.platform_server import create_app

    app = create_app(
        db_path=app_env["db_path"],
        client_jwk_path=app_env["client_jwk_path"],
        signing_key_path=app_env["signing_key_path"],
    )

    port = app_env["platform_port"]
    server = make_server("127.0.0.1", port, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"

    # Wait for the server to be ready
    for _ in range(30):
        try:
            resp = requests.get(f"{base_url}/auth/client-metadata.json", timeout=2)
            if resp.status_code == 200:
                break
        except requests.ConnectionError:
            pass
        time.sleep(0.3)
    else:
        raise RuntimeError("Platform server failed to start")

    yield base_url

    server.shutdown()


# ---------------------------------------------------------------------------
# Browser fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def browser_context(browser, platform_server):
    """Session-scoped Playwright browser context."""
    context = browser.new_context(
        base_url=platform_server,
        ignore_https_errors=True,
    )
    yield context
    context.close()


@pytest.fixture(scope="session")
def page(browser_context):
    """Session-scoped page (shared across tests that don't need isolation)."""
    pg = browser_context.new_page()
    yield pg
    pg.close()


def _run_oauth_login(browser, platform_server, test_account):
    """Helper: run the full OAuth login flow and return the page with cookie."""
    import re
    context = browser.new_context(ignore_https_errors=True)
    pg = context.new_page()

    pg.goto(f"{platform_server}/auth/login")
    pg.fill("#username", test_account["did"])
    pg.click("#username ~ input[type='submit']")

    # Wait for PDS authorize page
    pg.wait_for_url(re.compile(r"127\.0\.0\.1.*oauth/authorize"), timeout=15000)

    # Fill mock PDS form
    pg.locator("input[name='identifier']").fill(test_account["handle"])
    pg.locator("input[type='password']").fill(test_account["password"])
    pg.locator("button[type='submit'][value='approve']").click()

    # Wait for redirect back to platform
    pg.wait_for_url(re.compile(r"127\.0\.0\.1"), timeout=15000)

    # Verify we got the cookie
    cookies = context.cookies()
    cookie_names = [c["name"] for c in cookies]
    assert "platform_token" in cookie_names, f"Login failed — cookies: {cookie_names}"

    return pg, context


@pytest.fixture
def authenticated_page(browser, platform_server, test_account):
    """Function-scoped: fresh browser context with valid platform_token cookie."""
    pg, context = _run_oauth_login(browser, platform_server, test_account)
    yield pg
    context.close()


@pytest.fixture
def destructive_page(browser, platform_server, test_account):
    """Function-scoped: separate browser context for tests that destroy state."""
    pg, context = _run_oauth_login(browser, platform_server, test_account)
    yield pg
    context.close()


# ---------------------------------------------------------------------------
# Wiki fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def wiki_fixture(app_env, test_account):
    """Create a wiki directly in DB + filesystem. Yield info dict. Clean up after."""
    import hashlib
    from uuid import uuid4
    from app.management.routes import _init_wiki_repo
    from app.resolver import _init_wiki_db
    from app.management.token import generate_mcp_token

    slug = f"e2e-wiki-{uuid4().hex[:8]}"
    display_name = "E2E Test Wiki"
    wiki_base = app_env["wiki_base"]
    db_path = app_env["db_path"]
    owner_did = test_account["did"]

    repo_path = os.path.join(wiki_base, slug, "repo")
    wiki_db_path = os.path.join(wiki_base, slug, "wiki.db")

    plaintext_token, token_hash = generate_mcp_token()

    # Insert into platform DB
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO wikis (slug, owner_did, display_name, repo_path,
           mcp_token_hash, is_public, created_at, last_accessed, page_count)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)""",
        (slug, owner_did, display_name, repo_path, token_hash, 0, now, now),
    )
    conn.commit()
    conn.close()

    # Init git repo
    _init_wiki_repo(repo_path, display_name, f"A wiki created by E2E tests")

    # Init per-wiki DB
    _init_wiki_db(wiki_db_path, site_name=display_name)

    yield {
        "slug": slug,
        "display_name": display_name,
        "repo_path": repo_path,
        "db_path": wiki_db_path,
        "mcp_token": plaintext_token,
    }

    # Teardown
    import shutil
    try:
        wiki_dir = os.path.join(wiki_base, slug)
        if os.path.exists(wiki_dir):
            shutil.rmtree(wiki_dir)
    except Exception:
        pass

    try:
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM wikis WHERE slug = ?", (slug,))
        conn.commit()
        conn.close()
    except Exception:
        pass
