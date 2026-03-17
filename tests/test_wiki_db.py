"""Tests for per-wiki SQLite database initialization in app.resolver."""

from __future__ import annotations

import os
import sqlite3

import pytest

from app.resolver import _init_wiki_db, _initialized_dbs

# The full set of preferences that _init_wiki_db should seed on every init.
# These are the access-control preferences that Otterwiki reads from the DB
# but for which otterwiki's defaults (ANONYMOUS) are wrong for a platform wiki.
EXPECTED_SEEDED_PREFERENCES = {
    "READ_ACCESS",
    "WRITE_ACCESS",
    "ATTACHMENT_ACCESS",
    "AUTH_METHOD",
    "DISABLE_REGISTRATION",
    "_schema_version",
}


@pytest.fixture(autouse=True)
def clear_initialized_dbs():
    """Clear the _initialized_dbs set before each test to avoid cross-test pollution."""
    _initialized_dbs.clear()
    yield
    _initialized_dbs.clear()


@pytest.fixture
def tmp_wiki_dir(tmp_path):
    """Return a temporary directory path for a wiki."""
    wiki_dir = tmp_path / "wikis" / "test-wiki"
    wiki_dir.mkdir(parents=True)
    return str(wiki_dir)


@pytest.fixture
def db_path(tmp_wiki_dir):
    return os.path.join(tmp_wiki_dir, "wiki.db")


def _get_tables(db_path: str) -> set:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        return {r[0] for r in rows}
    finally:
        conn.close()


def _get_preference(db_path: str, name: str):
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT value FROM preferences WHERE name = ?", (name,)
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def _get_all_preferences(db_path: str) -> dict:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT name, value FROM preferences").fetchall()
        return {r[0]: r[1] for r in rows}
    finally:
        conn.close()


def _get_user(db_path: str, email: str) -> dict | None:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            'SELECT name, email, is_admin, is_approved, allow_read, allow_write, allow_upload '
            'FROM "user" WHERE email = ?',
            (email,)
        ).fetchone()
        if row is None:
            return None
        return {
            "name": row[0],
            "email": row[1],
            "is_admin": bool(row[2]),
            "is_approved": bool(row[3]),
            "allow_read": bool(row[4]),
            "allow_write": bool(row[5]),
            "allow_upload": bool(row[6]),
        }
    finally:
        conn.close()


def _get_journal_mode(db_path: str) -> str:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("PRAGMA journal_mode").fetchone()
        return row[0] if row else ""
    finally:
        conn.close()


# --- Existing tests (preserved) ---


def test_init_wiki_db_creates_tables(db_path):
    _init_wiki_db(db_path)
    tables = _get_tables(db_path)
    assert "preferences" in tables
    assert "drafts" in tables
    assert "user" in tables
    assert "cache" in tables


def test_init_wiki_db_idempotent(db_path):
    _init_wiki_db(db_path)
    # Should not raise on second call (CREATE TABLE IF NOT EXISTS + cache check)
    _initialized_dbs.discard(db_path)  # bypass cache to force second DB open
    _init_wiki_db(db_path)
    tables = _get_tables(db_path)
    assert "preferences" in tables


def test_init_wiki_db_seeds_site_name(db_path):
    _init_wiki_db(db_path, site_name="My Test Wiki")
    value = _get_preference(db_path, "SITE_NAME")
    assert value == "My Test Wiki"


def test_init_wiki_db_preserves_existing_site_name(db_path):
    _init_wiki_db(db_path, site_name="Original Name")
    # Clear cache and call again with a different name
    _initialized_dbs.discard(db_path)
    _init_wiki_db(db_path, site_name="Different Name")
    # INSERT OR IGNORE means original value is preserved
    value = _get_preference(db_path, "SITE_NAME")
    assert value == "Original Name"


def test_init_wiki_db_caching(db_path):
    assert db_path not in _initialized_dbs
    _init_wiki_db(db_path)
    assert db_path in _initialized_dbs


def test_init_wiki_db_creates_parent_dirs(tmp_path):
    """_init_wiki_db should create missing parent directories."""
    db_path = str(tmp_path / "new" / "nested" / "dir" / "wiki.db")
    _init_wiki_db(db_path)
    assert os.path.exists(db_path)


def test_init_wiki_db_skips_when_cached(db_path):
    """Second call with db_path already in _initialized_dbs is a no-op."""
    _initialized_dbs.add(db_path)
    # db_path does not exist — if _init_wiki_db tried to open it, it would succeed
    # but we verify it does NOT touch the file by confirming it still doesn't exist
    _init_wiki_db(db_path)
    assert not os.path.exists(db_path)


# --- Phase 2 Unit 5: comprehensive hardening tests ---


def test_init_seeds_all_preferences(db_path):
    """After init, all expected platform-mode preferences exist in DB."""
    _init_wiki_db(db_path)
    prefs = _get_all_preferences(db_path)
    for key in EXPECTED_SEEDED_PREFERENCES:
        assert key in prefs, f"Missing preference: {key}"


def test_init_sets_wal_mode(db_path):
    """Database journal_mode should be WAL after init."""
    _init_wiki_db(db_path)
    mode = _get_journal_mode(db_path)
    assert mode == "wal"


def test_init_seeds_owner(db_path):
    """When owner_handle is provided, owner is seeded with admin flags."""
    _init_wiki_db(db_path, owner_handle="alice.bsky.social", owner_name="Alice")
    user = _get_user(db_path, "@alice.bsky.social")
    assert user is not None
    assert user["is_admin"] is True
    assert user["is_approved"] is True
    assert user["allow_read"] is True
    assert user["allow_write"] is True
    assert user["allow_upload"] is True
    assert user["name"] == "Alice"


def test_init_idempotent_no_duplicate_rows(db_path):
    """Calling _init_wiki_db twice doesn't duplicate preference rows."""
    _init_wiki_db(db_path, site_name="Wiki", owner_handle="alice.bsky.social")
    first_prefs = _get_all_preferences(db_path)

    _initialized_dbs.discard(db_path)
    _init_wiki_db(db_path, site_name="Wiki", owner_handle="alice.bsky.social")
    second_prefs = _get_all_preferences(db_path)

    assert first_prefs == second_prefs

    # Verify user table has exactly one owner row
    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute(
            'SELECT COUNT(*) FROM "user" WHERE email = ?', ("@alice.bsky.social",)
        ).fetchone()[0]
    finally:
        conn.close()
    assert count == 1


def test_init_preserves_existing_preferences(db_path):
    """If a preference was changed by user, re-init doesn't overwrite it."""
    # First init seeds defaults
    _init_wiki_db(db_path)

    # Simulate user changing READ_ACCESS to APPROVED
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE preferences SET value = ? WHERE name = ?",
            ("APPROVED", "READ_ACCESS"),
        )
        conn.commit()
    finally:
        conn.close()

    # Re-init (bypass cache)
    _initialized_dbs.discard(db_path)
    _init_wiki_db(db_path)

    # User's change must be preserved
    assert _get_preference(db_path, "READ_ACCESS") == "APPROVED"


def test_init_schema_version_present(db_path):
    """_schema_version key must be present after init."""
    _init_wiki_db(db_path)
    version = _get_preference(db_path, "_schema_version")
    assert version is not None
    assert len(version) > 0


def test_init_access_defaults_are_registered(db_path):
    """Default access levels should be REGISTERED (not ANONYMOUS) in platform mode."""
    _init_wiki_db(db_path)
    assert _get_preference(db_path, "READ_ACCESS") == "REGISTERED"
    assert _get_preference(db_path, "WRITE_ACCESS") == "REGISTERED"
    assert _get_preference(db_path, "ATTACHMENT_ACCESS") == "REGISTERED"


def test_init_auth_method_is_proxy_header(db_path):
    """AUTH_METHOD should be PROXY_HEADER for platform wikis."""
    _init_wiki_db(db_path)
    assert _get_preference(db_path, "AUTH_METHOD") == "PROXY_HEADER"


def test_init_disable_registration_is_true(db_path):
    """DISABLE_REGISTRATION should be seeded True for platform wikis."""
    _init_wiki_db(db_path)
    assert _get_preference(db_path, "DISABLE_REGISTRATION") == "True"
