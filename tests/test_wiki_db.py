"""Tests for per-wiki SQLite database initialization in app.resolver."""

from __future__ import annotations

import os
import sqlite3

import pytest

from app.resolver import _init_wiki_db, _initialized_dbs


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


# --- Tests ---


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


def test_init_wiki_db_no_site_name(db_path):
    _init_wiki_db(db_path)
    # No preferences row should exist when site_name is omitted
    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM preferences").fetchone()[0]
    finally:
        conn.close()
    assert count == 0


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
