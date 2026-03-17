"""Shared fixtures for robot.wtf tests."""

from __future__ import annotations

import sqlite3

import pytest

from app.db import init_schema
from app.models.user import UserModel
from app.models.wiki import WikiModel


@pytest.fixture
def db():
    """In-memory SQLite database with schema initialized."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    init_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def user_model(db):
    return UserModel(db)


@pytest.fixture
def wiki_model(db):
    return WikiModel(db)


@pytest.fixture
def sample_user(user_model):
    """Create and return a sample user."""
    return user_model.create(
        did="did:plc:abc123",
        handle="alice.bsky.social",
        display_name="Alice",
        username="alice",
    )


@pytest.fixture
def sample_wiki(wiki_model, sample_user):
    """Create and return a sample wiki (requires sample_user for FK)."""
    return wiki_model.create(
        slug="test-wiki",
        owner_did="did:plc:abc123",
        display_name="Test Wiki",
        repo_path="/srv/data/wikis/test-wiki/repo",
        mcp_token_hash="a" * 64,
    )
