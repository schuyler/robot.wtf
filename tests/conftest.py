"""Shared fixtures for robot.wtf tests."""

from __future__ import annotations

import sqlite3

import pytest

from app.db import init_schema
from app.models.user import UserModel
from app.models.wiki import WikiModel


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    """Reset module-level rate limiter singletons between tests.

    The WSGIRateLimiter singletons in management.routes and resolver use
    MemoryStorage which is process-local and persists across test runs.
    This fixture replaces the storage with a fresh instance before each
    test so rate-limit state doesn't bleed between tests.
    """
    from app.rate_limit import WSGIRateLimiter
    import app.management.routes as management_routes
    import app.resolver as resolver_module

    # Replace management limiter
    fresh_mgmt = WSGIRateLimiter()
    fresh_mgmt.add_limit("api_write", "5/minute")
    fresh_mgmt.add_limit("api_read", "15/minute")
    old_mgmt = management_routes._management_limiter
    management_routes._management_limiter = fresh_mgmt

    # Replace resolver limiter
    fresh_resolver = WSGIRateLimiter()
    fresh_resolver.add_limit("wiki_write", "5/minute")
    old_resolver = resolver_module._resolver_limiter
    resolver_module._resolver_limiter = fresh_resolver

    yield

    # Restore originals (not strictly needed since we replaced at start,
    # but keeps the module state cleaner after the suite)
    management_routes._management_limiter = old_mgmt
    resolver_module._resolver_limiter = old_resolver


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
