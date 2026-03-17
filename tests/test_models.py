"""Unit tests for SQLite data models."""

from __future__ import annotations

import sqlite3

import pytest

from app.models.user import UserModel, validate_username, default_username_from_handle
from app.models.wiki import WikiModel


# --- UserModel ---


class TestUserModel:
    def test_create_and_get(self, user_model):
        user = user_model.create(
            did="did:plc:test1",
            handle="bob.bsky.social",
            display_name="Bob",
            username="bob",
        )
        assert user["did"] == "did:plc:test1"
        assert user["handle"] == "bob.bsky.social"
        assert user["display_name"] == "Bob"
        assert user["username"] == "bob"
        assert user["wiki_count"] == 0
        assert user["created_at"] is not None

        fetched = user_model.get("did:plc:test1")
        assert fetched is not None
        assert fetched["did"] == "did:plc:test1"

    def test_get_not_found(self, user_model):
        assert user_model.get("did:plc:nonexistent") is None

    def test_get_by_username(self, user_model):
        user_model.create(
            did="did:plc:u1",
            handle="charlie.bsky.social",
            display_name="Charlie",
            username="charlie",
        )
        found = user_model.get_by_username("charlie")
        assert found is not None
        assert found["did"] == "did:plc:u1"

        assert user_model.get_by_username("nonexistent") is None

    def test_update(self, user_model):
        user_model.create(
            did="did:plc:u2",
            handle="dave.bsky.social",
            display_name="Dave",
            username="dave",
        )
        updated = user_model.update("did:plc:u2", display_name="David")
        assert updated["display_name"] == "David"
        assert updated["handle"] == "dave.bsky.social"  # unchanged

    def test_update_no_updates(self, user_model):
        with pytest.raises(ValueError, match="No updates"):
            user_model.update("did:plc:u2")

    def test_update_not_found(self, user_model):
        with pytest.raises(ValueError, match="User not found"):
            user_model.update("did:plc:nonexistent", display_name="X")

    def test_delete(self, user_model):
        user_model.create(
            did="did:plc:u3",
            handle="eve.bsky.social",
            display_name="Eve",
            username="eve",
        )
        assert user_model.get("did:plc:u3") is not None
        user_model.delete("did:plc:u3")
        assert user_model.get("did:plc:u3") is None

    def test_unique_username_constraint(self, db, user_model):
        user_model.create(
            did="did:plc:u4",
            handle="frank.bsky.social",
            display_name="Frank",
            username="frank",
        )
        with pytest.raises(sqlite3.IntegrityError):
            user_model.create(
                did="did:plc:u5",
                handle="frank2.bsky.social",
                display_name="Frank2",
                username="frank",
            )

    def test_unique_did_constraint(self, db, user_model):
        user_model.create(
            did="did:plc:u6",
            handle="grace.bsky.social",
            display_name="Grace",
            username="grace",
        )
        with pytest.raises(sqlite3.IntegrityError):
            user_model.create(
                did="did:plc:u6",
                handle="grace2.bsky.social",
                display_name="Grace2",
                username="grace2",
            )

    def test_set_username(self, user_model):
        user_model.create(
            did="did:plc:u7",
            handle="heidi.bsky.social",
            display_name="Heidi",
            username="heidi",
        )
        updated = user_model.set_username("did:plc:u7", "heidi-new")
        assert updated["username"] == "heidi-new"

    def test_set_username_taken(self, user_model):
        user_model.create(
            did="did:plc:u8",
            handle="ivan.bsky.social",
            display_name="Ivan",
            username="ivan",
        )
        user_model.create(
            did="did:plc:u9",
            handle="judy.bsky.social",
            display_name="Judy",
            username="judy",
        )
        with pytest.raises(ValueError, match="already taken"):
            user_model.set_username("did:plc:u9", "ivan")


class TestValidateUsername:
    def test_valid(self):
        assert validate_username("alice")[0] is True
        assert validate_username("my-wiki-123")[0] is True
        assert validate_username("abc")[0] is True

    def test_empty(self):
        ok, err = validate_username("")
        assert ok is False
        assert "required" in err.lower()

    def test_uppercase(self):
        ok, err = validate_username("Alice")
        assert ok is False
        assert "lowercase" in err.lower()

    def test_too_short(self):
        ok, err = validate_username("ab")
        assert ok is False
        assert "3 characters" in err

    def test_too_long(self):
        ok, err = validate_username("a" * 31)
        assert ok is False
        assert "30 characters" in err

    def test_leading_hyphen(self):
        ok, err = validate_username("-alice")
        assert ok is False

    def test_trailing_hyphen(self):
        ok, err = validate_username("alice-")
        assert ok is False

    def test_reserved(self):
        ok, err = validate_username("admin")
        assert ok is False
        assert "reserved" in err.lower()


class TestDefaultUsernameFromHandle:
    def test_normal_handle(self):
        assert default_username_from_handle("alice.bsky.social") == "alice"

    def test_short_prefix_padded(self):
        assert default_username_from_handle("ab.bsky.social") == "abwiki"

    def test_empty_handle(self):
        assert default_username_from_handle("") == ""

    def test_reserved_admin(self):
        assert default_username_from_handle("admin.bsky.social") == ""

    def test_not_reserved_user(self):
        # "user" is not in RESERVED_USERNAMES so it passes through
        assert default_username_from_handle("user.bsky.social") == "user"

    def test_hyphen_handle(self):
        assert default_username_from_handle("a-b.bsky.social") == "a-b"

    def test_underscore_stripped(self):
        assert default_username_from_handle("alice_bob.bsky.social") == "alicebob"

    def test_all_hyphens_reserved(self):
        # "----" stripped of hyphens yields "", padded to "wiki",
        # but "wiki" is reserved so the result is ""
        result = default_username_from_handle("----.bsky.social")
        assert result == ""


# --- WikiModel ---


class TestWikiModel:
    def test_create_and_get(self, wiki_model, sample_user):
        wiki = wiki_model.create(
            slug="my-wiki",
            owner_did="did:plc:abc123",
            display_name="My Wiki",
            repo_path="/srv/data/wikis/my-wiki/repo",
            mcp_token_hash="$2b$12$somehash",
        )
        assert wiki["slug"] == "my-wiki"
        assert wiki["owner_did"] == "did:plc:abc123"
        assert wiki["display_name"] == "My Wiki"
        assert wiki["page_count"] == 0
        assert wiki["is_public"] == 0

        fetched = wiki_model.get("my-wiki")
        assert fetched is not None
        assert fetched["slug"] == "my-wiki"

    def test_get_not_found(self, wiki_model):
        assert wiki_model.get("nonexistent") is None

    def test_list_by_owner(self, wiki_model, sample_user):
        wiki_model.create(
            slug="wiki-a",
            owner_did="did:plc:abc123",
            display_name="Wiki A",
            repo_path="/srv/data/wikis/wiki-a/repo",
            mcp_token_hash="$2b$12$hash1",
        )
        wiki_model.create(
            slug="wiki-b",
            owner_did="did:plc:abc123",
            display_name="Wiki B",
            repo_path="/srv/data/wikis/wiki-b/repo",
            mcp_token_hash="$2b$12$hash2",
        )
        wikis = wiki_model.list_by_owner("did:plc:abc123")
        assert len(wikis) == 2
        slugs = {w["slug"] for w in wikis}
        assert slugs == {"wiki-a", "wiki-b"}

    def test_update(self, wiki_model, sample_user):
        wiki_model.create(
            slug="upd-wiki",
            owner_did="did:plc:abc123",
            display_name="Original",
            repo_path="/srv/data/wikis/upd-wiki/repo",
            mcp_token_hash="$2b$12$hash3",
        )
        updated = wiki_model.update("upd-wiki", display_name="Updated")
        assert updated["display_name"] == "Updated"

    def test_update_not_found(self, wiki_model):
        with pytest.raises(ValueError, match="Wiki not found"):
            wiki_model.update("nonexistent", display_name="X")

    def test_delete(self, wiki_model, sample_user):
        wiki_model.create(
            slug="del-wiki",
            owner_did="did:plc:abc123",
            display_name="Delete Me",
            repo_path="/srv/data/wikis/del-wiki/repo",
            mcp_token_hash="$2b$12$hash4",
        )
        assert wiki_model.get("del-wiki") is not None
        wiki_model.delete("del-wiki")
        assert wiki_model.get("del-wiki") is None

    def test_unique_slug_constraint(self, wiki_model, sample_user):
        wiki_model.create(
            slug="unique-wiki",
            owner_did="did:plc:abc123",
            display_name="First",
            repo_path="/srv/data/wikis/unique-wiki/repo",
            mcp_token_hash="$2b$12$hash5",
        )
        with pytest.raises(sqlite3.IntegrityError):
            wiki_model.create(
                slug="unique-wiki",
                owner_did="did:plc:abc123",
                display_name="Second",
                repo_path="/srv/data/wikis/unique-wiki2/repo",
                mcp_token_hash="$2b$12$hash6",
            )

    def test_foreign_key_enforcement(self, wiki_model):
        """Wiki creation should fail if owner_did doesn't exist in users."""
        with pytest.raises(sqlite3.IntegrityError):
            wiki_model.create(
                slug="orphan-wiki",
                owner_did="did:plc:nonexistent",
                display_name="Orphan",
                repo_path="/srv/data/wikis/orphan-wiki/repo",
                mcp_token_hash="$2b$12$hash7",
            )

    def test_get_by_token(self, wiki_model, sample_user):
        import hashlib

        plaintext = "test-token-123"
        hashed = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

        wiki_model.create(
            slug="token-wiki",
            owner_did="did:plc:abc123",
            display_name="Token Wiki",
            repo_path="/srv/data/wikis/token-wiki/repo",
            mcp_token_hash=hashed,
        )

        found = wiki_model.get_by_token(plaintext)
        assert found is not None
        assert found["slug"] == "token-wiki"

        assert wiki_model.get_by_token("wrong-token") is None


