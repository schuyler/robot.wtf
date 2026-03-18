"""Unit tests for SQLite data models."""

from __future__ import annotations

import sqlite3

import pytest

from app.models.user import UserModel, default_username_from_handle
from app.models.wiki import WikiModel


# --- UserModel ---


class TestUserModel:
    def test_create_and_get(self, user_model):
        user = user_model.create(
            did="did:plc:test1",
            handle="bob.bsky.social",
            display_name="Bob",
        )
        assert user["did"] == "did:plc:test1"
        assert user["handle"] == "bob.bsky.social"
        assert user["display_name"] == "Bob"
        assert user["username"] is None
        assert user["wiki_count"] == 0
        assert user["created_at"] is not None

        fetched = user_model.get("did:plc:test1")
        assert fetched is not None
        assert fetched["did"] == "did:plc:test1"

    def test_create_without_username_succeeds(self, user_model):
        """Creating a user without username should succeed (nullable)."""
        user = user_model.create(
            did="did:plc:nouser1",
            handle="nouser.bsky.social",
            display_name="No User",
        )
        assert user["username"] is None

    def test_create_with_username(self, user_model):
        """Creating a user with username should still work."""
        user = user_model.create(
            did="did:plc:withuser1",
            handle="withuser.bsky.social",
            display_name="With User",
            username="withuser",
        )
        assert user["username"] == "withuser"

    def test_get_not_found(self, user_model):
        assert user_model.get("did:plc:nonexistent") is None

    def test_update(self, user_model):
        user_model.create(
            did="did:plc:u2",
            handle="dave.bsky.social",
            display_name="Dave",
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
        )
        assert user_model.get("did:plc:u3") is not None
        user_model.delete("did:plc:u3")
        assert user_model.get("did:plc:u3") is None

    def test_unique_username_constraint(self, db, user_model):
        """Two users with the same non-NULL username should fail."""
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

    def test_null_username_not_unique_constraint(self, db, user_model):
        """Two users with NULL username should NOT conflict (nullable unique)."""
        user_model.create(
            did="did:plc:null1",
            handle="null1.bsky.social",
            display_name="Null1",
        )
        # This should not raise
        user_model.create(
            did="did:plc:null2",
            handle="null2.bsky.social",
            display_name="Null2",
        )
        assert user_model.get("did:plc:null1") is not None
        assert user_model.get("did:plc:null2") is not None

    def test_unique_did_constraint(self, db, user_model):
        user_model.create(
            did="did:plc:u6",
            handle="grace.bsky.social",
            display_name="Grace",
        )
        with pytest.raises(sqlite3.IntegrityError):
            user_model.create(
                did="did:plc:u6",
                handle="grace2.bsky.social",
                display_name="Grace2",
            )



class TestDefaultUsernameFromHandle:
    def test_normal_handle(self):
        assert default_username_from_handle("alice.bsky.social") == "alice"

    def test_short_prefix_padded(self):
        assert default_username_from_handle("ab.bsky.social") == "abwiki"

    def test_empty_handle(self):
        assert default_username_from_handle("") == ""

    def test_reserved_admin(self):
        assert default_username_from_handle("admin.bsky.social") == ""

    def test_reserved_user(self):
        # "user" is now in RESERVED_NAMES so it returns ""
        assert default_username_from_handle("user.bsky.social") == ""

    def test_reserved_mail(self):
        # DNS-sensitive names are reserved
        assert default_username_from_handle("mail.bsky.social") == ""

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


