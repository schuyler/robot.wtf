"""Data access layer for the wikis SQLite table.

Wiki primary key is just the slug (not a composite owner_id:wiki_slug).
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

import hashlib


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    """Convert a sqlite3.Row to a plain dict, or return None."""
    if row is None:
        return None
    return dict(row)


class WikiModel:
    """SQLite data access for the wikis table."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def create(
        self,
        *,
        slug: str,
        owner_did: str,
        display_name: str,
        repo_path: str,
        mcp_token_hash: str,
        is_public: bool = False,
    ) -> dict[str, Any]:
        """Create a new wiki. Returns the wiki dict."""
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT INTO wikis (slug, owner_did, display_name, repo_path,
               mcp_token_hash, is_public, created_at, last_accessed, page_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (slug, owner_did, display_name, repo_path, mcp_token_hash,
             int(is_public), now, now),
        )
        self._conn.commit()
        return self.get(slug)  # type: ignore[return-value]

    def get(self, slug: str) -> dict[str, Any] | None:
        """Get wiki by slug. Returns None if not found."""
        row = self._conn.execute(
            "SELECT * FROM wikis WHERE slug = ?", (slug,)
        ).fetchone()
        return _row_to_dict(row)

    def list_by_owner(self, owner_did: str) -> list[dict[str, Any]]:
        """List all wikis for an owner."""
        rows = self._conn.execute(
            "SELECT * FROM wikis WHERE owner_did = ?", (owner_did,)
        ).fetchall()
        return [dict(r) for r in rows]

    def update(self, slug: str, **updates: Any) -> dict[str, Any]:
        """Update wiki attributes. Returns the updated wiki dict.

        Raises:
            ValueError: If no updates provided or wiki not found.
        """
        if not updates:
            raise ValueError("No updates provided")

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [slug]
        cursor = self._conn.execute(
            f"UPDATE wikis SET {set_clause} WHERE slug = ?",
            values,
        )
        self._conn.commit()
        if cursor.rowcount == 0:
            raise ValueError("Wiki not found")
        return self.get(slug)  # type: ignore[return-value]

    def delete(self, slug: str) -> None:
        """Delete a wiki by slug."""
        self._conn.execute("DELETE FROM wikis WHERE slug = ?", (slug,))
        self._conn.commit()

    def get_by_token(self, plaintext_token: str) -> dict[str, Any] | None:
        """Find a wiki by its MCP bearer token.

        Computes SHA-256 of the plaintext token and looks up by indexed hash.

        Args:
            plaintext_token: The plaintext bearer token to validate.

        Returns:
            The matching wiki dict, or None if no match.
        """
        token_hash = hashlib.sha256(plaintext_token.encode("utf-8")).hexdigest()
        row = self._conn.execute(
            "SELECT * FROM wikis WHERE mcp_token_hash = ?", (token_hash,)
        ).fetchone()
        return dict(row) if row else None
