"""Data access layer for the acls SQLite table.

ACL primary key is (wiki_slug, grantee_did). No composite wiki_id format.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    """Convert a sqlite3.Row to a plain dict, or return None."""
    if row is None:
        return None
    return dict(row)


class AclModel:
    """SQLite data access for the acls table."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def create(
        self,
        *,
        wiki_slug: str,
        grantee_did: str,
        role: str,
        granted_by: str,
    ) -> dict[str, Any]:
        """Create or overwrite an ACL entry (upsert). Returns the ACL dict.

        Raises:
            ValueError: If the role is not valid.
        """
        if role not in ("owner", "editor", "viewer"):
            raise ValueError(f"Invalid role: {role}")

        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT OR REPLACE INTO acls
               (wiki_slug, grantee_did, role, granted_by, granted_at)
               VALUES (?, ?, ?, ?, ?)""",
            (wiki_slug, grantee_did, role, granted_by, now),
        )
        self._conn.commit()
        return self.get(wiki_slug, grantee_did)  # type: ignore[return-value]

    def get(self, wiki_slug: str, grantee_did: str) -> dict[str, Any] | None:
        """Get ACL entry by wiki_slug + grantee_did."""
        row = self._conn.execute(
            "SELECT * FROM acls WHERE wiki_slug = ? AND grantee_did = ?",
            (wiki_slug, grantee_did),
        ).fetchone()
        return _row_to_dict(row)

    def list_by_wiki(self, wiki_slug: str) -> list[dict[str, Any]]:
        """List all ACL entries for a wiki."""
        rows = self._conn.execute(
            "SELECT * FROM acls WHERE wiki_slug = ?", (wiki_slug,)
        ).fetchall()
        return [dict(r) for r in rows]

    def delete(self, wiki_slug: str, grantee_did: str) -> None:
        """Revoke an ACL entry."""
        self._conn.execute(
            "DELETE FROM acls WHERE wiki_slug = ? AND grantee_did = ?",
            (wiki_slug, grantee_did),
        )
        self._conn.commit()
