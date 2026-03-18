"""Data access layer for the users SQLite table.

User primary key is an ATProto DID (text), not a UUID.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

# Canonical set of reserved names — used for wiki slug validation.
# Includes infrastructure subdomains and DNS-sensitive names that would
# conflict if slugs become subdomains ({slug}.robot.wtf).
RESERVED_NAMES = frozenset({
    "admin", "api", "app", "assets", "auth", "billing", "blog",
    "dev", "docs", "ftp", "git", "help", "imap", "mail", "mcp",
    "ns", "ns1", "ns2", "null", "pop", "smtp", "ssh", "static",
    "status", "support", "undefined", "user", "vpn", "wiki", "www",
})


def default_username_from_handle(handle: str) -> str:
    """Derive a default username from a Bluesky handle.

    Takes the first segment (before the first dot), lowercases it,
    strips non-alphanumeric/hyphen chars, and pads short results with "wiki".

    Returns "" for empty/None handles or if the derived slug is reserved.
    """
    if not handle:
        return ""
    prefix = handle.split(".")[0].lower()
    # Keep only lowercase alphanumeric and hyphens
    prefix = re.sub(r"[^a-z0-9-]", "", prefix)
    # Strip leading/trailing hyphens
    prefix = prefix.strip("-")
    # Ensure minimum length
    if len(prefix) < 3:
        prefix = prefix + "wiki"
    # Truncate to 30 chars
    prefix = prefix[:30]
    # Return "" if the derived slug is reserved
    if prefix in RESERVED_NAMES:
        return ""
    return prefix


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    """Convert a sqlite3.Row to a plain dict, or return None."""
    if row is None:
        return None
    return dict(row)


class UserModel:
    """SQLite data access for the users table."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def create(
        self,
        *,
        did: str,
        handle: str,
        display_name: str | None = None,
        avatar_url: str | None = None,
        username: str | None = None,
    ) -> dict[str, Any]:
        """Create a new user. Returns the user dict."""
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT INTO users (did, handle, display_name, avatar_url,
               username, created_at, wiki_count)
               VALUES (?, ?, ?, ?, ?, ?, 0)""",
            (did, handle, display_name, avatar_url, username, now),
        )
        self._conn.commit()
        return self.get(did)  # type: ignore[return-value]

    def get(self, did: str) -> dict[str, Any] | None:
        """Get user by DID. Returns None if not found."""
        row = self._conn.execute(
            "SELECT * FROM users WHERE did = ?", (did,)
        ).fetchone()
        return _row_to_dict(row)

    def update(self, did: str, **updates: Any) -> dict[str, Any]:
        """Update user attributes. Returns the updated user dict.

        Raises:
            ValueError: If no updates provided or user not found.
        """
        if not updates:
            raise ValueError("No updates provided")

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [did]
        cursor = self._conn.execute(
            f"UPDATE users SET {set_clause} WHERE did = ?",
            values,
        )
        self._conn.commit()
        if cursor.rowcount == 0:
            raise ValueError("User not found")
        return self.get(did)  # type: ignore[return-value]

    def count(self) -> int:
        """Return the total number of users."""
        row = self._conn.execute("SELECT COUNT(*) FROM users").fetchone()
        return row[0] if row else 0

    def delete(self, did: str) -> None:
        """Delete a user by DID."""
        self._conn.execute("DELETE FROM users WHERE did = ?", (did,))
        self._conn.commit()
