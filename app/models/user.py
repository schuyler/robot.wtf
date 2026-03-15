"""Data access layer for the users SQLite table.

User primary key is an ATProto DID (text), not a UUID.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

# Username validation: lowercase alphanumeric + hyphens, 3-30 chars,
# no leading/trailing hyphens
_USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,28}[a-z0-9]$")

RESERVED_USERNAMES = frozenset({
    "admin", "api", "app", "assets", "auth", "billing", "blog",
    "dev", "docs", "help", "mcp", "null", "static", "status",
    "support", "undefined", "wiki", "www",
})


def validate_username(username: str) -> tuple[bool, str | None]:
    """Validate a username against format and reserved-name rules.

    Returns:
        (True, None) if valid, (False, error_message) if invalid.
    """
    if not username:
        return False, "Username is required"
    if username != username.lower():
        return False, "Username must be lowercase"
    if not _USERNAME_PATTERN.match(username):
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        if len(username) > 30:
            return False, "Username must be at most 30 characters"
        if username.startswith("-") or username.endswith("-"):
            return False, "Username must not start or end with a hyphen"
        return False, "Username must contain only lowercase letters, digits, and hyphens"
    if username in RESERVED_USERNAMES:
        return False, "Username is reserved"
    return True, None


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
        username: str,
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

    def get_by_username(self, username: str) -> dict[str, Any] | None:
        """Look up user by username."""
        row = self._conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
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

    def set_username(self, did: str, username: str) -> dict[str, Any]:
        """Set a username for a user, with validation and uniqueness check.

        Raises:
            ValueError: If username is invalid, reserved, or already taken.
        """
        valid, error = validate_username(username)
        if not valid:
            raise ValueError(error)

        existing = self.get_by_username(username)
        if existing and existing["did"] != did:
            raise ValueError("Username is already taken")

        return self.update(did, username=username)

    def delete(self, did: str) -> None:
        """Delete a user by DID."""
        self._conn.execute("DELETE FROM users WHERE did = ?", (did,))
        self._conn.commit()
