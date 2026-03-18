"""SQLite connection management for robot.wtf.

Provides a connection factory that configures WAL mode and foreign keys.
Database path is configurable via the ROBOT_DB_PATH environment variable.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = "/srv/data/robot.db"


def get_db_path() -> str:
    """Return the configured database file path."""
    return os.environ.get("ROBOT_DB_PATH", DEFAULT_DB_PATH)


def get_connection(db_path: str | None = None) -> sqlite3.Connection:
    """Create a new SQLite connection with WAL mode and foreign keys enabled.

    Args:
        db_path: Path to the SQLite database file. If None, uses
            the ROBOT_DB_PATH env var (default /srv/data/robot.db).
            Use ":memory:" for in-memory databases (testing).

    Returns:
        Configured sqlite3.Connection with row_factory set to sqlite3.Row.
    """
    path = db_path or get_db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def migrate_drop_username(conn: sqlite3.Connection) -> bool:
    """Migrate the users table to drop the username column entirely.

    Uses the SQLite table-rebuild pattern:
      CREATE users_new → INSERT SELECT → DROP users → RENAME users_new

    NOTE: This rebuild loses any triggers on the users table.
    As of this migration there are no triggers, so that is safe.

    Foreign keys are temporarily disabled because wikis.owner_did references
    users(did), and SQLite would otherwise refuse the DROP.

    Returns True if migration was performed, False if column already absent.
    """
    # Check if username column exists via PRAGMA table_info
    rows = conn.execute("PRAGMA table_info(users)").fetchall()
    username_col = next((r for r in rows if r[1] == "username"), None)
    if username_col is None:
        return False  # column doesn't exist — nothing to do

    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        with conn:
            conn.execute(
                """CREATE TABLE users_new (
                    did TEXT PRIMARY KEY,
                    handle TEXT NOT NULL,
                    display_name TEXT,
                    avatar_url TEXT,
                    created_at TEXT NOT NULL,
                    wiki_count INTEGER DEFAULT 0
                )"""
            )
            conn.execute(
                "INSERT INTO users_new SELECT did, handle, display_name, avatar_url, "
                "created_at, wiki_count FROM users"
            )
            conn.execute("DROP TABLE users")
            conn.execute("ALTER TABLE users_new RENAME TO users")
    finally:
        conn.execute("PRAGMA foreign_keys=ON")
    return True


def init_schema(conn: sqlite3.Connection, schema_path: str | None = None) -> None:
    """Initialize the database schema from the SQL file.

    Args:
        conn: An open SQLite connection.
        schema_path: Path to the schema SQL file. Defaults to
            ansible/roles/database/files/schema.sql relative to the repo root.
    """
    if schema_path is None:
        repo_root = Path(__file__).resolve().parent.parent
        schema_path = str(repo_root / "ansible" / "roles" / "database" / "files" / "schema.sql")

    with open(schema_path) as f:
        conn.executescript(f.read())

    migrate_drop_username(conn)
