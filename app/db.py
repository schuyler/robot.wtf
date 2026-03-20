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
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


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
