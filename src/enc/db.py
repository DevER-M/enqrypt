"""SQLite storage for accounts and sessions.

Only account metadata lives here: username, password hash, identity public key
and login sessions. Message contents and private keys never reach the server.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash    TEXT NOT NULL,
    identity_public  TEXT NOT NULL,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    # -- users ---------------------------------------------------------

    def create_user(self, username: str, password_hash: str, identity_public: str) -> sqlite3.Row:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO users (username, password_hash, identity_public, created_at)"
                " VALUES (?, ?, ?, ?)",
                (username, password_hash, identity_public, _now()),
            )
            user_id = cursor.lastrowid
        return self.get_user_by_id(user_id)

    def get_user(self, username: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()

    def get_user_by_id(self, user_id: int) -> sqlite3.Row:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        assert row is not None
        return row

    def set_identity(self, user_id: int, identity_public: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE users SET identity_public = ? WHERE id = ?",
                (identity_public, user_id),
            )

    def list_users(self) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                "SELECT username, identity_public FROM users ORDER BY username COLLATE NOCASE"
            ).fetchall()

    # -- sessions ------------------------------------------------------

    def create_session(self, token_hash: str, user_id: int, expires_at: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, user_id, expires_at),
            )

    def get_session_user(self, token_hash: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id"
                " WHERE sessions.token_hash = ? AND sessions.expires_at > ?",
                (token_hash, _now()),
            ).fetchone()
        return row

    def delete_session(self, token_hash: str) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
