"""Password hashing and cookie sessions.

Passwords use scrypt from the standard library, so there is no extra
dependency. Session tokens are stored hashed in the database, so a leaked
database cannot be replayed as a login.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, Response, WebSocket

from enc.db import Database

SESSION_COOKIE = "enc_session"
SESSION_TTL = timedelta(days=14)

_SCRYPT_PARAMS = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT_PARAMS)
    return "scrypt${}${}".format(
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except (ValueError, TypeError):
        return False
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT_PARAMS)
    return hmac.compare_digest(digest, expected)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def start_session(database: Database, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(UTC) + SESSION_TTL).isoformat()
    database.create_session(_hash_token(token), user_id, expires)
    return token


def user_for_token(database: Database, token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    return database.get_session_user(_hash_token(token))


def end_session(database: Database, token: str | None) -> None:
    if token:
        database.delete_session(_hash_token(token))


def set_session_cookie(response: Response, token: str, secure: bool) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


def current_user(request: Request) -> sqlite3.Row:
    """FastAPI dependency: the logged-in user, or 401."""
    user = user_for_token(request.app.state.db, request.cookies.get(SESSION_COOKIE))
    if user is None:
        raise HTTPException(status_code=401, detail="Not signed in")
    return user


def websocket_user(websocket: WebSocket) -> sqlite3.Row | None:
    return user_for_token(
        websocket.app.state.db, websocket.cookies.get(SESSION_COOKIE)
    )
