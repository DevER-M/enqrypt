"""FastAPI app: accounts, a websocket relay and the static web app.

The server stores accounts (username, password hash, identity public key) and
login sessions in SQLite. It does not store messages, and it never holds a
private key: chat traffic is public keys and ciphertext it forwards verbatim.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import re
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from enc import auth
from enc.db import Database

log = logging.getLogger("enc.server")

WEB_DIR = Path(__file__).parent / "web"
STATIC_DIR = WEB_DIR / "static"

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
IDENTITY_PUBLIC_BYTES = 1952  # ML-DSA-65 public key
MAX_FRAME_CHARS = 512 * 1024
DEFAULT_DB = "enc.db"

CLOSE_UNAUTHORIZED = 4401
CLOSE_TAKEN_OVER = 4409

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "base-uri 'none'; "
        "form-action 'self'"
    ),
}


class Credentials(BaseModel):
    username: str
    password: str
    identityPublic: str


class Login(BaseModel):
    username: str
    password: str


class IdentityUpdate(BaseModel):
    identityPublic: str


def _clean_username(username: str) -> str:
    if not USERNAME_RE.match(username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3-32 letters, digits, dots, underscores or hyphens.",
        )
    return username


def _clean_password(password: str) -> str:
    if not 8 <= len(password) <= 128:
        raise HTTPException(status_code=400, detail="Password must be 8-128 characters.")
    return password


def _clean_identity(identity_public: str) -> str:
    try:
        raw = base64.b64decode(identity_public, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Identity key is not valid base64.")
    if len(raw) != IDENTITY_PUBLIC_BYTES:
        raise HTTPException(
            status_code=400, detail="Identity key has the wrong length."
        )
    return identity_public


class Hub:
    """Who is connected, one socket per account.

    A new connection for an account replaces the previous one. Presence is
    keyed by lowercase username but always reported with the canonical spelling
    from the database.
    """

    def __init__(self) -> None:
        self._sockets: dict[str, tuple[str, WebSocket]] = {}

    def add(self, username: str, websocket: WebSocket) -> WebSocket | None:
        key = username.lower()
        previous = self._sockets.get(key)
        self._sockets[key] = (username, websocket)
        return previous[1] if previous else None

    def release(self, username: str, websocket: WebSocket) -> bool:
        key = username.lower()
        current = self._sockets.get(key)
        if current is not None and current[1] is websocket:
            del self._sockets[key]
            return True
        return False

    def socket_for(self, username: str) -> WebSocket | None:
        current = self._sockets.get(username.lower())
        return current[1] if current else None

    def names(self) -> list[str]:
        return sorted((name for name, _ in self._sockets.values()), key=str.lower)

    def is_online(self, username: str) -> bool:
        return username.lower() in self._sockets

    async def send(self, websocket: WebSocket, frame: dict[str, Any]) -> bool:
        try:
            await websocket.send_json(frame)
            return True
        except Exception:  # noqa: BLE001 - a dead socket is reported, not raised
            return False

    async def broadcast(self, frame: dict[str, Any], exclude: WebSocket | None = None) -> None:
        for _, websocket in list(self._sockets.values()):
            if websocket is exclude:
                continue
            await self.send(websocket, frame)


def create_app(db_path: str | Path = DEFAULT_DB, secure_cookies: bool = False) -> FastAPI:
    app = FastAPI(title="enc", docs_url=None, redoc_url=None)
    app.state.db = Database(db_path)
    app.state.secure_cookies = secure_cookies
    hub = Hub()
    app.state.hub = hub

    @app.middleware("http")
    async def add_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"ok": True, "online": len(hub.names())}

    # -- accounts ------------------------------------------------------

    @app.post("/api/register")
    async def register(payload: Credentials, response: Response) -> dict[str, Any]:
        username = _clean_username(payload.username)
        password = _clean_password(payload.password)
        identity = _clean_identity(payload.identityPublic)

        database: Database = app.state.db
        if database.get_user(username) is not None:
            raise HTTPException(status_code=409, detail="That username is taken.")

        user = database.create_user(username, auth.hash_password(password), identity)
        token = auth.start_session(database, user["id"])
        auth.set_session_cookie(response, token, secure_cookies)
        return {"username": user["username"], "identityPublic": user["identity_public"]}

    @app.post("/api/login")
    async def login(payload: Login, response: Response) -> dict[str, Any]:
        database: Database = app.state.db
        user = database.get_user(payload.username.strip())
        if user is None or not auth.verify_password(payload.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Wrong username or password.")

        token = auth.start_session(database, user["id"])
        auth.set_session_cookie(response, token, secure_cookies)
        return {"username": user["username"], "identityPublic": user["identity_public"]}

    @app.post("/api/logout")
    async def logout(request: Request, response: Response) -> dict[str, bool]:
        auth.end_session(app.state.db, request.cookies.get(auth.SESSION_COOKIE))
        auth.clear_session_cookie(response)
        return {"ok": True}

    @app.get("/api/me")
    async def me(user=Depends(auth.current_user)) -> dict[str, Any]:
        return {"username": user["username"], "identityPublic": user["identity_public"]}

    @app.post("/api/identity")
    async def set_identity(
        payload: IdentityUpdate, user=Depends(auth.current_user)
    ) -> dict[str, Any]:
        identity = _clean_identity(payload.identityPublic)
        app.state.db.set_identity(user["id"], identity)
        return {"username": user["username"], "identityPublic": identity}

    @app.get("/api/users")
    async def users(user=Depends(auth.current_user)) -> dict[str, Any]:
        directory = [
            {
                "username": row["username"],
                "identityPublic": row["identity_public"],
                "online": hub.is_online(row["username"]),
            }
            for row in app.state.db.list_users()
            if row["username"].lower() != user["username"].lower()
        ]
        return {"users": directory}

    # -- realtime ------------------------------------------------------

    @app.websocket("/ws")
    async def socket(websocket: WebSocket) -> None:
        user = auth.websocket_user(websocket)
        if user is None:
            await websocket.close(code=CLOSE_UNAUTHORIZED, reason="not signed in")
            return

        username: str = user["username"]
        await websocket.accept()

        previous = hub.add(username, websocket)
        if previous is not None:
            try:
                await previous.close(code=CLOSE_TAKEN_OVER, reason="connected elsewhere")
            except Exception:  # noqa: BLE001
                pass

        others = [name for name in hub.names() if name.lower() != username.lower()]
        await hub.send(
            websocket,
            {
                "type": "welcome",
                "user": username,
                "identityPublic": user["identity_public"],
                "online": others,
            },
        )
        await hub.broadcast(
            {"type": "presence", "user": username, "online": True}, exclude=websocket
        )
        log.info("%s connected (%d online)", username, len(hub.names()))

        try:
            while True:
                raw = await websocket.receive_text()
                await _handle_frame(websocket, hub, username, raw)
        except Exception as error:  # noqa: BLE001 - disconnect or dead socket
            if not isinstance(error, asyncio.CancelledError):
                log.debug("connection ended for %s: %s", username, error)
        finally:
            if hub.release(username, websocket):
                log.info("%s disconnected (%d online)", username, len(hub.names()))
                await hub.broadcast({"type": "presence", "user": username, "online": False})

    return app


async def _handle_frame(websocket: WebSocket, hub: Hub, sender: str, raw: str) -> None:
    if len(raw) > MAX_FRAME_CHARS:
        await hub.send(websocket, {"type": "error", "message": "Frame too large."})
        return

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        await hub.send(websocket, {"type": "error", "message": "Malformed frame."})
        return

    if not isinstance(data, dict) or data.get("type") != "relay":
        return

    recipient = data.get("to")
    frame = data.get("frame")
    if (
        not isinstance(recipient, str)
        or not USERNAME_RE.match(recipient)
        or not isinstance(frame, dict)
    ):
        await hub.send(websocket, {"type": "error", "message": "Invalid relay frame."})
        return

    target = hub.socket_for(recipient)
    if target is None:
        await hub.send(websocket, {"type": "undelivered", "to": recipient})
        return

    await hub.send(target, {"type": "relay", "from": sender, "frame": frame})
