from __future__ import annotations

import base64
from contextlib import ExitStack

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from enc.server import create_app

IDENTITY_A = base64.b64encode(bytes([1]) * 1952).decode()
IDENTITY_B = base64.b64encode(bytes([2]) * 1952).decode()
PASSWORD = "correct horse battery"


@pytest.fixture
def app(tmp_path) -> FastAPI:
    return create_app(db_path=tmp_path / "test.db")


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def new_client(app: FastAPI):
    with ExitStack() as stack:
        def factory() -> TestClient:
            return stack.enter_context(TestClient(app))

        yield factory


def register(client: TestClient, username: str, password: str = PASSWORD, identity: str = IDENTITY_A):
    response = client.post(
        "/api/register",
        json={"username": username, "password": password, "identityPublic": identity},
    )
    assert response.status_code == 200, response.text
    return response.json()


def hello_frame(sender: str = "alice", recipient: str = "bob") -> dict:
    return {
        "version": 1,
        "kind": "hello",
        "from": sender,
        "to": recipient,
        "session": None,
        "payload": {"x25519Public": "AAAA", "mlkemPublic": "BBBB", "nonce": "CCCC"},
    }


# ----------------------------------------------------------------------
# static app
# ----------------------------------------------------------------------


def test_index_serves_app_with_security_headers(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "<title>enc</title>" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_static_assets_are_served(client: TestClient) -> None:
    for path in (
        "/static/app.css",
        "/static/js/main.js",
        "/static/js/crypto.js",
        "/static/js/session.js",
        "/static/js/identity.js",
        "/static/js/api.js",
        "/static/js/connection.js",
        "/static/js/history.js",
        "/static/js/idb.js",
        "/static/js/verify.js",
        "/static/vendor/noble.js",
    ):
        response = client.get(path)
        assert response.status_code == 200, path


def test_health(client: TestClient) -> None:
    assert client.get("/health").json() == {"ok": True, "online": 0}


# ----------------------------------------------------------------------
# accounts
# ----------------------------------------------------------------------


def test_register_creates_an_account_and_signs_in(client: TestClient) -> None:
    body = register(client, "alice")
    assert body == {"username": "alice", "identityPublic": IDENTITY_A}
    assert client.cookies.get("enc_session")
    assert client.get("/api/me").json() == body


def test_register_rejects_duplicate_usernames_case_insensitively(client: TestClient) -> None:
    register(client, "alice")
    response = client.post(
        "/api/register",
        json={"username": "ALICE", "password": PASSWORD, "identityPublic": IDENTITY_B},
    )
    assert response.status_code == 409


def test_register_validates_input(client: TestClient) -> None:
    assert client.post(
        "/api/register",
        json={"username": "no spaces", "password": PASSWORD, "identityPublic": IDENTITY_A},
    ).status_code == 400
    assert client.post(
        "/api/register",
        json={"username": "short", "password": "1234", "identityPublic": IDENTITY_A},
    ).status_code == 400
    assert client.post(
        "/api/register",
        json={"username": "short", "password": PASSWORD, "identityPublic": "not base64!"},
    ).status_code == 400
    assert client.post(
        "/api/register",
        json={
            "username": "short",
            "password": PASSWORD,
            "identityPublic": base64.b64encode(b"short").decode(),
        },
    ).status_code == 400


def test_me_requires_a_session(client: TestClient) -> None:
    assert client.get("/api/me").status_code == 401


def test_login_and_logout(client: TestClient) -> None:
    register(client, "alice")
    client.post("/api/logout")
    assert client.get("/api/me").status_code == 401

    assert client.post(
        "/api/login", json={"username": "ALICE", "password": "wrong"}
    ).status_code == 401

    response = client.post("/api/login", json={"username": "alice", "password": PASSWORD})
    assert response.status_code == 200
    assert response.json() == {"username": "alice", "identityPublic": IDENTITY_A}
    assert client.get("/api/me").status_code == 200


def test_password_is_not_stored_in_plaintext(tmp_path) -> None:
    database = tmp_path / "test.db"
    app = create_app(db_path=database)
    with TestClient(app) as client:
        register(client, "alice")
    assert PASSWORD.encode() not in database.read_bytes()


def test_identity_can_be_replaced(client: TestClient) -> None:
    register(client, "alice")
    response = client.post("/api/identity", json={"identityPublic": IDENTITY_B})
    assert response.status_code == 200
    assert client.get("/api/me").json()["identityPublic"] == IDENTITY_B


def test_directory_lists_other_accounts(new_client) -> None:
    alice = new_client()
    bob = new_client()
    register(alice, "alice")
    register(bob, "bob", identity=IDENTITY_B)

    directory = alice.get("/api/users").json()["users"]
    assert directory == [{"username": "bob", "identityPublic": IDENTITY_B, "online": False}]

    alice.post("/api/logout")
    assert alice.get("/api/users").status_code == 401


# ----------------------------------------------------------------------
# realtime
# ----------------------------------------------------------------------


def test_websocket_requires_a_session(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/ws"):
            pass
    assert excinfo.value.code == 4401


def test_welcome_and_presence(new_client) -> None:
    alice = new_client()
    bob = new_client()
    register(alice, "alice")
    register(bob, "bob", identity=IDENTITY_B)

    with alice.websocket_connect("/ws") as alice_socket:
        assert alice_socket.receive_json() == {
            "type": "welcome",
            "user": "alice",
            "identityPublic": IDENTITY_A,
            "online": [],
        }

        with bob.websocket_connect("/ws") as bob_socket:
            assert bob_socket.receive_json()["online"] == ["alice"]
            assert alice_socket.receive_json() == {
                "type": "presence",
                "user": "bob",
                "online": True,
            }

        assert alice_socket.receive_json() == {
            "type": "presence",
            "user": "bob",
            "online": False,
        }


def test_presence_uses_canonical_spelling(new_client) -> None:
    alice = new_client()
    bob = new_client()
    register(alice, "Alice")
    register(bob, "bob", identity=IDENTITY_B)

    with alice.websocket_connect("/ws") as alice_socket:
        assert alice_socket.receive_json()["user"] == "Alice"
        with bob.websocket_connect("/ws") as bob_socket:
            assert bob_socket.receive_json()["online"] == ["Alice"]


def test_relay_forwards_frames_verbatim(new_client) -> None:
    alice = new_client()
    bob = new_client()
    register(alice, "alice")
    register(bob, "bob", identity=IDENTITY_B)

    with alice.websocket_connect("/ws") as alice_socket:
        alice_socket.receive_json()
        with bob.websocket_connect("/ws") as bob_socket:
            bob_socket.receive_json()
            alice_socket.receive_json()  # presence

            frame = hello_frame()
            alice_socket.send_json({"type": "relay", "to": "bob", "frame": frame})
            assert bob_socket.receive_json() == {
                "type": "relay",
                "from": "alice",
                "frame": frame,
            }


def test_relay_reports_undelivered(new_client) -> None:
    alice = new_client()
    register(alice, "alice")

    with alice.websocket_connect("/ws") as alice_socket:
        alice_socket.receive_json()
        alice_socket.send_json({"type": "relay", "to": "nobody", "frame": hello_frame()})
        assert alice_socket.receive_json() == {"type": "undelivered", "to": "nobody"}


def test_a_new_login_takes_over_the_socket(new_client) -> None:
    alice = new_client()
    register(alice, "alice")

    with alice.websocket_connect("/ws") as first:
        first.receive_json()
        with alice.websocket_connect("/ws") as second:
            second.receive_json()
            with pytest.raises(WebSocketDisconnect) as excinfo:
                first.receive_json()
            assert excinfo.value.code == 4409


def test_malformed_input_does_not_close_the_connection(new_client) -> None:
    alice = new_client()
    register(alice, "alice")

    with alice.websocket_connect("/ws") as socket:
        socket.receive_json()

        socket.send_text("not json")
        assert socket.receive_json()["type"] == "error"

        socket.send_json({"type": "relay", "to": "bad name", "frame": {}})
        assert socket.receive_json()["type"] == "error"

        socket.send_json({"type": "relay", "to": "nobody", "frame": hello_frame()})
        assert socket.receive_json()["type"] == "undelivered"


def test_oversized_frames_are_rejected(new_client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("enc.server.MAX_FRAME_CHARS", 128)
    alice = new_client()
    register(alice, "alice")

    with alice.websocket_connect("/ws") as socket:
        socket.receive_json()
        socket.send_text("x" * 200)
        assert socket.receive_json() == {"type": "error", "message": "Frame too large."}
