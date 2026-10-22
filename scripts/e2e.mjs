/**
 * End-to-end check against the real server.
 *
 * Starts `enc serve`, registers two accounts over HTTP, connects two websocket
 * clients with their session cookies, runs the same browser handshake and
 * message code the UI uses, and asserts that:
 *   - both sides derive the same keys and verification code
 *   - the identity signatures are actually verified
 *   - messages arrive in both directions
 *   - the bytes sent over the wire never contain the plaintext
 *
 * Run with: node scripts/e2e.mjs   (or: npm run e2e)
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";

import { createIdentity } from "../src/enc/web/static/js/crypto.js";
import { Session, State } from "../src/enc/web/static/js/session.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PASSWORD = "correct horse battery";
const SECRET_A = "the eagle lands at midnight";
const SECRET_B = "acknowledged, bringing snacks";

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function pythonPath() {
  const candidate =
    process.platform === "win32"
      ? path.join(ROOT, ".venv", "Scripts", "python.exe")
      : path.join(ROOT, ".venv", "bin", "python");
  return fs.existsSync(candidate) ? candidate : "python3";
}

async function register(base, username, identityPublic) {
  const response = await fetch(`${base}/api/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password: PASSWORD, identityPublic }),
  });
  assert.equal(response.status, 200, await response.text());
  const cookie = response.headers.get("set-cookie");
  assert.ok(cookie, "registration should set a session cookie");
  return cookie.split(";")[0];
}

class Client {
  constructor(url, cookie) {
    this.ws = new WebSocket(url, { headers: { Cookie: cookie } });
    this.buffer = [];
    this.waiters = [];
    this.sent = [];
    this.closed = false;
  }

  async open() {
    await new Promise((resolve, reject) => {
      this.ws.on("open", resolve);
      this.ws.on("error", reject);
    });
    this.ws.on("message", (data) => {
      let message;
      try {
        message = JSON.parse(String(data));
      } catch {
        return;
      }
      const index = this.waiters.findIndex((waiter) => waiter.predicate(message));
      if (index === -1) {
        this.buffer.push(message);
        return;
      }
      const [waiter] = this.waiters.splice(index, 1);
      clearTimeout(waiter.timer);
      waiter.resolve(message);
    });
    this.ws.on("close", () => {
      this.closed = true;
      for (const waiter of this.waiters.splice(0)) {
        clearTimeout(waiter.timer);
        waiter.reject(new Error("websocket closed while waiting"));
      }
    });
    return this;
  }

  send(message) {
    const text = JSON.stringify(message);
    this.sent.push(text);
    this.ws.send(text);
  }

  next(predicate = () => true, timeoutMs = 8000) {
    const existing = this.buffer.findIndex(predicate);
    if (existing !== -1) {
      return Promise.resolve(this.buffer.splice(existing, 1)[0]);
    }
    return new Promise((resolve, reject) => {
      const waiter = { predicate, resolve, reject, timer: null };
      waiter.timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter);
        if (index !== -1) this.waiters.splice(index, 1);
        reject(new Error("timed out waiting for a websocket message"));
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }

  close() {
    this.ws.close();
  }
}

async function waitForHealth(url, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Not listening yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`server did not become healthy at ${url}`);
}

async function stop(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 4000)),
  ]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

async function main() {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const wsBase = `ws://127.0.0.1:${port}/ws`;
  const database = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "enc-e2e-")), "enc.db");

  let logs = "";
  const server = spawn(
    pythonPath(),
    [
      "-m",
      "enc",
      "serve",
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
      "--db",
      database,
      "--log-level",
      "warning",
    ],
    { cwd: ROOT, env: { ...process.env, PYTHONUNBUFFERED: "1" } },
  );
  server.stdout.on("data", (chunk) => (logs += chunk));
  server.stderr.on("data", (chunk) => (logs += chunk));

  try {
    await waitForHealth(`${base}/health`);

    // --- accounts with long-lived identity keys ---
    const aliceIdentity = createIdentity();
    const bobIdentity = createIdentity();
    const aliceCookie = await register(base, "alice", b64(aliceIdentity.publicKey));
    const bobCookie = await register(base, "bob", b64(bobIdentity.publicKey));

    const alice = await new Client(wsBase, aliceCookie).open();
    const welcomeA = await alice.next((m) => m.type === "welcome");
    assert.equal(welcomeA.user, "alice");
    assert.equal(welcomeA.online.length, 0);

    const bob = await new Client(wsBase, bobCookie).open();
    const welcomeB = await bob.next((m) => m.type === "welcome");
    assert.deepEqual(welcomeB.online, ["alice"]);
    await alice.next((m) => m.type === "presence" && m.user === "bob" && m.online === true);
    console.log("accounts registered and both clients connected");

    // --- handshake, using the same code the browser runs ---
    const aliceOptions = {
      identity: aliceIdentity,
      peerIdentity: b64(bobIdentity.publicKey),
    };
    const bobOptions = {
      identity: bobIdentity,
      peerIdentity: b64(aliceIdentity.publicKey),
    };

    const aliceSession = Session.initiate("alice", "bob", aliceOptions);
    alice.send({ type: "relay", to: "bob", frame: aliceSession.start() });

    const relayedHello = await bob.next(
      (m) => m.type === "relay" && m.frame.kind === "hello",
    );
    const bobSession = Session.respond("bob", "alice", bobOptions);
    const bobHandshake = bobSession.handle(relayedHello.frame);
    for (const frame of bobHandshake.out) bob.send({ type: "relay", to: "alice", frame });

    const ack = await alice.next((m) => m.type === "relay" && m.frame.kind === "ack");
    const bobConfirm = await alice.next(
      (m) => m.type === "relay" && m.frame.kind === "confirm",
    );
    const aliceHandshake = aliceSession.handle(ack.frame);
    for (const frame of aliceHandshake.out) alice.send({ type: "relay", to: "bob", frame });

    const aliceConfirm = await bob.next(
      (m) => m.type === "relay" && m.frame.kind === "confirm",
    );
    const bobResult = bobSession.handle(aliceConfirm.frame);
    const aliceResult = aliceSession.handle(bobConfirm.frame);

    assert.equal(bobResult.events[0].type, "established");
    assert.equal(aliceResult.events[0].type, "established");
    assert.equal(aliceSession.state, State.ACTIVE);
    assert.equal(bobSession.state, State.ACTIVE);
    assert.equal(aliceResult.events[0].verifyCode, bobResult.events[0].verifyCode);
    console.log(`identity-verified session, code ${aliceSession.verifyCode}`);

    // --- messages, plus a typing frame and a read receipt ---
    alice.send({ type: "relay", to: "bob", frame: aliceSession.encrypt(SECRET_A) });
    const messageAtBob = await bob.next(
      (m) => m.type === "relay" && m.frame.kind === "message",
    );
    const bobText = bobSession.handle(messageAtBob.frame);
    assert.equal(bobText.events[0].text, SECRET_A);

    bob.send({
      type: "relay",
      to: "alice",
      frame: {
        version: 1,
        kind: "receipt",
        from: "bob",
        to: "alice",
        session: null,
        payload: { seq: bobText.events[0].seq, state: "read" },
      },
    });
    const receipt = await alice.next(
      (m) => m.type === "relay" && m.frame.kind === "receipt",
    );
    assert.equal(receipt.from, "bob");
    assert.equal(receipt.frame.payload.state, "read");

    bob.send({ type: "relay", to: "alice", frame: bobSession.encrypt(SECRET_B) });
    const messageAtAlice = await alice.next(
      (m) => m.type === "relay" && m.frame.kind === "message",
    );
    assert.equal(aliceSession.handle(messageAtAlice.frame).events[0].text, SECRET_B);
    console.log("messages and control frames delivered in both directions");

    // --- the wire carries no plaintext ---
    const wire = [...alice.sent, ...bob.sent].join("\n");
    assert.ok(!wire.includes(SECRET_A), "plaintext leaked onto the wire");
    assert.ok(!wire.includes(SECRET_B), "plaintext leaked onto the wire");
    console.log(`inspected ${alice.sent.length + bob.sent.length} client frames: no plaintext`);

    // --- one connection per account ---
    const closedCode = new Promise((resolve) => bob.ws.on("close", resolve));
    const second = await new Client(wsBase, bobCookie).open();
    await second.next((m) => m.type === "welcome");
    assert.equal(await closedCode, 4409);
    assert.equal(bob.closed, true);
    console.log("a second login takes over the first socket");

    second.close();
    alice.close();
    return 0;
  } catch (error) {
    if (logs.trim()) {
      console.error("\n--- server output ---\n" + logs.trim() + "\n");
    }
    throw error;
  } finally {
    await stop(server);
  }
}

function b64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

main()
  .then((code) => process.exit(code))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
