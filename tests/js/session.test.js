import assert from "node:assert/strict";
import test from "node:test";

import {
  b64encode,
  createIdentity,
  verifyCode,
} from "../../src/enc/web/static/js/crypto.js";
import { Role, Session, State } from "../../src/enc/web/static/js/session.js";

const aliceIdentity = createIdentity();
const bobIdentity = createIdentity();
const malloryIdentity = createIdentity();

const alicePublic = b64encode(aliceIdentity.publicKey);
const bobPublic = b64encode(bobIdentity.publicKey);
const malloryPublic = b64encode(malloryIdentity.publicKey);

function aliceOptions(peerIdentity = bobPublic) {
  return { identity: aliceIdentity, peerIdentity };
}

function bobOptions(peerIdentity = alicePublic) {
  return { identity: bobIdentity, peerIdentity };
}

function establish() {
  const alice = Session.initiate("alice", "bob", aliceOptions());
  const bob = Session.respond("bob", "alice", bobOptions());

  const hello = alice.start();
  assert.equal(hello.kind, "hello");
  assert.equal(hello.from, "alice");
  assert.equal(hello.to, "bob");
  assert.equal(hello.session, null);

  const bobResult = bob.handle(hello);
  assert.deepEqual(
    bobResult.out.map((frame) => frame.kind),
    ["ack", "confirm"],
  );
  assert.equal(bobResult.events.length, 0);
  assert.equal(bob.state, State.CONFIRMING);

  const [ack, bobConfirm] = bobResult.out;
  const aliceResult = alice.handle(ack);
  assert.deepEqual(
    aliceResult.out.map((frame) => frame.kind),
    ["confirm"],
  );
  assert.equal(alice.state, State.CONFIRMING);

  const bobDone = bob.handle(aliceResult.out[0]);
  assert.equal(bob.state, State.ACTIVE);
  assert.equal(bobDone.events[0].type, "established");

  const aliceDone = alice.handle(bobConfirm);
  assert.equal(alice.state, State.ACTIVE);
  assert.equal(aliceDone.events[0].type, "established");
  assert.equal(aliceDone.events[0].verifyCode, bobDone.events[0].verifyCode);

  return { alice, bob };
}

test("full handshake and messages both ways", () => {
  const { alice, bob } = establish();

  const atBob = bob.handle(alice.encrypt("hi bob"));
  assert.equal(atBob.events[0].type, "text");
  assert.equal(atBob.events[0].text, "hi bob");
  assert.equal(atBob.events[0].seq, 0);

  const atAlice = alice.handle(bob.encrypt("hi alice"));
  assert.equal(atAlice.events[0].text, "hi alice");
});

test("unicode roundtrips", () => {
  const { alice, bob } = establish();
  const text = "snöbär 🔐 — مرحبا";
  assert.equal(bob.handle(alice.encrypt(text)).events[0].text, text);
});

test("replayed messages are dropped silently", () => {
  const { alice, bob } = establish();
  const frame = alice.encrypt("once");
  assert.equal(bob.handle(frame).events[0].text, "once");
  assert.deepEqual(bob.handle(frame).events, []);
  assert.equal(bob.state, State.ACTIVE);
});

test("tampered messages close the session", () => {
  const { alice, bob } = establish();
  const frame = alice.encrypt("transfer 100");
  frame.payload.ciphertext = b64encode(new Uint8Array(48));
  const result = bob.handle(frame);
  assert.equal(bob.state, State.CLOSED);
  assert.equal(result.events[0].type, "ended");
});

test("confirmation mismatch closes the session", () => {
  const alice = Session.initiate("alice", "bob", aliceOptions());
  const bob = Session.respond("bob", "alice", bobOptions());
  const hello = alice.start();
  const bobResult = bob.handle(hello);

  const ack = structuredClone(bobResult.out[0]);
  ack.payload.nonce = b64encode(new Uint8Array(32).fill(9));
  const aliceResult = alice.handle(ack);
  assert.equal(alice.state, State.CLOSED);
  assert.equal(aliceResult.events[0].type, "ended");
});

test("an unexpected peer identity closes the session", () => {
  const alice = Session.initiate("alice", "bob", aliceOptions());
  // The responder expects a different key for alice than the one she uses.
  const bob = Session.respond("bob", "alice", bobOptions(malloryPublic));

  const result = bob.handle(alice.start());
  assert.equal(bob.state, State.CLOSED);
  assert.equal(result.events[0].type, "ended");
  assert.match(result.events[0].reason, /identity/);
});

test("malformed hello is rejected", () => {
  const alice = Session.initiate("alice", "bob", aliceOptions());
  const bob = Session.respond("bob", "alice", bobOptions());
  const hello = alice.start();
  hello.payload.mlkemPublic = b64encode(new Uint8Array(16));
  const result = bob.handle(hello);
  assert.equal(result.out.length, 0);
  assert.equal(bob.state, State.CLOSED);
  assert.equal(result.events[0].type, "ended");
});

test("messages are rejected before establishment", () => {
  const alice = Session.initiate("alice", "bob", aliceOptions());
  const bob = Session.respond("bob", "alice", bobOptions());
  bob.handle(alice.start());
  assert.throws(() => bob.encrypt("too early"));
});

test("responder cannot start a session", () => {
  assert.throws(() => Session.respond("bob", "alice", bobOptions()).start());
});

test("a session needs an identity and a peer identity", () => {
  assert.throws(() => Session.initiate("alice", "bob", {}));
  assert.throws(() => Session.respond("bob", "alice", { identity: bobIdentity }));
});

test("session ids match and the verification code is stable", () => {
  const { alice, bob } = establish();
  assert.equal(alice.sessionId, bob.sessionId);
  assert.equal(alice.role, Role.INITIATOR);
  assert.equal(bob.role, Role.RESPONDER);
  assert.equal(
    alice.verifyCode,
    verifyCode(aliceIdentity.publicKey, bobIdentity.publicKey),
  );
});

test("the verification code does not change between sessions", () => {
  const first = establish();
  const second = establish();
  assert.notEqual(first.alice.sessionId, second.alice.sessionId);
  assert.equal(first.alice.verifyCode, second.alice.verifyCode);
});

test("the relay-visible frame never contains plaintext", () => {
  const { alice } = establish();
  const text = "the launch code is 0000";
  const serialized = JSON.stringify(alice.encrypt(text));
  assert.ok(!serialized.includes(text));
  assert.ok(serialized.includes("ciphertext"));
});
