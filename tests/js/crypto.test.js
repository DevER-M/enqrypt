import assert from "node:assert/strict";
import test from "node:test";

import {
  CipherState,
  DecryptError,
  ReplayError,
  b64decode,
  b64encode,
  confirmTag,
  createIdentity,
  createInitiatorHandshake,
  createResponderHandshake,
  fingerprint,
  verifyCode,
  verifyConfirm,
} from "../../src/enc/web/static/js/crypto.js";

const INITIATOR = "initiator_to_responder";
const RESPONDER = "responder_to_initiator";

const alice = createIdentity();
const bob = createIdentity();

function pair(initiatorIdentity = alice, responderIdentity = bob) {
  const initiator = createInitiatorHandshake(initiatorIdentity, "alice", "bob");
  const responder = createResponderHandshake(responderIdentity, "bob", "alice", initiator.hello());
  return { initiator, responder, keys: responder.keys };
}

function cipherPair(direction = INITIATOR, sessionId = "deadbeef") {
  const key = crypto.getRandomValues(new Uint8Array(32));
  return [
    new CipherState(key, direction, sessionId),
    new CipherState(key, direction, sessionId),
  ];
}

test("handshake derives identical directional keys", () => {
  const { initiator, responder, keys } = pair();
  const a = initiator.finish(responder.ack());
  const b = keys;

  assert.deepEqual(a.initiatorToResponder, b.initiatorToResponder);
  assert.deepEqual(a.responderToInitiator, b.responderToInitiator);
  assert.deepEqual(a.confirmKey, b.confirmKey);
  assert.deepEqual(a.transcript, b.transcript);
  assert.equal(a.sessionId, b.sessionId);
  assert.notDeepEqual(a.initiatorToResponder, a.responderToInitiator);
  assert.notDeepEqual(a.initiatorToResponder, a.confirmKey);
});

test("every handshake is fresh", () => {
  const first = pair();
  const second = pair();
  const a = first.initiator.finish(first.responder.ack());
  const b = second.initiator.finish(second.responder.ack());
  assert.notDeepEqual(a.initiatorToResponder, b.initiatorToResponder);
  assert.notEqual(a.sessionId, b.sessionId);
});

test("the handshake carries both identity keys", () => {
  const initiator = createInitiatorHandshake(alice, "alice", "bob");
  const hello = initiator.hello();
  assert.equal(hello.identityPublic, b64encode(alice.publicKey));
  assert.equal(b64decode(hello.identityPublic).length, 1952);
  assert.equal(b64decode(hello.signature).length, 3309);

  const responder = createResponderHandshake(bob, "bob", "alice", hello);
  assert.equal(responder.ack().identityPublic, b64encode(bob.publicKey));
});

test("a hello signed by a different key is rejected", () => {
  const impostor = createIdentity();
  const initiator = createInitiatorHandshake(impostor, "alice", "bob");
  const hello = initiator.hello();
  // The impostor signs correctly, but with their own key, then claims to be
  // alice. Verification uses alice's key and the claimed identity, so it fails.
  hello.identityPublic = b64encode(alice.publicKey);
  assert.throws(() => createResponderHandshake(bob, "bob", "alice", hello));
});

test("a tampered hello signature is rejected", () => {
  const initiator = createInitiatorHandshake(alice, "alice", "bob");
  const hello = initiator.hello();
  hello.nonce = b64encode(new Uint8Array(32).fill(5));
  assert.throws(() => createResponderHandshake(bob, "bob", "alice", hello));
});

test("a tampered ack signature is rejected", () => {
  const initiator = createInitiatorHandshake(alice, "alice", "bob");
  const responder = createResponderHandshake(bob, "bob", "alice", initiator.hello());
  const ack = responder.ack();
  ack.signature = b64encode(new Uint8Array(b64decode(ack.signature).length));
  assert.throws(() => initiator.finish(ack));
});

test("confirmation tags are role bound", () => {
  const { initiator, responder, keys } = pair();
  const derived = initiator.finish(responder.ack());
  assert.deepEqual(derived.initiatorToResponder, keys.initiatorToResponder);

  assert.ok(verifyConfirm(keys, "initiator", confirmTag(keys, "initiator")));
  assert.ok(verifyConfirm(keys, "responder", confirmTag(keys, "responder")));
  assert.ok(!verifyConfirm(keys, "responder", confirmTag(keys, "initiator")));
});

test("confirmation tag rejects unknown roles", () => {
  const { keys } = pair();
  assert.throws(() => confirmTag(keys, "bystander"));
});

test("modifying the ack changes the derived keys", () => {
  const initiator = createInitiatorHandshake(alice, "alice", "bob");
  const responder = createResponderHandshake(bob, "bob", "alice", initiator.hello());
  const ack = responder.ack();
  ack.nonce = b64encode(new Uint8Array(32).fill(7));
  // Re-sign is impossible without bob's key, so the ack is rejected outright.
  assert.throws(() => initiator.finish(ack));
});

test("wrong key sizes are rejected", () => {
  const initiator = createInitiatorHandshake(alice, "alice", "bob");
  const hello = initiator.hello();
  hello.mlkemPublic = b64encode(new Uint8Array(32));
  assert.throws(() => createResponderHandshake(bob, "bob", "alice", hello));
});

test("bad base64 is rejected", () => {
  const initiator = createInitiatorHandshake(alice, "alice", "bob");
  const hello = initiator.hello();
  hello.nonce = "not base64!!";
  assert.throws(() => createResponderHandshake(bob, "bob", "alice", hello));
});

test("fingerprints are six groups of five digits", () => {
  const value = fingerprint(alice.publicKey);
  const groups = value.split(" ");
  assert.equal(groups.length, 6);
  for (const group of groups) assert.match(group, /^\d{5}$/);
  assert.equal(value, fingerprint(alice.publicKey));
  assert.notEqual(value, fingerprint(bob.publicKey));
});

test("the verification code is stable and symmetric", () => {
  const code = verifyCode(alice.publicKey, bob.publicKey);
  const groups = code.split(" ");
  assert.equal(groups.length, 12);
  for (const group of groups) assert.match(group, /^\d{5}$/);
  assert.equal(code, verifyCode(alice.publicKey, bob.publicKey));
  assert.equal(code, verifyCode(bob.publicKey, alice.publicKey));
  assert.notEqual(code, verifyCode(alice.publicKey, createIdentity().publicKey));
});

test("base64 roundtrips binary data", () => {
  const bytes = crypto.getRandomValues(new Uint8Array(1184));
  assert.deepEqual(b64decode(b64encode(bytes)), bytes);
});

test("AEAD roundtrip and sequence numbers", () => {
  const state = new CipherState(crypto.getRandomValues(new Uint8Array(32)), INITIATOR, "s");
  const first = state.encrypt("hello");
  const second = state.encrypt("again");
  assert.equal(first.seq, 0);
  assert.equal(second.seq, 1);
  assert.equal(state.decrypt(first), "hello");
  assert.equal(state.decrypt(second), "again");
});

test("replayed payloads are rejected", () => {
  const [sender, receiver] = cipherPair();
  const payload = sender.encrypt("hi");
  assert.equal(receiver.decrypt(payload), "hi");
  assert.throws(() => receiver.decrypt(payload), ReplayError);
});

test("reordered payloads are rejected", () => {
  const [sender, receiver] = cipherPair();
  const first = sender.encrypt("one");
  const second = sender.encrypt("two");
  assert.equal(receiver.decrypt(second), "two");
  assert.throws(() => receiver.decrypt(first), ReplayError);
});

test("tampered ciphertext fails authentication", () => {
  const [sender, receiver] = cipherPair();
  const payload = sender.encrypt("hi");
  const bytes = b64decode(payload.ciphertext);
  bytes[0] ^= 1;
  payload.ciphertext = b64encode(bytes);
  assert.throws(() => receiver.decrypt(payload), DecryptError);
});

test("tampered sequence number fails authentication", () => {
  const [sender, receiver] = cipherPair();
  const payload = sender.encrypt("hi");
  payload.seq = 5;
  assert.throws(() => receiver.decrypt(payload), DecryptError);
});

test("direction is bound into the AAD", () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const sender = new CipherState(key, INITIATOR, "s");
  const wrongDirection = new CipherState(key, RESPONDER, "s");
  assert.throws(() => wrongDirection.decrypt(sender.encrypt("hi")), DecryptError);
});

test("session id is bound into the AAD", () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const sender = new CipherState(key, INITIATOR, "aaaa");
  const other = new CipherState(key, INITIATOR, "bbbb");
  assert.throws(() => other.decrypt(sender.encrypt("hi")), DecryptError);
});

test("a different key cannot decrypt", () => {
  const sender = new CipherState(
    crypto.getRandomValues(new Uint8Array(32)),
    INITIATOR,
    "s",
  );
  const other = new CipherState(
    crypto.getRandomValues(new Uint8Array(32)),
    INITIATOR,
    "s",
  );
  assert.throws(() => other.decrypt(sender.encrypt("hi")), DecryptError);
});

test("malformed payloads are rejected", () => {
  const state = new CipherState(crypto.getRandomValues(new Uint8Array(32)), INITIATOR, "s");
  assert.throws(() => state.decrypt({}), DecryptError);
  assert.throws(
    () => state.decrypt({ seq: 0, nonce: b64encode(new Uint8Array(4)), ciphertext: b64encode(new Uint8Array(4)) }),
    DecryptError,
  );
  assert.throws(
    () => state.decrypt({ seq: "0", nonce: b64encode(new Uint8Array(12)), ciphertext: b64encode(new Uint8Array(4)) }),
    DecryptError,
  );
});
