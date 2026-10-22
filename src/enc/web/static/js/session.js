/**
 * Session state machine: identity-signed hybrid handshake, then encrypted
 * messages.
 *
 *   negotiating --(initiator: hello out / responder: hello in)--> confirming
 *   confirming  --(peer confirmation verified)------------------> active
 *   any         --(failure, peer offline, close())--------------> closed
 *
 * Each side must know its own long-lived identity key pair and the identity
 * public key it expects for the peer (learned from the server directory and
 * pinned locally). Both handshake peers sign the transcript, so a wrong or
 * substituted identity key fails the session instead of silently succeeding.
 *
 * `handle()` returns envelopes to send plus UI-facing events. It never touches
 * the network.
 */

import {
  CipherState,
  DecryptError,
  ReplayError,
  b64decode,
  b64encode,
  confirmTag,
  createInitiatorHandshake,
  createResponderHandshake,
  verifyCode,
  verifyConfirm,
} from "./crypto.js";

export const State = {
  NEGOTIATING: "negotiating",
  CONFIRMING: "confirming",
  ACTIVE: "active",
  CLOSED: "closed",
};

export const Role = {
  INITIATOR: "initiator",
  RESPONDER: "responder",
};

export const HANDSHAKE_TIMEOUT_MS = 20_000;

function makeEnvelope(kind, me, peer, payload, sessionId = null) {
  return {
    version: 1,
    kind,
    from: me,
    to: peer,
    session: sessionId,
    payload,
  };
}

export class Session {
  constructor(me, peer, role, { identity, peerIdentity } = {}) {
    if (!identity) throw new Error("an identity key pair is required");
    if (!peerIdentity) throw new Error("the peer identity key is required");
    this.me = me;
    this.peer = peer;
    this.role = role;
    this.identity = identity;
    this.peerIdentity = peerIdentity;
    this.state = State.NEGOTIATING;
    this.keys = null;
    this.sendCipher = null;
    this.receiveCipher = null;
    this.initiatorHandshake = null;
    this.responderHandshake = null;
  }

  static initiate(me, peer, options) {
    const session = new Session(me, peer, Role.INITIATOR, options);
    session.initiatorHandshake = createInitiatorHandshake(session.identity, me, peer);
    return session;
  }

  static respond(me, peer, options) {
    return new Session(me, peer, Role.RESPONDER, options);
  }

  get sessionId() {
    return this.keys ? this.keys.sessionId : null;
  }

  get verifyCode() {
    return verifyCode(this.identity.publicKey, b64decode(this.peerIdentity));
  }

  get isActive() {
    return this.state === State.ACTIVE;
  }

  start() {
    if (this.role !== Role.INITIATOR) {
      throw new Error("only the initiator can start a session");
    }
    if (this.state !== State.NEGOTIATING) {
      throw new Error(`cannot start a session in state ${this.state}`);
    }
    return makeEnvelope("hello", this.me, this.peer, this.initiatorHandshake.hello());
  }

  encrypt(text) {
    if (this.state !== State.ACTIVE || !this.sendCipher) {
      throw new Error("no active session");
    }
    return makeEnvelope(
      "message",
      this.me,
      this.peer,
      this.sendCipher.encrypt(text),
      this.sessionId,
    );
  }

  handle(frame) {
    const out = [];
    const events = [];
    if (this.state === State.CLOSED) return { out, events };

    const payload = frame?.payload || {};
    switch (frame?.kind) {
      case "hello":
        this.#onHello(payload, out, events);
        break;
      case "ack":
        this.#onAck(payload, out, events);
        break;
      case "confirm":
        this.#onConfirm(payload, events);
        break;
      case "message":
        this.#onMessage(payload, events);
        break;
      default:
        break;
    }
    return { out, events };
  }

  close() {
    this.state = State.CLOSED;
    this.sendCipher = null;
    this.receiveCipher = null;
  }

  /* ---------------- inbound ---------------- */

  #onHello(payload, out, events) {
    if (this.role !== Role.RESPONDER || this.state !== State.NEGOTIATING) return;
    if (payload.identityPublic !== this.peerIdentity) {
      this.#fail("peer identity key does not match", events);
      return;
    }

    let handshake;
    try {
      handshake = createResponderHandshake(this.identity, this.me, this.peer, payload);
    } catch (error) {
      this.#fail(`invalid handshake offer: ${error.message}`, events);
      return;
    }

    this.responderHandshake = handshake;
    this.#installKeys(handshake.keys);
    this.state = State.CONFIRMING;
    out.push(makeEnvelope("ack", this.me, this.peer, handshake.ack()));
    out.push(
      makeEnvelope(
        "confirm",
        this.me,
        this.peer,
        { tag: b64encode(confirmTag(handshake.keys, Role.RESPONDER)) },
        this.sessionId,
      ),
    );
  }

  #onAck(payload, out, events) {
    if (this.role !== Role.INITIATOR || this.state !== State.NEGOTIATING) return;
    if (payload.identityPublic !== this.peerIdentity) {
      this.#fail("peer identity key does not match", events);
      return;
    }

    let keys;
    try {
      keys = this.initiatorHandshake.finish(payload);
    } catch (error) {
      this.#fail(`invalid handshake response: ${error.message}`, events);
      return;
    }

    this.#installKeys(keys);
    this.state = State.CONFIRMING;
    out.push(
      makeEnvelope(
        "confirm",
        this.me,
        this.peer,
        { tag: b64encode(confirmTag(keys, Role.INITIATOR)) },
        this.sessionId,
      ),
    );
  }

  #onConfirm(payload, events) {
    if (this.state !== State.CONFIRMING || !this.keys) return;

    const peerRole = this.role === Role.INITIATOR ? Role.RESPONDER : Role.INITIATOR;
    let tag = new Uint8Array(0);
    let valid = false;
    try {
      tag = b64decode(payload.tag);
      valid = verifyConfirm(this.keys, peerRole, tag);
    } catch {
      valid = false;
    }
    if (!valid) {
      this.#fail("peer failed handshake confirmation", events);
      return;
    }

    this.state = State.ACTIVE;
    events.push({
      type: "established",
      sessionId: this.keys.sessionId,
      verifyCode: this.verifyCode,
    });
  }

  #onMessage(payload, events) {
    if (this.state !== State.ACTIVE || !this.receiveCipher) return;

    let text;
    try {
      text = this.receiveCipher.decrypt(payload);
    } catch (error) {
      if (error instanceof ReplayError) return;
      if (error instanceof DecryptError) {
        this.#fail(`message failed authentication: ${error.message}`, events);
        return;
      }
      this.#fail("malformed message", events);
      return;
    }
    events.push({ type: "text", text, seq: payload.seq });
  }

  /* ---------------- helpers ---------------- */

  #installKeys(keys) {
    this.keys = keys;
    if (this.role === Role.INITIATOR) {
      [this.sendCipher, this.receiveCipher] = CipherState.forInitiator(keys);
    } else {
      [this.sendCipher, this.receiveCipher] = CipherState.forResponder(keys);
    }
  }

  #fail(reason, events) {
    this.close(reason);
    events.push({ type: "ended", reason });
  }
}
