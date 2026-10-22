/**
 * Browser-side primitives: hybrid X25519 + ML-KEM-768 for key agreement,
 * ML-DSA-65 for identity signatures and ChaCha20-Poly1305 for messages.
 *
 * Nothing here touches the network. Keys are created in the browser and never
 * leave it.
 *
 * Two different trust anchors are in play:
 *   - the ephemeral hybrid handshake gives a forward-secret session key, and
 *   - the long-lived ML-DSA identity key signs the handshake so a peer can
 *     never be impersonated inside the session.
 *
 * The verification code shown to users is derived from the two identity keys,
 * so it is stable for a given pair of accounts instead of changing with every
 * session.
 */

import {
  chacha20poly1305,
  hkdf,
  hmac,
  ml_dsa65,
  ml_kem768,
  sha256,
  x25519,
} from "../vendor/noble.js";

/* ------------------------------------------------------------------ */
/* constants                                                           */
/* ------------------------------------------------------------------ */

const DOMAIN = utf8("enc/hybrid/v1");
const IDENTITY_DOMAIN = utf8("enc/identity/v1");
const AEAD_DOMAIN = "enc/aead/v1";

export const NONCE_BYTES = 32;
export const AEAD_NONCE_BYTES = 12;
export const MLKEM_PUBLIC_BYTES = 1184;
export const MLKEM_CIPHERTEXT_BYTES = 1088;
export const X25519_PUBLIC_BYTES = 32;
export const MLDSA_PUBLIC_BYTES = 1952;
export const MLDSA_SECRET_BYTES = 4032;
export const MLDSA_SIGNATURE_BYTES = 3309;
export const MAX_PLAINTEXT_BYTES = 64 * 1024;
export const MAX_TEXT_BYTES = 32 * 1024;

const ROLE_INITIATOR = "initiator";
const ROLE_RESPONDER = "responder";
const DIRECTION_INITIATOR = "initiator_to_responder";
const DIRECTION_RESPONDER = "responder_to_initiator";

export class DecryptError extends Error {}
export class ReplayError extends Error {}

/* ------------------------------------------------------------------ */
/* encoding helpers                                                    */
/* ------------------------------------------------------------------ */

export function utf8(text) {
  return new TextEncoder().encode(text);
}

export function fromUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

export function b64encode(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function b64decode(value) {
  if (typeof value !== "string") {
    throw new Error("expected a base64 string");
  }
  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new Error("invalid base64");
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function concatBytes(...parts) {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function hex(bytes) {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function u32be(value) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function checkLength(name, bytes, expected) {
  if (bytes.length !== expected) {
    throw new Error(`${name} must be ${expected} bytes, got ${bytes.length}`);
  }
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function compareBytes(a, b) {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/* ------------------------------------------------------------------ */
/* identities and fingerprints                                         */
/* ------------------------------------------------------------------ */

export function createIdentity() {
  const keypair = ml_dsa65.keygen();
  return { publicKey: keypair.publicKey, secretKey: keypair.secretKey };
}

export function fingerprint(publicKey) {
  return groups(concatBytes(IDENTITY_DOMAIN, utf8("/fingerprint|"), publicKey), 6);
}

export function verifyCode(publicKeyA, publicKeyB) {
  const [first, second] =
    compareBytes(publicKeyA, publicKeyB) <= 0
      ? [publicKeyA, publicKeyB]
      : [publicKeyB, publicKeyA];
  return groups(
    concatBytes(
      IDENTITY_DOMAIN,
      utf8("/pair|"),
      u32be(first.length),
      first,
      u32be(second.length),
      second,
    ),
    12,
  );
}

function groups(seed, count) {
  const out = [];
  let counter = 0;
  while (out.length < count) {
    const digest = sha256(concatBytes(seed, u32be(counter)));
    for (let offset = 0; offset + 4 <= digest.length && out.length < count; offset += 4) {
      const value =
        digest[offset] * 2 ** 24 +
        digest[offset + 1] * 2 ** 16 +
        digest[offset + 2] * 2 ** 8 +
        digest[offset + 3];
      out.push(String(value % 100000).padStart(5, "0"));
    }
    counter += 1;
  }
  return out.join(" ");
}

/* ------------------------------------------------------------------ */
/* handshake                                                           */
/* ------------------------------------------------------------------ */

function transcriptHash(parts) {
  const hasher = sha256.create();
  hasher.update(DOMAIN);
  for (const part of parts) {
    hasher.update(u32be(part.length));
    hasher.update(part);
  }
  return hasher.digest();
}

/**
 * Sign over the exact values that travel on the wire (base64 strings), so both
 * sides hash identical bytes without having to re-encode anything.
 */
function signable(label, parts) {
  const chunks = [IDENTITY_DOMAIN, utf8(`/${label}|`)];
  for (const part of parts) {
    const bytes = typeof part === "string" ? utf8(part) : part;
    chunks.push(u32be(bytes.length), bytes);
  }
  return concatBytes(...chunks);
}

function helloMessage(initiator, responder, identityPublic, x25519Public, mlkemPublic, nonce) {
  return signable("hello", [
    initiator,
    responder,
    identityPublic,
    x25519Public,
    mlkemPublic,
    nonce,
  ]);
}

function ackMessage(initiator, responder, hello, identityPublic, x25519Public, ciphertext, nonce) {
  return signable("ack", [
    initiator,
    responder,
    hello.identityPublic,
    hello.x25519Public,
    hello.mlkemPublic,
    hello.nonce,
    identityPublic,
    x25519Public,
    ciphertext,
    nonce,
  ]);
}

function deriveKeys(sharedMlkem, sharedX25519, transcript) {
  const okm = hkdf(
    sha256,
    concatBytes(sharedMlkem, sharedX25519),
    transcript,
    utf8("enc/hybrid/v1/session"),
    96,
  );
  return {
    sessionId: hex(transcript.slice(0, 8)),
    initiatorToResponder: okm.slice(0, 32),
    responderToInitiator: okm.slice(32, 64),
    confirmKey: okm.slice(64, 96),
    transcript,
  };
}

export function createInitiatorHandshake(identity, me, peer) {
  const x25519Secret = x25519.utils.randomSecretKey();
  const x25519Public = x25519.getPublicKey(x25519Secret);
  const kem = ml_kem768.keygen();
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));

  const identityPublic = b64encode(identity.publicKey);
  const helloFields = {
    x25519Public: b64encode(x25519Public),
    mlkemPublic: b64encode(kem.publicKey),
    nonce: b64encode(nonce),
  };
  const signature = ml_dsa65.sign(
    helloMessage(
      me,
      peer,
      identityPublic,
      helloFields.x25519Public,
      helloFields.mlkemPublic,
      helloFields.nonce,
    ),
    identity.secretKey,
  );

  return {
    hello() {
      return { ...helloFields, identityPublic, signature: b64encode(signature) };
    },

    finish(ack) {
      const peerX25519 = b64decode(ack.x25519Public);
      const ciphertext = b64decode(ack.mlkemCiphertext);
      const peerNonce = b64decode(ack.nonce);
      const peerIdentity = b64decode(ack.identityPublic);
      const peerSignature = b64decode(ack.signature);
      checkLength("x25519Public", peerX25519, X25519_PUBLIC_BYTES);
      checkLength("mlkemCiphertext", ciphertext, MLKEM_CIPHERTEXT_BYTES);
      checkLength("nonce", peerNonce, NONCE_BYTES);
      checkLength("identityPublic", peerIdentity, MLDSA_PUBLIC_BYTES);
      checkLength("signature", peerSignature, MLDSA_SIGNATURE_BYTES);

      const message = ackMessage(
        me,
        peer,
        { identityPublic, ...helloFields },
        ack.identityPublic,
        ack.x25519Public,
        ack.mlkemCiphertext,
        ack.nonce,
      );
      if (!ml_dsa65.verify(peerSignature, message, peerIdentity)) {
        throw new Error("peer signature is not valid");
      }

      const sharedMlkem = ml_kem768.decapsulate(ciphertext, kem.secretKey);
      const sharedX25519 = x25519.getSharedSecret(x25519Secret, peerX25519);
      const transcript = transcriptHash([
        identity.publicKey,
        x25519Public,
        kem.publicKey,
        nonce,
        peerIdentity,
        peerX25519,
        ciphertext,
        peerNonce,
      ]);
      return deriveKeys(sharedMlkem, sharedX25519, transcript);
    },
  };
}

export function createResponderHandshake(identity, me, peer, hello) {
  const peerX25519 = b64decode(hello.x25519Public);
  const peerMlkem = b64decode(hello.mlkemPublic);
  const peerNonce = b64decode(hello.nonce);
  const peerIdentity = b64decode(hello.identityPublic);
  const peerSignature = b64decode(hello.signature);
  checkLength("x25519Public", peerX25519, X25519_PUBLIC_BYTES);
  checkLength("mlkemPublic", peerMlkem, MLKEM_PUBLIC_BYTES);
  checkLength("nonce", peerNonce, NONCE_BYTES);
  checkLength("identityPublic", peerIdentity, MLDSA_PUBLIC_BYTES);
  checkLength("signature", peerSignature, MLDSA_SIGNATURE_BYTES);

  const message = helloMessage(
    peer,
    me,
    hello.identityPublic,
    hello.x25519Public,
    hello.mlkemPublic,
    hello.nonce,
  );
  if (!ml_dsa65.verify(peerSignature, message, peerIdentity)) {
    throw new Error("peer signature is not valid");
  }

  const x25519Secret = x25519.utils.randomSecretKey();
  const x25519Public = x25519.getPublicKey(x25519Secret);
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));

  const sharedX25519 = x25519.getSharedSecret(x25519Secret, peerX25519);
  const encapsulated = ml_kem768.encapsulate(peerMlkem);

  const transcript = transcriptHash([
    peerIdentity,
    peerX25519,
    peerMlkem,
    peerNonce,
    identity.publicKey,
    x25519Public,
    encapsulated.cipherText,
    nonce,
  ]);

  const signature = ml_dsa65.sign(
    ackMessage(
      peer,
      me,
      hello,
      b64encode(identity.publicKey),
      b64encode(x25519Public),
      b64encode(encapsulated.cipherText),
      b64encode(nonce),
    ),
    identity.secretKey,
  );

  return {
    peerIdentityPublic: hello.identityPublic,
    keys: deriveKeys(encapsulated.sharedSecret, sharedX25519, transcript),
    ack() {
      return {
        x25519Public: b64encode(x25519Public),
        mlkemCiphertext: b64encode(encapsulated.cipherText),
        nonce: b64encode(nonce),
        identityPublic: b64encode(identity.publicKey),
        signature: b64encode(signature),
      };
    },
  };
}

export function confirmTag(keys, role) {
  if (role !== ROLE_INITIATOR && role !== ROLE_RESPONDER) {
    throw new Error("role must be 'initiator' or 'responder'");
  }
  return hmac(
    sha256,
    keys.confirmKey,
    concatBytes(DOMAIN, utf8(`/confirm|${role}|`), keys.transcript),
  );
}

export function verifyConfirm(keys, role, tag) {
  return equalBytes(confirmTag(keys, role), tag);
}

/* ------------------------------------------------------------------ */
/* messages                                                            */
/* ------------------------------------------------------------------ */

export class CipherState {
  constructor(key, direction, sessionId) {
    if (key.length !== 32) throw new Error("key must be 32 bytes");
    if (direction !== DIRECTION_INITIATOR && direction !== DIRECTION_RESPONDER) {
      throw new Error("invalid direction");
    }
    this.key = key;
    this.direction = direction;
    this.sessionId = sessionId;
    this.sendSeq = 0;
    this.highestRecvSeq = -1;
  }

  static forInitiator(keys) {
    return [
      new CipherState(keys.initiatorToResponder, DIRECTION_INITIATOR, keys.sessionId),
      new CipherState(keys.responderToInitiator, DIRECTION_RESPONDER, keys.sessionId),
    ];
  }

  static forResponder(keys) {
    return [
      new CipherState(keys.responderToInitiator, DIRECTION_RESPONDER, keys.sessionId),
      new CipherState(keys.initiatorToResponder, DIRECTION_INITIATOR, keys.sessionId),
    ];
  }

  #aad(seq) {
    return utf8(`${AEAD_DOMAIN}|${this.sessionId}|${this.direction}|${seq}`);
  }

  #messageKey(nonce) {
    return hkdf(
      sha256,
      this.key,
      nonce,
      utf8(`${AEAD_DOMAIN}/message-key|${this.direction}`),
      32,
    );
  }

  encrypt(text) {
    const plaintext = utf8(text);
    if (plaintext.length > MAX_PLAINTEXT_BYTES) {
      throw new Error(`message exceeds ${MAX_PLAINTEXT_BYTES} bytes`);
    }
    const seq = this.sendSeq;
    this.sendSeq += 1;
    const nonce = crypto.getRandomValues(new Uint8Array(AEAD_NONCE_BYTES));
    const ciphertext = chacha20poly1305(
      this.#messageKey(nonce),
      nonce,
      this.#aad(seq),
    ).encrypt(plaintext);
    return {
      seq,
      nonce: b64encode(nonce),
      ciphertext: b64encode(ciphertext),
    };
  }

  decrypt(payload) {
    const seq = payload?.seq;
    if (!Number.isInteger(seq) || seq < 0) {
      throw new DecryptError("invalid sequence number");
    }
    if (seq <= this.highestRecvSeq) {
      throw new ReplayError("sequence number already seen");
    }
    const nonce = b64decode(payload.nonce);
    const ciphertext = b64decode(payload.ciphertext);
    if (nonce.length !== AEAD_NONCE_BYTES) {
      throw new DecryptError("invalid nonce");
    }

    let plaintext;
    try {
      plaintext = chacha20poly1305(
        this.#messageKey(nonce),
        nonce,
        this.#aad(seq),
      ).decrypt(ciphertext);
    } catch {
      throw new DecryptError("authentication failed");
    }
    this.highestRecvSeq = seq;
    return fromUtf8(plaintext);
  }
}
