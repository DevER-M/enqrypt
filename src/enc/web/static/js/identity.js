/**
 * Long-lived identity key pair.
 *
 * The ML-DSA-65 private key is generated in the browser and kept in IndexedDB.
 * Only the public key is registered with the account, so the server can never
 * sign as a user. The pair can be exported as a text backup and imported on
 * another browser.
 */

import { ml_dsa65 } from "../vendor/noble.js";
import {
  MLDSA_PUBLIC_BYTES,
  MLDSA_SECRET_BYTES,
  b64decode,
  b64encode,
  fingerprint,
  fromUtf8,
  utf8,
} from "./crypto.js";
import { META, openDatabase, requestResult, transactionDone } from "./idb.js";

const STORE_KEY = "identity";

export class Identity {
  constructor(publicKey, secretKey) {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
  }

  static create() {
    const keypair = ml_dsa65.keygen();
    return new Identity(keypair.publicKey, keypair.secretKey);
  }

  get publicKeyBase64() {
    return b64encode(this.publicKey);
  }

  get fingerprint() {
    return fingerprint(this.publicKey);
  }

  exportKey() {
    return b64encode(
      utf8(JSON.stringify({ publicKey: this.publicKeyBase64, secretKey: b64encode(this.secretKey) })),
    );
  }

  static importKey(text) {
    let parsed;
    try {
      parsed = JSON.parse(fromUtf8(b64decode(String(text).trim())));
    } catch {
      throw new Error("that does not look like an exported identity key");
    }
    const publicKey = b64decode(parsed.publicKey);
    const secretKey = b64decode(parsed.secretKey);
    if (publicKey.length !== MLDSA_PUBLIC_BYTES || secretKey.length !== MLDSA_SECRET_BYTES) {
      throw new Error("identity key has the wrong length");
    }
    return new Identity(publicKey, secretKey);
  }
}

export async function loadIdentity() {
  if (!("indexedDB" in globalThis)) return null;
  const database = await openDatabase();
  try {
    const stored = await requestResult(
      database.transaction(META, "readonly").objectStore(META).get(STORE_KEY),
    );
    if (!stored) return null;
    const publicKey = new Uint8Array(stored.publicKey);
    const secretKey = new Uint8Array(stored.secretKey);
    if (publicKey.length !== MLDSA_PUBLIC_BYTES || secretKey.length !== MLDSA_SECRET_BYTES) {
      return null;
    }
    return new Identity(publicKey, secretKey);
  } finally {
    database.close();
  }
}

export async function saveIdentity(identity) {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(META, "readwrite");
    const done = transactionDone(transaction);
    transaction
      .objectStore(META)
      .put({ publicKey: identity.publicKey, secretKey: identity.secretKey }, STORE_KEY);
    await done;
  } finally {
    database.close();
  }
}

export async function clearIdentity() {
  if (!("indexedDB" in globalThis)) return;
  const database = await openDatabase();
  try {
    const transaction = database.transaction(META, "readwrite");
    const done = transactionDone(transaction);
    transaction.objectStore(META).delete(STORE_KEY);
    await done;
  } finally {
    database.close();
  }
}
