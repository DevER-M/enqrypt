/**
 * Local conversation storage.
 *
 * Messages are stored in IndexedDB encrypted with a random per-browser key
 * using XChaCha20-Poly1305. The key lives in the same database, so this keeps
 * casual inspection from reading the database, not a determined attacker with
 * access to the browser profile. It is a convenience layer, not a vault.
 */

import { xchacha20poly1305 } from "../vendor/noble.js";
import { fromUtf8, utf8 } from "./crypto.js";
import {
  MESSAGES,
  META,
  openDatabase,
  requestResult,
  transactionDone,
} from "./idb.js";

const DEVICE_KEY = "device-key";

export class History {
  #db;
  #key;

  constructor(database) {
    this.#db = database;
  }

  static async open() {
    if (!("indexedDB" in globalThis)) return new History(null);
    const database = await openDatabase();
    const history = new History(database);
    history.#key = await history.#loadKey();
    return history;
  }

  async #loadKey() {
    const store = this.#db.transaction(META, "readonly").objectStore(META);
    const existing = await requestResult(store.get(DEVICE_KEY));
    if (existing instanceof Uint8Array && existing.length === 32) {
      return existing;
    }

    const key = crypto.getRandomValues(new Uint8Array(32));
    const transaction = this.#db.transaction(META, "readwrite");
    const finished = transactionDone(transaction);
    transaction.objectStore(META).put(key, DEVICE_KEY);
    await finished;
    return key;
  }

  async add(peer, entry) {
    if (!this.#db || !this.#key) return;
    const nonce = crypto.getRandomValues(new Uint8Array(24));
    const plaintext = utf8(
      JSON.stringify({
        direction: entry.direction,
        text: entry.text,
        at: entry.at,
      }),
    );
    const ciphertext = xchacha20poly1305(this.#key, nonce).encrypt(plaintext);

    const transaction = this.#db.transaction(MESSAGES, "readwrite");
    const finished = transactionDone(transaction);
    transaction.objectStore(MESSAGES).put({ peer, at: entry.at, nonce, ciphertext });
    await finished;
  }

  async list(peer) {
    if (!this.#db || !this.#key) return [];
    const index = this.#db
      .transaction(MESSAGES, "readonly")
      .objectStore(MESSAGES)
      .index("peer");
    const records = await requestResult(index.getAll(IDBKeyRange.only(peer)));

    const messages = [];
    for (const record of records) {
      try {
        const plaintext = xchacha20poly1305(this.#key, record.nonce).decrypt(
          record.ciphertext,
        );
        const entry = JSON.parse(fromUtf8(plaintext));
        messages.push({
          direction: entry.direction,
          text: entry.text,
          at: entry.at,
        });
      } catch {
        // Encrypted with a different device key: skip it.
      }
    }
    messages.sort((a, b) => String(a.at).localeCompare(String(b.at)));
    return messages;
  }
}
