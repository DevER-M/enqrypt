/**
 * IndexedDB helpers shared by local history and the identity key store.
 *
 * One database per browser origin: `messages` for encrypted chat history and
 * `meta` for the device key and the identity key pair. Everything here is
 * local to the browser; none of it is ever sent to the server.
 */

export const DB_NAME = "enc";
export const DB_VERSION = 1;
export const MESSAGES = "messages";
export const META = "meta";

export function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(MESSAGES)) {
        const store = database.createObjectStore(MESSAGES, {
          keyPath: "id",
          autoIncrement: true,
        });
        store.createIndex("peer", "peer", { unique: false });
      }
      if (!database.objectStoreNames.contains(META)) {
        database.createObjectStore(META);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export function transactionDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
}
