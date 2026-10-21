import type { StoredSession } from '@/lib/crypto/session';

const DB_NAME = 'enqrypt';
const DB_VERSION = 1;
const IDENTITY_STORE = 'identities';
const KEYRING_STORE = 'keyrings';

export type IdentityRecord = {
  version: 1;
  userId: string;
  username: string;
  publicKeyB64: string;
  fingerprintHex: string;
  wrappedSecretKeyB64: string;
  wrapNonceB64: string;
  kdfSaltB64: string;
  kdfIterations: number;
  createdAt: string;
};

export type KeyringEnvelope = {
  version: 1;
  userId: string;
  nonceB64: string;
  ciphertextB64: string;
  updatedAt: string;
};

export type KeyringPayload = {
  version: 1;
  sessions: Record<string, StoredSession>;
};

export type IdentityBackup = {
  version: 1;
  kind: 'enqrypt-key-backup';
  identity: IdentityRecord;
  keyring: KeyringEnvelope | null;
};

let dbPromise: Promise<IDBDatabase> | null = null;

function openDb(): Promise<IDBDatabase> {
  if (typeof indexedDB === 'undefined') {
    return Promise.reject(
      new Error('IndexedDB is not available in this browser. Private mode may block it.'),
    );
  }
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(IDENTITY_STORE)) {
          db.createObjectStore(IDENTITY_STORE, { keyPath: 'userId' });
        }
        if (!db.objectStoreNames.contains(KEYRING_STORE)) {
          db.createObjectStore(KEYRING_STORE, { keyPath: 'userId' });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Could not open IndexedDB.'));
      request.onblocked = () => reject(new Error('IndexedDB upgrade is blocked by another tab.'));
    });
  }
  return dbPromise;
}

function requestToPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed.'));
  });
}

async function getRecord<T>(storeName: string, key: string): Promise<T | null> {
  const db = await openDb();
  const tx = db.transaction(storeName, 'readonly');
  const result = await requestToPromise<T | undefined>(tx.objectStore(storeName).get(key));
  return result ?? null;
}

async function putRecord(storeName: string, value: unknown): Promise<void> {
  const db = await openDb();
  const tx = db.transaction(storeName, 'readwrite');
  await requestToPromise(tx.objectStore(storeName).put(value));
}

export async function getIdentity(userId: string): Promise<IdentityRecord | null> {
  return getRecord<IdentityRecord>(IDENTITY_STORE, userId);
}

export async function saveIdentity(identity: IdentityRecord): Promise<void> {
  await putRecord(IDENTITY_STORE, identity);
}

export async function getKeyring(userId: string): Promise<KeyringEnvelope | null> {
  return getRecord<KeyringEnvelope>(KEYRING_STORE, userId);
}

export async function saveKeyring(envelope: KeyringEnvelope): Promise<void> {
  await putRecord(KEYRING_STORE, envelope);
}

export async function deleteIdentity(userId: string): Promise<void> {
  const db = await openDb();
  const tx = db.transaction([IDENTITY_STORE, KEYRING_STORE], 'readwrite');
  await Promise.all([
    requestToPromise(tx.objectStore(IDENTITY_STORE).delete(userId)),
    requestToPromise(tx.objectStore(KEYRING_STORE).delete(userId)),
  ]);
}
