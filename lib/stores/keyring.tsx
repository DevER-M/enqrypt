'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from 'react';
import { base64ToBytes, bytesToBase64, utf8Decode, utf8Encode } from '@/lib/encoding';
import { generateKeypair as generateMlKemKeypair } from '@/lib/crypto/mlkem';
import { ML_KEM_768_SIZES } from '@/lib/protocol';
import { publicKeyFingerprint } from '@/lib/crypto/safetyNumber';
import type { StoredSession } from '@/lib/crypto/session';
import {
  KEY_WRAP_ITERATIONS,
  deriveWrappingKey,
  keyringWrapAad,
  secretKeyWrapAad,
  unwrapBytes,
  validateIterations,
  wrapBytes,
} from '@/lib/crypto/wrap';
import {
  getIdentity,
  getKeyring,
  saveIdentity,
  saveKeyring,
  type IdentityBackup,
  type IdentityRecord,
  type KeyringEnvelope,
  type KeyringPayload,
} from './keyStore';

export type KeyringUser = {
  id: string;
  username: string;
};

export type KeyringStatus = 'loading' | 'anonymous' | 'no-identity' | 'locked' | 'unlocked';

type RegisterIdentityInput = {
  userId: string;
  username: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  passphrase: string;
};

type KeyringContextValue = {
  user: KeyringUser | null;
  status: KeyringStatus;
  busy: boolean;
  error: string | null;
  identity: IdentityRecord | null;
  sessions: Record<string, StoredSession>;
  unlockDialogOpen: boolean;
  openUnlockDialog: () => void;
  closeUnlockDialog: () => void;
  clearError: () => void;
  unlock: (passphrase: string) => Promise<boolean>;
  registerIdentity: (input: RegisterIdentityInput) => Promise<void>;
  lock: () => void;
  getSecretKey: () => Uint8Array | null;
  getSession: (conversationId: string) => StoredSession | null;
  saveSession: (session: StoredSession) => Promise<void>;
  restoreBackup: (file: File) => Promise<void>;
  downloadBackup: () => Promise<void>;
  generateKeypair: typeof generateMlKemKeypair;
};

const KeyringContext = createContext<KeyringContextValue | null>(null);

function parseKeyringPayload(plaintext: Uint8Array): KeyringPayload {
  const parsed = JSON.parse(utf8Decode(plaintext)) as unknown;
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    (parsed as { version?: unknown }).version !== 1 ||
    typeof (parsed as { sessions?: unknown }).sessions !== 'object' ||
    (parsed as { sessions?: unknown }).sessions === null
  ) {
    throw new Error('Keyring payload is malformed.');
  }

  const sessions: Record<string, StoredSession> = {};
  for (const [conversationId, raw] of Object.entries(
    (parsed as KeyringPayload).sessions,
  )) {
    const value = raw as Partial<StoredSession> | null;
    if (
      !value ||
      typeof value.sessionId !== 'string' ||
      typeof value.peerId !== 'string' ||
      typeof value.lowUserId !== 'string' ||
      typeof value.highUserId !== 'string' ||
      typeof value.lowToHighB64 !== 'string' ||
      typeof value.highToLowB64 !== 'string' ||
      typeof value.peerFingerprint !== 'string'
    ) {
      throw new Error('Keyring session entry is malformed.');
    }
    sessions[conversationId] = {
      conversationId,
      sessionId: value.sessionId,
      peerId: value.peerId,
      lowUserId: value.lowUserId,
      highUserId: value.highUserId,
      lowToHighB64: value.lowToHighB64,
      highToLowB64: value.highToLowB64,
      peerFingerprint: value.peerFingerprint,
    };
  }
  return { version: 1, sessions };
}

function parseBackup(value: unknown): IdentityBackup {
  if (typeof value !== 'object' || value === null) throw new Error('Backup is not an object.');
  const backup = value as Partial<IdentityBackup>;
  if (backup.version !== 1 || backup.kind !== 'enqrypt-key-backup') {
    throw new Error('This is not an enqrypt key backup.');
  }
  const identity = backup.identity as Partial<IdentityRecord> | undefined;
  if (
    !identity ||
    identity.version !== 1 ||
    typeof identity.userId !== 'string' ||
    typeof identity.username !== 'string' ||
    typeof identity.publicKeyB64 !== 'string' ||
    typeof identity.fingerprintHex !== 'string' ||
    typeof identity.wrappedSecretKeyB64 !== 'string' ||
    typeof identity.wrapNonceB64 !== 'string' ||
    typeof identity.kdfSaltB64 !== 'string' ||
    typeof identity.kdfIterations !== 'number'
  ) {
    throw new Error('Backup identity is malformed.');
  }
  validateIterations(identity.kdfIterations);
  if (base64ToBytes(identity.wrappedSecretKeyB64).length < ML_KEM_768_SIZES.secretKey) {
    throw new Error('Backup secret key is too short.');
  }
  if (base64ToBytes(identity.publicKeyB64).length !== ML_KEM_768_SIZES.publicKey) {
    throw new Error('Backup public key is the wrong size.');
  }

  let keyring: KeyringEnvelope | null = null;
  if (backup.keyring !== null && backup.keyring !== undefined) {
    const value = backup.keyring as Partial<KeyringEnvelope>;
    if (
      value.version !== 1 ||
      typeof value.userId !== 'string' ||
      typeof value.nonceB64 !== 'string' ||
      typeof value.ciphertextB64 !== 'string'
    ) {
      throw new Error('Backup keyring is malformed.');
    }
    keyring = {
      version: 1,
      userId: value.userId,
      nonceB64: value.nonceB64,
      ciphertextB64: value.ciphertextB64,
      updatedAt: typeof value.updatedAt === 'string' ? value.updatedAt : new Date().toISOString(),
    };
  }

  return {
    version: 1,
    kind: 'enqrypt-key-backup',
    identity: identity as IdentityRecord,
    keyring,
  };
}

async function persistKeyring(
  wrappingKey: CryptoKey,
  identity: IdentityRecord,
  sessions: Record<string, StoredSession>,
): Promise<KeyringEnvelope> {
  const payload: KeyringPayload = { version: 1, sessions };
  const { ciphertext, nonce } = await wrapBytes(
    wrappingKey,
    utf8Encode(JSON.stringify(payload)),
    keyringWrapAad(identity.userId),
  );
  const envelope: KeyringEnvelope = {
    version: 1,
    userId: identity.userId,
    nonceB64: bytesToBase64(nonce),
    ciphertextB64: bytesToBase64(ciphertext),
    updatedAt: new Date().toISOString(),
  };
  await saveKeyring(envelope);
  return envelope;
}

export function KeyringProvider({
  initialUser,
  children,
}: {
  initialUser: KeyringUser | null;
  children: ReactNode;
}) {
  const [status, setStatus] = useState<KeyringStatus>(
    initialUser ? 'loading' : 'anonymous',
  );
  const [identity, setIdentity] = useState<IdentityRecord | null>(null);
  const [sessions, setSessions] = useState<Record<string, StoredSession>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unlockDialogOpen, setUnlockDialogOpen] = useState(false);

  const statusRef = useRef<KeyringStatus>(status);
  const secretKeyRef = useRef<Uint8Array | null>(null);
  const wrappingKeyRef = useRef<CryptoKey | null>(null);
  const identityRef = useRef<IdentityRecord | null>(null);
  const keyringEnvelopeRef = useRef<KeyringEnvelope | null>(null);
  const sessionsRef = useRef<Record<string, StoredSession>>({});
  const persistenceQueueRef = useRef<Promise<void>>(Promise.resolve());

  const setStatusBoth = useCallback((next: KeyringStatus) => {
    statusRef.current = next;
    setStatus(next);
  }, []);

  const clearSecrets = useCallback(() => {
    if (secretKeyRef.current) {
      secretKeyRef.current.fill(0);
      secretKeyRef.current = null;
    }
    wrappingKeyRef.current = null;
    sessionsRef.current = {};
    setSessions({});
  }, []);

  const lock = useCallback(() => {
    clearSecrets();
    setUnlockDialogOpen(false);
    setStatusBoth(identityRef.current ? 'locked' : 'no-identity');
  }, [clearSecrets, setStatusBoth]);

  const loadIdentity = useCallback(
    async (user: KeyringUser) => {
      setError(null);
      setBusy(false);
      setStatusBoth('loading');
      try {
        const [record, envelope] = await Promise.all([
          getIdentity(user.id),
          getKeyring(user.id),
        ]);
        identityRef.current = record;
        keyringEnvelopeRef.current = envelope;
        setIdentity(record);
        clearSecrets();
        if (record) {
          setStatusBoth('locked');
        } else {
          setStatusBoth('no-identity');
        }
      } catch (loadError) {
        console.error('[keyring] failed to load local key material', loadError);
        identityRef.current = null;
        setIdentity(null);
        setStatusBoth('no-identity');
        setError(
          loadError instanceof Error
            ? loadError.message
            : 'Could not read the browser key store.',
        );
      }
    },
    [clearSecrets, setStatusBoth],
  );

  useEffect(() => {
    if (!initialUser) {
      identityRef.current = null;
      keyringEnvelopeRef.current = null;
      setIdentity(null);
      clearSecrets();
      setStatusBoth('anonymous');
      setError(null);
      setUnlockDialogOpen(false);
      return;
    }

    // Registration keeps the freshly created keys in memory while
    // router.refresh() updates the server-provided user.
    if (
      identityRef.current?.userId === initialUser.id &&
      secretKeyRef.current !== null
    ) {
      setStatusBoth('unlocked');
      return;
    }

    void loadIdentity(initialUser);
    // Deliberately keyed by user id; username changes are not supported.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialUser?.id]);

  const unlock = useCallback(async (passphrase: string): Promise<boolean> => {
    const record = identityRef.current;
    if (!record) {
      setError('No wrapped key exists in this browser. Restore a key backup first.');
      return false;
    }

    setBusy(true);
    setError(null);
    let candidateSecretKey: Uint8Array | null = null;

    try {
      const salt = base64ToBytes(record.kdfSaltB64);
      validateIterations(record.kdfIterations);
      const wrappingKey = await deriveWrappingKey(passphrase, salt, record.kdfIterations);
      candidateSecretKey = await unwrapBytes(
        wrappingKey,
        base64ToBytes(record.wrappedSecretKeyB64),
        base64ToBytes(record.wrapNonceB64),
        secretKeyWrapAad(record.userId),
      );
      if (candidateSecretKey.length !== ML_KEM_768_SIZES.secretKey) {
        throw new Error('Unwrapped secret key has the wrong length.');
      }

      let payload: KeyringPayload = { version: 1, sessions: {} };
      const envelope =
        keyringEnvelopeRef.current ?? (await getKeyring(record.userId));
      if (envelope) {
        const plaintext = await unwrapBytes(
          wrappingKey,
          base64ToBytes(envelope.ciphertextB64),
          base64ToBytes(envelope.nonceB64),
          keyringWrapAad(record.userId),
        );
        payload = parseKeyringPayload(plaintext);
      }

      secretKeyRef.current = candidateSecretKey;
      candidateSecretKey = null;
      wrappingKeyRef.current = wrappingKey;
      keyringEnvelopeRef.current = envelope;
      identityRef.current = record;
      setIdentity(record);
      sessionsRef.current = payload.sessions;
      setSessions(payload.sessions);
      setStatusBoth('unlocked');
      setUnlockDialogOpen(false);
      return true;
    } catch (unlockError) {
      if (candidateSecretKey) candidateSecretKey.fill(0);
      setStatusBoth('locked');
      setError(
        unlockError instanceof Error
          ? unlockError.message
          : 'Could not unlock the private key.',
      );
      return false;
    } finally {
      setBusy(false);
    }
  }, [setStatusBoth]);

  const registerIdentity = useCallback(
    async (input: RegisterIdentityInput): Promise<void> => {
      if (input.publicKey.length !== ML_KEM_768_SIZES.publicKey) {
        throw new Error('Public key has the wrong length.');
      }
      if (input.secretKey.length !== ML_KEM_768_SIZES.secretKey) {
        throw new Error('Secret key has the wrong length.');
      }

      setBusy(true);
      setError(null);
      try {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const wrappingKey = await deriveWrappingKey(
          input.passphrase,
          salt,
          KEY_WRAP_ITERATIONS,
        );
        const wrapped = await wrapBytes(
          wrappingKey,
          input.secretKey,
          secretKeyWrapAad(input.userId),
        );
        const record: IdentityRecord = {
          version: 1,
          userId: input.userId,
          username: input.username,
          publicKeyB64: bytesToBase64(input.publicKey),
          fingerprintHex: publicKeyFingerprint(input.publicKey),
          wrappedSecretKeyB64: bytesToBase64(wrapped.ciphertext),
          wrapNonceB64: bytesToBase64(wrapped.nonce),
          kdfSaltB64: bytesToBase64(salt),
          kdfIterations: KEY_WRAP_ITERATIONS,
          createdAt: new Date().toISOString(),
        };

        await saveIdentity(record);
        const envelope = await persistKeyring(wrappingKey, record, {});
        keyringEnvelopeRef.current = envelope;
        identityRef.current = record;
        secretKeyRef.current = input.secretKey;
        wrappingKeyRef.current = wrappingKey;
        sessionsRef.current = {};
        setSessions({});
        setIdentity(record);
        setStatusBoth('unlocked');
      } catch (registrationError) {
        setError(
          registrationError instanceof Error
            ? registrationError.message
            : 'Could not create local keys.',
        );
        throw registrationError;
      } finally {
        setBusy(false);
      }
    },
    [setStatusBoth],
  );

  const getSession = useCallback(
    (conversationId: string): StoredSession | null =>
      sessions[conversationId] ?? null,
    [sessions],
  );

  const saveSession = useCallback(async (session: StoredSession): Promise<void> => {
    const wrappingKey = wrappingKeyRef.current;
    const record = identityRef.current;
    if (!wrappingKey || !record) {
      throw new Error('Unlock your keys before starting a session.');
    }

    const next = { ...sessionsRef.current, [session.conversationId]: session };
    sessionsRef.current = next;
    setSessions(next);

    const task = persistenceQueueRef.current
      .catch(() => undefined)
      .then(async () => {
        const envelope = await persistKeyring(
          wrappingKey,
          record,
          sessionsRef.current,
        );
        keyringEnvelopeRef.current = envelope;
      });

    persistenceQueueRef.current = task;
    try {
      await task;
      setError(null);
    } catch (persistError) {
      console.error('[keyring] could not persist session keys', persistError);
      setError(
        'Session keys are unlocked for this tab, but could not be saved to IndexedDB. They may be lost when the tab closes.',
      );
    }
  }, []);

  const restoreBackup = useCallback(
    async (file: File): Promise<void> => {
      setBusy(true);
      setError(null);
      try {
        if (file.size > 100_000) throw new Error('Backup file is too large.');
        const text = await file.text();
        const backup = parseBackup(JSON.parse(text) as unknown);
        if (!initialUser || backup.identity.userId !== initialUser.id) {
          throw new Error('This backup belongs to a different account.');
        }
        if (backup.keyring && backup.keyring.userId !== backup.identity.userId) {
          throw new Error('Backup keyring does not match the identity.');
        }

        await saveIdentity(backup.identity);
        if (backup.keyring) {
          await saveKeyring(backup.keyring);
        }
        identityRef.current = backup.identity;
        keyringEnvelopeRef.current = backup.keyring;
        setIdentity(backup.identity);
        clearSecrets();
        setStatusBoth('locked');
      } catch (restoreError) {
        setError(
          restoreError instanceof Error ? restoreError.message : 'Could not restore backup.',
        );
        throw restoreError;
      } finally {
        setBusy(false);
      }
    },
    [clearSecrets, initialUser, setStatusBoth],
  );

  const downloadBackup = useCallback(async (): Promise<void> => {
    const record = identityRef.current;
    if (!record) throw new Error('No local identity to export.');
    const keyring = keyringEnvelopeRef.current ?? (await getKeyring(record.userId));
    const backup: IdentityBackup = {
      version: 1,
      kind: 'enqrypt-key-backup',
      identity: record,
      keyring,
    };
    const blob = new Blob([JSON.stringify(backup, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `enqrypt-key-backup-${record.username}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }, []);

  useEffect(() => {
    const onPageHide = () => {
      // Best effort: drop key references when the page is being discarded.
      if (secretKeyRef.current) secretKeyRef.current.fill(0);
      secretKeyRef.current = null;
      wrappingKeyRef.current = null;
    };
    window.addEventListener('pagehide', onPageHide);
    return () => window.removeEventListener('pagehide', onPageHide);
  }, []);

  const value = useMemo<KeyringContextValue>(
    () => ({
      user: initialUser,
      status,
      busy,
      error,
      identity,
      sessions,
      unlockDialogOpen,
      openUnlockDialog: () => setUnlockDialogOpen(true),
      closeUnlockDialog: () => setUnlockDialogOpen(false),
      clearError: () => setError(null),
      unlock,
      registerIdentity,
      lock,
      getSecretKey: () => secretKeyRef.current,
      getSession,
      saveSession,
      restoreBackup,
      downloadBackup,
      generateKeypair: generateMlKemKeypair,
    }),
    [
      initialUser,
      status,
      busy,
      error,
      identity,
      sessions,
      unlockDialogOpen,
      unlock,
      registerIdentity,
      lock,
      getSession,
      saveSession,
      restoreBackup,
      downloadBackup,
    ],
  );

  return (
    <KeyringContext.Provider value={value}>
      {children}
      <KeyringDialog />
    </KeyringContext.Provider>
  );
}

export function useKeyring(): KeyringContextValue {
  const context = useContext(KeyringContext);
  if (!context) {
    throw new Error('useKeyring must be used inside <KeyringProvider>.');
  }
  return context;
}

function KeyringDialog() {
  const keyring = useKeyring();
  const [passphrase, setPassphrase] = useState('');

  if (!keyring.unlockDialogOpen) return null;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const ok = await keyring.unlock(passphrase);
    if (ok) setPassphrase('');
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="keyring-dialog-title"
    >
      <div className="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 id="keyring-dialog-title" className="text-lg font-semibold text-slate-100">
              Unlock your keys
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              Your ML-KEM secret key is stored passphrase-wrapped in this browser.
            </p>
          </div>
          <button
            type="button"
            onClick={keyring.closeUnlockDialog}
            className="rounded-lg px-2 py-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        {keyring.status === 'no-identity' ? (
          <div className="mt-5 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">
            No private key was found in this browser. If you registered on another
            device, restore the passphrase-wrapped key backup you exported there.
          </div>
        ) : (
          <form onSubmit={submit} className="mt-5 space-y-3">
            <label className="block text-sm font-medium text-slate-300" htmlFor="unlock-passphrase">
              Passphrase
            </label>
            <input
              id="unlock-passphrase"
              type="password"
              autoFocus
              autoComplete="current-password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-violet-500"
              placeholder="The passphrase you chose at registration"
            />
            <button
              type="submit"
              disabled={keyring.busy || passphrase.length === 0}
              className="w-full rounded-xl bg-violet-600 px-3 py-2 font-medium text-white transition hover:bg-violet-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {keyring.busy ? 'Deriving key…' : 'Unlock'}
            </button>
          </form>
        )}

        {keyring.error ? (
          <p className="mt-3 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
            {keyring.error}
          </p>
        ) : null}

        <div className="mt-6 border-t border-slate-800 pt-4">
          <label className="block text-xs font-medium uppercase tracking-wide text-slate-500">
            Restore key backup
          </label>
          <input
            type="file"
            accept="application/json,.json"
            disabled={keyring.busy}
            onChange={async (event) => {
              const file = event.target.files?.[0];
              event.target.value = '';
              if (!file) return;
              try {
                await keyring.restoreBackup(file);
              } catch {
                // Error is surfaced through keyring.error.
              }
            }}
            className="mt-2 block w-full text-sm text-slate-400 file:mr-3 file:rounded-lg file:border-0 file:bg-slate-800 file:px-3 file:py-2 file:text-sm file:text-slate-200"
          />
          <p className="mt-2 text-xs text-slate-500">
            The backup contains only passphrase-wrapped key material. Without the
            passphrase it is useless.
          </p>
        </div>
      </div>
    </div>
  );
}
