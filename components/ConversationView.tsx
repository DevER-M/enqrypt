'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { apiGet, apiPost, ApiClientError } from '@/lib/client/api';
import {
  subscribeToConversation,
  type RealtimeEvent,
  type RealtimeStatus,
} from '@/lib/client/realtime';
import {
  buildAad,
  decryptMessage,
  deriveSessionKeys,
  encodeSessionKeys,
  encryptMessage,
  keyForSender,
  orderUserIds,
  type StoredSession,
} from '@/lib/crypto/session';
import { decapsulate, encapsulate } from '@/lib/crypto/mlkem';
import { base64ToBytes, bytesToBase64, bytesEqual } from '@/lib/encoding';
import { useKeyring } from '@/lib/stores/keyring';
import { MAX_MESSAGE_PAGE_SIZE } from '@/lib/protocol';
import { SafetyNumber } from './SafetyNumber';
import { MessageList } from './MessageList';
import { Composer } from './Composer';
import type { DecryptionEntry, UiMessage } from './message-types';
import { Alert, Button } from '@/components/ui';
import {
  AlertIcon,
  KeyIcon,
  LockIcon,
  RefreshIcon,
  ShieldIcon,
  SpinnerIcon,
} from '@/components/icons';

type Participant = {
  id: string;
  username: string;
  publicKeyB64: string;
  fingerprint: string;
};

type WireMessage = {
  id: string;
  conversation_id: string;
  sender_id: string;
  sequence: number;
  nonce_b64: string;
  ciphertext_b64: string;
  created_at: string;
};

type SessionPayload = {
  session_id: string;
  conversation_id: string;
  initiator_id: string;
  kem_ciphertext_b64: string;
  created_at: string;
};

type Verification = {
  safety_number: string;
  verified_at: string;
} | null;

type MessagesResponse = {
  messages: WireMessage[];
  latest_sequence: number;
  has_more: boolean;
  next_before: number | null;
};

type HandshakeStatus = 'idle' | 'working' | 'ready' | 'error';

function toUiMessage(message: WireMessage): UiMessage {
  return {
    id: message.id,
    senderId: message.sender_id,
    sequence: message.sequence,
    nonceB64: message.nonce_b64,
    ciphertextB64: message.ciphertext_b64,
    createdAt: message.created_at,
    streamId: null,
  };
}

function sortMessages(a: UiMessage, b: UiMessage): number {
  return a.sequence - b.sequence;
}

function realtimeLabel(status: RealtimeStatus): string {
  switch (status) {
    case 'live':
      return 'Live';
    case 'connecting':
      return 'Connecting…';
    case 'reconnecting':
      return 'Reconnecting…';
    default:
      return 'Offline';
  }
}

function realtimeTone(status: RealtimeStatus): string {
  return status === 'live'
    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
    : status === 'offline'
      ? 'border-rose-500/30 bg-rose-500/10 text-rose-200'
      : 'border-amber-500/30 bg-amber-500/10 text-amber-200';
}

export function ConversationView({
  conversationId,
  self,
  peer,
  initialMessages,
  initialLatestSequence,
  initialHasMore,
  initialNextBefore,
  initialSession,
  initialVerification,
  latestStreamId,
}: {
  conversationId: string;
  self: Participant;
  peer: Participant;
  initialMessages: WireMessage[];
  initialLatestSequence: number;
  initialHasMore: boolean;
  initialNextBefore: number | null;
  initialSession: SessionPayload | null;
  initialVerification: Verification;
  latestStreamId: string | null;
}) {
  const router = useRouter();
  const keyring = useKeyring();

  const [messages, setMessages] = useState<UiMessage[]>(() =>
    initialMessages.map(toUiMessage).sort(sortMessages),
  );
  const [decrypted, setDecrypted] = useState<Record<number, DecryptionEntry>>({});
  const [session, setSession] = useState<StoredSession | null>(null);
  const [handshake, setHandshake] = useState<HandshakeStatus>('idle');
  const [handshakeError, setHandshakeError] = useState<string | null>(null);
  const [handshakeNonce, setHandshakeNonce] = useState(0);
  const [hasMore, setHasMore] = useState(initialHasMore);
  const [nextBefore, setNextBefore] = useState<number | null>(initialNextBefore);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [sending, setSending] = useState(false);
  const [realtimeStatus, setRealtimeStatus] = useState<RealtimeStatus>('connecting');
  const [realtimeNonce, setRealtimeNonce] = useState(0);

  const messagesRef = useRef(messages);
  const decryptedRef = useRef<Record<number, DecryptionEntry>>({});
  const sessionRef = useRef<StoredSession | null>(null);
  const lastSequenceRef = useRef(initialLatestSequence);
  const handshakeRunRef = useRef<{
    conversationId: string;
    promise: Promise<StoredSession>;
  } | null>(null);
  const syncingRef = useRef(false);
  const syncSinceRef = useRef<(after: number) => Promise<void>>(async () => undefined);

  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  const mergeDecrypted = useCallback((entries: Record<number, DecryptionEntry>) => {
    const next = { ...decryptedRef.current, ...entries };
    decryptedRef.current = next;
    setDecrypted(next);
  }, []);

  const clearDecrypted = useCallback(() => {
    decryptedRef.current = {};
    setDecrypted({});
  }, []);

  const decryptDto = useCallback(
    async (message: WireMessage) => {
      const activeSession = sessionRef.current;
      if (!activeSession) return { ok: false as const };
      try {
        const key = keyForSender(activeSession, message.sender_id);
        const result = await decryptMessage(
          key,
          base64ToBytes(message.nonce_b64),
          base64ToBytes(message.ciphertext_b64),
          buildAad(conversationId, message.sender_id, message.sequence),
        );
        key.fill(0);
        return result.ok
          ? { ok: true as const, plaintext: result.plaintext }
          : { ok: false as const };
      } catch {
        return { ok: false as const };
      }
    },
    [conversationId],
  );

  const decryptItems = useCallback(
    async (items: UiMessage[]) => {
      if (!sessionRef.current) return;
      const entries: Record<number, DecryptionEntry> = {};
      for (const item of items) {
        if (item.pending || decryptedRef.current[item.sequence]) continue;
        const result = await decryptDto({
          id: item.id,
          conversation_id: conversationId,
          sender_id: item.senderId,
          sequence: item.sequence,
          nonce_b64: item.nonceB64,
          ciphertext_b64: item.ciphertextB64,
          created_at: item.createdAt,
        });
        entries[item.sequence] = result.ok
          ? { plaintext: result.plaintext }
          : { error: true };
      }
      if (Object.keys(entries).length > 0) mergeDecrypted(entries);
    },
    [conversationId, decryptDto, mergeDecrypted],
  );

  // Lock zeroes the provider's key and removes the derived session keys from
  // this component; decrypted plaintext must not survive a lock.
  useEffect(() => {
    if (keyring.status !== 'unlocked') {
      setSession(null);
      setHandshake('idle');
      setHandshakeError(null);
      clearDecrypted();
      return;
    }
    const cached = keyring.sessions[conversationId] ?? null;
    if (cached) {
      setSession(cached);
      setHandshake('ready');
    }
  }, [keyring.status, keyring.sessions, conversationId, clearDecrypted]);

  // Establish the KEM session if this tab does not have derived keys yet.
  // The in-flight promise is cached per conversation: React StrictMode, keyring
  // state updates, and re-renders must not start a second encapsulation, which
  // would overwrite the initiator's keys with a secret nobody else can derive.
  useEffect(() => {
    if (keyring.status !== 'unlocked') return;

    const cachedSession = keyring.sessions[conversationId] ?? null;
    if (cachedSession) {
      setSession(cachedSession);
      setHandshake('ready');
      return;
    }
    if (session) {
      setHandshake('ready');
      return;
    }

    let entry = handshakeRunRef.current;
    if (!entry || entry.conversationId !== conversationId) {
      setHandshake('working');
      setHandshakeError(null);
      const { lowUserId, highUserId } = orderUserIds(self.id, peer.id);

      const promise = (async (): Promise<StoredSession> => {
        const secretKey = keyring.getSecretKey();
        if (!secretKey) throw new Error('The private key is not unlocked in memory.');
        const peerPublicKey = base64ToBytes(peer.publicKeyB64);
        let activeSession = initialSession;
        let keys: { lowToHigh: Uint8Array; highToLow: Uint8Array } | null = null;

        if (!activeSession) {
          const encapsulated = encapsulate(peerPublicKey);
          keys = await deriveSessionKeys(encapsulated.sharedSecret, conversationId);
          encapsulated.sharedSecret.fill(0);

          const response = await apiPost<{ created: boolean; session: SessionPayload }>(
            `/api/conversations/${encodeURIComponent(conversationId)}/session`,
            { kem_ciphertext_b64: bytesToBase64(encapsulated.ciphertext) },
          );
          activeSession = response.session;

          if (activeSession.initiator_id !== self.id) {
            // Lost the initiate race. Decapsulate the winner's ciphertext.
            keys.lowToHigh.fill(0);
            keys.highToLow.fill(0);
            const sharedSecret = decapsulate(
              base64ToBytes(activeSession.kem_ciphertext_b64),
              secretKey,
            );
            keys = await deriveSessionKeys(sharedSecret, conversationId);
            sharedSecret.fill(0);
          } else if (
            !response.created &&
            !bytesEqual(
              base64ToBytes(activeSession.kem_ciphertext_b64),
              encapsulated.ciphertext,
            )
          ) {
            // Another client of this account won the session race. This tab
            // never saw the matching encapsulation, so it cannot derive the
            // key; fail instead of encrypting under a secret the peer lacks.
            keys.lowToHigh.fill(0);
            keys.highToLow.fill(0);
            throw new Error(
              'This account already has an ML-KEM session for this conversation, but this device is missing its keys. Restore a key backup that includes the session keyring.',
            );
          }
        } else if (activeSession.initiator_id === self.id) {
          throw new Error(
            'This device is missing the initiator session keys for this conversation. Restore a key backup that includes the session keyring.',
          );
        } else {
          const sharedSecret = decapsulate(
            base64ToBytes(activeSession.kem_ciphertext_b64),
            secretKey,
          );
          keys = await deriveSessionKeys(sharedSecret, conversationId);
          sharedSecret.fill(0);
        }

        if (!keys) throw new Error('Could not derive session keys.');

        const stored = encodeSessionKeys(keys, {
          conversationId,
          sessionId: activeSession.session_id,
          peerId: peer.id,
          lowUserId,
          highUserId,
          peerFingerprint: peer.fingerprint,
        });
        keys.lowToHigh.fill(0);
        keys.highToLow.fill(0);

        await keyring.saveSession(stored);
        return stored;
      })();

      entry = { conversationId, promise };
      handshakeRunRef.current = entry;
      promise.catch(() => {
        if (handshakeRunRef.current === entry) handshakeRunRef.current = null;
      });
    }

    let cancelled = false;
    entry.promise
      .then((stored) => {
        if (cancelled) return;
        setSession(stored);
        sessionRef.current = stored;
        setHandshake('ready');
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        console.error('[session] handshake failed', error);
        setHandshake('error');
        setHandshakeError(
          error instanceof Error
            ? error.message
            : 'Could not establish the ML-KEM session.',
        );
      });

    return () => {
      cancelled = true;
    };
  }, [
    keyring.status,
    keyring.sessions,
    keyring.getSecretKey,
    keyring.saveSession,
    session,
    conversationId,
    self.id,
    peer.id,
    peer.publicKeyB64,
    peer.fingerprint,
    initialSession,
    handshakeNonce,
  ]);

  const decryptMissing = useCallback(async () => {
    if (!sessionRef.current) return;
    await decryptItems(messagesRef.current);
  }, [decryptItems]);

  useEffect(() => {
    if (keyring.status === 'unlocked' && session) {
      void decryptMissing();
    }
  }, [keyring.status, session, decryptMissing]);

  const applyServerMessage = useCallback(
    (message: WireMessage) => {
      lastSequenceRef.current = Math.max(
        lastSequenceRef.current,
        message.sequence,
      );
      const ui = toUiMessage(message);
      setMessages((previous) => {
        const existingIndex = previous.findIndex(
          (item) => item.sequence === message.sequence,
        );
        if (existingIndex >= 0) {
          const next = [...previous];
          next[existingIndex] = ui;
          return next.sort(sortMessages);
        }
        return [...previous, ui].sort(sortMessages);
      });

      if (sessionRef.current && !decryptedRef.current[message.sequence]) {
        void decryptDto(message).then((result) => {
          mergeDecrypted({
            [message.sequence]: result.ok
              ? { plaintext: result.plaintext }
              : { error: true },
          });
        });
      }
    },
    [decryptDto, mergeDecrypted],
  );

  const syncSince = useCallback(
    async (after: number) => {
      if (syncingRef.current) return;
      syncingRef.current = true;
      try {
        let cursor = after;
        for (let page = 0; page < 10; page += 1) {
          const response = await apiGet<MessagesResponse>(
            `/api/conversations/${encodeURIComponent(conversationId)}/messages?after=${cursor}&limit=${MAX_MESSAGE_PAGE_SIZE}`,
          );
          for (const message of response.messages) applyServerMessage(message);
          if (
            !response.has_more ||
            response.messages.length === 0 ||
            response.messages[response.messages.length - 1].sequence <= cursor
          ) {
            break;
          }
          cursor = response.messages[response.messages.length - 1].sequence;
        }
      } catch (error) {
        console.error('[sync] could not reconcile messages', error);
      } finally {
        syncingRef.current = false;
      }
    },
    [applyServerMessage, conversationId],
  );

  useEffect(() => {
    syncSinceRef.current = syncSince;
  }, [syncSince]);

  // Realtime transport: WebSocket in production when available, SSE otherwise.
  // It always replays from the last sequence/stream cursor, and every ready
  // event triggers a Postgres reconciliation for messages missed while down.
  useEffect(() => {
    if (!session || keyring.status !== 'unlocked') return;

    const unsubscribe = subscribeToConversation({
      conversationId,
      afterSequence: lastSequenceRef.current,
      afterStreamId: latestStreamId,
      onEvent: (event: RealtimeEvent) => {
        if (event.sequence > lastSequenceRef.current + 1) {
          void syncSinceRef.current(lastSequenceRef.current);
        }
        applyServerMessage({
          id: event.id,
          conversation_id: event.conversation_id,
          sender_id: event.sender_id,
          sequence: event.sequence,
          nonce_b64: event.nonce_b64,
          ciphertext_b64: event.ciphertext_b64,
          created_at: event.created_at,
        });
      },
      onReady: () => {
        void syncSinceRef.current(lastSequenceRef.current);
      },
      onStatus: setRealtimeStatus,
    });

    return unsubscribe;
  }, [
    session,
    keyring.status,
    conversationId,
    latestStreamId,
    applyServerMessage,
    realtimeNonce,
  ]);

  const loadOlder = async () => {
    if (!hasMore || loadingOlder) return;
    setLoadingOlder(true);
    try {
      const params = new URLSearchParams({ limit: String(MAX_MESSAGE_PAGE_SIZE) });
      if (nextBefore !== null) params.set('before', String(nextBefore));
      const response = await apiGet<MessagesResponse>(
        `/api/conversations/${encodeURIComponent(conversationId)}/messages?${params.toString()}`,
      );
      const incoming = response.messages.map(toUiMessage);
      setMessages((previous) => {
        const bySequence = new Map(previous.map((item) => [item.sequence, item]));
        for (const item of incoming) {
          if (!bySequence.has(item.sequence)) bySequence.set(item.sequence, item);
        }
        return [...bySequence.values()].sort(sortMessages);
      });
      setHasMore(response.has_more);
      setNextBefore(response.next_before);
      void decryptItems(incoming);
    } catch (error) {
      console.error('[messages] could not load older messages', error);
    } finally {
      setLoadingOlder(false);
    }
  };

  const sendMessage = useCallback(
    async (plaintext: string): Promise<boolean> => {
      const activeSession = sessionRef.current;
      if (!activeSession || keyring.status !== 'unlocked') return false;

      setSending(true);
      const localId = `local-${crypto.randomUUID()}`;
      let sequence = lastSequenceRef.current + 1;
      lastSequenceRef.current = sequence;

      const pending: UiMessage = {
        id: localId,
        senderId: self.id,
        sequence,
        nonceB64: '',
        ciphertextB64: '',
        createdAt: new Date().toISOString(),
        streamId: null,
        pending: true,
        localPlaintext: plaintext,
      };
      setMessages((previous) => [...previous, pending].sort(sortMessages));
      mergeDecrypted({ [sequence]: { plaintext } });

      const fail = () => {
        setMessages((previous) =>
          previous.map((item) =>
            item.id === localId
              ? { ...item, pending: false, failed: true }
              : item,
          ),
        );
      };

      try {
        for (let attempt = 0; attempt < 3; attempt += 1) {
          const key = keyForSender(activeSession, self.id);
          const aad = buildAad(conversationId, self.id, sequence);
          const encrypted = await encryptMessage(key, plaintext, aad);
          key.fill(0);

          const nonceB64 = bytesToBase64(encrypted.nonce);
          const ciphertextB64 = bytesToBase64(encrypted.ciphertext);

          setMessages((previous) =>
            previous.map((item) =>
              item.id === localId
                ? { ...item, sequence, nonceB64, ciphertextB64 }
                : item,
            ),
          );

          try {
            const response = await apiPost<{ message: WireMessage }>(
              `/api/conversations/${encodeURIComponent(conversationId)}/messages`,
              {
                sequence,
                nonce_b64: nonceB64,
                ciphertext_b64: ciphertextB64,
              },
            );
            const serverMessage = response.message;
            lastSequenceRef.current = Math.max(
              lastSequenceRef.current,
              serverMessage.sequence,
            );
            setMessages((previous) => {
              const next = previous.map((item) =>
                item.id === localId || item.sequence === serverMessage.sequence
                  ? toUiMessage(serverMessage)
                  : item,
              );
              const seen = new Set<number>();
              return next
                .filter((item) => {
                  if (seen.has(item.sequence)) return false;
                  seen.add(item.sequence);
                  return true;
                })
                .sort(sortMessages);
            });
            mergeDecrypted({ [serverMessage.sequence]: { plaintext } });
            router.refresh();
            return true;
          } catch (error) {
            if (
              error instanceof ApiClientError &&
              error.code === 'sequence_conflict' &&
              error.nextSequence !== null &&
              error.nextSequence > sequence
            ) {
              const previousSequence = sequence;
              sequence = error.nextSequence;
              const nextDecrypted = { ...decryptedRef.current };
              delete nextDecrypted[previousSequence];
              nextDecrypted[sequence] = { plaintext };
              decryptedRef.current = nextDecrypted;
              setDecrypted(nextDecrypted);
              setMessages((previous) =>
                previous
                  .map((item) =>
                    item.id === localId ? { ...item, sequence } : item,
                  )
                  .sort(sortMessages),
              );
              lastSequenceRef.current = sequence - 1;
              continue;
            }
            console.error('[messages] send failed', error);
            fail();
            return false;
          }
        }

        fail();
        return false;
      } catch (error) {
        console.error('[messages] encryption failed', error);
        fail();
        return false;
      } finally {
        setSending(false);
      }
    },
    [conversationId, keyring.status, mergeDecrypted, router, self.id],
  );

  const retryMessage = (message: UiMessage) => {
    if (!message.localPlaintext) return;
    const plaintext = message.localPlaintext;
    setMessages((previous) => previous.filter((item) => item.id !== message.id));
    const maxPersisted = messagesRef.current
      .filter(
        (item) =>
          !item.pending && !item.failed && item.sequence !== message.sequence,
      )
      .reduce((max, item) => Math.max(max, item.sequence), 0);
    lastSequenceRef.current = Math.max(maxPersisted, initialLatestSequence);
    void sendMessage(plaintext);
  };

  const keysReady = session !== null && keyring.status === 'unlocked';
  const composerDisabled = !keysReady || handshake === 'error';
  const composerReason = !keysReady
    ? keyring.status === 'locked'
      ? 'Unlock your keys to send'
      : keyring.status === 'no-identity'
        ? 'No private key on this device'
        : 'Establishing encryption…'
    : handshake === 'error'
      ? 'Session setup failed'
      : 'Write a message…';

  const headerFingerprint = useMemo(() => peer.fingerprint.slice(0, 16), [peer.fingerprint]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 px-4 py-3">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-slate-700 bg-slate-800 text-sm font-semibold text-slate-200">
            {peer.username.slice(0, 1).toUpperCase()}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="truncate text-sm font-semibold text-slate-100">
                {peer.username}
              </h1>
              <LockIcon className="h-3.5 w-3.5 text-emerald-400/80" />
            </div>
            <div className="mono truncate text-[10px] text-slate-500">
              ML-KEM-768 · key {headerFingerprint}…
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="pill border-emerald-500/30 bg-emerald-500/10 text-emerald-200">
            <ShieldIcon className="h-3.5 w-3.5" />
            E2EE
          </span>
          <span className={`pill ${realtimeTone(realtimeStatus)}`}>
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                realtimeStatus === 'live'
                  ? 'bg-emerald-400'
                  : realtimeStatus === 'offline'
                    ? 'bg-rose-400'
                    : 'bg-amber-400'
              }`}
            />
            {realtimeLabel(realtimeStatus)}
          </span>
          {realtimeStatus !== 'live' ? (
            <button
              type="button"
              className="btn-ghost h-8 w-8 p-0"
              title="Restart realtime connection"
              onClick={() => setRealtimeNonce((value) => value + 1)}
            >
              <RefreshIcon className="h-3.5 w-3.5" />
            </button>
          ) : null}
        </div>
      </header>

      <SafetyNumber
        conversationId={conversationId}
        self={self}
        peer={peer}
        initialVerification={initialVerification}
      />

      {keyring.status === 'loading' ? (
        <div className="border-b border-slate-800 px-4 py-2 text-xs text-slate-400">
          <SpinnerIcon className="mr-2 inline h-3.5 w-3.5" />
          Reading wrapped key from IndexedDB…
        </div>
      ) : null}

      {keyring.status === 'locked' ? (
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-amber-500/20 bg-amber-500/5 px-4 py-2.5">
          <div className="flex items-center gap-2 text-xs text-amber-200">
            <LockIcon className="h-4 w-4" />
            Keys are locked. Unlock with your passphrase to decrypt history and send.
          </div>
          <Button className="h-8 px-3 py-1 text-xs" onClick={keyring.openUnlockDialog}>
            <KeyIcon className="h-3.5 w-3.5" />
            Unlock
          </Button>
        </div>
      ) : null}

      {keyring.status === 'no-identity' ? (
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rose-500/20 bg-rose-500/5 px-4 py-2.5">
          <div className="flex items-center gap-2 text-xs text-rose-200">
            <AlertIcon className="h-4 w-4" />
            This browser has no wrapped private key for this account.
          </div>
          <Button className="h-8 px-3 py-1 text-xs" onClick={keyring.openUnlockDialog}>
            Restore backup
          </Button>
        </div>
      ) : null}

      {keyring.status === 'unlocked' && handshake === 'working' ? (
        <div className="flex items-center gap-2 border-b border-sky-500/20 bg-sky-500/5 px-4 py-2.5 text-xs text-sky-200">
          <SpinnerIcon className="h-4 w-4" />
          Establishing ML-KEM-768 session and deriving directional AES keys…
        </div>
      ) : null}

      {handshake === 'error' ? (
        <div className="border-b border-rose-500/20 bg-rose-500/5 px-4 py-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs text-rose-200">
              <AlertIcon className="h-4 w-4" />
              {handshakeError ?? 'Session setup failed.'}
            </div>
            <Button
              variant="secondary"
              className="h-8 px-3 py-1 text-xs"
              onClick={() => {
                setHandshakeError(null);
                setHandshakeNonce((value) => value + 1);
              }}
            >
              <RefreshIcon className="h-3.5 w-3.5" />
              Retry
            </Button>
          </div>
        </div>
      ) : null}

      {keyring.error ? (
        <div className="border-b border-amber-500/20 px-4 py-2">
          <Alert tone="warn">{keyring.error}</Alert>
        </div>
      ) : null}

      <MessageList
        messages={messages}
        decrypted={decrypted}
        selfId={self.id}
        keysReady={keysReady}
        hasMore={hasMore}
        loadingOlder={loadingOlder}
        onLoadOlder={() => void loadOlder()}
        onRetry={retryMessage}
      />

      <Composer
        disabled={composerDisabled}
        disabledReason={composerReason}
        sending={sending}
        onSend={sendMessage}
      />
    </div>
  );
}
