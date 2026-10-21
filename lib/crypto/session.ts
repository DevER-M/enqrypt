import {
  bytesToBase64,
  base64ToBytes,
  toArrayBufferBytes,
  utf8Encode,
} from '@/lib/encoding';
import {
  AES_GCM_NONCE_BYTES,
  AES_GCM_TAG_BYTES,
  DIRECTIONAL_KEY_BYTES,
  HKDF_INFO_HIGH_TO_LOW,
  HKDF_INFO_LOW_TO_HIGH,
} from '@/lib/protocol';
import { hkdfSha256, sha256Utf8 } from './kdf';

export { AES_GCM_NONCE_BYTES, AES_GCM_TAG_BYTES, DIRECTIONAL_KEY_BYTES };

/**
 * The user with the lexicographically smaller UUID is "A" in the HKDF info
 * strings. Both peers sort identically, so no role negotiation is needed.
 */
export function orderUserIds(a: string, b: string): { lowUserId: string; highUserId: string } {
  return a < b ? { lowUserId: a, highUserId: b } : { lowUserId: b, highUserId: a };
}

export type DerivedSessionKeys = {
  lowToHigh: Uint8Array;
  highToLow: Uint8Array;
};

export type StoredSession = {
  conversationId: string;
  sessionId: string;
  peerId: string;
  lowUserId: string;
  highUserId: string;
  lowToHighB64: string;
  highToLowB64: string;
  peerFingerprint: string;
};

export function encodeSessionKeys(
  keys: DerivedSessionKeys,
  meta: Omit<StoredSession, 'lowToHighB64' | 'highToLowB64'>,
): StoredSession {
  return {
    ...meta,
    lowToHighB64: bytesToBase64(keys.lowToHigh),
    highToLowB64: bytesToBase64(keys.highToLow),
  };
}

export function keyForSender(session: StoredSession, senderId: string): Uint8Array {
  if (senderId === session.lowUserId) return base64ToBytes(session.lowToHighB64);
  if (senderId === session.highUserId) return base64ToBytes(session.highToLowB64);
  throw new Error('Sender is not a participant in this session.');
}

export async function deriveSessionKeys(
  sharedSecret: Uint8Array,
  conversationId: string,
): Promise<DerivedSessionKeys> {
  if (sharedSecret.length !== 32) {
    throw new Error('ML-KEM shared secret must be 32 bytes.');
  }
  // salt = SHA-256(session_id); session_id is the deterministic conversation id.
  const salt = sha256Utf8(conversationId);
  const [lowToHigh, highToLow] = await Promise.all([
    hkdfSha256(sharedSecret, salt, HKDF_INFO_LOW_TO_HIGH, DIRECTIONAL_KEY_BYTES),
    hkdfSha256(sharedSecret, salt, HKDF_INFO_HIGH_TO_LOW, DIRECTIONAL_KEY_BYTES),
  ]);
  return { lowToHigh, highToLow };
}

export function buildAad(
  conversationId: string,
  senderUserId: string,
  sequence: number,
): Uint8Array {
  return utf8Encode(`${conversationId}|${senderUserId}|${sequence}`);
}

async function importAesGcmKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== DIRECTIONAL_KEY_BYTES) {
    throw new Error('AES-256-GCM key must be 32 bytes.');
  }
  return crypto.subtle.importKey(
    'raw',
    toArrayBufferBytes(raw),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encryptMessage(
  key: Uint8Array,
  plaintext: string,
  aad: Uint8Array,
): Promise<{ nonce: Uint8Array; ciphertext: Uint8Array }> {
  const nonce = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_BYTES));
  const cryptoKey = await importAesGcmKey(key);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: toArrayBufferBytes(aad),
      tagLength: 128,
    },
    cryptoKey,
    utf8Encode(plaintext),
  );
  return { nonce, ciphertext: new Uint8Array(ciphertext) };
}

export type DecryptResult =
  | { ok: true; plaintext: string }
  | { ok: false; reason: 'authentication_failed' };

export async function decryptMessage(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Promise<DecryptResult> {
  if (nonce.length !== AES_GCM_NONCE_BYTES) {
    return { ok: false, reason: 'authentication_failed' };
  }
  if (ciphertext.length < AES_GCM_TAG_BYTES) {
    return { ok: false, reason: 'authentication_failed' };
  }

  const cryptoKey = await importAesGcmKey(key);
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBufferBytes(nonce),
        additionalData: toArrayBufferBytes(aad),
        tagLength: 128,
      },
      cryptoKey,
      toArrayBufferBytes(ciphertext),
    );
    return { ok: true, plaintext: new TextDecoder().decode(plaintext) };
  } catch {
    // GCM tag mismatch: wrong key, tampered ciphertext/nonce/AAD, or replayed
    // under a different identity/sequence.
    return { ok: false, reason: 'authentication_failed' };
  }
}
