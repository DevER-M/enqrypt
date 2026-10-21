import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { toArrayBufferBytes, utf8Encode } from '@/lib/encoding';

export function sha256Bytes(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(sha256(data));
}

export function sha512Bytes(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(sha512(data));
}

export function sha256Utf8(value: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(sha256(utf8Encode(value)));
}

/**
 * HKDF-SHA256 via WebCrypto. `info` provides domain separation between the
 * two directional keys in a conversation.
 */
export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  length = 32,
): Promise<Uint8Array> {
  if (![16, 24, 32].includes(length)) {
    throw new Error('Unsupported HKDF output length.');
  }
  const key = await crypto.subtle.importKey(
    'raw',
    toArrayBufferBytes(ikm),
    'HKDF',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: toArrayBufferBytes(salt),
      info: utf8Encode(info),
    },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}
