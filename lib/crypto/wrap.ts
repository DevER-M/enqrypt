import { toArrayBufferBytes, utf8Encode } from '@/lib/encoding';

export const KEY_WRAP_ITERATIONS = 600_000;
export const MIN_KEY_WRAP_ITERATIONS = 100_000;
export const MAX_KEY_WRAP_ITERATIONS = 2_000_000;
export const KDF_SALT_BYTES = 16;
export const WRAP_NONCE_BYTES = 12;

export type WrappedBytes = {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
};

export function validateIterations(iterations: number): number {
  if (
    !Number.isInteger(iterations) ||
    iterations < MIN_KEY_WRAP_ITERATIONS ||
    iterations > MAX_KEY_WRAP_ITERATIONS
  ) {
    throw new Error('Unsupported key-wrapping iteration count.');
  }
  return iterations;
}

/**
 * PBKDF2-SHA256 (600k iterations by default) -> AES-256-GCM wrapping key.
 * PBKDF2 is used instead of Argon2id to keep the browser bundle dependency-free
 * while still meeting the passphrase-wrapping requirement.
 */
export async function deriveWrappingKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  if (passphrase.length < 1 || passphrase.length > 1024) {
    throw new Error('Passphrase must be between 1 and 1024 characters.');
  }
  if (salt.length !== KDF_SALT_BYTES) {
    throw new Error('KDF salt must be 16 bytes.');
  }
  validateIterations(iterations);

  const baseKey = await crypto.subtle.importKey(
    'raw',
    utf8Encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toArrayBufferBytes(salt),
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function wrapBytes(
  wrappingKey: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<WrappedBytes> {
  const nonce = crypto.getRandomValues(new Uint8Array(WRAP_NONCE_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: toArrayBufferBytes(aad),
      tagLength: 128,
    },
    wrappingKey,
    toArrayBufferBytes(plaintext),
  );
  return { ciphertext: new Uint8Array(ciphertext), nonce };
}

export async function unwrapBytes(
  wrappingKey: CryptoKey,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (nonce.length !== WRAP_NONCE_BYTES) {
    throw new Error('Invalid wrapping nonce.');
  }
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBufferBytes(nonce),
        additionalData: toArrayBufferBytes(aad),
        tagLength: 128,
      },
      wrappingKey,
      toArrayBufferBytes(ciphertext),
    );
    return new Uint8Array(plaintext);
  } catch {
    // Do not reveal whether the passphrase or the ciphertext was wrong.
    throw new Error('Unable to unwrap: incorrect passphrase or corrupted key material.');
  }
}

export function secretKeyWrapAad(userId: string): Uint8Array {
  return utf8Encode(`enqrypt:keywrap:v1|${userId}`);
}

export function keyringWrapAad(userId: string): Uint8Array {
  return utf8Encode(`enqrypt:keyring:v1|${userId}`);
}
