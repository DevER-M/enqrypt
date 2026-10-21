import { describe, expect, it } from 'vitest';
import { generateKeypair, encapsulate, decapsulate } from '@/lib/crypto/mlkem';
import { hkdfSha256, sha256Utf8 } from '@/lib/crypto/kdf';
import {
  buildAad,
  decryptMessage,
  deriveSessionKeys,
  encryptMessage,
  keyForSender,
  orderUserIds,
  encodeSessionKeys,
} from '@/lib/crypto/session';
import {
  deriveWrappingKey,
  keyringWrapAad,
  unwrapBytes,
  wrapBytes,
} from '@/lib/crypto/wrap';
import {
  computeSafetyNumber,
  formatSafetyNumber,
  publicKeyFingerprint,
} from '@/lib/crypto/safetyNumber';
import { bytesToBase64, utf8Encode } from '@/lib/encoding';
import { ML_KEM_768_SIZES } from '@/lib/protocol';

const USER_A = '00000000-0000-4000-8000-00000000000a';
const USER_B = '00000000-0000-4000-8000-00000000000b';
const CONVERSATION_ID = `${USER_A}:${USER_B}`;

describe('ML-KEM-768', () => {
  it('produces FIPS 203 sized keys and a matching shared secret', () => {
    const alice = generateKeypair();
    const bob = generateKeypair();

    expect(alice.publicKey).toHaveLength(ML_KEM_768_SIZES.publicKey);
    expect(alice.secretKey).toHaveLength(ML_KEM_768_SIZES.secretKey);
    expect(bob.publicKey).toHaveLength(ML_KEM_768_SIZES.publicKey);

    const { ciphertext, sharedSecret } = encapsulate(bob.publicKey);
    expect(ciphertext).toHaveLength(ML_KEM_768_SIZES.ciphertext);
    expect(sharedSecret).toHaveLength(ML_KEM_768_SIZES.sharedSecret);

    const recovered = decapsulate(ciphertext, bob.secretKey);
    expect(Buffer.from(recovered)).toEqual(Buffer.from(sharedSecret));
  });

  it('rejects keys and ciphertexts of the wrong length', () => {
    expect(() => encapsulate(new Uint8Array(32))).toThrow(/1184 bytes/);
    expect(() => decapsulate(new Uint8Array(32), new Uint8Array(2400))).toThrow(
      /1088 bytes/,
    );
  });
});

describe('HKDF-SHA256 directional keys', () => {
  it('is deterministic but separates the two directions', async () => {
    const secret = new Uint8Array(32).fill(7);
    const first = await deriveSessionKeys(secret, CONVERSATION_ID);
    const second = await deriveSessionKeys(secret, CONVERSATION_ID);

    expect(bytesToBase64(first.lowToHigh)).toBe(bytesToBase64(second.lowToHigh));
    expect(bytesToBase64(first.highToLow)).toBe(bytesToBase64(second.highToLow));
    expect(bytesToBase64(first.lowToHigh)).not.toBe(
      bytesToBase64(first.highToLow),
    );

    const differentContext = await hkdfSha256(
      secret,
      sha256Utf8('another-conversation'),
      'chat-v1:A->B',
      32,
    );
    expect(bytesToBase64(differentContext)).not.toBe(
      bytesToBase64(first.lowToHigh),
    );
  });

  it('orders user ids identically on both sides', () => {
    expect(orderUserIds(USER_B, USER_A)).toEqual({
      lowUserId: USER_A,
      highUserId: USER_B,
    });
    expect(orderUserIds(USER_A, USER_B)).toEqual({
      lowUserId: USER_A,
      highUserId: USER_B,
    });

    const session = encodeSessionKeys(
      { lowToHigh: new Uint8Array(32).fill(1), highToLow: new Uint8Array(32).fill(2) },
      {
        conversationId: CONVERSATION_ID,
        sessionId: CONVERSATION_ID,
        peerId: USER_B,
        lowUserId: USER_A,
        highUserId: USER_B,
        peerFingerprint: 'f'.repeat(64),
      },
    );
    expect(keyForSender(session, USER_A)[0]).toBe(1);
    expect(keyForSender(session, USER_B)[0]).toBe(2);
    expect(() => keyForSender(session, 'someone-else')).toThrow(/not a participant/);
  });
});

describe('AES-256-GCM messages', () => {
  const key = new Uint8Array(32).fill(9);
  const plaintext = 'hello post-quantum world 🌍';

  it('round-trips with conversation, sender, and sequence in the AAD', async () => {
    const aad = buildAad(CONVERSATION_ID, USER_A, 4);
    const encrypted = await encryptMessage(key, plaintext, aad);

    const result = await decryptMessage(
      key,
      encrypted.nonce,
      encrypted.ciphertext,
      aad,
    );
    expect(result).toEqual({ ok: true, plaintext });
  });

  it('fails authentication when the ciphertext is tampered with', async () => {
    const aad = buildAad(CONVERSATION_ID, USER_A, 4);
    const encrypted = await encryptMessage(key, plaintext, aad);
    const tampered = new Uint8Array(encrypted.ciphertext);
    tampered[tampered.length - 1] ^= 0x01;

    const result = await decryptMessage(key, encrypted.nonce, tampered, aad);
    expect(result).toEqual({ ok: false, reason: 'authentication_failed' });
  });

  it('fails when sequence, sender, or conversation is changed', async () => {
    const encrypted = await encryptMessage(
      key,
      plaintext,
      buildAad(CONVERSATION_ID, USER_A, 4),
    );

    const wrongSequence = await decryptMessage(
      key,
      encrypted.nonce,
      encrypted.ciphertext,
      buildAad(CONVERSATION_ID, USER_A, 5),
    );
    const wrongSender = await decryptMessage(
      key,
      encrypted.nonce,
      encrypted.ciphertext,
      buildAad(CONVERSATION_ID, USER_B, 4),
    );
    const wrongConversation = await decryptMessage(
      key,
      encrypted.nonce,
      encrypted.ciphertext,
      buildAad(`other:${CONVERSATION_ID}`, USER_A, 4),
    );

    expect(wrongSequence.ok).toBe(false);
    expect(wrongSender.ok).toBe(false);
    expect(wrongConversation.ok).toBe(false);
  });

  it('rejects a key of the wrong size or a truncated tag', async () => {
    await expect(
      encryptMessage(new Uint8Array(16), plaintext, new Uint8Array(0)),
    ).rejects.toThrow(/32 bytes/);

    const encrypted = await encryptMessage(key, plaintext, new Uint8Array(0));
    const truncated = encrypted.ciphertext.slice(0, 15);
    const result = await decryptMessage(
      key,
      encrypted.nonce,
      truncated,
      new Uint8Array(0),
    );
    expect(result.ok).toBe(false);
  });
});

describe('passphrase key wrapping', () => {
  it('wraps and unwraps key material with the correct passphrase', async () => {
    const passphrase = 'correct horse battery staple';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const secret = crypto.getRandomValues(new Uint8Array(2400));
    const wrappingKey = await deriveWrappingKey(passphrase, salt, 100_000);

    const wrapped = await wrapBytes(
      wrappingKey,
      secret,
      keyringWrapAad(USER_A),
    );
    expect(bytesToBase64(wrapped.ciphertext)).not.toContain(
      bytesToBase64(secret),
    );

    const recovered = await unwrapBytes(
      wrappingKey,
      wrapped.ciphertext,
      wrapped.nonce,
      keyringWrapAad(USER_A),
    );
    expect(Buffer.from(recovered)).toEqual(Buffer.from(secret));
  });

  it('fails with a wrong passphrase or mismatched AAD', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const secret = crypto.getRandomValues(new Uint8Array(64));
    const wrappingKey = await deriveWrappingKey('right passphrase', salt, 100_000);
    const wrapped = await wrapBytes(wrappingKey, secret, keyringWrapAad(USER_A));

    const wrongPassphraseKey = await deriveWrappingKey(
      'wrong passphrase',
      salt,
      100_000,
    );
    await expect(
      unwrapBytes(
        wrongPassphraseKey,
        wrapped.ciphertext,
        wrapped.nonce,
        keyringWrapAad(USER_A),
      ),
    ).rejects.toThrow(/incorrect passphrase or corrupted/);

    await expect(
      unwrapBytes(
        wrappingKey,
        wrapped.ciphertext,
        wrapped.nonce,
        keyringWrapAad(USER_B),
      ),
    ).rejects.toThrow(/incorrect passphrase or corrupted/);
  });

  it('rejects a salt that is not 16 bytes', async () => {
    await expect(
      deriveWrappingKey('passphrase', new Uint8Array(8), 100_000),
    ).rejects.toThrow(/16 bytes/);
  });
});

describe('safety numbers', () => {
  const alice = generateKeypair();
  const bob = generateKeypair();

  it('is deterministic and independent of argument order', () => {
    const one = computeSafetyNumber(USER_A, alice.publicKey, USER_B, bob.publicKey);
    const two = computeSafetyNumber(USER_B, bob.publicKey, USER_A, alice.publicKey);

    expect(one).toBe(two);
    expect(one).toMatch(/^\d{5}( \d{5}){11}$/);
    expect(one.split(' ')).toHaveLength(12);
    expect(formatSafetyNumber(one)).toHaveLength(3);
  });

  it('changes when either public key changes', () => {
    const otherKey = generateKeypair().publicKey;
    const changed = computeSafetyNumber(USER_A, otherKey, USER_B, bob.publicKey);
    const original = computeSafetyNumber(
      USER_A,
      alice.publicKey,
      USER_B,
      bob.publicKey,
    );
    expect(changed).not.toBe(original);
  });

  it('fingerprints public keys as 64 hex characters', () => {
    expect(publicKeyFingerprint(alice.publicKey)).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe('legacy teaching material', () => {
  it('does not ship the XOR helper in a runtime module', async () => {
    const lesson = await import('@/lib/crypto/xor-lesson');
    // The module may export documentation, but the live protocol must not depend
    // on it. This test simply asserts the module is not silently reachable via
    // the session helpers.
    const sessionModule = await import('@/lib/crypto/session');
    expect(Object.keys(sessionModule)).not.toContain('xorBytes');
    expect(utf8Encode('ok').length).toBe(2);
  });
});
