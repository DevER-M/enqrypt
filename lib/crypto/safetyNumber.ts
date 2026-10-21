import { bytesToBase64, bytesToHex, utf8Encode } from '@/lib/encoding';
import { sha256Bytes, sha512Bytes } from './kdf';

export function publicKeyFingerprint(publicKey: Uint8Array): string {
  return bytesToHex(sha256Bytes(publicKey));
}

/**
 * Signal-style safety number: deterministic for a pair of identities and
 * public keys, independent of who opens the conversation first. It changes if
 * either public key changes.
 */
export function computeSafetyNumber(
  userAId: string,
  publicKeyA: Uint8Array,
  userBId: string,
  publicKeyB: Uint8Array,
): string {
  const [firstId, firstKey, secondId, secondKey] =
    userAId < userBId
      ? [userAId, publicKeyA, userBId, publicKeyB]
      : [userBId, publicKeyB, userAId, publicKeyA];

  const digest = sha512Bytes(
    utf8Encode(
      [
        'enqrypt-safety-number-v1',
        firstId,
        bytesToBase64(firstKey),
        secondId,
        bytesToBase64(secondKey),
      ].join('\n'),
    ),
  );

  const groups: string[] = [];
  for (let i = 0; i < 12; i += 1) {
    const offset = i * 4;
    const value =
      ((digest[offset] << 24) |
        (digest[offset + 1] << 16) |
        (digest[offset + 2] << 8) |
        digest[offset + 3]) >>>
      0;
    groups.push(String(value % 100_000).padStart(5, '0'));
  }
  return groups.join(' ');
}

export function formatSafetyNumber(safetyNumber: string): string[] {
  const groups = safetyNumber.split(' ');
  return [groups.slice(0, 4).join(' '), groups.slice(4, 8).join(' '), groups.slice(8, 12).join(' ')];
}
