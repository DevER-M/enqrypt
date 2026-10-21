import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ML_KEM_768_SIZES } from '@/lib/protocol';

export { ML_KEM_768_SIZES };

export type MlKemKeypair = {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

export type MlKemEncapsulation = {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
};

function assertLength(value: Uint8Array, expected: number, label: string): void {
  if (!(value instanceof Uint8Array) || value.length !== expected) {
    throw new Error(`${label} must be ${expected} bytes.`);
  }
}

/**
 * FIPS 203 ML-KEM-768. This is the only post-quantum primitive in the live
 * path; there is deliberately no X25519 hybrid in v1.
 */
export function generateKeypair(): MlKemKeypair {
  const { publicKey, secretKey } = ml_kem768.keygen();
  assertLength(publicKey, ML_KEM_768_SIZES.publicKey, 'ML-KEM public key');
  assertLength(secretKey, ML_KEM_768_SIZES.secretKey, 'ML-KEM secret key');
  return { publicKey, secretKey };
}

export function encapsulate(publicKey: Uint8Array): MlKemEncapsulation {
  assertLength(publicKey, ML_KEM_768_SIZES.publicKey, 'ML-KEM public key');
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  assertLength(cipherText, ML_KEM_768_SIZES.ciphertext, 'ML-KEM ciphertext');
  assertLength(sharedSecret, ML_KEM_768_SIZES.sharedSecret, 'ML-KEM shared secret');
  return { ciphertext: cipherText, sharedSecret };
}

export function decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  assertLength(ciphertext, ML_KEM_768_SIZES.ciphertext, 'ML-KEM ciphertext');
  assertLength(secretKey, ML_KEM_768_SIZES.secretKey, 'ML-KEM secret key');
  const sharedSecret = ml_kem768.decapsulate(ciphertext, secretKey);
  assertLength(sharedSecret, ML_KEM_768_SIZES.sharedSecret, 'ML-KEM shared secret');
  return sharedSecret;
}
