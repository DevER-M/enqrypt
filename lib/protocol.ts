/**
 * Wire-protocol constants shared by browser and server. No secret material and
 * no cryptographic implementation lives here.
 */
export const ML_KEM_768_SIZES = {
  publicKey: 1184,
  secretKey: 2400,
  ciphertext: 1088,
  sharedSecret: 32,
} as const;

export const AES_GCM_NONCE_BYTES = 12;
export const AES_GCM_TAG_BYTES = 16;
export const DIRECTIONAL_KEY_BYTES = 32;

export const HKDF_INFO_LOW_TO_HIGH = 'chat-v1:A->B';
export const HKDF_INFO_HIGH_TO_LOW = 'chat-v1:B->A';

export const MESSAGE_PAGE_SIZE = 50;
export const MAX_MESSAGE_PAGE_SIZE = 100;
export const MAX_MESSAGE_PLAINTEXT_CHARS = 4000;
export const MAX_MESSAGE_CIPHERTEXT_BYTES = 64 * 1024;

export const REALTIME_STREAM_PREFIX = 'enqrypt:conv:';
