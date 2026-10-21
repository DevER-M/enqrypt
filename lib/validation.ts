import { z } from 'zod';

export const usernameSchema = z
  .string()
  .transform((value) => value.trim().toLowerCase())
  .pipe(
    z
      .string()
      .min(3, 'Username must be at least 3 characters.')
      .max(32, 'Username must be at most 32 characters.')
      .regex(/^[a-z0-9_]+$/, 'Use lowercase letters, numbers, and underscores only.'),
  );

export const passwordSchema = z
  .string()
  .min(10, 'Password must be at least 10 characters.')
  .max(72, 'Password must be at most 72 characters (bcrypt limit).');

export const uuidSchema = z.string().uuid('Expected a UUID.');

export const base64Schema = z
  .string()
  .min(1, 'Expected base64 data.')
  .max(300_000, 'Base64 payload is too large.')
  .regex(/^[A-Za-z0-9+/]+={0,2}$/, 'Expected standard base64.')
  .refine((value) => value.length % 4 === 0, 'Base64 length must be a multiple of 4.');

export const fingerprintSchema = z
  .string()
  .regex(/^[a-f0-9]{64}$/, 'Fingerprint must be 64 lowercase hex characters.');

export const sequenceSchema = z
  .number()
  .int('Sequence must be an integer.')
  .positive('Sequence must be positive.')
  .max(Number.MAX_SAFE_INTEGER, 'Sequence is too large.');

export const safetyNumberSchema = z
  .string()
  .regex(/^\d{5}( \d{5}){11}$/, 'Safety number must be 12 groups of 5 digits.');

export const registerBodySchema = z.object({
  username: usernameSchema,
  password: passwordSchema,
  ml_kem_public_key_b64: base64Schema,
  key_fingerprint: fingerprintSchema,
});

export const loginBodySchema = z.object({
  username: usernameSchema,
  password: z.string().min(1).max(200),
});

export const createConversationBodySchema = z.object({
  peer_user_id: uuidSchema,
});

export const createSessionBodySchema = z.object({
  kem_ciphertext_b64: base64Schema,
});

export const sendMessageBodySchema = z.object({
  sequence: sequenceSchema,
  nonce_b64: base64Schema,
  ciphertext_b64: base64Schema,
});

export const verifyBodySchema = z.object({
  safety_number: safetyNumberSchema,
});
