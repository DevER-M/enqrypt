import { eq } from 'drizzle-orm';
import { getDb } from '@/lib/db/client';
import { publicKeys, users } from '@/lib/db/schema';
import { handleRouteError, jsonCreated, readJson } from '@/lib/api';
import { ApiError } from '@/lib/api-error';
import { assertSameOrigin } from '@/lib/auth/origin';
import { hashPassword } from '@/lib/auth/password';
import { SESSION_COOKIE, sessionCookieOptions, signSessionToken } from '@/lib/auth/jwt';
import { base64ToBytes } from '@/lib/encoding';
import { ML_KEM_768_SIZES } from '@/lib/protocol';
import { registerBodySchema } from '@/lib/validation';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  try {
    assertSameOrigin(req);
    const body = await readJson(req, registerBodySchema);

    let publicKey: Uint8Array;
    try {
      publicKey = base64ToBytes(body.ml_kem_public_key_b64);
    } catch {
      throw new ApiError(400, 'invalid_public_key', 'Public key is not valid base64.');
    }
    if (publicKey.length !== ML_KEM_768_SIZES.publicKey) {
      throw new ApiError(
        400,
        'invalid_public_key',
        `ML-KEM-768 public key must be ${ML_KEM_768_SIZES.publicKey} bytes.`,
      );
    }

    const db = await getDb();
    const passwordHash = await hashPassword(body.password);
    const userId = crypto.randomUUID();

    try {
      await db.insert(users).values({
        id: userId,
        username: body.username,
        passwordHash,
      });
    } catch (insertError) {
      if ((insertError as { code?: string }).code === '23505') {
        throw new ApiError(409, 'username_taken', 'That username is already taken.');
      }
      throw insertError;
    }

    try {
      await db.insert(publicKeys).values({
        userId,
        mlKemPublicKey: publicKey,
        keyFingerprint: body.key_fingerprint,
      });
    } catch (keyError) {
      // Avoid leaving a half-registered account without a public key.
      await db.delete(users).where(eq(users.id, userId)).catch(() => undefined);
      throw keyError;
    }

    const token = await signSessionToken({ id: userId, username: body.username });
    const response = jsonCreated({
      user_id: userId,
      username: body.username,
    });
    response.cookies.set(SESSION_COOKIE, token, sessionCookieOptions());
    return response;
  } catch (error) {
    return handleRouteError(error);
  }
}
