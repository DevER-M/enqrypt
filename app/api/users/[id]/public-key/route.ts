import { handleRouteError, jsonOk } from '@/lib/api';
import { ApiError } from '@/lib/api-error';
import { requireSessionUser } from '@/lib/auth/request';
import { bytesToBase64 } from '@/lib/encoding';
import { getUserWithPublicKey } from '@/lib/server/users';
import { uuidSchema } from '@/lib/validation';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(
  req: Request,
  context: { params: Promise<{ id: string }> },
) {
  try {
    await requireSessionUser(req);
    const { id } = await context.params;
    const parsed = uuidSchema.safeParse(id);
    if (!parsed.success) {
      throw new ApiError(400, 'invalid_user_id', 'User id must be a UUID.');
    }

    const user = await getUserWithPublicKey(parsed.data);
    if (!user) {
      throw new ApiError(404, 'user_not_found', 'User not found.');
    }
    if (!user.publicKey || !user.fingerprint) {
      throw new ApiError(404, 'public_key_not_found', 'That user has no published public key.');
    }

    return jsonOk({
      user_id: user.id,
      username: user.username,
      public_key_b64: bytesToBase64(user.publicKey),
      fingerprint: user.fingerprint,
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
