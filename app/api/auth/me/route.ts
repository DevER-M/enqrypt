import { handleRouteError, jsonOk } from '@/lib/api';
import { ApiError } from '@/lib/api-error';
import { requireSessionUser } from '@/lib/auth/request';
import { getUserWithPublicKey } from '@/lib/server/users';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  try {
    const session = await requireSessionUser(req);
    const user = await getUserWithPublicKey(session.id);
    if (!user) {
      throw new ApiError(401, 'unauthorized', 'Account no longer exists.');
    }
    return jsonOk({
      user_id: user.id,
      username: user.username,
      has_public_key: user.publicKey !== null,
      key_fingerprint: user.fingerprint,
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
