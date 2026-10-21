import { handleRouteError, jsonOk } from '@/lib/api';
import { ApiError } from '@/lib/api-error';
import { requireSessionUser } from '@/lib/auth/request';
import { getPublicKeyForUser, getUserByUsername } from '@/lib/server/users';
import { usernameSchema } from '@/lib/validation';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(
  req: Request,
  context: { params: Promise<{ username: string }> },
) {
  try {
    await requireSessionUser(req);
    const { username } = await context.params;
    const parsed = usernameSchema.safeParse(username);
    if (!parsed.success) {
      throw new ApiError(400, 'invalid_username', 'Username is invalid.');
    }

    const user = await getUserByUsername(parsed.data);
    if (!user) {
      throw new ApiError(404, 'user_not_found', 'No user with that username.');
    }
    const key = await getPublicKeyForUser(user.id);

    return jsonOk({
      user_id: user.id,
      username: user.username,
      has_public_key: key !== null,
      fingerprint: key?.fingerprint ?? null,
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
