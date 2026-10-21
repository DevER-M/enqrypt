import { eq } from 'drizzle-orm';
import { getDb } from '@/lib/db/client';
import { users } from '@/lib/db/schema';
import { handleRouteError, jsonOk, readJson } from '@/lib/api';
import { ApiError } from '@/lib/api-error';
import { assertSameOrigin } from '@/lib/auth/origin';
import { burnPasswordComparison, verifyPassword } from '@/lib/auth/password';
import { SESSION_COOKIE, sessionCookieOptions, signSessionToken } from '@/lib/auth/jwt';
import { loginBodySchema } from '@/lib/validation';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  try {
    assertSameOrigin(req);
    const body = await readJson(req, loginBodySchema);

    const db = await getDb();
    const [row] = await db
      .select({
        id: users.id,
        username: users.username,
        passwordHash: users.passwordHash,
      })
      .from(users)
      .where(eq(users.username, body.username))
      .limit(1);

    if (!row) {
      await burnPasswordComparison(body.password);
      throw new ApiError(401, 'invalid_credentials', 'Invalid username or password.');
    }

    const valid = await verifyPassword(body.password, row.passwordHash);
    if (!valid) {
      throw new ApiError(401, 'invalid_credentials', 'Invalid username or password.');
    }

    const token = await signSessionToken({ id: row.id, username: row.username });
    const response = jsonOk({ user_id: row.id, username: row.username });
    response.cookies.set(SESSION_COOKIE, token, sessionCookieOptions());
    return response;
  } catch (error) {
    return handleRouteError(error);
  }
}
