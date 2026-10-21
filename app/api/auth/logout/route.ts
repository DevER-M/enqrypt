import { handleRouteError, jsonOk } from '@/lib/api';
import { assertSameOrigin } from '@/lib/auth/origin';
import { SESSION_COOKIE, sessionCookieOptions } from '@/lib/auth/jwt';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  try {
    assertSameOrigin(req);
    const response = jsonOk({ ok: true });
    response.cookies.set(SESSION_COOKIE, '', {
      ...sessionCookieOptions(),
      maxAge: 0,
    });
    return response;
  } catch (error) {
    return handleRouteError(error);
  }
}
