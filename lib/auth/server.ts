import { cookies } from 'next/headers';
import { SESSION_COOKIE, verifySessionToken, type SessionUser } from './jwt';

/**
 * Server Component / layout helper. It only verifies the JWT; authorization
 * against the database still happens in each page or route handler.
 */
export async function getSessionUserFromCookies(): Promise<SessionUser | null> {
  const store = await cookies();
  const token = store.get(SESSION_COOKIE)?.value;
  if (!token) return null;
  return verifySessionToken(token);
}
