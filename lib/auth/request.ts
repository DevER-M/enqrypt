import { SESSION_COOKIE, verifySessionToken, type SessionUser } from './jwt';
import { ApiError } from '@/lib/api-error';

export function getSessionTokenFromRequest(req: Request): string | null {
  const header = req.headers.get('cookie');
  if (!header) return null;

  for (const part of header.split(';')) {
    const trimmed = part.trim();
    const separator = trimmed.indexOf('=');
    if (separator === -1) continue;
    const name = trimmed.slice(0, separator);
    if (name === SESSION_COOKIE) {
      return decodeURIComponent(trimmed.slice(separator + 1));
    }
  }
  return null;
}

export async function getSessionUserFromRequest(req: Request): Promise<SessionUser | null> {
  const token = getSessionTokenFromRequest(req);
  if (!token) return null;
  return verifySessionToken(token);
}

export async function requireSessionUser(req: Request): Promise<SessionUser> {
  const user = await getSessionUserFromRequest(req);
  if (!user) {
    throw new ApiError(401, 'unauthorized', 'A valid session is required.');
  }
  return user;
}
