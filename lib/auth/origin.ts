import { ApiError } from '@/lib/api-error';

function firstHeaderValue(value: string | null): string | null {
  if (!value) return null;
  return value.split(',')[0]?.trim() || null;
}

/**
 * Defense-in-depth against CSRF and cross-site WebSocket hijacking. SameSite
 * cookies already block most cross-site POSTs, but checking Origin is cheap.
 */
export function isSameOrigin(req: Request): boolean {
  const origin = req.headers.get('origin');
  if (!origin) return true; // Non-browser clients and same-origin navigations.

  const host =
    firstHeaderValue(req.headers.get('x-forwarded-host')) ??
    firstHeaderValue(req.headers.get('host'));
  if (!host) return false;

  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

export function assertSameOrigin(req: Request): void {
  if (!isSameOrigin(req)) {
    throw new ApiError(403, 'bad_origin', 'Cross-origin requests are not allowed.');
  }
}
