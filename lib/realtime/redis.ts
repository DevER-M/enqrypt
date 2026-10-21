import { Redis } from '@upstash/redis';

let cached: Redis | null | undefined;

export function getRedis(): Redis | null {
  if (cached !== undefined) return cached;

  const url =
    process.env.UPSTASH_REDIS_REST_URL?.trim() ?? process.env.UPSTASH_REDIS_URL?.trim();
  const token =
    process.env.UPSTASH_REDIS_REST_TOKEN?.trim() ?? process.env.UPSTASH_REDIS_TOKEN?.trim();

  if (!url || !token) {
    cached = null;
    return cached;
  }
  if (!url.startsWith('https://')) {
    console.warn(
      '[realtime] Redis is disabled: use the Upstash REST URL (https://...), not a redis:// URL.',
    );
    cached = null;
    return cached;
  }

  cached = new Redis({ url, token });
  return cached;
}
