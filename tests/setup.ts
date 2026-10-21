import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

// Tests always use on-disk PGlite, never a real Neon database.
delete process.env.DATABASE_URL;
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;

process.env.JWT_SECRET =
  'test-only-jwt-secret-that-is-at-least-32-characters-long';
process.env.BCRYPT_ROUNDS = '4';
process.env.PGLITE_DIR = mkdtempSync(path.join(tmpdir(), 'enqrypt-test-'));

process.on('exit', () => {
  try {
    rmSync(process.env.PGLITE_DIR as string, { recursive: true, force: true });
  } catch {
    // Best effort cleanup.
  }
});
