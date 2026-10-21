import path from 'node:path';
import type { PgDatabase } from 'drizzle-orm/pg-core';
import * as schema from './schema';

/**
 * Both the Neon HTTP driver and PGlite expose the same Drizzle query API for
 * the operations used here. Write transactions are avoided because
 * drizzle-orm/neon-http intentionally does not support interactive
 * transactions; single-statement atomicity + unique constraints are used
 * instead.
 */
export type Db = PgDatabase<any, typeof schema>;

type DbGlobal = typeof globalThis & {
  __enqryptDbPromise?: Promise<Db>;
};

const globalForDb = globalThis as DbGlobal;

async function initDb(): Promise<Db> {
  const databaseUrl = process.env.DATABASE_URL?.trim();

  if (databaseUrl) {
    const [{ neon }, { drizzle }] = await Promise.all([
      import('@neondatabase/serverless'),
      import('drizzle-orm/neon-http'),
    ]);
    return drizzle(neon(databaseUrl), { schema }) as unknown as Db;
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'DATABASE_URL is required in production. Connect Neon Postgres in the Vercel Marketplace.',
    );
  }

  // Local development / tests: a real PostgreSQL engine compiled to WASM, on disk.
  // This is not used in production; production always uses Neon.
  const [{ PGlite }, { drizzle }, { migrate }] = await Promise.all([
    import('@electric-sql/pglite'),
    import('drizzle-orm/pglite'),
    import('drizzle-orm/pglite/migrator'),
  ]);

  const dataDir = process.env.PGLITE_DIR ?? path.join(process.cwd(), '.data', 'pglite');
  const client = new PGlite(dataDir);
  const db = drizzle(client, { schema });

  await migrate(db, {
    migrationsFolder: path.join(process.cwd(), 'drizzle'),
  });

  return db as unknown as Db;
}

export function getDb(): Promise<Db> {
  if (!globalForDb.__enqryptDbPromise) {
    const promise = initDb();
    globalForDb.__enqryptDbPromise = promise;
    promise.catch(() => {
      // Do not cache a failed initialization forever (e.g. DB still starting).
      if (globalForDb.__enqryptDbPromise === promise) {
        globalForDb.__enqryptDbPromise = undefined;
      }
    });
  }
  return globalForDb.__enqryptDbPromise;
}
