import path from 'node:path';

// Node 20.12+ can load .env files without a dependency.
for (const file of ['.env.local', '.env']) {
  try {
    process.loadEnvFile(file);
  } catch {
    // File is optional.
  }
}

async function main() {
  const databaseUrl = process.env.DATABASE_URL?.trim();
  const migrationsFolder = path.join(process.cwd(), 'drizzle');

  if (databaseUrl) {
    const [{ neon }, { drizzle }, { migrate }] = await Promise.all([
      import('@neondatabase/serverless'),
      import('drizzle-orm/neon-http'),
      import('drizzle-orm/neon-http/migrator'),
    ]);
    const db = drizzle(neon(databaseUrl));
    await migrate(db, { migrationsFolder });
    console.log('Migrations applied to Neon Postgres.');
    return;
  }

  const [{ PGlite }, { drizzle }, { migrate }] = await Promise.all([
    import('@electric-sql/pglite'),
    import('drizzle-orm/pglite'),
    import('drizzle-orm/pglite/migrator'),
  ]);
  const dataDir = process.env.PGLITE_DIR ?? path.join(process.cwd(), '.data', 'pglite');
  const db = drizzle(new PGlite(dataDir));
  await migrate(db, { migrationsFolder });
  console.log(`Migrations applied to local PGlite at ${dataDir}.`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
