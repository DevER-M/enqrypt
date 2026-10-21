import { eq } from 'drizzle-orm';
import { getDb } from '@/lib/db/client';
import { publicKeys, users } from '@/lib/db/schema';

export type UserWithKey = {
  id: string;
  username: string;
  publicKey: Uint8Array | null;
  fingerprint: string | null;
};

export async function getUserById(userId: string): Promise<{ id: string; username: string } | null> {
  const db = await getDb();
  const [row] = await db
    .select({ id: users.id, username: users.username })
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);
  return row ?? null;
}

export async function getUserByUsername(
  username: string,
): Promise<{ id: string; username: string } | null> {
  const db = await getDb();
  const [row] = await db
    .select({ id: users.id, username: users.username })
    .from(users)
    .where(eq(users.username, username))
    .limit(1);
  return row ?? null;
}

export async function getUserWithPublicKey(userId: string): Promise<UserWithKey | null> {
  const db = await getDb();
  const [row] = await db
    .select({
      id: users.id,
      username: users.username,
      publicKey: publicKeys.mlKemPublicKey,
      fingerprint: publicKeys.keyFingerprint,
    })
    .from(users)
    .leftJoin(publicKeys, eq(publicKeys.userId, users.id))
    .where(eq(users.id, userId))
    .limit(1);
  return row ?? null;
}

export async function getPublicKeyForUser(
  userId: string,
): Promise<{ publicKey: Uint8Array; fingerprint: string } | null> {
  const db = await getDb();
  const [row] = await db
    .select({
      publicKey: publicKeys.mlKemPublicKey,
      fingerprint: publicKeys.keyFingerprint,
    })
    .from(publicKeys)
    .where(eq(publicKeys.userId, userId))
    .limit(1);
  return row ?? null;
}
