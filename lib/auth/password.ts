import { compare, hash } from 'bcryptjs';

// 12 rounds in production. Tests lower this to keep the suite fast.
const BCRYPT_ROUNDS = Math.max(4, Number(process.env.BCRYPT_ROUNDS ?? 12));

// A valid bcrypt hash used to keep login timing roughly constant for unknown
// usernames. The password is irrelevant; compare() will always fail.
const DUMMY_HASH = '$2b$12$C6UzMDM.H6dfI/f/IKcEe.6O5KxJcM0dP7c1uQeFh8vX0QYfVn7Yq';

export async function hashPassword(password: string): Promise<string> {
  return hash(password, BCRYPT_ROUNDS);
}

export async function verifyPassword(password: string, passwordHash: string): Promise<boolean> {
  return compare(password, passwordHash);
}

export async function burnPasswordComparison(password: string): Promise<void> {
  try {
    await compare(password, DUMMY_HASH);
  } catch {
    // Ignore malformed dummy hash; this path is timing-hardening only.
  }
}
