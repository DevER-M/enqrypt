import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  index,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { bytea } from './columns';

export const users = pgTable(
  'users',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    username: text('username').notNull(),
    passwordHash: text('password_hash').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [uniqueIndex('users_username_idx').on(table.username)],
);

export const publicKeys = pgTable('public_keys', {
  userId: uuid('user_id')
    .primaryKey()
    .references(() => users.id, { onDelete: 'cascade' }),
  mlKemPublicKey: bytea('ml_kem_public_key').notNull(),
  keyFingerprint: text('key_fingerprint').notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

export const conversations = pgTable(
  'conversations',
  {
    // Deterministic: sorted(userAId) + ":" + sorted(userBId).
    id: text('id').primaryKey(),
    userAId: uuid('user_a_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    userBId: uuid('user_b_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex('conversations_pair_idx').on(table.userAId, table.userBId),
    index('conversations_user_a_idx').on(table.userAId),
    index('conversations_user_b_idx').on(table.userBId),
    check('conversations_order_check', sql`${table.userAId} < ${table.userBId}`),
  ],
);

export const sessions = pgTable(
  'sessions',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    conversationId: text('conversation_id')
      .notNull()
      .references(() => conversations.id, { onDelete: 'cascade' }),
    initiatorId: uuid('initiator_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    // ML-KEM-768 ciphertext (1088 bytes). The shared secret is never stored.
    kemCiphertext: bytea('kem_ciphertext').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    // One KEM session per conversation in v1.
    uniqueIndex('sessions_conversation_idx').on(table.conversationId),
  ],
);

export const messages = pgTable(
  'messages',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    conversationId: text('conversation_id')
      .notNull()
      .references(() => conversations.id, { onDelete: 'cascade' }),
    senderId: uuid('sender_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    // Monotonic per conversation. Part of the GCM AAD.
    sequence: bigint('sequence', { mode: 'number' }).notNull(),
    nonce: bytea('nonce').notNull(),
    ciphertext: bytea('ciphertext').notNull(),
    // Redundant copy of the sender id bound into the AAD, useful for audits.
    aadSender: uuid('aad_sender').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex('messages_conversation_sequence_idx').on(table.conversationId, table.sequence),
    index('messages_conversation_created_idx').on(table.conversationId, table.createdAt),
  ],
);

export const contactVerifications = pgTable(
  'contact_verifications',
  {
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    contactId: uuid('contact_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    safetyNumber: text('safety_number').notNull(),
    verifiedAt: timestamp('verified_at', { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [primaryKey({ columns: [table.userId, table.contactId] })],
);

export type UserRow = typeof users.$inferSelect;
export type PublicKeyRow = typeof publicKeys.$inferSelect;
export type ConversationRow = typeof conversations.$inferSelect;
export type SessionRow = typeof sessions.$inferSelect;
export type MessageRow = typeof messages.$inferSelect;
export type ContactVerificationRow = typeof contactVerifications.$inferSelect;
