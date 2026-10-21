import { and, asc, desc, eq, gt, inArray, lt, max, or } from 'drizzle-orm';
import { getDb } from '@/lib/db/client';
import {
  contactVerifications,
  conversations,
  messages,
  sessions,
  users,
  type ConversationRow,
  type MessageRow,
  type SessionRow,
} from '@/lib/db/schema';
import { ApiError } from '@/lib/api-error';

export const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function canonicalConversationId(a: string, b: string): string {
  if (a === b) {
    throw new ApiError(400, 'self_conversation', 'You cannot start a conversation with yourself.');
  }
  const [first, second] = [a, b].sort();
  return `${first}:${second}`;
}

export function isValidConversationId(id: string): boolean {
  const parts = id.split(':');
  if (parts.length !== 2) return false;
  const [a, b] = parts;
  return UUID_RE.test(a) && UUID_RE.test(b) && a < b;
}

export async function getConversationForUser(
  conversationId: string,
  userId: string,
): Promise<ConversationRow | null> {
  if (!isValidConversationId(conversationId)) return null;
  const db = await getDb();
  const [row] = await db
    .select()
    .from(conversations)
    .where(
      and(
        eq(conversations.id, conversationId),
        or(eq(conversations.userAId, userId), eq(conversations.userBId, userId)),
      ),
    )
    .limit(1);
  return row ?? null;
}

export async function requireConversationForUser(
  conversationId: string,
  userId: string,
): Promise<ConversationRow> {
  const conversation = await getConversationForUser(conversationId, userId);
  if (!conversation) {
    // Deliberately do not distinguish "not found" from "not a member".
    throw new ApiError(404, 'conversation_not_found', 'Conversation not found.');
  }
  return conversation;
}

export function peerIdOf(conversation: ConversationRow, userId: string): string {
  if (conversation.userAId === userId) return conversation.userBId;
  if (conversation.userBId === userId) return conversation.userAId;
  throw new ApiError(403, 'not_a_member', 'You are not a member of this conversation.');
}

export type ConversationListEntry = {
  id: string;
  peerId: string;
  peerUsername: string;
  createdAt: Date;
  lastMessageAt: Date | null;
};

export async function listConversationsForUser(userId: string): Promise<ConversationListEntry[]> {
  const db = await getDb();
  const rows = await db
    .select()
    .from(conversations)
    .where(or(eq(conversations.userAId, userId), eq(conversations.userBId, userId)));

  if (rows.length === 0) return [];

  const peerIds = rows.map((row) => peerIdOf(row, userId));
  const peers = await db
    .select({ id: users.id, username: users.username })
    .from(users)
    .where(inArray(users.id, peerIds));
  const peerById = new Map(peers.map((peer) => [peer.id, peer.username]));

  const lastRows = await db
    .select({
      conversationId: messages.conversationId,
      lastMessageAt: max(messages.createdAt),
    })
    .from(messages)
    .where(inArray(messages.conversationId, rows.map((row) => row.id)))
    .groupBy(messages.conversationId);
  const lastByConversation = new Map(
    lastRows.map((row) => [row.conversationId, row.lastMessageAt ?? null]),
  );

  return rows
    .map((row) => {
      const peerId = peerIdOf(row, userId);
      return {
        id: row.id,
        peerId,
        peerUsername: peerById.get(peerId) ?? 'unknown',
        createdAt: row.createdAt,
        lastMessageAt: lastByConversation.get(row.id) ?? null,
      };
    })
    .sort((a, b) => {
      const aTime = (a.lastMessageAt ?? a.createdAt).getTime();
      const bTime = (b.lastMessageAt ?? b.createdAt).getTime();
      return bTime - aTime;
    });
}

export async function getSessionForConversation(
  conversationId: string,
): Promise<SessionRow | null> {
  const db = await getDb();
  const [row] = await db
    .select()
    .from(sessions)
    .where(eq(sessions.conversationId, conversationId))
    .limit(1);
  return row ?? null;
}

export async function getLatestSequence(conversationId: string): Promise<number> {
  const db = await getDb();
  const [row] = await db
    .select({ value: max(messages.sequence) })
    .from(messages)
    .where(eq(messages.conversationId, conversationId));
  return Number(row?.value ?? 0);
}

export type MessagePage = {
  messages: MessageRow[];
  latestSequence: number;
  hasMore: boolean;
  nextBefore: number | null;
};

export async function getMessagesBefore(
  conversationId: string,
  before: number | null,
  limit: number,
): Promise<MessagePage> {
  const db = await getDb();
  const where =
    before === null
      ? eq(messages.conversationId, conversationId)
      : and(eq(messages.conversationId, conversationId), lt(messages.sequence, before));

  const rows = await db
    .select()
    .from(messages)
    .where(where)
    .orderBy(desc(messages.sequence))
    .limit(limit + 1);

  const hasMore = rows.length > limit;
  const page = rows.slice(0, limit).reverse();
  const latestSequence = await getLatestSequence(conversationId);

  return {
    messages: page,
    latestSequence,
    hasMore,
    nextBefore: page[0]?.sequence ?? null,
  };
}

export async function getMessagesAfter(
  conversationId: string,
  after: number,
  limit: number,
): Promise<MessageRow[]> {
  const db = await getDb();
  return db
    .select()
    .from(messages)
    .where(and(eq(messages.conversationId, conversationId), gt(messages.sequence, after)))
    .orderBy(asc(messages.sequence))
    .limit(limit);
}

export async function getVerification(
  userId: string,
  contactId: string,
): Promise<{ safetyNumber: string; verifiedAt: Date } | null> {
  const db = await getDb();
  const [row] = await db
    .select({
      safetyNumber: contactVerifications.safetyNumber,
      verifiedAt: contactVerifications.verifiedAt,
    })
    .from(contactVerifications)
    .where(
      and(
        eq(contactVerifications.userId, userId),
        eq(contactVerifications.contactId, contactId),
      ),
    )
    .limit(1);
  return row ?? null;
}
