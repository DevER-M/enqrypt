import { eq } from 'drizzle-orm';
import { getDb } from '@/lib/db/client';
import { conversations } from '@/lib/db/schema';
import { handleRouteError, jsonCreated, jsonOk, readJson } from '@/lib/api';
import { ApiError } from '@/lib/api-error';
import { assertSameOrigin } from '@/lib/auth/origin';
import { requireSessionUser } from '@/lib/auth/request';
import { bytesToBase64 } from '@/lib/encoding';
import {
  canonicalConversationId,
  getSessionForConversation,
  listConversationsForUser,
} from '@/lib/server/conversations';
import { getPublicKeyForUser, getUserById } from '@/lib/server/users';
import { createConversationBodySchema } from '@/lib/validation';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  try {
    const user = await requireSessionUser(req);
    const rows = await listConversationsForUser(user.id);
    return jsonOk({
      conversations: rows.map((row) => ({
        conversation_id: row.id,
        peer: { user_id: row.peerId, username: row.peerUsername },
        created_at: row.createdAt.toISOString(),
        last_message_at: row.lastMessageAt?.toISOString() ?? null,
      })),
    });
  } catch (error) {
    return handleRouteError(error);
  }
}

export async function POST(req: Request) {
  try {
    const user = await requireSessionUser(req);
    assertSameOrigin(req);
    const body = await readJson(req, createConversationBodySchema);

    if (body.peer_user_id === user.id) {
      throw new ApiError(400, 'self_conversation', 'You cannot start a conversation with yourself.');
    }

    const peer = await getUserById(body.peer_user_id);
    if (!peer) {
      throw new ApiError(404, 'user_not_found', 'User not found.');
    }

    const conversationId = canonicalConversationId(user.id, peer.id);
    const [first, second] = [user.id, peer.id].sort();
    const db = await getDb();

    await db
      .insert(conversations)
      .values({
        id: conversationId,
        userAId: first,
        userBId: second,
      })
      .onConflictDoNothing();

    const [conversation] = await db
      .select()
      .from(conversations)
      .where(eq(conversations.id, conversationId))
      .limit(1);
    if (!conversation) {
      throw new ApiError(500, 'conversation_create_failed', 'Could not create conversation.');
    }

    const peerKey = await getPublicKeyForUser(peer.id);
    if (!peerKey) {
      throw new ApiError(
        409,
        'peer_key_missing',
        'That user has not published an ML-KEM public key.',
      );
    }

    const session = await getSessionForConversation(conversationId);
    const response = {
      conversation_id: conversationId,
      peer: { user_id: peer.id, username: peer.username },
      peer_public_key_b64: bytesToBase64(peerKey.publicKey),
      peer_fingerprint: peerKey.fingerprint,
      has_session: session !== null,
    };

    return session ? jsonOk(response) : jsonCreated(response);
  } catch (error) {
    return handleRouteError(error);
  }
}
