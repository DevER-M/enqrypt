import { and, eq } from 'drizzle-orm';
import { getDb } from '@/lib/db/client';
import { messages, type MessageRow } from '@/lib/db/schema';
import { handleRouteError, jsonCreated, jsonOk, parseIntParam, readJson } from '@/lib/api';
import { ApiError } from '@/lib/api-error';
import { assertSameOrigin } from '@/lib/auth/origin';
import { requireSessionUser } from '@/lib/auth/request';
import { base64ToBytes, bytesEqual } from '@/lib/encoding';
import {
  AES_GCM_NONCE_BYTES,
  AES_GCM_TAG_BYTES,
  MAX_MESSAGE_CIPHERTEXT_BYTES,
  MAX_MESSAGE_PAGE_SIZE,
  MESSAGE_PAGE_SIZE,
} from '@/lib/protocol';
import { toMessageDto } from '@/lib/serializers';
import { publishMessageEvent } from '@/lib/realtime/events';
import {
  getLatestSequence,
  getMessagesAfter,
  getMessagesBefore,
  requireConversationForUser,
} from '@/lib/server/conversations';
import { sendMessageBodySchema } from '@/lib/validation';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

async function findExisting(
  conversationId: string,
  sequence: number,
): Promise<MessageRow | null> {
  const db = await getDb();
  const [row] = await db
    .select()
    .from(messages)
    .where(
      and(
        eq(messages.conversationId, conversationId),
        eq(messages.sequence, sequence),
      ),
    )
    .limit(1);
  return row ?? null;
}

function isSameCiphertext(
  existing: MessageRow,
  senderId: string,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): boolean {
  return (
    existing.senderId === senderId &&
    bytesEqual(existing.nonce, nonce) &&
    bytesEqual(existing.ciphertext, ciphertext)
  );
}

function sequenceConflict(nextSequence: number): ApiError {
  return new ApiError(
    409,
    'sequence_conflict',
    'Message sequence is no longer the next value for this conversation.',
    { next_sequence: nextSequence },
  );
}

export async function GET(
  req: Request,
  context: { params: Promise<{ id: string }> },
) {
  try {
    const user = await requireSessionUser(req);
    const { id } = await context.params;
    await requireConversationForUser(id, user.id);

    const url = new URL(req.url);
    const beforeRaw = url.searchParams.get('before');
    const afterRaw = url.searchParams.get('after');
    if (beforeRaw !== null && afterRaw !== null) {
      throw new ApiError(400, 'invalid_parameter', 'Use either before or after, not both.');
    }

    const limit = parseIntParam(url.searchParams.get('limit'), {
      min: 1,
      max: MAX_MESSAGE_PAGE_SIZE,
      fallback: MESSAGE_PAGE_SIZE,
    });

    if (afterRaw !== null) {
      const after = parseIntParam(afterRaw, {
        min: 0,
        max: Number.MAX_SAFE_INTEGER,
        fallback: 0,
      });
      const rows = await getMessagesAfter(id, after, limit);
      return jsonOk({
        messages: rows.map(toMessageDto),
        latest_sequence: await getLatestSequence(id),
        has_more: rows.length === limit,
        next_before: null,
      });
    }

    const before =
      beforeRaw === null
        ? null
        : parseIntParam(beforeRaw, {
            min: 1,
            max: Number.MAX_SAFE_INTEGER,
            fallback: 1,
          });
    const page = await getMessagesBefore(id, before, limit);
    return jsonOk({
      messages: page.messages.map(toMessageDto),
      latest_sequence: page.latestSequence,
      has_more: page.hasMore,
      next_before: page.nextBefore,
    });
  } catch (error) {
    return handleRouteError(error);
  }
}

export async function POST(
  req: Request,
  context: { params: Promise<{ id: string }> },
) {
  try {
    const user = await requireSessionUser(req);
    assertSameOrigin(req);
    const { id } = await context.params;
    await requireConversationForUser(id, user.id);
    const body = await readJson(req, sendMessageBodySchema);

    let nonce: Uint8Array;
    let ciphertext: Uint8Array;
    try {
      nonce = base64ToBytes(body.nonce_b64);
      ciphertext = base64ToBytes(body.ciphertext_b64);
    } catch {
      throw new ApiError(400, 'invalid_ciphertext', 'Nonce or ciphertext is not valid base64.');
    }

    if (nonce.length !== AES_GCM_NONCE_BYTES) {
      throw new ApiError(
        400,
        'invalid_nonce',
        `AES-GCM nonce must be ${AES_GCM_NONCE_BYTES} bytes.`,
      );
    }
    if (
      ciphertext.length < AES_GCM_TAG_BYTES ||
      ciphertext.length > MAX_MESSAGE_CIPHERTEXT_BYTES
    ) {
      throw new ApiError(400, 'invalid_ciphertext', 'Ciphertext length is out of range.');
    }

    const latestSequence = await getLatestSequence(id);
    const existing = await findExisting(id, body.sequence);

    if (existing) {
      if (isSameCiphertext(existing, user.id, nonce, ciphertext)) {
        return jsonOk({
          message: toMessageDto(existing),
          stream_id: null,
          idempotent: true,
        });
      }
      throw sequenceConflict(latestSequence + 1);
    }

    if (body.sequence !== latestSequence + 1) {
      throw sequenceConflict(latestSequence + 1);
    }

    const db = await getDb();
    const newId = crypto.randomUUID();
    const inserted = await db
      .insert(messages)
      .values({
        id: newId,
        conversationId: id,
        senderId: user.id,
        sequence: body.sequence,
        nonce,
        ciphertext,
        aadSender: user.id,
      })
      .onConflictDoNothing({
        target: [messages.conversationId, messages.sequence],
      })
      .returning();

    if (inserted.length === 0) {
      // Lost a race with another client. If it is exactly the same message,
      // treat the retry as idempotent; otherwise report the new cursor.
      const raced = await findExisting(id, body.sequence);
      if (raced && isSameCiphertext(raced, user.id, nonce, ciphertext)) {
        return jsonOk({
          message: toMessageDto(raced),
          stream_id: null,
          idempotent: true,
        });
      }
      const current = await getLatestSequence(id);
      throw sequenceConflict(current + 1);
    }

    const dto = toMessageDto(inserted[0]);
    const streamId = await publishMessageEvent(dto);

    return jsonCreated({
      message: dto,
      stream_id: streamId,
      idempotent: false,
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
