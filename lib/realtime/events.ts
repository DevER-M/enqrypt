import { bytesToBase64 } from '@/lib/encoding';
import { REALTIME_STREAM_PREFIX } from '@/lib/protocol';
import { getMessagesAfter } from '@/lib/server/conversations';
import type { MessageDto } from '@/lib/serializers';
import { getRedis } from './redis';

export type RelayEvent = {
  id: string;
  conversation_id: string;
  sender_id: string;
  sequence: number;
  nonce_b64: string;
  ciphertext_b64: string;
  created_at: string;
  stream_id: string | null;
};

export type RelayCursor = {
  afterSequence: number;
  streamId: string | null;
};

function streamKey(conversationId: string): string {
  return `${REALTIME_STREAM_PREFIX}${conversationId}`;
}

function streamIdIsValid(value: string | null | undefined): value is string {
  return typeof value === 'string' && /^\d+-\d+$/.test(value);
}

function parseStreamEntry(
  conversationId: string,
  streamId: string,
  fields: Record<string, unknown>,
): RelayEvent | null {
  const id = typeof fields.messageId === 'string' ? fields.messageId : null;
  const senderId = typeof fields.senderId === 'string' ? fields.senderId : null;
  const sequence = Number(fields.sequence);
  const nonce = typeof fields.nonce === 'string' ? fields.nonce : null;
  const ciphertext = typeof fields.ciphertext === 'string' ? fields.ciphertext : null;
  const createdAt = typeof fields.createdAt === 'string' ? fields.createdAt : null;

  if (
    !id ||
    !senderId ||
    !nonce ||
    !ciphertext ||
    !createdAt ||
    !Number.isSafeInteger(sequence) ||
    sequence <= 0
  ) {
    return null;
  }

  return {
    id,
    conversation_id: conversationId,
    sender_id: senderId,
    sequence,
    nonce_b64: nonce,
    ciphertext_b64: ciphertext,
    created_at: createdAt,
    stream_id: streamId,
  };
}

/**
 * Fan out a stored ciphertext to Redis Streams. The stream is a delivery
 * optimization: Postgres remains the durable source of truth, so a Redis
 * outage never loses a message.
 */
export async function publishMessageEvent(message: MessageDto): Promise<string | null> {
  const redis = getRedis();
  if (!redis) return null;

  try {
    return await redis.xadd(
      streamKey(message.conversation_id),
      '*',
      {
        messageId: message.id,
        senderId: message.sender_id,
        sequence: String(message.sequence),
        nonce: message.nonce_b64,
        ciphertext: message.ciphertext_b64,
        createdAt: message.created_at,
      },
      {
        trim: { type: 'MAXLEN', comparison: '~', threshold: 5000 },
      },
    );
  } catch (error) {
    console.error('[realtime] Redis XADD failed; Postgres cursor will deliver the message.', error);
    return null;
  }
}

async function readRedisEvents(
  conversationId: string,
  cursor: RelayCursor,
  limit: number,
): Promise<{ events: RelayEvent[]; nextStreamId: string | null }> {
  const redis = getRedis();
  if (!redis) return { events: [], nextStreamId: cursor.streamId };

  const key = streamKey(conversationId);
  const events: RelayEvent[] = [];
  let nextStreamId = cursor.streamId;

  try {
    let raw: Record<string, Record<string, unknown>>;
    if (cursor.streamId) {
      // Redis 6.2+ exclusive range start.
      raw = await redis.xrange(key, `(${cursor.streamId}`, '+', limit);
    } else {
      raw = await redis.xrange(key, '-', '+', limit);
    }

    for (const [streamId, fields] of Object.entries(raw ?? {})) {
      nextStreamId = streamId;
      const event = parseStreamEntry(conversationId, streamId, fields);
      if (event && event.sequence > cursor.afterSequence) {
        events.push(event);
      }
    }
  } catch (error) {
    console.error('[realtime] Redis XRANGE failed; falling back to Postgres.', error);
  }

  return { events, nextStreamId };
}

/**
 * Read from Redis Streams first (fast fan-out / replay) and reconcile against
 * Postgres (durable cursor). Duplicate sequences are collapsed by the caller's
 * idempotent merge; Postgres wins if both sources are present.
 */
export async function readRelayEvents(
  conversationId: string,
  cursor: RelayCursor,
  limit: number,
): Promise<{ events: RelayEvent[]; nextStreamId: string | null }> {
  const redisResult = await readRedisEvents(conversationId, cursor, limit);
  const bySequence = new Map<number, RelayEvent>();

  for (const event of redisResult.events) {
    bySequence.set(event.sequence, event);
  }

  const rows = await getMessagesAfter(conversationId, cursor.afterSequence, limit);
  for (const row of rows) {
    const existing = bySequence.get(Number(row.sequence));
    if (existing) continue;
    bySequence.set(Number(row.sequence), {
      id: row.id,
      conversation_id: row.conversationId,
      sender_id: row.senderId,
      sequence: Number(row.sequence),
      nonce_b64: bytesToBase64(row.nonce),
      ciphertext_b64: bytesToBase64(row.ciphertext),
      created_at:
        row.createdAt instanceof Date ? row.createdAt.toISOString() : String(row.createdAt),
      stream_id: null,
    });
  }

  return {
    events: [...bySequence.values()].sort((a, b) => a.sequence - b.sequence),
    nextStreamId: redisResult.nextStreamId,
  };
}

export async function getLatestStreamId(conversationId: string): Promise<string | null> {
  const redis = getRedis();
  if (!redis) return null;
  try {
    const raw = await redis.xrevrange(streamKey(conversationId), '+', '-', 1);
    const first = Object.keys(raw ?? {})[0];
    return streamIdIsValid(first) ? first : null;
  } catch (error) {
    console.error('[realtime] Redis XREVRANGE failed.', error);
    return null;
  }
}

export { streamIdIsValid };
