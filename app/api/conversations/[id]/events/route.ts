import { handleRouteError, parseIntParam } from '@/lib/api';
import { requireSessionUser } from '@/lib/auth/request';
import { getLatestSequence, requireConversationForUser } from '@/lib/server/conversations';
import { readRelayEvents, streamIdIsValid } from '@/lib/realtime/events';
import { MAX_MESSAGE_PAGE_SIZE } from '@/lib/protocol';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}

/**
 * SSE fallback / local-development transport. It reads the same Redis Streams
 * cursor as the WebSocket route, so a reconnect replays everything after the
 * last stream id (and reconciles with Postgres).
 */
export async function GET(
  req: Request,
  context: { params: Promise<{ id: string }> },
) {
  try {
    const user = await requireSessionUser(req);
    const { id: conversationId } = await context.params;
    await requireConversationForUser(conversationId, user.id);

    const url = new URL(req.url);
    const afterSequence = parseIntParam(url.searchParams.get('after'), {
      min: 0,
      max: Number.MAX_SAFE_INTEGER,
      fallback: 0,
    });
    const streamParam =
      url.searchParams.get('stream') ?? req.headers.get('last-event-id') ?? null;
    let streamId = streamIdIsValid(streamParam) ? streamParam : null;
    const latestSequence = await getLatestSequence(conversationId);
    const signal = req.signal;
    const encoder = new TextEncoder();

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        let closed = false;
        let cursorSequence = afterSequence;
        let lastWrite = Date.now();

        const close = () => {
          if (closed) return;
          closed = true;
          try {
            controller.close();
          } catch {
            // Already closed by the platform.
          }
        };

        const enqueue = (chunk: string): boolean => {
          if (closed || signal.aborted) return false;
          try {
            controller.enqueue(encoder.encode(chunk));
            lastWrite = Date.now();
            return true;
          } catch {
            closed = true;
            return false;
          }
        };

        const sendEvent = (
          eventName: string,
          data: unknown,
          id?: string,
        ): boolean => {
          const lines = [];
          if (id) lines.push(`id: ${id}`);
          lines.push(`event: ${eventName}`);
          lines.push(`data: ${JSON.stringify(data)}`);
          return enqueue(`${lines.join('\n')}\n\n`);
        };

        signal.addEventListener('abort', close, { once: true });

        void (async () => {
          sendEvent('ready', {
            type: 'ready',
            latest_sequence: latestSequence,
          });

          const deadline = Date.now() + 55_000;

          while (!closed && !signal.aborted && Date.now() < deadline) {
            try {
              const { events, nextStreamId } = await readRelayEvents(
                conversationId,
                { afterSequence: cursorSequence, streamId },
                MAX_MESSAGE_PAGE_SIZE,
              );
              streamId = nextStreamId;

              for (const event of events) {
                const sent = sendEvent(
                  'message',
                  { type: 'message', event },
                  event.stream_id ?? String(event.sequence),
                );
                if (!sent) break;
                cursorSequence = Math.max(cursorSequence, event.sequence);
              }

              if (Date.now() - lastWrite > 15_000) {
                enqueue(`: heartbeat ${Date.now()}\n\n`);
              }
            } catch (error) {
              console.error('[sse] relay read failed', error);
              sendEvent('relay-error', {
                type: 'error',
                retryable: true,
                message: 'Realtime relay temporarily unavailable.',
              });
              await sleep(2000, signal);
              continue;
            }

            await sleep(1000, signal);
          }

          if (!closed) {
            sendEvent('reconnect', { type: 'reconnect' });
          }
          close();
        })();
      },
    });

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
      },
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
