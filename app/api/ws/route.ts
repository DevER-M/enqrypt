import { upgradeWebSocket, type WebSocketData } from '@vercel/functions';
import { getSessionUserFromRequest } from '@/lib/auth/request';
import { isSameOrigin } from '@/lib/auth/origin';
import {
  getConversationForUser,
  getLatestSequence,
} from '@/lib/server/conversations';
import { readRelayEvents, streamIdIsValid } from '@/lib/realtime/events';
import { MAX_MESSAGE_PAGE_SIZE } from '@/lib/protocol';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 300;

type ClientMessage = {
  type?: string;
  conversationId?: unknown;
  afterSequence?: unknown;
  afterStreamId?: unknown;
};

function rawToString(raw: WebSocketData): string {
  if (typeof raw === 'string') return raw;
  if (raw instanceof ArrayBuffer) return new TextDecoder().decode(raw);
  if (Array.isArray(raw)) return Buffer.concat(raw).toString('utf8');
  return Buffer.from(raw as Uint8Array).toString('utf8');
}

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
 * Vercel Function WebSocket endpoint. Each socket is pinned to one instance,
 * so it never broadcasts to an in-process hub: it reads the shared Redis
 * Stream (and reconciles with Postgres), which makes cross-instance delivery
 * work without a global registry.
 *
 * Local `next dev` does not support WebSocket upgrades; this route returns 501
 * and the browser client automatically uses the SSE endpoint instead.
 */
export async function GET(req: Request) {
  const user = await getSessionUserFromRequest(req);
  if (!user) {
    return Response.json(
      { error: 'unauthorized', message: 'A valid session is required.' },
      { status: 401 },
    );
  }
  if (!isSameOrigin(req)) {
    return Response.json(
      { error: 'bad_origin', message: 'Cross-origin requests are not allowed.' },
      { status: 403 },
    );
  }

  try {
    return await upgradeWebSocket((ws) => {
      let abortController: AbortController | null = null;
      let generation = 0;

      const send = (payload: unknown): void => {
        if (ws.readyState !== 1) return;
        try {
          ws.send(JSON.stringify(payload));
        } catch {
          // Socket closed between the readyState check and send.
        }
      };

      const runSubscription = async (
        subscriptionGeneration: number,
        subscription: {
          conversationId: string;
          afterSequence: number;
          afterStreamId: string | null;
        },
      ): Promise<void> => {
        const controller = new AbortController();
        abortController = controller;
        const signal = controller.signal;

        try {
          const conversation = await getConversationForUser(
            subscription.conversationId,
            user.id,
          );
          if (!conversation) {
            send({
              type: 'error',
              error: 'conversation_not_found',
              message: 'Conversation not found.',
            });
            return;
          }

          const latestSequence = await getLatestSequence(subscription.conversationId);
          send({
            type: 'ready',
            conversationId: subscription.conversationId,
            latestSequence,
          });

          let cursorSequence = subscription.afterSequence;
          let streamId = subscription.afterStreamId;
          let lastWrite = Date.now();

          while (
            !signal.aborted &&
            ws.readyState === 1 &&
            generation === subscriptionGeneration
          ) {
            try {
              const { events, nextStreamId } = await readRelayEvents(
                subscription.conversationId,
                { afterSequence: cursorSequence, streamId },
                MAX_MESSAGE_PAGE_SIZE,
              );
              streamId = nextStreamId;

              for (const event of events) {
                send({ type: 'message', event });
                cursorSequence = Math.max(cursorSequence, event.sequence);
              }

              if (Date.now() - lastWrite > 20_000) {
                send({ type: 'heartbeat', at: Date.now() });
                lastWrite = Date.now();
              }
            } catch (error) {
              console.error('[ws] relay read failed', error);
              send({
                type: 'error',
                error: 'relay_unavailable',
                retryable: true,
                message: 'Realtime relay temporarily unavailable.',
              });
              await sleep(2000, signal);
              continue;
            }

            await sleep(1000, signal);
          }
        } catch (error) {
          console.error('[ws] subscription failed', error);
          send({
            type: 'error',
            error: 'subscription_failed',
            retryable: true,
            message: 'Could not start the realtime subscription.',
          });
        }
      };

      ws.on('message', (raw) => {
        let parsed: unknown;
        try {
          parsed = JSON.parse(rawToString(raw));
        } catch {
          send({ type: 'error', error: 'invalid_json' });
          return;
        }

        const message = parsed as ClientMessage;
        if (message.type === 'ping') {
          send({ type: 'pong', at: Date.now() });
          return;
        }
        if (message.type !== 'subscribe') {
          send({ type: 'error', error: 'unsupported_message' });
          return;
        }

        const conversationId =
          typeof message.conversationId === 'string' ? message.conversationId : '';
        const afterSequence =
          typeof message.afterSequence === 'number' &&
          Number.isSafeInteger(message.afterSequence) &&
          message.afterSequence >= 0
            ? message.afterSequence
            : 0;
        const afterStreamId =
          typeof message.afterStreamId === 'string' &&
          streamIdIsValid(message.afterStreamId)
            ? message.afterStreamId
            : null;

        if (!conversationId) {
          send({ type: 'error', error: 'invalid_subscription' });
          return;
        }

        abortController?.abort();
        generation += 1;
        const currentGeneration = generation;

        void runSubscription(currentGeneration, {
          conversationId,
          afterSequence,
          afterStreamId,
        });
      });

      ws.on('close', () => {
        generation += 1;
        abortController?.abort();
        abortController = null;
      });

      ws.on('error', () => {
        generation += 1;
        abortController?.abort();
        abortController = null;
      });
    });
  } catch (error) {
    console.error('[ws] WebSocket upgrade unavailable', error);
    return Response.json(
      {
        error: 'websocket_unavailable',
        message: 'WebSocket upgrades are not available in this runtime.',
      },
      { status: 501 },
    );
  }
}
