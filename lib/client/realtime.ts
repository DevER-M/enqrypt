export type RealtimeEvent = {
  id: string;
  conversation_id: string;
  sender_id: string;
  sequence: number;
  nonce_b64: string;
  ciphertext_b64: string;
  created_at: string;
  stream_id: string | null;
};

export type RealtimeStatus = 'connecting' | 'live' | 'reconnecting' | 'offline';

export type SubscribeOptions = {
  conversationId: string;
  afterSequence: number;
  afterStreamId: string | null;
  onEvent: (event: RealtimeEvent) => void;
  onReady: () => void;
  onStatus: (status: RealtimeStatus) => void;
};

const STREAM_ID_RE = /^\d+-\d+$/;

function parseEvent(value: unknown): RealtimeEvent | null {
  if (typeof value !== 'object' || value === null) return null;
  const event = value as Partial<RealtimeEvent>;
  if (
    typeof event.id !== 'string' ||
    typeof event.conversation_id !== 'string' ||
    typeof event.sender_id !== 'string' ||
    typeof event.sequence !== 'number' ||
    !Number.isSafeInteger(event.sequence) ||
    event.sequence <= 0 ||
    typeof event.nonce_b64 !== 'string' ||
    typeof event.ciphertext_b64 !== 'string' ||
    typeof event.created_at !== 'string'
  ) {
    return null;
  }
  return {
    id: event.id,
    conversation_id: event.conversation_id,
    sender_id: event.sender_id,
    sequence: event.sequence,
    nonce_b64: event.nonce_b64,
    ciphertext_b64: event.ciphertext_b64,
    created_at: event.created_at,
    stream_id:
      typeof event.stream_id === 'string' && STREAM_ID_RE.test(event.stream_id)
        ? event.stream_id
        : null,
  };
}

/**
 * WebSocket is preferred in production (Vercel Functions support native
 * upgrades). If the upgrade is unavailable — or the project is running under
 * `next dev`, which cannot upgrade — the client switches to SSE. Both transports
 * use the same replay cursor, so switching does not lose messages.
 */
export function subscribeToConversation(options: SubscribeOptions): () => void {
  const preference = process.env.NEXT_PUBLIC_REALTIME_TRANSPORT ?? 'auto';
  const shouldTryWebSocket =
    preference === 'ws' ||
    (preference === 'auto' && process.env.NODE_ENV === 'production');

  let stopped = false;
  let mode: 'ws' | 'sse' | null = null;
  let socket: WebSocket | null = null;
  let eventSource: EventSource | null = null;
  let retry = 0;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let openTimer: ReturnType<typeof setTimeout> | null = null;
  let wsReady = false;
  let wsFailures = 0;
  const cursor = {
    sequence: options.afterSequence,
    streamId: options.afterStreamId,
  };

  const setStatus = (status: RealtimeStatus) => {
    if (!stopped) options.onStatus(status);
  };

  const clearTimers = () => {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (openTimer) {
      clearTimeout(openTimer);
      openTimer = null;
    }
  };

  const backoffMs = () => {
    const base = Math.min(15_000, 1000 * 2 ** Math.min(retry, 4));
    return base + Math.floor(Math.random() * 250);
  };

  const applyEvent = (raw: unknown) => {
    const event = parseEvent(raw);
    if (!event) return;
    cursor.sequence = Math.max(cursor.sequence, event.sequence);
    if (event.stream_id) cursor.streamId = event.stream_id;
    options.onEvent(event);
  };

  const cleanupWs = () => {
    if (socket) {
      socket.onopen = null;
      socket.onmessage = null;
      socket.onerror = null;
      socket.onclose = null;
      try {
        socket.close();
      } catch {
        // Already closed.
      }
      socket = null;
    }
    wsReady = false;
  };

  const cleanupSse = () => {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
  };

  const scheduleReconnect = (connect: () => void) => {
    if (stopped) return;
    clearTimers();
    retry += 1;
    setStatus('reconnecting');
    reconnectTimer = setTimeout(connect, backoffMs());
  };

  const startSse = () => {
    if (stopped) return;
    cleanupWs();
    cleanupSse();
    mode = 'sse';
    setStatus(retry > 0 ? 'reconnecting' : 'connecting');

    const params = new URLSearchParams({ after: String(cursor.sequence) });
    if (cursor.streamId) params.set('stream', cursor.streamId);

    const source = new EventSource(
      `/api/conversations/${encodeURIComponent(options.conversationId)}/events?${params.toString()}`,
    );
    eventSource = source;

    source.onopen = () => {
      if (stopped) return;
      retry = 0;
      setStatus('live');
    };

    source.addEventListener('ready', () => {
      if (stopped) return;
      retry = 0;
      setStatus('live');
      options.onReady();
    });

    source.addEventListener('message', (message) => {
      if (stopped) return;
      try {
        const payload = JSON.parse((message as MessageEvent).data as string) as {
          type?: string;
          event?: unknown;
        };
        if (payload.type === 'message') applyEvent(payload.event);
      } catch {
        // Ignore malformed frames; the next cursor read will reconcile.
      }
    });

    source.addEventListener('reconnect', () => {
      cleanupSse();
      scheduleReconnect(startSse);
    });

    source.addEventListener('relay-error', () => {
      setStatus('reconnecting');
    });

    source.onerror = () => {
      if (stopped) return;
      cleanupSse();
      scheduleReconnect(startSse);
    };
  };

  const fallbackToSse = () => {
    if (stopped || mode === 'sse') return;
    cleanupWs();
    clearTimers();
    startSse();
  };

  const connectWs = () => {
    if (stopped) return;
    cleanupSse();
    cleanupWs();
    mode = 'ws';
    wsReady = false;
    retry += 1;
    setStatus('connecting');

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socketUrl = `${protocol}//${window.location.host}/api/ws`;
    const nextSocket = new WebSocket(socketUrl);
    socket = nextSocket;

    openTimer = setTimeout(() => {
      if (!wsReady) {
        wsFailures += 1;
        cleanupWs();
        fallbackToSse();
      }
    }, 5000);

    nextSocket.onopen = () => {
      if (stopped) return;
      nextSocket.send(
        JSON.stringify({
          type: 'subscribe',
          conversationId: options.conversationId,
          afterSequence: cursor.sequence,
          afterStreamId: cursor.streamId,
        }),
      );
    };

    nextSocket.onmessage = (message) => {
      if (stopped) return;
      let payload: {
        type?: string;
        event?: unknown;
        retryable?: boolean;
      };
      try {
        payload = JSON.parse(String(message.data)) as typeof payload;
      } catch {
        return;
      }

      if (payload.type === 'ready') {
        wsReady = true;
        wsFailures = 0;
        retry = 0;
        if (openTimer) {
          clearTimeout(openTimer);
          openTimer = null;
        }
        setStatus('live');
        options.onReady();
        return;
      }
      if (payload.type === 'message') {
        applyEvent(payload.event);
        return;
      }
      if (payload.type === 'error' && payload.retryable) {
        setStatus('reconnecting');
      }
    };

    nextSocket.onerror = () => {
      if (stopped) return;
      if (!wsReady) {
        wsFailures += 1;
        cleanupWs();
        fallbackToSse();
      }
    };

    nextSocket.onclose = () => {
      if (stopped) return;
      if (openTimer) {
        clearTimeout(openTimer);
        openTimer = null;
      }
      if (!wsReady) {
        wsFailures += 1;
        fallbackToSse();
        return;
      }
      wsFailures += 1;
      if (wsFailures >= 3) {
        fallbackToSse();
        return;
      }
      scheduleReconnect(connectWs);
    };
  };

  if (shouldTryWebSocket && typeof window !== 'undefined' && 'WebSocket' in window) {
    connectWs();
  } else {
    startSse();
  }

  return () => {
    stopped = true;
    clearTimers();
    cleanupWs();
    cleanupSse();
    setStatus('offline');
  };
}
