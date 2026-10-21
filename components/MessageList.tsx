'use client';

import { useEffect, useRef } from 'react';
import { AlertIcon, LockIcon, RefreshIcon, SpinnerIcon } from '@/components/icons';
import { Button, cn } from '@/components/ui';
import type { DecryptionEntry, UiMessage } from './message-types';

function timeLabel(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return `${iso.slice(11, 16)} UTC`;
}

export function MessageList({
  messages,
  decrypted,
  selfId,
  keysReady,
  hasMore,
  loadingOlder,
  onLoadOlder,
  onRetry,
}: {
  messages: UiMessage[];
  decrypted: Record<number, DecryptionEntry>;
  selfId: string;
  keysReady: boolean;
  hasMore: boolean;
  loadingOlder: boolean;
  onLoadOlder: () => void;
  onRetry: (message: UiMessage) => void;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const stickToBottomRef = useRef(true);
  const previousCountRef = useRef(0);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    if (messages.length !== previousCountRef.current && stickToBottomRef.current) {
      container.scrollTop = container.scrollHeight;
    }
    previousCountRef.current = messages.length;
  }, [messages.length]);

  const onScroll = () => {
    const container = containerRef.current;
    if (!container) return;
    stickToBottomRef.current =
      container.scrollHeight - container.scrollTop - container.clientHeight < 120;
  };

  return (
    <div
      ref={containerRef}
      onScroll={onScroll}
      className="thin-scrollbar flex-1 overflow-y-auto px-4 py-4"
    >
      {hasMore ? (
        <div className="mb-4 flex justify-center">
          <Button variant="secondary" onClick={onLoadOlder} disabled={loadingOlder} className="h-8 text-xs">
            {loadingOlder ? 'Loading…' : 'Load older ciphertext'}
          </Button>
        </div>
      ) : null}

      {messages.length === 0 ? (
        <div className="flex h-full min-h-52 flex-col items-center justify-center gap-3 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-slate-800 bg-slate-900">
            <LockIcon className="h-5 w-5 text-violet-400" />
          </div>
          <div>
            <p className="text-sm font-medium text-slate-300">No messages yet</p>
            <p className="mt-1 text-xs text-slate-500">
              The first message establishes the encrypted transcript.
            </p>
          </div>
        </div>
      ) : null}

      <div className="space-y-2.5">
        {messages.map((message) => {
          const own = message.senderId === selfId;
          const entry = decrypted[message.sequence];
          const plaintext = entry?.plaintext ?? message.localPlaintext;
          const failed = entry?.error;

          return (
            <div key={message.id} className={cn('flex', own ? 'justify-end' : 'justify-start')}>
              <div
                className={cn(
                  'max-w-[85%] rounded-2xl border px-3.5 py-2.5 text-sm shadow-sm sm:max-w-[72%]',
                  own
                    ? 'border-violet-500/30 bg-violet-600/20 text-slate-100'
                    : 'border-slate-800 bg-slate-900/80 text-slate-100',
                  message.pending ? 'opacity-70' : '',
                  message.failed ? 'border-rose-500/40 bg-rose-950/30' : '',
                  failed ? 'border-rose-500/40 bg-rose-950/30' : '',
                )}
              >
                {failed ? (
                  <div className="flex items-start gap-2 text-rose-200">
                    <AlertIcon className="mt-0.5 h-4 w-4 shrink-0" />
                    <div>
                      <p className="font-medium">Decryption failed</p>
                      <p className="mt-1 text-xs leading-5 text-rose-200/80">
                        The ciphertext, nonce, sender, sequence, or GCM tag did not
                        authenticate. The message is not rendered.
                      </p>
                    </div>
                  </div>
                ) : plaintext !== undefined ? (
                  <p className="whitespace-pre-wrap break-words leading-6">{plaintext}</p>
                ) : !keysReady ? (
                  <p className="flex items-center gap-2 text-xs text-slate-400">
                    <LockIcon className="h-3.5 w-3.5" />
                    Unlock your keys to decrypt this ciphertext.
                  </p>
                ) : (
                  <p className="flex items-center gap-2 text-xs text-slate-400">
                    <SpinnerIcon className="h-3.5 w-3.5" />
                    Authenticating…
                  </p>
                )}

                <div
                  className={cn(
                    'mt-1.5 flex items-center gap-1.5 text-[10px]',
                    own ? 'text-violet-200/60' : 'text-slate-500',
                  )}
                >
                  <span className="mono">#{message.sequence}</span>
                  <span>·</span>
                  <time dateTime={message.createdAt} title={message.createdAt}>
                    {timeLabel(message.createdAt)}
                  </time>
                  {message.pending ? <span>· sending…</span> : null}
                  {message.failed ? <span>· not delivered</span> : null}
                  {message.failed && message.localPlaintext && onRetry ? (
                    <button
                      type="button"
                      onClick={() => onRetry(message)}
                      className="ml-1 inline-flex items-center gap-1 rounded px-1 py-0.5 text-rose-200 hover:bg-rose-500/10"
                    >
                      <RefreshIcon className="h-3 w-3" />
                      retry
                    </button>
                  ) : null}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
