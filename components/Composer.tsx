'use client';

import { useRef, useState, type FormEvent, type KeyboardEvent } from 'react';
import { MAX_MESSAGE_PLAINTEXT_CHARS } from '@/lib/protocol';
import { LockIcon, SendIcon } from '@/components/icons';
import { Alert, Button } from '@/components/ui';

export function Composer({
  disabled,
  disabledReason,
  sending,
  onSend,
}: {
  disabled: boolean;
  disabledReason: string;
  sending: boolean;
  onSend: (plaintext: string) => Promise<boolean>;
}) {
  const [text, setText] = useState('');
  const [error, setError] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const composingRef = useRef(false);

  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    const plaintext = text.trim();
    if (!plaintext || disabled || sending) return;
    setError(null);
    const ok = await onSend(plaintext);
    if (ok) {
      setText('');
      textareaRef.current?.focus();
    } else {
      setError('The message was not delivered. Your plaintext is still in the box.');
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key !== 'Enter' || event.shiftKey) return;
    if (composingRef.current) return;
    event.preventDefault();
    void submit();
  };

  const tooLong = text.length > MAX_MESSAGE_PLAINTEXT_CHARS;

  return (
    <form onSubmit={submit} className="border-t border-slate-800 bg-slate-950/40 p-3">
      {error ? <div className="mb-2"><Alert tone="error">{error}</Alert></div> : null}
      <div className="flex items-end gap-2">
        <textarea
          ref={textareaRef}
          value={text}
          onChange={(event) => setText(event.target.value)}
          onKeyDown={onKeyDown}
          onCompositionStart={() => {
            composingRef.current = true;
          }}
          onCompositionEnd={() => {
            composingRef.current = false;
          }}
          disabled={disabled || sending}
          rows={1}
          placeholder={disabled ? disabledReason : 'Write a message…'}
          className="input max-h-40 min-h-11 flex-1 resize-y py-2.5"
          maxLength={MAX_MESSAGE_PLAINTEXT_CHARS + 200}
        />
        <Button
          type="submit"
          disabled={disabled || sending || tooLong || text.trim().length === 0}
          className="h-11 w-11 shrink-0 p-0"
          aria-label="Send encrypted message"
          title={disabled ? disabledReason : 'Encrypt and send'}
        >
          <SendIcon className="h-4 w-4" />
        </Button>
      </div>
      <div className="mt-1.5 flex items-center justify-between px-1 text-[10px] text-slate-500">
        <span className="flex items-center gap-1">
          <LockIcon className="h-3 w-3 text-emerald-500/80" />
          AES-256-GCM · Enter to send · Shift+Enter for newline
        </span>
        <span className={tooLong ? 'text-rose-300' : ''}>
          {text.length}/{MAX_MESSAGE_PLAINTEXT_CHARS}
        </span>
      </div>
    </form>
  );
}
