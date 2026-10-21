'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { apiGet, apiPost } from '@/lib/client/api';
import { Alert, Button, Input } from '@/components/ui';
import { PlusIcon } from '@/components/icons';

export function NewChatForm({ autoFocus = false }: { autoFocus?: boolean }) {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const normalized = username.trim().toLowerCase();
    if (!normalized) return;

    setBusy(true);
    setError(null);
    try {
      const peer = await apiGet<{ user_id: string; username: string }>(
        `/api/users/by-username/${encodeURIComponent(normalized)}`,
      );
      const conversation = await apiPost<{ conversation_id: string }>(
        '/api/conversations',
        { peer_user_id: peer.user_id },
      );
      router.push(`/chat/${conversation.conversation_id}`);
    } catch (submitError) {
      setError(
        submitError instanceof Error ? submitError.message : 'Could not start the conversation.',
      );
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-3">
      <label htmlFor="peer-username" className="label">
        Start a conversation
      </label>
      <div className="flex gap-2">
        <Input
          id="peer-username"
          autoFocus={autoFocus}
          value={username}
          onChange={(event) => setUsername(event.target.value.toLowerCase())}
          placeholder="Contact's username"
          autoComplete="off"
          maxLength={32}
        />
        <Button type="submit" disabled={busy || username.trim().length < 3}>
          <PlusIcon className="h-4 w-4" />
          {busy ? 'Starting…' : 'Start'}
        </Button>
      </div>
      {error ? <Alert tone="error">{error}</Alert> : null}
      <p className="text-xs text-slate-500">
        The conversation id is deterministic from both user ids. A KEM handshake starts
        when either participant opens it.
      </p>
    </form>
  );
}
