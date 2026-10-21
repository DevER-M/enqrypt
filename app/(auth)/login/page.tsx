'use client';

import Link from 'next/link';
import { useState, type FormEvent } from 'react';
import { apiPost } from '@/lib/client/api';
import { Alert, Button, Input } from '@/components/ui';
import { ArrowRightIcon } from '@/components/icons';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiPost<{ user_id: string; username: string }>('/api/auth/login', {
        username,
        password,
      });
      // Full reload so the server layout receives the new cookie and the
      // KeyringProvider loads this browser's wrapped key.
      window.location.assign('/chat');
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Could not log in.');
      setBusy(false);
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-semibold text-slate-100">Welcome back</h1>
      <p className="mt-1 text-sm text-slate-400">
        Sign in to the relay. Your passphrase is asked separately to unlock local keys.
      </p>

      <form onSubmit={submit} className="mt-6 space-y-4">
        <div>
          <label htmlFor="username" className="label">
            Username
          </label>
          <Input
            id="username"
            name="username"
            autoComplete="username"
            required
            minLength={3}
            maxLength={32}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            placeholder="alice"
          />
        </div>
        <div>
          <label htmlFor="password" className="label">
            Password
          </label>
          <Input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Your account password"
          />
        </div>

        {error ? <Alert tone="error">{error}</Alert> : null}

        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
          {!busy ? <ArrowRightIcon className="h-4 w-4" /> : null}
        </Button>
      </form>

      <p className="mt-5 text-center text-sm text-slate-400">
        No account?{' '}
        <Link href="/register" className="font-medium text-violet-300 hover:text-violet-200">
          Create one
        </Link>
      </p>
    </div>
  );
}
