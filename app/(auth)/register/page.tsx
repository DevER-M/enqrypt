'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { apiPost } from '@/lib/client/api';
import { publicKeyFingerprint } from '@/lib/crypto/safetyNumber';
import { bytesToBase64 } from '@/lib/encoding';
import { useKeyring } from '@/lib/stores/keyring';
import { Alert, Button, Input } from '@/components/ui';
import { ArrowRightIcon } from '@/components/icons';

type PendingKeys = {
  userId: string;
  username: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  passphrase: string;
};

type Phase = 'idle' | 'generating' | 'wrapping' | 'done';

export default function RegisterPage() {
  const router = useRouter();
  const keyring = useKeyring();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingKeys | null>(null);

  const saveLocalKeys = async (keys: PendingKeys) => {
    await keyring.registerIdentity({
      userId: keys.userId,
      username: keys.username,
      publicKey: keys.publicKey,
      secretKey: keys.secretKey,
      passphrase: keys.passphrase,
    });
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);

    if (password.length < 10) {
      setError('Account password must be at least 10 characters.');
      return;
    }
    if (passphrase.length < 12) {
      setError('Key passphrase must be at least 12 characters.');
      return;
    }
    if (passphrase !== confirm) {
      setError('Passphrases do not match.');
      return;
    }

    setBusy(true);
    setPending(null);

    let keypair: ReturnType<typeof keyring.generateKeypair> | null = null;
    let accountCreated = false;

    try {
      setPhase('generating');
      // Let the UI paint before running synchronous ML-KEM keygen.
      await new Promise((resolve) => setTimeout(resolve, 20));
      keypair = keyring.generateKeypair();
      const fingerprint = publicKeyFingerprint(keypair.publicKey);

      setPhase('wrapping');
      const account = await apiPost<{ user_id: string; username: string }>(
        '/api/auth/register',
        {
          username,
          password,
          ml_kem_public_key_b64: bytesToBase64(keypair.publicKey),
          key_fingerprint: fingerprint,
        },
      );
      accountCreated = true;

      const keys: PendingKeys = {
        userId: account.user_id,
        username: account.username,
        publicKey: keypair.publicKey,
        secretKey: keypair.secretKey,
        passphrase,
      };

      try {
        await saveLocalKeys(keys);
      } catch {
        // The account exists and the session cookie is set, but the browser
        // could not persist the wrapped key. Keep the keypair in memory so the
        // user can retry without re-registering.
        setPending(keys);
        setPhase('idle');
        setBusy(false);
        setError(
          'Your account was created, but this browser could not save the wrapped key. Retry below before leaving this page.',
        );
        return;
      }

      setPhase('done');
      keypair = null; // Ownership moved to the keyring provider.
      router.replace('/chat');
      router.refresh();
    } catch (submitError) {
      setError(
        submitError instanceof Error ? submitError.message : 'Could not create the account.',
      );
      if (keypair && !accountCreated) {
        keypair.secretKey.fill(0);
      }
      setPhase('idle');
      setBusy(false);
    }
  };

  const retryLocalSave = async () => {
    if (!pending) return;
    setBusy(true);
    setError(null);
    try {
      await saveLocalKeys(pending);
      setPending(null);
      setPhase('done');
      router.replace('/chat');
      router.refresh();
    } catch (retryError) {
      setError(
        retryError instanceof Error
          ? retryError.message
          : 'Still could not save the wrapped key.',
      );
      setBusy(false);
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-semibold text-slate-100">Create your account</h1>
      <p className="mt-1 text-sm leading-6 text-slate-400">
        Your ML-KEM keypair is generated in this browser. The secret key is wrapped with
        your passphrase before it touches IndexedDB and is never sent to the server.
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
            pattern="[a-z0-9_]+"
            value={username}
            onChange={(event) => setUsername(event.target.value.toLowerCase())}
            placeholder="alice"
          />
          <p className="mt-1 text-xs text-slate-600">
            Lowercase letters, numbers, and underscores.
          </p>
        </div>
        <div>
          <label htmlFor="password" className="label">
            Account password
          </label>
          <Input
            id="password"
            name="password"
            type="password"
            autoComplete="new-password"
            required
            minLength={10}
            maxLength={72}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="At least 10 characters"
          />
        </div>
        <div>
          <label htmlFor="passphrase" className="label">
            Key passphrase
          </label>
          <Input
            id="passphrase"
            name="passphrase"
            type="password"
            autoComplete="new-password"
            required
            minLength={12}
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
            placeholder="At least 12 characters"
          />
        </div>
        <div>
          <label htmlFor="confirm" className="label">
            Confirm passphrase
          </label>
          <Input
            id="confirm"
            name="confirm"
            type="password"
            autoComplete="new-password"
            required
            minLength={12}
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            placeholder="Repeat the key passphrase"
          />
        </div>

        <Alert tone="warn">
          The account password signs you in. The <strong>key passphrase</strong> wraps your
          private key. If you lose the passphrase (and have no backup), you cannot decrypt
          your history. The server cannot recover it.
        </Alert>

        {error ? <Alert tone="error">{error}</Alert> : null}

        {pending ? (
          <Button type="button" className="w-full" onClick={retryLocalSave} disabled={busy}>
            {busy ? 'Saving…' : 'Retry saving wrapped key'}
          </Button>
        ) : (
          <Button type="submit" className="w-full" disabled={busy}>
            {phase === 'generating'
              ? 'Generating ML-KEM-768 keys…'
              : phase === 'wrapping'
                ? 'Wrapping private key…'
                : busy
                  ? 'Creating account…'
                  : 'Create account'}
            {!busy ? <ArrowRightIcon className="h-4 w-4" /> : null}
          </Button>
        )}
      </form>

      <p className="mt-5 text-center text-sm text-slate-400">
        Already registered?{' '}
        <Link href="/login" className="font-medium text-violet-300 hover:text-violet-200">
          Sign in
        </Link>
      </p>
    </div>
  );
}
