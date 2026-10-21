import { getSessionUserFromCookies } from '@/lib/auth/server';
import { redirect } from 'next/navigation';
import { NewChatForm } from '@/components/NewChatForm';
import { LockIcon, ShieldIcon } from '@/components/icons';

export const dynamic = 'force-dynamic';

export default async function ChatIndexPage() {
  const user = await getSessionUserFromCookies();
  if (!user) redirect('/login');

  return (
    <div className="thin-scrollbar flex-1 overflow-y-auto px-4 py-8 sm:px-8">
      <div className="mx-auto flex w-full max-w-2xl flex-col gap-8">
        <div>
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-slate-800 bg-slate-900">
            <LockIcon className="h-5 w-5 text-violet-400" />
          </div>
          <h1 className="mt-4 text-2xl font-semibold tracking-tight text-slate-100">
            Start a private conversation
          </h1>
          <p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">
            Enter the username of someone who has registered. The first time either of
            you opens the conversation, this browser performs an ML-KEM-768 key
            encapsulation and derives directional AES-256-GCM keys locally.
          </p>
        </div>

        <div className="card bg-slate-950/40 p-4 sm:p-5">
          <NewChatForm autoFocus />
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
            <ShieldIcon className="h-4 w-4 text-violet-400" />
            <h2 className="mt-2 text-sm font-medium text-slate-200">Post-quantum KEM</h2>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              ML-KEM-768 from <span className="mono">@noble/post-quantum</span>. No
              classical X25519 fallback is used.
            </p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
            <LockIcon className="h-4 w-4 text-violet-400" />
            <h2 className="mt-2 text-sm font-medium text-slate-200">Directional keys</h2>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              HKDF-SHA256 derives separate sender keys. Sequence, sender, and
              conversation are bound into the GCM AAD.
            </p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
            <ShieldIcon className="h-4 w-4 text-violet-400" />
            <h2 className="mt-2 text-sm font-medium text-slate-200">Blind relay</h2>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              The server stores ciphertext and public keys. Unlock your keys in this
              browser to decrypt history.
            </p>
          </div>
        </div>

        <p className="text-xs leading-5 text-slate-600">
          Metadata — who talks to whom, when, and ciphertext sizes — remains visible to
          the relay. Verify a contact&apos;s safety number out of band after your first
          exchange.
        </p>
      </div>
    </div>
  );
}
