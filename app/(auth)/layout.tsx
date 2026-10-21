import { redirect } from 'next/navigation';
import { getSessionUserFromCookies } from '@/lib/auth/server';
import { Brand } from '@/components/ui';
import { LockIcon, ShieldIcon } from '@/components/icons';

export const dynamic = 'force-dynamic';

export default async function AuthLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  const user = await getSessionUserFromCookies();
  if (user) redirect('/chat');

  return (
    <div className="mx-auto flex min-h-dvh w-full max-w-6xl flex-col items-center justify-center gap-8 px-4 py-10 lg:flex-row lg:gap-16">
      <section className="hidden max-w-md flex-1 lg:block">
        <Brand />
        <h1 className="mt-8 text-4xl font-semibold leading-tight tracking-tight text-slate-100">
          Messages only you
          <br />
          and your contact can read.
        </h1>
        <p className="mt-4 text-sm leading-6 text-slate-400">
          enqrypt uses <span className="text-slate-200">ML-KEM-768</span> for
          post-quantum key establishment and <span className="text-slate-200">AES-256-GCM</span>{' '}
          for messages. The server is a blind relay: it stores ciphertext and public keys,
          never your plaintext or private key.
        </p>
        <div className="mt-8 grid gap-3 text-sm text-slate-400">
          <div className="flex items-center gap-3">
            <ShieldIcon className="h-5 w-5 text-violet-400" />
            Directional keys with HKDF domain separation
          </div>
          <div className="flex items-center gap-3">
            <LockIcon className="h-5 w-5 text-violet-400" />
            Passphrase-wrapped key material in IndexedDB
          </div>
          <div className="flex items-center gap-3">
            <ShieldIcon className="h-5 w-5 text-violet-400" />
            Safety numbers for key verification (TOFU)
          </div>
        </div>
      </section>

      <section className="w-full max-w-md">
        <div className="mb-6 lg:hidden">
          <Brand />
        </div>
        <div className="card p-6 shadow-2xl shadow-black/30 sm:p-8">{children}</div>
        <p className="mt-4 text-center text-xs text-slate-600">
          Metadata (who talks to whom, when, and message sizes) is visible to the server.
        </p>
      </section>
    </div>
  );
}
