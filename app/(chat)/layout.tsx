import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getSessionUserFromCookies } from '@/lib/auth/server';
import { listConversationsForUser } from '@/lib/server/conversations';
import { KeyStatus } from '@/components/KeyStatus';
import { LogoutButton } from '@/components/LogoutButton';
import { SidebarNav, type ConversationListItem } from '@/components/SidebarNav';
import { Brand } from '@/components/ui';
import { LockIcon, PlusIcon, ShieldIcon } from '@/components/icons';

export const dynamic = 'force-dynamic';

export default async function ChatLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  const user = await getSessionUserFromCookies();
  if (!user) redirect('/login');

  const rows = await listConversationsForUser(user.id);
  const conversations: ConversationListItem[] = rows.map((row) => ({
    conversationId: row.id,
    peerId: row.peerId,
    peerUsername: row.peerUsername,
    createdAt: row.createdAt.toISOString(),
    lastMessageAt: row.lastMessageAt?.toISOString() ?? null,
  }));

  return (
    <div className="mx-auto flex min-h-dvh w-full max-w-7xl flex-col gap-3 p-3 sm:p-4 md:h-dvh md:flex-row md:gap-5 md:py-5">
      <aside className="card flex shrink-0 flex-col gap-4 p-3 md:w-72 md:overflow-hidden">
        <div className="flex items-center justify-between gap-2">
          <Link href="/chat" className="rounded-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-violet-500/50">
            <Brand />
          </Link>
          <LogoutButton />
        </div>

        <div className="flex items-center justify-between gap-2 rounded-xl border border-slate-800 bg-slate-950/50 px-3 py-2">
          <div className="min-w-0">
            <div className="truncate text-sm font-medium text-slate-200">
              {user.username}
            </div>
            <div className="mono truncate text-[10px] text-slate-500">{user.id}</div>
          </div>
          <KeyStatus />
        </div>

        <Link
          href="/chat"
          className="btn-secondary h-9 justify-start px-3 text-xs"
          aria-label="Start a new conversation"
        >
          <PlusIcon className="h-4 w-4" />
          New conversation
        </Link>

        <div className="min-h-0 flex-1 md:overflow-y-auto md:pr-1">
          <div className="mb-2 hidden px-1 text-[11px] font-medium uppercase tracking-wide text-slate-500 md:block">
            Conversations
          </div>
          <SidebarNav conversations={conversations} />
        </div>

        <div className="hidden space-y-2 border-t border-slate-800 pt-3 md:block">
          <div className="flex items-center gap-2 text-[11px] text-slate-500">
            <ShieldIcon className="h-3.5 w-3.5 text-emerald-400/80" />
            ML-KEM-768 · HKDF-SHA256 · AES-256-GCM
          </div>
          <div className="flex items-center gap-2 text-[11px] text-slate-500">
            <LockIcon className="h-3.5 w-3.5 text-violet-400/80" />
            Only ciphertext and public keys leave this browser.
          </div>
        </div>
      </aside>

      <main className="card flex min-h-0 flex-1 flex-col overflow-hidden">
        {children}
      </main>
    </div>
  );
}
