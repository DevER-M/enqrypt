'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { LockIcon } from '@/components/icons';
import { cn } from '@/components/ui';

export type ConversationListItem = {
  conversationId: string;
  peerId: string;
  peerUsername: string;
  createdAt: string;
  lastMessageAt: string | null;
};

function utcLabel(iso: string | null): string {
  if (!iso) return 'No messages yet';
  return `${iso.slice(0, 16).replace('T', ' ')} UTC`;
}

export function SidebarNav({ conversations }: { conversations: ConversationListItem[] }) {
  const pathname = usePathname();

  if (conversations.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 px-3 py-6 text-center text-sm text-slate-500">
        No conversations yet.
        <br />
        Start one with a username.
      </div>
    );
  }

  return (
    <nav className="flex gap-2 overflow-x-auto md:flex-col md:overflow-visible">
      {conversations.map((conversation) => {
        const href = `/chat/${conversation.conversationId}`;
        const active = pathname === href;
        return (
          <Link
            key={conversation.conversationId}
            href={href}
            className={cn(
              'min-w-48 rounded-xl border px-3 py-2.5 transition md:min-w-0',
              active
                ? 'border-violet-500/40 bg-violet-500/10'
                : 'border-slate-800 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-800/50',
            )}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="truncate text-sm font-medium text-slate-200">
                {conversation.peerUsername}
              </span>
              <LockIcon className="h-3.5 w-3.5 shrink-0 text-emerald-400/80" />
            </div>
            <div className="mt-1 truncate text-[11px] text-slate-500">
              {utcLabel(conversation.lastMessageAt)}
            </div>
          </Link>
        );
      })}
    </nav>
  );
}
