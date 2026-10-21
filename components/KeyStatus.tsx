'use client';

import { useKeyring } from '@/lib/stores/keyring';
import { DownloadIcon, KeyIcon, LockIcon } from '@/components/icons';
import { cn } from '@/components/ui';

export function KeyStatus() {
  const keyring = useKeyring();

  const label =
    keyring.status === 'loading'
      ? 'Checking keys…'
      : keyring.status === 'unlocked'
        ? 'Keys unlocked'
        : keyring.status === 'locked'
          ? 'Keys locked'
          : keyring.status === 'no-identity'
            ? 'No key on device'
            : 'Signed out';

  const tone =
    keyring.status === 'unlocked'
      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
      : keyring.status === 'locked'
        ? 'border-amber-500/30 bg-amber-500/10 text-amber-200'
        : keyring.status === 'loading'
          ? 'border-slate-700 bg-slate-800/60 text-slate-300'
          : 'border-rose-500/30 bg-rose-500/10 text-rose-200';

  return (
    <div className="flex items-center gap-1.5">
      <button
        type="button"
        onClick={keyring.openUnlockDialog}
        className={cn('pill transition hover:brightness-110', tone)}
        title={keyring.error ?? 'Manage local encryption keys'}
      >
        {keyring.status === 'unlocked' ? (
          <KeyIcon className="h-3.5 w-3.5" />
        ) : (
          <LockIcon className="h-3.5 w-3.5" />
        )}
        <span className="hidden sm:inline">{label}</span>
        <span className="sm:hidden">
          {keyring.status === 'unlocked' ? 'Unlocked' : 'Locked'}
        </span>
        {keyring.error ? <span aria-label="Key warning">!</span> : null}
      </button>

      {keyring.identity ? (
        <button
          type="button"
          className="btn-ghost h-8 w-8 p-0"
          title="Download passphrase-wrapped key backup"
          onClick={() => {
            void keyring.downloadBackup().catch((error) => {
              console.error('[keyring] backup failed', error);
            });
          }}
        >
          <DownloadIcon className="h-4 w-4" />
        </button>
      ) : null}

      {keyring.status === 'unlocked' ? (
        <button
          type="button"
          className="btn-ghost h-8 px-2 text-xs"
          onClick={keyring.lock}
          title="Zero the in-memory private key"
        >
          Lock
        </button>
      ) : null}
    </div>
  );
}
