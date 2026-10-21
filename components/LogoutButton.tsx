'use client';

import { useState } from 'react';
import { apiPost } from '@/lib/client/api';
import { useKeyring } from '@/lib/stores/keyring';
import { Button } from '@/components/ui';

export function LogoutButton() {
  const keyring = useKeyring();
  const [busy, setBusy] = useState(false);

  const logout = async () => {
    setBusy(true);
    // Drop key material before touching the network.
    keyring.lock();
    try {
      await apiPost('/api/auth/logout');
    } catch (error) {
      console.error('[auth] logout request failed', error);
    }
    window.location.assign('/login');
  };

  return (
    <Button variant="ghost" onClick={logout} disabled={busy} className="h-8 px-2 text-xs">
      {busy ? 'Signing out…' : 'Sign out'}
    </Button>
  );
}
