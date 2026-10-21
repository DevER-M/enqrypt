import type { Metadata } from 'next';
import './globals.css';
import { getSessionUserFromCookies } from '@/lib/auth/server';
import { KeyringProvider } from '@/lib/stores/keyring';

export const metadata: Metadata = {
  title: 'enqrypt — post-quantum private chat',
  description:
    'A 1:1 end-to-end encrypted chat using ML-KEM-768, HKDF-SHA256, and AES-256-GCM. The server only relays ciphertext.',
};

export default async function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  const user = await getSessionUserFromCookies();

  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-dvh antialiased">
        <KeyringProvider initialUser={user}>{children}</KeyringProvider>
      </body>
    </html>
  );
}
