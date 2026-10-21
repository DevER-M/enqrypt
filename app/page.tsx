import { redirect } from 'next/navigation';
import { getSessionUserFromCookies } from '@/lib/auth/server';

export const dynamic = 'force-dynamic';

export default async function HomePage() {
  const user = await getSessionUserFromCookies();
  redirect(user ? '/chat' : '/login');
}
