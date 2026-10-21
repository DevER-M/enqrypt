import { notFound, redirect } from 'next/navigation';
import type { Metadata } from 'next';
import { getSessionUserFromCookies } from '@/lib/auth/server';
import { bytesToBase64 } from '@/lib/encoding';
import { MESSAGE_PAGE_SIZE } from '@/lib/protocol';
import { toMessageDto, toSessionDto } from '@/lib/serializers';
import {
  getConversationForUser,
  getMessagesBefore,
  getSessionForConversation,
  getVerification,
  peerIdOf,
} from '@/lib/server/conversations';
import { getUserWithPublicKey } from '@/lib/server/users';
import { getLatestStreamId } from '@/lib/realtime/events';
import { ConversationView } from '@/components/ConversationView';
import { AlertIcon } from '@/components/icons';
import Link from 'next/link';

export const dynamic = 'force-dynamic';

type PageProps = {
  params: Promise<{ conversationId: string }>;
};

/**
 * Next 16 can hand dynamic page params through percent-encoded (notably the
 * ":" in a conversation id). Decode once, but tolerate an already-decoded
 * value that happens to contain a literal "%".
 */
function decodeParam(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export async function generateMetadata({
  params,
}: PageProps): Promise<Metadata> {
  await params;
  return { title: 'Conversation · enqrypt' };
}

function MissingKeyNotice({
  title,
  message,
  peerUsername,
}: {
  title: string;
  message: string;
  peerUsername?: string;
}) {
  return (
    <div className="flex flex-1 items-center justify-center px-4 py-10">
      <div className="card max-w-md bg-slate-950/60 p-6">
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-rose-500/30 bg-rose-500/10">
          <AlertIcon className="h-5 w-5 text-rose-300" />
        </div>
        <h1 className="mt-4 text-lg font-semibold text-slate-100">{title}</h1>
        <p className="mt-2 text-sm leading-6 text-slate-400">{message}</p>
        {peerUsername ? (
          <p className="mono mt-3 break-all text-[11px] text-slate-500">
            peer: {peerUsername}
          </p>
        ) : null}
        <Link href="/chat" className="btn-secondary mt-5 inline-flex">
          Back to conversations
        </Link>
      </div>
    </div>
  );
}

export default async function ConversationPage({ params }: PageProps) {
  const user = await getSessionUserFromCookies();
  if (!user) redirect('/login');

  const { conversationId: rawConversationId } = await params;
  const conversationId = decodeParam(rawConversationId);
  const conversation = await getConversationForUser(conversationId, user.id);
  if (!conversation) notFound();

  const peerId = peerIdOf(conversation, user.id);
  const [self, peer] = await Promise.all([
    getUserWithPublicKey(user.id),
    getUserWithPublicKey(peerId),
  ]);

  if (!peer) notFound();

  if (!self?.publicKey || !self.fingerprint) {
    return (
      <MissingKeyNotice
        title="Your public key is not published"
        message="This account has no ML-KEM public key on the relay, so contacts cannot start an encrypted session with you. Sign out and register again, or contact the operator if this persists."
        peerUsername={peer.username}
      />
    );
  }

  if (!peer.publicKey || !peer.fingerprint) {
    return (
      <MissingKeyNotice
        title="This contact has no public key"
        message={`${peer.username} has not published an ML-KEM public key, so no encrypted session can be established yet.`}
        peerUsername={peer.username}
      />
    );
  }

  const [sessionRow, page, verification, latestStreamId] = await Promise.all([
    getSessionForConversation(conversationId),
    getMessagesBefore(conversationId, null, MESSAGE_PAGE_SIZE),
    getVerification(user.id, peerId),
    getLatestStreamId(conversationId),
  ]);

  const selfParticipant = {
    id: self.id,
    username: self.username,
    publicKeyB64: bytesToBase64(self.publicKey),
    fingerprint: self.fingerprint,
  };
  const peerParticipant = {
    id: peer.id,
    username: peer.username,
    publicKeyB64: bytesToBase64(peer.publicKey),
    fingerprint: peer.fingerprint,
  };

  return (
    <ConversationView
      key={conversationId}
      conversationId={conversationId}
      self={selfParticipant}
      peer={peerParticipant}
      initialMessages={page.messages.map(toMessageDto)}
      initialLatestSequence={page.latestSequence}
      initialHasMore={page.hasMore}
      initialNextBefore={page.nextBefore}
      initialSession={sessionRow ? toSessionDto(sessionRow) : null}
      initialVerification={
        verification
          ? {
              safety_number: verification.safetyNumber,
              verified_at: verification.verifiedAt.toISOString(),
            }
          : null
      }
      latestStreamId={latestStreamId}
    />
  );
}
