import { and, eq } from 'drizzle-orm';
import { getDb } from '@/lib/db/client';
import { contactVerifications } from '@/lib/db/schema';
import { handleRouteError, jsonOk, readJson } from '@/lib/api';
import { assertSameOrigin } from '@/lib/auth/origin';
import { requireSessionUser } from '@/lib/auth/request';
import { getVerification, peerIdOf, requireConversationForUser } from '@/lib/server/conversations';
import { verifyBodySchema } from '@/lib/validation';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(
  req: Request,
  context: { params: Promise<{ id: string }> },
) {
  try {
    const user = await requireSessionUser(req);
    const { id } = await context.params;
    const conversation = await requireConversationForUser(id, user.id);
    const peerId = peerIdOf(conversation, user.id);
    const verification = await getVerification(user.id, peerId);

    return jsonOk({
      verification: verification
        ? {
            safety_number: verification.safetyNumber,
            verified_at: verification.verifiedAt.toISOString(),
          }
        : null,
    });
  } catch (error) {
    return handleRouteError(error);
  }
}

export async function POST(
  req: Request,
  context: { params: Promise<{ id: string }> },
) {
  try {
    const user = await requireSessionUser(req);
    assertSameOrigin(req);
    const { id } = await context.params;
    const conversation = await requireConversationForUser(id, user.id);
    const peerId = peerIdOf(conversation, user.id);
    const body = await readJson(req, verifyBodySchema);

    const db = await getDb();
    const verifiedAt = new Date();
    await db
      .insert(contactVerifications)
      .values({
        userId: user.id,
        contactId: peerId,
        safetyNumber: body.safety_number,
        verifiedAt,
      })
      .onConflictDoUpdate({
        target: [contactVerifications.userId, contactVerifications.contactId],
        set: {
          safetyNumber: body.safety_number,
          verifiedAt,
        },
      });

    return jsonOk({
      verification: {
        safety_number: body.safety_number,
        verified_at: verifiedAt.toISOString(),
      },
    });
  } catch (error) {
    return handleRouteError(error);
  }
}

export async function DELETE(
  req: Request,
  context: { params: Promise<{ id: string }> },
) {
  try {
    const user = await requireSessionUser(req);
    assertSameOrigin(req);
    const { id } = await context.params;
    const conversation = await requireConversationForUser(id, user.id);
    const peerId = peerIdOf(conversation, user.id);

    const db = await getDb();
    await db
      .delete(contactVerifications)
      .where(
        and(
          eq(contactVerifications.userId, user.id),
          eq(contactVerifications.contactId, peerId),
        ),
      );

    return jsonOk({ verification: null });
  } catch (error) {
    return handleRouteError(error);
  }
}
