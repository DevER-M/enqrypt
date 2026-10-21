import { eq } from 'drizzle-orm';
import { getDb } from '@/lib/db/client';
import { sessions } from '@/lib/db/schema';
import { handleRouteError, jsonCreated, jsonOk, readJson } from '@/lib/api';
import { ApiError } from '@/lib/api-error';
import { assertSameOrigin } from '@/lib/auth/origin';
import { requireSessionUser } from '@/lib/auth/request';
import { base64ToBytes } from '@/lib/encoding';
import { ML_KEM_768_SIZES } from '@/lib/protocol';
import { toSessionDto } from '@/lib/serializers';
import {
  getSessionForConversation,
  requireConversationForUser,
} from '@/lib/server/conversations';
import { createSessionBodySchema } from '@/lib/validation';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(
  req: Request,
  context: { params: Promise<{ id: string }> },
) {
  try {
    const user = await requireSessionUser(req);
    const { id } = await context.params;
    await requireConversationForUser(id, user.id);

    const session = await getSessionForConversation(id);
    if (!session) {
      throw new ApiError(404, 'no_session', 'This conversation has no KEM session yet.');
    }
    return jsonOk({ session: toSessionDto(session) });
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
    await requireConversationForUser(id, user.id);
    const body = await readJson(req, createSessionBodySchema);

    let kemCiphertext: Uint8Array;
    try {
      kemCiphertext = base64ToBytes(body.kem_ciphertext_b64);
    } catch {
      throw new ApiError(400, 'invalid_kem_ciphertext', 'KEM ciphertext is not valid base64.');
    }
    if (kemCiphertext.length !== ML_KEM_768_SIZES.ciphertext) {
      throw new ApiError(
        400,
        'invalid_kem_ciphertext',
        `ML-KEM-768 ciphertext must be ${ML_KEM_768_SIZES.ciphertext} bytes.`,
      );
    }

    const db = await getDb();
    const inserted = await db
      .insert(sessions)
      .values({
        conversationId: id,
        initiatorId: user.id,
        kemCiphertext,
      })
      .onConflictDoNothing({ target: sessions.conversationId })
      .returning();

    if (inserted.length > 0) {
      return jsonCreated({ created: true, session: toSessionDto(inserted[0]) });
    }

    const existing = await getSessionForConversation(id);
    if (!existing) {
      throw new ApiError(500, 'session_create_failed', 'Could not create KEM session.');
    }
    return jsonOk({ created: false, session: toSessionDto(existing) });
  } catch (error) {
    return handleRouteError(error);
  }
}
