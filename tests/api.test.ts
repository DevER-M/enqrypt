import { beforeAll, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import { POST as registerRoute } from '@/app/api/auth/register/route';
import { GET as meRoute } from '@/app/api/auth/me/route';
import {
  GET as listConversationsRoute,
  POST as createConversationRoute,
} from '@/app/api/conversations/route';
import {
  GET as getMessagesRoute,
  POST as sendMessageRoute,
} from '@/app/api/conversations/[id]/messages/route';
import {
  GET as getSessionRoute,
  POST as createSessionRoute,
} from '@/app/api/conversations/[id]/session/route';
import {
  DELETE as deleteVerificationRoute,
  GET as getVerificationRoute,
  POST as verifyRoute,
} from '@/app/api/conversations/[id]/verify/route';
import { getDb } from '@/lib/db/client';
import { messages, publicKeys } from '@/lib/db/schema';
import { generateKeypair, encapsulate, decapsulate } from '@/lib/crypto/mlkem';
import {
  buildAad,
  decryptMessage,
  deriveSessionKeys,
  encryptMessage,
  orderUserIds,
  type DerivedSessionKeys,
} from '@/lib/crypto/session';
import { computeSafetyNumber, publicKeyFingerprint } from '@/lib/crypto/safetyNumber';
import {
  base64ToBytes,
  bytesEqual,
  bytesToBase64,
  utf8Encode,
} from '@/lib/encoding';

type TestUser = {
  userId: string;
  username: string;
  cookie: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

type Json = Record<string, any>;

function request(
  method: string,
  path: string,
  options: { cookie?: string; body?: unknown; origin?: string } = {},
): Request {
  const headers = new Headers();
  if (options.cookie) headers.set('cookie', options.cookie);
  if (options.body !== undefined) headers.set('content-type', 'application/json');
  if (options.origin) headers.set('origin', options.origin);
  return new Request(`http://localhost${path}`, {
    method,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
}

function sessionCookie(response: Response): string {
  const header = response.headers.get('set-cookie');
  if (!header) throw new Error('Expected a session cookie.');
  const pair = header.split(';')[0];
  if (!pair.includes('=')) throw new Error('Malformed Set-Cookie header.');
  return pair;
}

async function readJson(response: Response): Promise<Json> {
  return (await response.json()) as Json;
}

async function register(username: string): Promise<TestUser> {
  const keypair = generateKeypair();
  const response = await registerRoute(
    request('POST', '/api/auth/register', {
      body: {
        username,
        password: 'correct-horse-battery',
        ml_kem_public_key_b64: bytesToBase64(keypair.publicKey),
        key_fingerprint: publicKeyFingerprint(keypair.publicKey),
      },
    }),
  );
  expect(response.status).toBe(201);
  const body = await readJson(response);
  expect(body.user_id).toMatch(/^[0-9a-f-]{36}$/);

  return {
    userId: body.user_id,
    username,
    cookie: sessionCookie(response),
    publicKey: keypair.publicKey,
    secretKey: keypair.secretKey,
  };
}

async function createConversation(
  creator: TestUser,
  peer: TestUser,
): Promise<string> {
  const response = await createConversationRoute(
    request('POST', '/api/conversations', {
      cookie: creator.cookie,
      body: { peer_user_id: peer.userId },
    }),
  );
  expect(response.status).toBe(201);
  const body = await readJson(response);
  return body.conversation_id;
}

function context(id: string): { params: Promise<{ id: string }> } {
  return { params: Promise.resolve({ id }) };
}

async function sendMessage(
  sender: TestUser,
  conversationId: string,
  keys: DerivedSessionKeys,
  lowUserId: string,
  highUserId: string,
  sequence: number,
  plaintext: string,
): Promise<{ nonce: string; ciphertext: string; response: Response }> {
  const key =
    sender.userId === lowUserId ? keys.lowToHigh : keys.highToLow;
  const encrypted = await encryptMessage(
    key,
    plaintext,
    buildAad(conversationId, sender.userId, sequence),
  );
  const nonce = bytesToBase64(encrypted.nonce);
  const ciphertext = bytesToBase64(encrypted.ciphertext);
  const response = await sendMessageRoute(
    request('POST', `/api/conversations/${conversationId}/messages`, {
      cookie: sender.cookie,
      body: { sequence, nonce_b64: nonce, ciphertext_b64: ciphertext },
    }),
    context(conversationId),
  );
  return { nonce, ciphertext, response };
}

let alice: TestUser;
let bob: TestUser;
let carol: TestUser;
let conversationId: string;
let sessionCiphertext: Uint8Array;
let aliceKeys: DerivedSessionKeys;
let bobKeys: DerivedSessionKeys;
let lowUserId: string;
let highUserId: string;

beforeAll(async () => {
  [alice, bob, carol] = await Promise.all([
    register('alice_api'),
    register('bob_api'),
    register('carol_api'),
  ]);

  conversationId = await createConversation(alice, bob);

  const encapsulation = encapsulate(bob.publicKey);
  sessionCiphertext = encapsulation.ciphertext;

  const createSession = await createSessionRoute(
    request('POST', `/api/conversations/${conversationId}/session`, {
      cookie: alice.cookie,
      body: { kem_ciphertext_b64: bytesToBase64(encapsulation.ciphertext) },
    }),
    context(conversationId),
  );
  expect(createSession.status).toBe(201);
  const sessionBody = await readJson(createSession);
  expect(sessionBody.created).toBe(true);

  aliceKeys = await deriveSessionKeys(
    encapsulation.sharedSecret,
    conversationId,
  );
  const bobSharedSecret = decapsulate(
    base64ToBytes(sessionBody.session.kem_ciphertext_b64),
    bob.secretKey,
  );
  bobKeys = await deriveSessionKeys(bobSharedSecret, conversationId);

  const order = orderUserIds(alice.userId, bob.userId);
  lowUserId = order.lowUserId;
  highUserId = order.highUserId;
});

describe('authentication', () => {
  it('rejects requests without a valid signed cookie', async () => {
    const noCookie = await getMessagesRoute(
      request('GET', `/api/conversations/${conversationId}/messages`),
      context(conversationId),
    );
    expect(noCookie.status).toBe(401);

    const invalid = await getMessagesRoute(
      request('GET', `/api/conversations/${conversationId}/messages`, {
        cookie: 'enqrypt_session=not-a-real-token',
      }),
      context(conversationId),
    );
    expect(invalid.status).toBe(401);
  });

  it('returns the signed-in user', async () => {
    const response = await meRoute(
      request('GET', '/api/auth/me', { cookie: alice.cookie }),
    );
    expect(response.status).toBe(200);
    const body = await readJson(response);
    expect(body.user_id).toBe(alice.userId);
    expect(body.username).toBe('alice_api');
    expect(body.has_public_key).toBe(true);
  });

  it('rejects cross-origin state-changing requests', async () => {
    const response = await createConversationRoute(
      request('POST', '/api/conversations', {
        cookie: alice.cookie,
        origin: 'https://evil.example',
        body: { peer_user_id: bob.userId },
      }),
    );
    expect(response.status).toBe(403);
  });
});

describe('conversation authorization', () => {
  it('lists the conversation for both members', async () => {
    for (const user of [alice, bob]) {
      const response = await listConversationsRoute(
        request('GET', '/api/conversations', { cookie: user.cookie }),
      );
      expect(response.status).toBe(200);
      const body = await readJson(response);
      expect(body.conversations.map((row: Json) => row.conversation_id)).toContain(
        conversationId,
      );
    }
  });

  it('hides the conversation from non-members', async () => {
    const read = await getMessagesRoute(
      request('GET', `/api/conversations/${conversationId}/messages`, {
        cookie: carol.cookie,
      }),
      context(conversationId),
    );
    expect(read.status).toBe(404);

    const write = await sendMessageRoute(
      request('POST', `/api/conversations/${conversationId}/messages`, {
        cookie: carol.cookie,
        body: {
          sequence: 1,
          nonce_b64: bytesToBase64(new Uint8Array(12)),
          ciphertext_b64: bytesToBase64(new Uint8Array(32)),
        },
      }),
      context(conversationId),
    );
    expect(write.status).toBe(404);
  });
});

describe('KEM session', () => {
  it('returns the existing session to a peer that loses the initiate race', async () => {
    const response = await createSessionRoute(
      request('POST', `/api/conversations/${conversationId}/session`, {
        cookie: bob.cookie,
        body: {
          kem_ciphertext_b64: bytesToBase64(
            encapsulate(alice.publicKey).ciphertext,
          ),
        },
      }),
      context(conversationId),
    );
    expect(response.status).toBe(200);
    const body = await readJson(response);
    expect(body.created).toBe(false);
    expect(body.session.initiator_id).toBe(alice.userId);
    expect(base64ToBytes(body.session.kem_ciphertext_b64)).toEqual(
      new Uint8Array(sessionCiphertext),
    );
  });

  it('keeps the original session when the initiator retries with a new encapsulation', async () => {
    const retry = encapsulate(bob.publicKey);
    const response = await createSessionRoute(
      request('POST', `/api/conversations/${conversationId}/session`, {
        cookie: alice.cookie,
        body: { kem_ciphertext_b64: bytesToBase64(retry.ciphertext) },
      }),
      context(conversationId),
    );
    expect(response.status).toBe(200);
    const body = await readJson(response);
    expect(body.created).toBe(false);
    expect(body.session.initiator_id).toBe(alice.userId);
    expect(base64ToBytes(body.session.kem_ciphertext_b64)).toEqual(
      new Uint8Array(sessionCiphertext),
    );
  });

  it('exposes the session ciphertext but never the shared secret', async () => {
    const response = await getSessionRoute(
      request('GET', `/api/conversations/${conversationId}/session`, {
        cookie: bob.cookie,
      }),
      context(conversationId),
    );
    expect(response.status).toBe(200);
    const body = await readJson(response);
    expect(Object.keys(body.session).sort()).toEqual([
      'conversation_id',
      'created_at',
      'initiator_id',
      'kem_ciphertext_b64',
      'session_id',
    ]);
    expect(body.session.shared_secret).toBeUndefined();
  });
});

describe('end-to-end messages', () => {
  it('derives the same directional keys on both sides', () => {
    expect(bytesToBase64(aliceKeys.lowToHigh)).toBe(
      bytesToBase64(bobKeys.lowToHigh),
    );
    expect(bytesToBase64(aliceKeys.highToLow)).toBe(
      bytesToBase64(bobKeys.highToLow),
    );
    expect(bytesToBase64(aliceKeys.lowToHigh)).not.toBe(
      bytesToBase64(aliceKeys.highToLow),
    );
  });

  it('relays ciphertext that each peer can decrypt', async () => {
    const first = await sendMessage(
      alice,
      conversationId,
      aliceKeys,
      lowUserId,
      highUserId,
      1,
      'hello bob, this is alice',
    );
    expect(first.response.status).toBe(201);

    const second = await sendMessage(
      bob,
      conversationId,
      bobKeys,
      lowUserId,
      highUserId,
      2,
      'hi alice, bob here',
    );
    expect(second.response.status).toBe(201);

    const page = await getMessagesRoute(
      request('GET', `/api/conversations/${conversationId}/messages`, {
        cookie: bob.cookie,
      }),
      context(conversationId),
    );
    expect(page.status).toBe(200);
    const body = await readJson(page);
    expect(body.messages).toHaveLength(2);
    expect(body.latest_sequence).toBe(2);

    const expected = ['hello bob, this is alice', 'hi alice, bob here'];
    for (const [index, message] of body.messages.entries()) {
      const key =
        message.sender_id === lowUserId
          ? bobKeys.lowToHigh
          : bobKeys.highToLow;
      const decrypted = await decryptMessage(
        key,
        base64ToBytes(message.nonce_b64),
        base64ToBytes(message.ciphertext_b64),
        buildAad(conversationId, message.sender_id, message.sequence),
      );
      expect(decrypted).toEqual({ ok: true, plaintext: expected[index] });
    }
  });

  it('stores only ciphertext and public keys', async () => {
    const db = await getDb();
    const rows = await db
      .select()
      .from(messages)
      .where(eq(messages.conversationId, conversationId));

    const serialized = JSON.stringify(rows);
    expect(serialized).not.toContain('hello bob, this is alice');
    expect(serialized).not.toContain('hi alice, bob here');

    const stored = rows.find((row) => row.sequence === 1);
    expect(stored).toBeDefined();
    expect(
      bytesEqual(stored!.ciphertext, utf8Encode('hello bob, this is alice')),
    ).toBe(false);

    const [publishedKey] = await db
      .select()
      .from(publicKeys)
      .where(eq(publicKeys.userId, alice.userId));
    expect(publishedKey.mlKemPublicKey).toHaveLength(1184);
    expect(Object.keys(publishedKey).sort()).toEqual([
      'keyFingerprint',
      'mlKemPublicKey',
      'updatedAt',
      'userId',
    ]);
  });

  it('rejects a stale or skipped sequence and reports the next value', async () => {
    const response = await sendMessage(
      alice,
      conversationId,
      aliceKeys,
      lowUserId,
      highUserId,
      99,
      'too far ahead',
    );
    expect(response.response.status).toBe(409);
    const body = await readJson(response.response);
    expect(body.error).toBe('sequence_conflict');
    expect(body.details.next_sequence).toBe(3);
  });

  it('treats an identical retry as idempotent', async () => {
    const first = await sendMessage(
      alice,
      conversationId,
      aliceKeys,
      lowUserId,
      highUserId,
      3,
      'third message',
    );
    expect(first.response.status).toBe(201);

    const retry = await sendMessageRoute(
      request('POST', `/api/conversations/${conversationId}/messages`, {
        cookie: alice.cookie,
        body: {
          sequence: 3,
          nonce_b64: first.nonce,
          ciphertext_b64: first.ciphertext,
        },
      }),
      context(conversationId),
    );
    expect(retry.status).toBe(200);
    const body = await readJson(retry);
    expect(body.idempotent).toBe(true);

    const db = await getDb();
    const rows = await db
      .select()
      .from(messages)
      .where(
        and(
          eq(messages.conversationId, conversationId),
          eq(messages.sequence, 3),
        ),
      );
    expect(rows).toHaveLength(1);
  });

  it('fails closed on tampered ciphertext even though the relay accepted it', async () => {
    const plaintext = 'tamper target';
    const encrypted = await encryptMessage(
      alice.userId === lowUserId ? aliceKeys.lowToHigh : aliceKeys.highToLow,
      plaintext,
      buildAad(conversationId, alice.userId, 4),
    );
    const tampered = new Uint8Array(encrypted.ciphertext);
    tampered[tampered.length - 1] ^= 0xff;

    const response = await sendMessageRoute(
      request('POST', `/api/conversations/${conversationId}/messages`, {
        cookie: alice.cookie,
        body: {
          sequence: 4,
          nonce_b64: bytesToBase64(encrypted.nonce),
          ciphertext_b64: bytesToBase64(tampered),
        },
      }),
      context(conversationId),
    );
    expect(response.status).toBe(201);

    const decrypted = await decryptMessage(
      bob.userId === lowUserId ? bobKeys.lowToHigh : bobKeys.highToLow,
      encrypted.nonce,
      tampered,
      buildAad(conversationId, alice.userId, 4),
    );
    expect(decrypted).toEqual({ ok: false, reason: 'authentication_failed' });
  });

  it('supports cursor replay after a reconnect', async () => {
    const response = await getMessagesRoute(
      request(
        'GET',
        `/api/conversations/${conversationId}/messages?after=2&limit=100`,
        { cookie: bob.cookie },
      ),
      context(conversationId),
    );
    expect(response.status).toBe(200);
    const body = await readJson(response);
    expect(body.messages.map((message: Json) => message.sequence)).toEqual([3, 4]);
  });
});

describe('safety number verification', () => {
  const safetyNumber = () =>
    computeSafetyNumber(
      alice.userId,
      alice.publicKey,
      bob.userId,
      bob.publicKey,
    );

  it('pins, reads, and removes a TOFU verification', async () => {
    const number = safetyNumber();
    const created = await verifyRoute(
      request('POST', `/api/conversations/${conversationId}/verify`, {
        cookie: alice.cookie,
        body: { safety_number: number },
      }),
      context(conversationId),
    );
    expect(created.status).toBe(200);

    const read = await getVerificationRoute(
      request('GET', `/api/conversations/${conversationId}/verify`, {
        cookie: alice.cookie,
      }),
      context(conversationId),
    );
    const readBody = await readJson(read);
    expect(readBody.verification.safety_number).toBe(number);

    const removed = await deleteVerificationRoute(
      request('DELETE', `/api/conversations/${conversationId}/verify`, {
        cookie: alice.cookie,
      }),
      context(conversationId),
    );
    const removedBody = await readJson(removed);
    expect(removedBody.verification).toBeNull();

    const after = await getVerificationRoute(
      request('GET', `/api/conversations/${conversationId}/verify`, {
        cookie: alice.cookie,
      }),
      context(conversationId),
    );
    const afterBody = await readJson(after);
    expect(afterBody.verification).toBeNull();
  });

  it('rejects malformed safety numbers', async () => {
    const response = await verifyRoute(
      request('POST', `/api/conversations/${conversationId}/verify`, {
        cookie: alice.cookie,
        body: { safety_number: '12345' },
      }),
      context(conversationId),
    );
    expect(response.status).toBe(400);
  });
});
