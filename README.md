# enqrypt

End-to-end encrypted 1:1 chat built around **ML-KEM-768 → HKDF-SHA256 → AES-256-GCM**. The server is a blind relay: it stores public keys, KEM ciphertexts, and message ciphertexts. Plaintext and ML-KEM secret keys never leave the browser.

This repository started as a Python XOR/ML-KEM teaching prototype. The prototype is preserved under [`legacy/python-prototype/`](legacy/python-prototype/) and is not part of the running application. XOR is documented as a lesson in [`lib/crypto/xor-lesson.ts`](lib/crypto/xor-lesson.ts) but is not imported by the live path.

## Stack

| Layer | Choice |
| --- | --- |
| App | Next.js 16 App Router, React 19, TypeScript |
| Postgres | Neon (`@neondatabase/serverless` + `drizzle-orm/neon-http`) in production |
| Local database | On-disk PGlite (PostgreSQL compiled to WASM) when `DATABASE_URL` is absent |
| Auth | `jose` HS256 JWT in an `httpOnly`, `Secure`, `SameSite=Lax` cookie |
| Post-quantum KEM | [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) ML-KEM-768 |
| Symmetric crypto | WebCrypto HKDF-SHA256 + AES-256-GCM |
| Key storage | Passphrase-wrapped keys in IndexedDB (PBKDF2-SHA256 → AES-GCM) |
| Realtime | Redis Streams fan-out; Vercel WebSockets in production, SSE fallback |
| Tests | Vitest + PGlite |

## Quick start

Requirements: Node.js 20.19+ (developed on Node 26).

```bash
npm install
cp .env.example .env.local

# At minimum, set a JWT secret (32+ characters):
#   openssl rand -base64 48
# DATABASE_URL may be omitted locally; PGlite then creates .data/pglite.

npm run dev
```

Open <http://localhost:3000>, create two accounts in two browser profiles (or one normal and one private window), and start a conversation by username.

Local development does not support WebSocket upgrades inside `next dev`, so the client uses the SSE replay endpoint automatically.

## Environment

| Variable | Required | Purpose |
| --- | --- | --- |
| `JWT_SECRET` | Yes | HS256 signing key, at least 32 characters. Rotating it invalidates sessions. |
| `DATABASE_URL` | Production | Neon Postgres connection string. Local dev falls back to PGlite. |
| `UPSTASH_REDIS_REST_URL` | No | Upstash REST endpoint (`https://…`). Without it, realtime reconciles directly from Postgres. |
| `UPSTASH_REDIS_REST_TOKEN` | No | Upstash REST token. |
| `NEXT_PUBLIC_REALTIME_TRANSPORT` | No | `auto` (default), `ws`, or `sse`. |
| `PGLITE_DIR` | No | Local PGlite data directory, default `.data/pglite`. |
| `BCRYPT_ROUNDS` | No | Password hashing rounds, default 12. Tests set 4. |

Production refuses to start without `DATABASE_URL`; there is no silent in-memory database in production.

## Architecture

```text
┌─────────────────────────── Browser ───────────────────────────┐
│ ML-KEM keypair (generated locally)                            │
│   secret key ── PBKDF2-SHA256(600k) ── AES-GCM ── IndexedDB   │
│                                                               │
│ KEM session: encapsulate(peer public key) or decapsulate(ct)  │
│   shared secret ── HKDF-SHA256 ── two directional AES keys    │
│   message ── AES-256-GCM(nonce, AAD) ── ciphertext            │
└───────────────┬───────────────────────────────────────────────┘
                │ HTTPS: public keys, ciphertext, metadata
┌───────────────▼───────────────────────────────────────────────┐
│ Next.js route handlers                                        │
│   JWT auth + conversation membership checks                   │
│   Postgres (Neon): users, public keys, KEM ct, messages       │
│   Redis Streams: per-conversation delivery cursor             │
└───────────────────────────────────────────────────────────────┘
```

### Message protocol

1. **Identity.** Each browser generates an ML-KEM-768 keypair. The public key (1184 bytes) and its SHA-256 fingerprint are sent to the relay. The 2400-byte secret key is wrapped locally and stored in IndexedDB.
2. **Session.** A conversation ID is deterministic: `sorted(userA_id) + ":" + sorted(userB_id)`. The first client to open the conversation encapsulates against the peer's public key and posts the 1088-byte KEM ciphertext. One session row exists per conversation; a concurrent initiator loses the race and decapsulates the winner's ciphertext instead.
3. **Key derivation.** Both sides derive two keys:

   ```text
   salt = SHA-256(conversation_id)
   K(A→B) = HKDF-SHA256(shared_secret, salt, info = "chat-v1:A->B", 32)
   K(B→A) = HKDF-SHA256(shared_secret, salt, info = "chat-v1:B->A", 32)
   ```

   `A` is the lexicographically smaller user UUID. Separate directional keys prevent nonce/key reuse across senders.
4. **Encryption.** Each message gets a random 96-bit GCM nonce and an authenticated-data string:

   ```text
   AAD = conversation_id | sender_id | sequence
   ciphertext = AES-256-GCM(K(sender→receiver), plaintext, nonce, AAD)
   ```

   The server assigns/validates a strictly monotonic per-conversation `sequence`. Reusing a sequence, changing the sender, or replaying under another conversation breaks GCM authentication and the client refuses to render.
5. **Key at rest.** PBKDF2-SHA256 (600,000 iterations, 16-byte salt) derives an AES-256-GCM wrapping key. AAD binds wrapped material to the user ID. Neither the raw secret key nor derived session keys touch IndexedDB unwrapped.
6. **Safety number.** A SHA-512 digest over the ordered pair of user IDs and public keys, rendered as 12 groups of five digits. It is identical on both sides, changes if either public key changes, and is pinned per contact with TOFU after out-of-band comparison.

### Server visibility

| Data | Server sees | Server can decrypt |
| --- | --- | --- |
| Username, account password hash | Yes | N/A (bcrypt) |
| ML-KEM public key + fingerprint | Yes | N/A |
| KEM ciphertext | Yes | No (needs a secret key) |
| Message ciphertext, nonce, sequence, sender | Yes | No |
| Plaintext message | Never | No |
| ML-KEM secret key | Never | No |
| Derived session keys | Never | No |
| Who talks to whom, timestamps, message sizes | Yes | Metadata only |

## Database

Schema: `users`, `public_keys`, `conversations`, `sessions`, `messages`, `contact_verifications`.

```bash
npm run db:generate   # generate SQL after schema changes
npm run db:migrate    # apply migrations (Neon when DATABASE_URL is set)
npm run db:studio     # Drizzle Studio
```

Local PGlite applies migrations automatically on first request. For Neon, run `npm run db:migrate` during deployment or once from your machine.

## Realtime and offline messages

Postgres is the durable source of truth. Every sent ciphertext is inserted first, then published to a Redis Stream (`enqrypt:conv:<conversation_id>`).

- **WebSocket** (`/api/ws`, production): the server subscribes by reading the shared stream and Postgres cursor, so delivery works across function instances without an in-process hub.
- **SSE** (`/api/conversations/:id/events`, local development and fallback): same replay cursor over server-sent events.
- On reconnect, the client reads after its last sequence/stream ID, then reconciles with Postgres. Duplicate sequences are merged idempotently, and out-of-order events trigger a catch-up fetch.

Without Upstash credentials, realtime still works by polling the Postgres cursor. Redis is a delivery optimization, not a dependency for correctness.

## Testing

```bash
npm run typecheck
npm test
npm run build
```

The suite uses a throwaway on-disk PGlite database and covers:

- ML-KEM-768 sizes and shared-secret agreement
- HKDF directional key separation and determinism
- AES-GCM round-trip, tampering, wrong AAD/sender/sequence/conversation
- PBKDF2/AES-GCM wrapping, wrong passphrase, mismatched AAD
- Safety-number determinism, order independence, key-change detection
- Registration/login cookie auth, invalid cookie rejection, cross-origin rejection
- Conversation membership checks for reads and writes
- KEM session race handling
- Two-party message exchange, ciphertext-only storage, sequence conflicts, idempotent retries
- Tampered ciphertext accepted by the relay but failing closed in the client
- Cursor replay, safety-number verify/read/delete

## Deployment (Vercel + Neon)

1. Import the repository into Vercel.
2. Add the Neon integration and confirm `DATABASE_URL` is present in the project environment.
3. Add `JWT_SECRET` (`openssl rand -base64 48`).
4. Optionally add Upstash Redis REST credentials for cross-instance stream fan-out.
5. Run `npm run db:migrate` against the production database.
6. Deploy. Set `NEXT_PUBLIC_REALTIME_TRANSPORT=auto` so the client tries WebSockets and falls back to SSE.

Security headers (`nosniff`, `DENY` framing, same-origin referrer policy, restrictive permissions policy) are configured in `next.config.ts`. Every state-changing route also checks `Origin` in addition to the SameSite cookie.

## Threat model and limitations

**Protected against:** a passive network observer; a database-only attacker who obtains ciphertext, public keys, and metadata; a malicious/curious relay that substitutes ciphertext or reorders/replays messages (GCM fails closed); quantum adversaries against key establishment (ML-KEM-768).

**Not protected against:** a compromised client or XSS while keys are unlocked; a malicious relay on the *first* key exchange (TOFU has no key transparency/audit log); traffic analysis from metadata; loss of the passphrase without a backup. There is one static KEM session per conversation and no double ratchet, so there is no per-message forward secrecy or post-compromise healing beyond rotating conversations/keys.

Export a key backup from the key status menu. The backup contains only passphrase-wrapped material; without the passphrase it is useless.

## Project layout

```text
app/(auth)/                 login + registration
app/(chat)/                 authenticated shell, chat index, conversation view
app/api/                    auth, users, conversations, session, messages, verify, SSE, WS
components/                 UI, safety number, message list, composer
lib/crypto/                 ML-KEM, HKDF, AES-GCM, wrapping, safety numbers
lib/stores/                 keyring provider + IndexedDB envelope
lib/server/                 membership-scoped queries
lib/realtime/               Redis Streams + Postgres reconciliation
lib/db/                     Drizzle schema, Neon/PGlite selection, migrations
tests/                      crypto + API integration tests
drizzle/                    generated SQL migrations
legacy/python-prototype/    original Python prototype (not deployed)
```
