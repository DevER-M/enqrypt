# enc

Server-hosted 1:1 chat where the encryption happens in the browser, so the
server only ever relays public keys and ciphertext.

You run one process behind a URL. Everyone creates an account with a username
and a password, and can then talk to anyone else in the directory. Key exchange
is hybrid **X25519 + ML-KEM-768** (post-quantum), messages are
**ChaCha20-Poly1305**, and each account has a long-lived **ML-DSA-65** identity
key that signs every handshake. Contacts show a verification code you can
compare out of band.

## Run it

```sh
uv sync
uv run enc serve --host 0.0.0.0 --port 8080 --db enc.db
```

- `--db PATH` — SQLite file for accounts and login sessions (default `enc.db`).
- `--secure-cookies` — mark the session cookie `Secure`. Use this when the site
  is served over HTTPS.

The server prints a local and a network URL:

```
  enc chat server
  local:   http://127.0.0.1:8080
  network: http://192.168.0.101:8080
```

Give people the network URL. Each person creates an account; accounts and
identity public keys are stored, message contents are not.

## Using it

1. Open the URL and **create an account** (3–32 letters, digits, `.`, `_`, `-`).
   Your identity key is generated in the browser and stored there.
2. Pick someone from the list. A secure session is negotiated automatically when
   both of you are online.
3. When the header says *end-to-end encrypted*, open **Verify** and read the
   code to each other over a call or in person. Mark the contact as verified
   once it matches; the pin is remembered in this browser, and a changed key is
   flagged loudly.
4. Chat. You get typing indicators and read receipts. History stays in your
   browser, encrypted with a per-browser key.

You can only message people who are online — there is no offline queue. If a
handshake fails, use **Restart session**. Your identity key can be exported as a
text backup (the **ID** button) and imported on another browser.

## What the server can and cannot see

| The server knows | The server never sees |
| --- | --- |
| usernames, password hashes, identity public keys | message contents |
| who is online, who sends frames to whom, and when | handshake secrets or session keys |
| frame sizes | your private keys (they never leave the browser) |

Passwords are hashed with `scrypt`. Login uses an HTTP-only session cookie;
the same cookie authenticates the websocket, so no token ever appears in a URL.

## Security notes

These are the limits you should actually care about:

- **Plain HTTP is not enough for the open internet.** Message contents are
  still encrypted, but whoever controls the network could serve modified
  JavaScript and steal your keys. Put this behind HTTPS (Caddy, nginx, a
  reverse proxy) for anything beyond a trusted LAN, and pass
  `--secure-cookies`.
- **Identity keys are trusted on first use.** The server hands out public keys,
  so a malicious server could present its own key on a first contact. Comparing
  the verification code out of band is what rules that out; after that the pin
  protects you.
- **No forward secrecy.** Session keys are ephemeral, but there is no ratchet,
  so a leaked session key decrypts that session. Sessions end when either side
  disconnects or reloads.
- **Local history is obfuscated, not vaulted.** Browsers do not expose a key
  store, so the device key sits next to the encrypted data in IndexedDB. It
  stops casual inspection, not XSS or someone with access to the browser
  profile.
- **The browser must be trusted.** End-to-end encryption cannot protect you
  from a server that hands out malicious JavaScript.

`main.py` at the repository root is an old reference implementation and is not
part of the running app.

## Development

```sh
npm install          # esbuild, Tailwind CLI and Playwright (uses your Chrome)

npm run build        # rebuild the vendor bundle and the Tailwind stylesheet
npm test             # JS crypto and session tests (node --test)
uv run pytest        # server account, presence and relay tests
npm run e2e          # two websocket clients against a real server
npm run test:browser # two real Chrome windows through the whole UI
```

The bundled `src/enc/web/static/vendor/noble.js` and the compiled
`src/enc/web/static/app.css` are committed, so running the server needs no Node
toolchain.

## Layout

```
src/enc/
  server.py          FastAPI app: accounts, static files, /ws relay + presence
  auth.py            scrypt password hashing and cookie sessions
  db.py              SQLite users and sessions
  cli.py             `enc serve`
  web/
    index.html       Tailwind markup
    static/app.css   compiled Tailwind (built artifact)
    static/js/
      crypto.js      hybrid handshake, identity signatures, AEAD, codes
      session.js     handshake + message state machine
      identity.js    ML-DSA-65 key pair, IndexedDB storage, backup
      verify.js      verification pins
      connection.js  websocket link, reconnect, takeover handling
      api.js         account HTTP calls
      history.js     IndexedDB conversation storage
      idb.js         shared IndexedDB helpers
      main.js        UI controller
      vendor/noble.js  bundled @noble crypto (built artifact)
tests/               Python tests, JS tests, browser test
scripts/e2e.mjs      end-to-end websocket check
web/src/             Tailwind input and vendor bundle entry point
```
