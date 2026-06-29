# edgeport - repo guide

TypeScript TCP-protocol library for the **Cloudflare Workers** runtime built on
`cloudflare:sockets`. Bun + strict ESM. Protocols: SSH, SFTP, SMTP, IMAP, POP3, WebSocket,
NATS, MQTT (+ MQTT-over-WS), STOMP, FTP, LDAP/LDAPS, Syslog. Runtime deps: `@noble/ciphers`
(SSH ChaCha) and `bcrypt-pbkdf` (encrypted OpenSSH keys) - both Workers-compatible, external.

## Architecture

- `src/core/` is the **only** code that imports `cloudflare:sockets` (the maintainability
  invariant). It provides `connect` / `startTls` / a buffered framed reader+writer / the
  shared error vocabulary. Never import `cloudflare:sockets` anywhere else.
- Each protocol lives under `src/<proto>/` and builds on the core. WebSocket is the
  exception: it uses the platform WebSocket API (fetch upgrade), not the raw-TCP core.
- Public surface per protocol: `connect(opts) -> session` (AsyncDisposable, `await using`)
  plus one-shot wrappers (`ssh.exec`, `smtp.send`, `sftp.getFile`, `pop3.retrieveAll`, ...).
- Errors are always one of `AuthError` / `ConnectionError` / `ProtocolError` / `TimeoutError`.
- Subpath exports (`edgeport/ssh`, etc.) keep bundles tree-shakeable; `core/` is unexported.

## SSH crypto notes (the high-risk code)

- ChaCha20-Poly1305 is absent from Workers WebCrypto; `chacha20-poly1305@openssh.com` is
  assembled from `@noble/ciphers` raw `chacha20orig` (8-byte nonce) + `poly1305` in
  `src/ssh/crypto/cipher.ts`. AES-GCM/CTR + HMAC use WebCrypto.
- Cipher framing differs per construction (the recurring trap): GCM aligns the encrypted
  portion EXCLUDING the 4-byte length (it's AAD); CTR includes it; the CTR MAC is over
  `seqnum || plaintext` with an implicit per-direction sequence number.
- Exchange hash H uses `string Q_C, string Q_S` (raw keys), `mpint K` - not classic-DH
  `mpint e/f`. Key derivation is RFC 4253 7.2 (`src/ssh/kex/exchange-hash.ts`).
- The decisive check for all of this is the live handshake, not the KATs.

## Commands

```sh
bun run typecheck                              # tsc --noEmit
bun run test                                   # gate: unit + KAT (hermetic, no docker)
docker compose -f docker/compose.yml up -d --wait
INTEGRATION=1 bun run test                     # integration under workerd vs real servers
docker compose -f docker/compose.yml down -v
bun run build                                  # bundle + emit d.ts to dist/
bun run docs:build                             # TypeDoc -> ./typedoc
bun run prettier                               # format
```

## Testing layers

1. **Unit** (`test/unit/`) - mocked sockets, parsers, FSMs. Uses `test/mock-socket.ts`.
2. **KAT** (`test/kat/`) - byte-exact crypto vectors (RFC 7748/8032/4231/8439). No mocks.
3. **Integration** (`test/integration/`, gated by `INTEGRATION=1`) - real servers via
   `docker/compose.yml` (digest-pinned), run under `workerd` via
   `@cloudflare/vitest-pool-workers`. Integration runs serially (shared servers).

Docker test creds/ports: SSH/SFTP `tester`/`testpass` on 2222 (OpenSSH) + 2223 (Dropbear);
mail `tester`/`testpass` (`tester@localhost`) on greenmail 3025/3143/3110; ws-echo 8081;
NATS `tester`/`testpass` 4222; FTP `tester`/`testpass` 21 (passive 40000-40009); OpenLDAP
admin `cn=admin,dc=example,dc=org`/`admin` 389; MQTT mosquitto anon 1883; STOMP ActiveMQ
`admin`/`admin` 61613; syslog socat sink 5514. The publickey test key is
`test/fixtures/ed25519_pkcs8.pem` (its pub is in compose); more key fixtures in `test/fixtures/`.

## Conventions

- Inline comments: terse, lowercase, no trailing period, only for non-obvious WHY. ASCII only.
- Public API: thorough TSDoc (`@param`/`@returns`/`@throws`/`@since`/`@example`).
- Do NOT commit/push/branch without being asked; leave work uncommitted on `master`.
