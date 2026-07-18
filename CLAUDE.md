# edgeport - repo guide

TypeScript TCP-protocol library for the **Cloudflare Workers** runtime built on
`cloudflare:sockets`. Bun + strict ESM. Protocols: SSH, SFTP, SMTP, IMAP, POP3, WebSocket,
NATS, MQTT (+ MQTT-over-WS), STOMP, FTP, LDAP/LDAPS, Syslog, SMPP (v3.4 ESME), SIP + MSRP
(the RCS chat protocol family; signaling/messaging only, no RTP media, no carrier RCS), DNS
(over TCP, RFC 1035 + 7766), XMPP (RFC 6120/6121 + pubsub), IRC (RFC 2812 + IRCv3). Also
`edgeport/util` (transport-free hex/base64/random/retry/address/timeout helpers) and SMTP
email-to-SMS gateways (`sendSms`).
Runtime deps: `@noble/ciphers` (SSH ChaCha) and `bcrypt-pbkdf` (encrypted OpenSSH keys) - both
Workers-compatible, external.

## Architecture

- `src/core/` is the **only** code that imports `cloudflare:sockets` (the maintainability
  invariant). It provides `connect` / `startTls` / a buffered framed reader+writer / the
  shared error vocabulary. Never import `cloudflare:sockets` anywhere else.
- Each protocol lives under `src/<proto>/` and builds on the core. WebSocket is the
  exception: it uses the platform WebSocket API (fetch upgrade), not the raw-TCP core.
- Public surface per protocol: `connect(opts) -> session` (AsyncDisposable, `await using`)
  plus one-shot wrappers (`ssh.exec`, `smtp.send`, `sftp.getFile`, `pop3.retrieveAll`, ...).
- Errors are always one of `AuthError` / `ConnectionError` / `ProtocolError` / `TimeoutError`.
- Subpath exports (`edgeport/ssh`, etc.) keep bundles tree-shakeable. `core/` is still the ONLY
  code that imports `cloudflare:sockets`, but as of v1.0.4 it is also published as `edgeport/core`
  (low-level framed-TCP access for protocols edgeport does not ship); the import invariant is
  unchanged (never import `cloudflare:sockets` outside `src/core/`).

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
   `docker/compose.yml` (images pinned as `tag@sha256:digest` - readable version + reproducible
   digest; docker pulls by digest, the tag is for humans/Renovate), run under `workerd` via
   `@cloudflare/vitest-pool-workers`. Integration runs serially (shared servers).

**Maximize coverage when writing tests (applies to the whole project).** Coverage is measured on
the gate run (unit + KAT, `istanbul` over `src/**`); integration does not count toward it. Take the
free wins: every wrapper/one-shot that just delegates should still be _called_ so its line is
covered, and every branch that throws on invalid input (`ProtocolError`/`AuthError`/...) should have
a test that trips it - a thin one-liner per branch. Still write the nitty-gritty edge cases and the
real between-methods flows in integration/e2e where they belong, but do not leave a delegating
wrapper, a niche codec type, or an error branch uncovered just because it looks trivial. When a
one-shot or session needs a live socket, add a small `@internal` `_xFromSocket` / `_xFromSession`
seam (the established pattern: `_sessionFromSocket`, `_imapSessionFromSocket`, `_connectOverSocket`,
`_msrpSessionFromSocket`, `_fetchRecentFromSession`) so the logic is drivable over a mock socket.

Docker test creds/ports: SSH/SFTP `tester`/`testpass` on 2222 (OpenSSH) + 2223 (Dropbear);
mail `tester`/`testpass` (`tester@localhost`) on greenmail 3025/3143/3110; ws-echo 8081;
NATS `tester`/`testpass` 4222; FTP `tester`/`testpass` 21 (passive 40000-40009); OpenLDAP
admin `cn=admin,dc=example,dc=org`/`admin` 389; MQTT mosquitto anon 1883; STOMP ActiveMQ
`admin`/`admin` 61613; syslog socat sink 5514; SMPP `ukarim/smscsim` (any system_id, no auth)
2775 + MO-inject HTTP 12775 (emits a `DELIVRD` receipt ~2s after a registered submit); SIP
Kamailio 5.6 (`docker/sip`, apt-at-runtime on pinned debian) 5060/tcp + MSRP relay 2855, realm
`edgeport.test`, `tester`/`testpass` (realm-static password, any username binds), routes MESSAGE
between registered AORs (MSRP relay needs an AUTH handshake edgeport's session skips - MSRP
session-mode is unit-tested, not E2E). DNS CoreDNS (distroless, digest-pinned) serving static
zone `edgeport.test` on 5354 (tcp+udp -> container 53): A/AAAA/MX/TXT/SRV/CNAME/CAA/NS/SOA plus
reverse zone `1.0.10.in-addr.arpa` (PTR for 10.0.1.x); no shell healthcheck (distroless is like
nats/mqtt/greenmail), readiness via the spec's beforeAll poll. XMPP ejabberd (`docker/xmpp`,
`ghcr.io/processone/ejabberd`) plaintext c2s 5222, VirtualHost/domain `localhost`, users
`tester`/`tester2` `testpass` (registered via `CTL_ON_CREATE`), pubsub component
`pubsub.localhost`; STARTTLS/implicit-TLS not E2E-testable under workerd (cert validation, the
LDAPS lesson), so XMPP integration uses tls:'off'. IRC ergo 2.18.0 (`docker/irc`, digest-pinned)
plaintext 6667, no accounts/SASL required to connect, channels creatable on join, `ip-limits`
disabled for many local clients (SASL is unit-tested only - ergo accounts need NickServ
registration, so integration is the plaintext NICK/USER + channel flow). The publickey test key
is `test/fixtures/ed25519_pkcs8.pem` (its pub is in compose); more key fixtures in
`test/fixtures/`.

## Conventions

- Inline comments: terse, lowercase, no trailing period, only for non-obvious WHY. ASCII only.
- Public API: thorough TSDoc (`@param`/`@returns`/`@throws`/`@since`/`@example`).
- Do NOT commit/push/branch without being asked; leave work uncommitted on `master`.
