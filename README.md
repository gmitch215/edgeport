# edgeport

> 🛜 TCP Library for Cloudflare Workers

edgeport gives Cloudflare Workers native clients for various TCP protocols, built directly on `cloudflare:sockets`.

Node libraries assume Node's `net`/`tls` and Node crypto, none of which exist in workerd;
edgeport is written for the Workers runtime from the ground up.

## Table of Contents

- [Why edgeport](#why-edgeport)
- [Features](#features)
- [Install](#install)
- [Getting Started](#getting-started)
- [SSH](#ssh)
- [SFTP](#sftp)
- [SMTP](#smtp)
- [IMAP](#imap)
- [POP3](#pop3)
- [WebSocket](#websocket)
- [Real-World Recipes](#real-world-recipes)
- [Error Handling](#error-handling)
- [Limitations](#limitations)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

## Why edgeport

Workers can open raw TCP sockets, but every existing SSH/mail client depends on Node APIs
the runtime does not provide. edgeport is:

- **Workers-Native.** One small core is the only code that imports `cloudflare:sockets`;
  every protocol builds on it. Nothing depends on Node.
- **TypeScript-first.** The types are the contract and the documentation.
- **Tree-Shakeable.** Import only the protocol you use (`edgeport/ssh`, `edgeport/smtp`, ...).
- **Tested against Real Servers.** Every protocol is verified under `workerd` against
  Dockerized OpenSSH, Dropbear, GreenMail, and a WebSocket echo server - not mocks.

## Features

- **SSH** transport, auth, and connection layers: `exec`, interactive `shell`, subsystems.
- **SFTP** v3 over SSH: read/write/list/stat/rename/remove, plus streaming.
- **SMTP** send with STARTTLS / implicit TLS and AUTH PLAIN/LOGIN.
- **IMAP** and **POP3** read access with STARTTLS / implicit TLS.
- **WebSocket** client via the platform API (`for await` message iteration).
- One uniform error vocabulary: `AuthError`, `ConnectionError`, `ProtocolError`, `TimeoutError`.

### SSH algorithm support

| Category         | Supported                                                                                                       |
| ---------------- | --------------------------------------------------------------------------------------------------------------- |
| Key Exchange     | `curve25519-sha256`, `ecdh-sha2-nistp256`                                                                       |
| Host / User Keys | Ed25519, ECDSA-P256, RSA-SHA2-256/512                                                                           |
| Ciphers          | `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `chacha20-poly1305@openssh.com`, `aes256-ctr`, `aes128-ctr` |
| MAC              | `hmac-sha2-256`, `hmac-sha2-512` (AEAD Ciphers carry their own)                                                 |
| Auth             | publickey, password, keyboard-interactive                                                                       |

ChaCha20-Poly1305 is assembled from [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers)
because Workers WebCrypto does not provide it.

## Install

```sh
bun add edgeport
# or: npm install edgeport
```

edgeport targets the Workers runtime. Use it inside a Worker, not in plain Node.

## Getting Started

```typescript
import { exec } from 'edgeport/ssh';

export default {
	async fetch(): Promise<Response> {
		const { stdout, code } = await exec({
			hostname: 'example.com',
			username: 'deploy',
			password: env.SSH_PASSWORD,
			command: 'uptime'
		});
		return new Response(`exit ${code}\n${new TextDecoder().decode(stdout)}`);
	}
};
```

## SSH

### One-shot Exec

```typescript
import { exec } from 'edgeport/ssh';

const { stdout, stderr, code } = await exec({
	hostname: 'host',
	username: 'user',
	privateKey: { pem: env.SSH_KEY }, // PKCS8 PEM, or pass a CryptoKey
	command: 'ls -la /var/log'
});
```

### A reusable Session

```typescript
import { connect } from 'edgeport/ssh';

await using ssh = await connect({ hostname: 'host', username: 'user', password: env.PW });
const a = await ssh.exec('hostname');
const b = await ssh.exec('date');
// the session closes automatically at the end of the `await using` scope
```

### Interactive Shell (streaming)

```typescript
await using ssh = await connect({ hostname: 'host', username: 'user', password: env.PW });
await using shell = await ssh.shell();

await shell.write(new TextEncoder().encode('echo hi\n'));
const reader = shell.stdout.getReader();
const { value } = await reader.read();
console.log(new TextDecoder().decode(value));
```

### Keyboard-Interactive and Host-Key Pinning

```typescript
await using ssh = await connect({
	hostname: 'host',
	username: 'user',
	onKeyboardInteractive: async (prompts) => prompts.map(() => env.OTP),
	hostKey: { verify: (type, key) => type === 'ssh-ed25519' && constantTimeEqual(key, PINNED) }
});
```

### Forcing a Cipher

```typescript
await using ssh = await connect({
	hostname: 'host',
	username: 'user',
	password: env.PW,
	algorithms: { cipher: ['chacha20-poly1305@openssh.com'] }
});
```

## SFTP

```typescript
import { connect, getFile, putFile } from 'edgeport/sftp';

// one-shots
const bytes = await getFile({ hostname: 'h', username: 'u', password: p, path: '/etc/hostname' });
await putFile({ hostname: 'h', username: 'u', password: p, path: '/tmp/x', data: bytes });

// a session
await using sftp = await connect({ hostname: 'h', username: 'u', password: p });
await sftp.mkdir('/tmp/reports');
await sftp.writeFile('/tmp/reports/today.csv', new TextEncoder().encode('a,b,c\n'));
for (const entry of await sftp.list('/tmp/reports')) {
	console.log(entry.filename, entry.attrs.size);
}

// stream a large download
const stream = sftp.createReadStream('/var/log/big.log');
```

Reuse an existing SSH session instead of opening a second connection:

```typescript
import { connect as sshConnect } from 'edgeport/ssh';
import { connect as sftpConnect } from 'edgeport/sftp';

await using ssh = await sshConnect({ hostname: 'h', username: 'u', password: p });
await using sftp = await sftpConnect({ session: ssh });
```

## SMTP

**Port 25 is blocked on Workers**, so edgeport sends over submission (587, STARTTLS) or
implicit TLS (465).

```typescript
import { send } from 'edgeport/smtp';

await send({
	hostname: 'smtp.example.com',
	port: 587, // STARTTLS (default)
	auth: { username: 'postmaster@example.com', password: env.SMTP_PW },
	from: 'postmaster@example.com',
	to: ['ops@example.com'],
	subject: 'Deploy finished',
	text: 'The 14:00 deploy completed successfully.'
});
```

HTML mail and a Reusable Session:

```typescript
import { connect } from 'edgeport/smtp';

await using smtp = await connect({
	hostname: 'smtp.example.com',
	port: 465,
	tls: 'implicit',
	auth: { username: 'u', password: env.SMTP_PW }
});
await smtp.send({ from: 'u@x', to: 'a@y', subject: 'Hi', html: '<h1>Hi</h1>', text: 'Hi' });
```

Using the [Cloudflare Email Service](https://developers.cloudflare.com/email-service/api/send-emails/smtp/), your workers can now send emails on-demand without the additional cost of a SMTP provider. For example:

```typescript
import { send } from 'edgeport/smtp';

await send({
	hostname: 'smtp.mx.cloudflare.net',
	tls: 'implicit', // port defaults to 465 for implicit
	auth: {
		username: 'api_token', // literal string, per Cloudflare docs
		password: env.CF_EMAIL_TOKEN, // API token w/ Email Sending: Edit
		mechanism: 'PLAIN' // LOGIN also supported
	},
	from: 'welcome@yourdomain.com', // domain must be onboarded to Email Sending
	to: 'user@example.com', // any valid email address rather than verified recipient
	subject: 'Hello',
	text: 'Sent from a Worker over edgeport SMTP.'
});
```

## IMAP

```typescript
import { connect, fetchRecent } from 'edgeport/imap';

const recent = await fetchRecent({
	hostname: 'imap.example.com',
	auth: { username: 'u', password: env.PW },
	mailbox: 'INBOX',
	count: 10
});

await using imap = await connect({
	hostname: 'imap.example.com',
	auth: { username: 'u', password: env.PW }
});
const { exists } = await imap.select('INBOX');
const uids = await imap.search({ unseen: true });
const messages = await imap.fetch(uids, { envelope: true, body: true });
```

## POP3

```typescript
import { retrieveAll, connect } from 'edgeport/pop3';

const all = await retrieveAll({
	hostname: 'pop.example.com',
	auth: { username: 'u', password: env.PW }
});

await using pop = await connect({
	hostname: 'pop.example.com',
	auth: { username: 'u', password: env.PW }
});
const { count } = await pop.stat();
const first = await pop.retrieve(1);
```

## WebSocket

The WebSocket client uses the platform WebSocket API; the runtime handles TLS, framing,
and masking.

```typescript
import { connect } from 'edgeport/ws';

const ws = await connect('wss://stream.example.com/feed', { protocols: ['v1'] });
ws.send(JSON.stringify({ subscribe: 'ticks' }));

for await (const msg of ws) {
	if (msg.type === 'text') handle(JSON.parse(msg.data));
}
const { code, reason } = await ws.closed;
```

## Real-World Recipes

### A cron Worker that runs a remote command

```typescript
import { exec } from 'edgeport/ssh';

export default {
	async scheduled(_event, env) {
		const { code } = await exec({
			hostname: env.BOX,
			username: 'deploy',
			privateKey: { pem: env.SSH_KEY },
			command: 'systemctl restart myapp'
		});
		if (code !== 0) throw new Error('restart failed');
	}
};
```

### Email an alert on a webhook

```typescript
import { send } from 'edgeport/smtp';

export default {
	async fetch(req, env) {
		const body = await req.text();
		await send({
			hostname: env.SMTP_HOST,
			auth: { username: env.SMTP_USER, password: env.SMTP_PW },
			from: env.SMTP_USER,
			to: env.ONCALL,
			subject: 'Webhook alert',
			text: body
		});
		return new Response('ok');
	}
};
```

### Poll a mailbox and archive attachments to SFTP

```typescript
import { connect as imapConnect } from 'edgeport/imap';
import { putFile } from 'edgeport/sftp';

await using imap = await imapConnect({
	hostname: env.IMAP,
	auth: { username: env.U, password: env.P }
});
await imap.select('INBOX');
const uids = await imap.search({ unseen: true });
const messages = await imap.fetch(uids, { body: true });
for (const m of messages) {
	if (m.body)
		await putFile({
			hostname: env.SFTP,
			username: env.U,
			password: env.P,
			path: `/archive/${m.uid}.eml`,
			data: m.body
		});
}
```

## Error Handling

Every edgeport call rejects with one of four types, all extending `EdgeportError`:

```typescript
import { AuthError, ConnectionError, ProtocolError, TimeoutError } from 'edgeport';

try {
  await exec({ hostname: 'h', username: 'u', password: 'wrong', command: 'id' });
} catch (err) {
  if (err instanceof AuthError) // bad credentials
  else if (err instanceof ConnectionError) // could not reach / TLS / dropped
  else if (err instanceof ProtocolError) // malformed or unsupported (e.g. no common cipher)
  else if (err instanceof TimeoutError) // a deadline elapsed
}
```

## Limitations

- **No port 25.** Cloudflare blocks outbound port 25; use 587 or 465 for SMTP.
- **ChaCha20 throughput.** `chacha20-poly1305@openssh.com` is pure-JS (via `@noble/ciphers`)
  and slower than the hardware-paced AES-GCM that WebCrypto provides; AES-GCM is preferred
  during negotiation. Watch Worker CPU limits on very large ChaCha transfers.
- **No agent forwarding, X11, or port forwarding.** edgeport implements the client side of
  exec/shell/subsystem and SFTP only.
- **Encrypted private keys** (passphrase-protected PEM) are not yet supported; decrypt first.
- **No in-session rekeying** (RFC 4253 section 9) yet. Sessions past the server's rekey
  threshold (commonly 1 GiB or 1 hour) will fail; open a fresh connection for very large
  or very long-lived transfers.

## Advanced: Building-Block Exports

Beyond the protocol modules, edgeport publishes the lower-level SSH building blocks it is
assembled from, for tooling that needs them directly:

| Import            | Provides                                                                                                                         |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `edgeport/wire`   | SSH binary wire codecs (`SshReader`, `SshWriter`, `toMpintBody`)                                                                 |
| `edgeport/crypto` | hashes/HMAC, the SSH packet ciphers (`createPacketCipher`, `cipherSizes`), host/user keys (`verifyHostSignature`, `loadUserKey`) |
| `edgeport/kex`    | KEXINIT negotiation, the exchange hash + key schedule, `createKex`, and the `curve25519`/`nistp256` namespaces                   |
| `edgeport/auth`   | SSH user authentication (`authenticate`)                                                                                         |

```typescript
import { SshReader, SshWriter } from 'edgeport/wire';
import { createPacketCipher, verifyHostSignature } from 'edgeport/crypto';
import { negotiate, createKex } from 'edgeport/kex';
```

These are stable but lower-level; most applications only need the protocol modules above.

## API Reference

Full generated API docs: see the published TypeDoc site (built from source by
`bun run docs:build`).

## Contributing

```sh
bun install
bun run typecheck
bun run test                                   # gate: unit + KAT, hermetic
docker compose -f docker/compose.yml up -d --wait
INTEGRATION=1 bun run test                     # integration under workerd vs real servers
docker compose -f docker/compose.yml down -v
```

Releases use npm [staged publishing](https://docs.npmjs.com/staged-publishing): CI runs
`npm stage publish` via OIDC, then a maintainer promotes the staged version with
`npm stage approve <id>` (2FA, run locally - it cannot run in CI).

## License

MIT (c) Gregory Mitchell
