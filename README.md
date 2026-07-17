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
- [NATS](#nats)
- [MQTT](#mqtt)
- [STOMP](#stomp)
- [FTP](#ftp)
- [LDAP / LDAPS](#ldap--ldaps)
- [Syslog](#syslog)
- [SMPP](#smpp)
- [SIP (RCS)](#sip-rcs)
- [DNS](#dns)
- [XMPP](#xmpp)
- [IRC](#irc)
- [Utilities](#utilities)
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
  Dockerized servers (OpenSSH, Dropbear, GreenMail, NATS with JetStream, Mosquitto, ActiveMQ,
  OpenLDAP, an FTP server, an SMPP SMSC simulator, a Kamailio SIP server, a CoreDNS resolver, an
  ejabberd XMPP server, an Ergo IRC server, and a WebSocket echo server) - not mocks.

## Features

- **SSH** transport, auth, and connection layers: `exec`, interactive `shell`, subsystems.
- **SFTP** v3 over SSH: read/write/list/stat/rename/remove, plus streaming.
- **SMTP** send with STARTTLS / implicit TLS and AUTH PLAIN/LOGIN.
- **IMAP** and **POP3** read access with STARTTLS / implicit TLS.
- **WebSocket** client via the platform API (`for await` message iteration).
- **NATS** pub/sub, request-reply, and queue groups; token / user-pass / nkey / JWT (creds) auth.
- **MQTT** v3.1.1 (QoS 0/1/2, keep-alive, wildcards) over raw TCP or WebSocket.
- **STOMP** 1.2 messaging (send / subscribe / ack) for ActiveMQ, RabbitMQ, and friends.
- **FTP** (plaintext, passive mode): upload, download, list, and directory ops.
- **LDAP / LDAPS** simple bind + search with RFC 4515 filters (BER codec, StartTLS).
- **Syslog** RFC 5424 over TCP/TLS with octet-counting or LF framing.
- **SMPP** v3.4 client (ESME): bind, `submit_sm`, and inbound `deliver_sm` / delivery receipts.
- **SIP / RCS** user agent over TCP/TLS: register, `MESSAGE`, `OPTIONS`, presence, and MSRP chat.
- **DNS** over TCP (RFC 1035): `resolve`, typed record helpers, reverse lookups, and raw queries.
- **XMPP** (RFC 6120/6121): presence, messages, roster, and pubsub through a concept API.
- **IRC** (RFC 1459/2812 + IRCv3): channels, messages, events, SASL, and raw commands.
- **Email-to-SMS** carrier-gateway addressing layered on SMTP (`sendSms`).
- **Utilities** (`edgeport/util`): hex/base64 codecs, random ids, retry-with-backoff, email-address
  parsing, and promise deadlines.
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
		const { stdoutText, code } = await exec({
			hostname: 'example.com',
			username: 'deploy',
			password: env.SSH_PASSWORD,
			command: 'uptime'
		});
		return new Response(`exit ${code}\n${stdoutText}`);
	}
};
```

## SSH

### One-shot Exec

```typescript
import { exec } from 'edgeport/ssh';

const { stdout, stdoutText, code } = await exec({
	hostname: 'host',
	username: 'user',
	privateKey: { pem: env.SSH_KEY }, // PKCS8 PEM, or pass a CryptoKey
	command: 'ls -la /var/log'
});
// stdoutText / stderrText are the decoded strings; stdout / stderr keep the raw bytes
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
import { connect } from 'edgeport/ssh';
import { toUtf8 } from 'edgeport/util';

await using ssh = await connect({ hostname: 'host', username: 'user', password: env.PW });
await using shell = await ssh.shell();

await shell.write('echo hi\n');
const reader = shell.stdout.getReader();
const { value } = await reader.read();
console.log(toUtf8(value!));
```

### Keyboard-Interactive and Host-Key Pinning

```typescript
await using ssh = await connect({
	hostname: 'host',
	username: 'user',
	onKeyboardInteractive: async (prompts) => prompts.map(() => env.OTP),
	hostKey: {
		verify: (type, key) => type === 'ssh-ed25519' /* && key matches your pinned host key */
	}
});
```

### Executing with Sudo

`sudo` does not read its password from SSH auth - it prompts over the channel. The `sudo`
helpers run `sudo -S -p ''` (read the password from stdin, silence sudo's own prompt) and
feed it the secret for you. The sudoers policy must allow password sudo without a tty
(`requiretty` off, the default on most modern distros).

One-shot over a fresh connection - `sudoPassword` defaults to `password`, so the SSH login
password is reused as the sudo password (the common case):

```typescript
import { sudoExec } from 'edgeport/ssh';

const { stdoutText, code } = await sudoExec({
	hostname: 'host',
	username: 'user',
	password: env.PW,
	command: 'systemctl restart myapp'
});
console.log(code, stdoutText);
```

Reusing an already-open session (pass the sudo password explicitly):

```typescript
import { connect, sudo } from 'edgeport/ssh';

await using ssh = await connect({ hostname: 'host', username: 'user', password: env.PW });
const result = await sudo(ssh, 'whoami', { password: env.PW });
console.log(result.lastLine()); // "root"
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

### Encrypted (Passphrase-Protected) Keys

Encrypted PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`) and OpenSSH-format keys (`BEGIN OPENSSH
PRIVATE KEY`, the `ssh-keygen` default), encrypted or not, are accepted - pass the
`passphrase`:

```typescript
await using ssh = await connect({
	hostname: 'host',
	username: 'user',
	privateKey: { pem: env.SSH_KEY, passphrase: env.SSH_KEY_PASSPHRASE }
});
```

### Key Re-Exchange (Rekey)

Long-lived sessions and large transfers rekey automatically (default every ~1 GiB, per
RFC 4253 §9); server-initiated rekeys are handled transparently. Tune or force it:

```typescript
await using ssh = await connect({
	hostname: 'host',
	username: 'user',
	password: env.PW,
	rekeyThresholdBytes: 256 * 1024 * 1024 // auto-rekey every 256 MiB (0 disables)
});
await ssh.rekey(); // or force one now
```

### Port Forwarding (Tunneling)

`forwardOut` opens a `direct-tcpip` channel: the SSH server connects to a target on your
behalf and pipes the bytes back, so a Worker can reach a service that isn't internet-exposed
through an SSH bastion (the `-L` reach-through). It returns a duplex channel - `stdout` is
inbound bytes, `write()` sends outbound.

```typescript
import { connect } from 'edgeport/ssh';

await using ssh = await connect({
	hostname: 'bastion',
	username: 'u',
	privateKey: { pem: env.SSH_KEY }
});

// reach an internal-only Postgres that sits behind the bastion
await using tunnel = await ssh.forwardOut('10.0.0.5', 5432);
await tunnel.write(startupPacket);
for await (const chunk of tunnel.stdout) {
	// handle each inbound chunk from the tunneled service here
}
```

Workers cannot accept inbound connections, so the listening half of `-L`/`-D` (a local SOCKS
listener) and remote forwarding (`-R`) are out of scope - the server-side reach-through is the
valuable part and is fully supported. The server must permit TCP forwarding
(`AllowTcpForwarding`).

### SSH Command Helpers

On top of `exec`/`execStream`, a session carries ergonomic shell helpers. Each one
single-quotes the paths and arguments it interpolates, so a space or `$` in a path cannot
break the command; the destructive `rm` also refuses obviously dangerous targets (`/`, `~`,
`.`, `..`).

These helpers assume a **POSIX shell**, so they work against Linux, macOS, and other Unix
remotes - `stat` and `spawnDetached` handle the GNU/BSD differences (GNU `stat -c` vs BSD
`stat -f`; `nohup` rather than Linux-only `setsid`). For a Windows (`cmd.exe`/PowerShell) or
other non-POSIX remote, drop down to `run`/`exec`/`execStream` with native commands.

```typescript
import { connect } from 'edgeport/ssh';

await using ssh = await connect({ hostname: 'host', username: 'user', password: env.PW });

const host = await ssh.run('hostname'); // decoded, trimmed stdout; throws on a nonzero exit
if (await ssh.test('command -v docker')) {
	// docker is installed
}
if (await ssh.exists('/etc/hosts')) {
	// the file is there
}
```

```typescript
// files and directories
await ssh.mkdirp('/srv/app/releases', { mode: 0o755 });
await ssh.writeTextFile('/srv/app/.env', 'PORT=8080\n');
const envFile = await ssh.readTextFile('/srv/app/.env');
await ssh.chmod('/srv/app/run.sh', 0o755);
const st = await ssh.stat('/srv/app'); // { size, mode, mtime, isDirectory, isSymlink }
await ssh.rm('/srv/app/tmp', { recursive: true, force: true });

// system introspection and background work
const usage = await ssh.df('/srv'); // [{ filesystem, sizeKb, usedKb, availKb, usePercent, mountedOn }]
const git = await ssh.which('git'); // '/usr/bin/git' | null
await ssh.spawnDetached('/srv/app/worker', { stdout: '/var/log/worker.log' });
```

For one-call workflows there are connect-run-close one-shots:

```typescript
import { run, test, exists } from 'edgeport/ssh';

const out = await run({ hostname: 'host', username: 'user', password: env.PW, command: 'uptime' });
const ok = await exists({
	hostname: 'host',
	username: 'user',
	password: env.PW,
	path: '/etc/hosts'
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
await sftp.writeFile('/tmp/reports/today.csv', 'a,b,c\n');
for (const entry of await sftp.list('/tmp/reports')) {
	console.log(entry.filename, entry.attrs.size);
}

// stream a large download
const stream = sftp.createReadStream('/var/log/big.log');
```

### Reusing an Existing Session

Reuse an existing SSH session instead of opening a second connection:

```typescript
import { connect as sshConnect } from 'edgeport/ssh';
import { connect as sftpConnect } from 'edgeport/sftp';

await using ssh = await sshConnect({ hostname: 'h', username: 'u', password: p });
await using sftp = await sftpConnect({ session: ssh });
```

### Large File Transfers

For large files, use the streaming API to avoid buffering the entire file in memory:

```typescript
await using sftp = await connect({ hostname: 'h', username: 'u', password: p });
const readStream = sftp.createReadStream('/var/log/big.log');
const writeStream = sftp.createWriteStream('/tmp/bigfile');
```

### SFTP Convenience Helpers

Higher-level helpers built on the same request/response framing:

```typescript
import { connect } from 'edgeport/sftp';

await using sftp = await connect({ hostname: 'h', username: 'u', password: p });

// presence check (a "no such file" status resolves false; other errors propagate)
if (!(await sftp.exists('/srv/app'))) {
	await sftp.ensureDir('/srv/app/releases/2026'); // recursive mkdir, one level per segment
}

// text and JSON round-trips (UTF-8)
await sftp.writeText('/srv/app/note.txt', 'deployed\n');
const note = await sftp.readText('/srv/app/note.txt');
await sftp.writeJson('/srv/app/config.json', { port: 8080 }, { space: 2 });
const config = await sftp.readJson<{ port: number }>('/srv/app/config.json');
await sftp.writeFile('/srv/app/data.txt', 'writeFile also accepts a string (UTF-8 encoded)');

await sftp.chmod('/srv/app/run.sh', 0o755);

// removal: one empty dir, a batch of files, or a whole tree
await sftp.rmdir('/srv/app/empty');
await sftp.removeMany(['/tmp/a.log', '/tmp/b.log'], { ignoreMissing: true });
await sftp.removeAll('/srv/app/releases/old'); // recursive, client-side, non-atomic
```

`removeAll` walks the tree from the client (one round trip per entry) and refuses an empty
path or `/`; `ensureDir` tolerates segments that already exist and verifies the leaf is a
directory.

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

### One-shot Connect + Send with HTML

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

### Cloudflare Email Service

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

### Attachments and Plaintext Relays

Pass `attachments` to build a `multipart/mixed` message; pass `tls: 'off'` to talk to a
trusted internal relay or dev server with no TLS.

```typescript
await send({
	hostname: 'relay.internal',
	tls: 'off', // plaintext (trusted network); 'starttls' (default) and 'implicit' also supported
	from: 'reports@internal',
	to: 'team@internal',
	subject: 'Daily report',
	text: 'Attached.',
	attachments: [{ filename: 'report.csv', content: csvBytes, contentType: 'text/csv' }]
});
```

### Email-to-SMS Gateway

Many carriers accept email at a gateway that forwards it to the handset as a text message.
`sendSms` builds that gateway address from a phone number and a carrier - a known key from
`CarrierGateways`, or a raw gateway domain - then sends a short plaintext message over the
normal SMTP path.

```typescript
import { sendSms, smsAddress } from 'edgeport/smtp';

// resolve the gateway address (number@gateway-domain), normalizing the number
smsAddress('+1 (555) 123-4567', 'att'); // '15551234567@txt.att.net'

await sendSms({
	hostname: 'smtp.example.com',
	auth: { username: 'me@example.com', password: env.SMTP_PW },
	from: 'me@example.com',
	to: { number: '5551234567', carrier: 'verizon' },
	text: 'Your code is 123456'
});
```

Coverage is US + Canadian carriers (`att`, `tmobile`, `verizon`, `sprint`, `cricket`,
`rogers`, `bell`, `telus`, ...); pass a raw gateway domain for anything not listed. Gateway
domains are best-effort and drift over time, so a raw-domain override is the escape hatch.
Use `type: 'mms'` for a carrier's picture-message gateway where it differs.

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
for (const m of messages) console.log(m.text()); // decoded body; m.body keeps the raw bytes
```

### One-shot Fetch Recent

Fetch the most recent N messages in one call (not streaming):

```typescript
import { fetchRecent } from 'edgeport/imap';
const recent = await fetchRecent({
	hostname: 'imap.example.com',
	auth: { username: 'u', password: env.PW },
	mailbox: 'INBOX',
	count: 10
});
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
const first = await pop.retrieve(1); // raw bytes
const firstText = await pop.retrieveText(1); // decoded string, no TextDecoder needed
```

### One-shot Retrieve All

Retrieve all messages in one call (not streaming):

```typescript
import { retrieveAll } from 'edgeport/pop3';
const all = await retrieveAll({
	hostname: 'pop.example.com',
	auth: { username: 'u', password: env.PW }
});
```

## WebSocket

The WebSocket client uses the platform WebSocket API; the runtime handles TLS, framing,
and masking.

```typescript
import { connect } from 'edgeport/ws';

const ws = await connect('wss://stream.example.com/feed', { protocols: ['v1'] });
ws.send(JSON.stringify({ subscribe: 'ticks' }));

// directly iterate messages with `for await`
for await (const msg of ws) {
	if (msg.type === 'text') {
		const event = JSON.parse(msg.data);
		// handle the parsed event here
	}
}
const { code, reason } = await ws.closed;
```

### JSON Helpers

```typescript
import { connect } from 'edgeport/ws';

const ws = await connect('wss://stream.example.com/feed');
ws.sendJson({ subscribe: 'ticks' });
// json() and text() work on every frame (text OR binary) - no branching on type, no
// TextDecoder; a server that sends JSON over binary frames just works
for await (const msg of ws) {
	const event = msg.json<{ price: number }>();
	// handle the parsed event here
}
```

## NATS

```typescript
import { connect } from 'edgeport/nats';

await using nc = await connect({ hostname: 'nats.example.com', token: env.NATS_TOKEN });

// pub/sub
const sub = nc.subscribe('orders.*', { queue: 'workers' });
await nc.publish('orders.created', JSON.stringify({ id: 42 }));
for await (const msg of sub) {
	const order = msg.json();
	// handle the order here
}

// request-reply
const reply = await nc.request('time.now', '', { timeoutMs: 1000 });
```

### NKey Authorization

nkey (ed25519) auth: pass `nkeySeed` (a `SU...` seed) instead of a token. For managed NATS
(Synadia NGS) or any JWT-secured deployment, pass the contents of a `.creds` file - the user
JWT and signing seed are extracted automatically:

```typescript
import { connect } from 'edgeport/nats';

await using nc = await connect({ hostname: 'connect.ngs.global', creds: env.NATS_CREDS });
```

### Subscribe with a Queue Group

Distribute messages across multiple workers by subscribing with a queue group:

```typescript
import { connect } from 'edgeport/nats';

await using nc = await connect({ hostname: 'nats.example.com', token: env.NATS_TOKEN });
const sub = nc.subscribe('orders.*', { queue: 'workers' });

// directly iterate messages with `for await`
for await (const msg of sub) {
	const order = msg.json();
	// one member of the 'workers' queue group receives each message
}
```

### JetStream

Durable, at-least-once streams via `nc.jetstream()`: ensure a stream, publish with a
`PubAck`, and pull with a durable consumer that survives reconnects (un-acked messages are
redelivered; acked ones are not).

```typescript
await using nc = await connect({ hostname: 'nats.example.com', token: env.NATS_TOKEN });
const js = nc.jetstream();

await js.ensureStream('EVENTS', { subjects: ['events.>'] });
const ack = await js.publish('events.created', JSON.stringify({ id: 42 })); // { stream, seq }

const consumer = await js.pullSubscribe('EVENTS', 'worker-durable', { ackWaitMs: 30_000 });
for (const msg of await consumer.fetch(10, { expiresMs: 5000 })) {
	// process msg.data here
	await msg.ack(); // un-acked messages are redelivered after a reconnect
}
```

### JSON Helpers

`publishJson`/`requestJson` and the per-message `json()`/`text()` accessors remove the
encode/parse boilerplate:

```typescript
import { connect } from 'edgeport/nats';

await using nc = await connect({ hostname: 'nats.example.com', token: env.NATS_TOKEN });

await nc.publishJson('readings', { temp: 21.5 });
for await (const { value } of nc.subscribeJson<{ temp: number }>('readings')) {
	console.log(value.temp);
}

const reply = await nc.requestJson<{ sum: number }>('calc.add', [2, 3]);
```

A subscribe responder replies with `msg.respond(value)`; any received message exposes
`msg.json<T>()` and `msg.text()`.

## MQTT

Raw TCP (1883 / TLS 8883) or over WebSocket - same API.

```typescript
import { connect, connectWebSocket } from 'edgeport/mqtt';

await using mqtt = await connect({
	hostname: 'broker.example.com',
	port: 8883,
	tls: 'implicit',
	clientId: 'edge-worker-1',
	username: env.MQTT_USER,
	password: env.MQTT_PASS
});

await mqtt.publish('sensors/edge/temp', '21.4', { qos: 1, retain: true });
const sub = mqtt.subscribe('sensors/+/temp', { qos: 1 });
for await (const m of sub) console.log(m.topic, m.text());

// or tunnel MQTT through a WebSocket broker endpoint
const overWs = await connectWebSocket('wss://broker.example.com:8884/mqtt', {
	clientId: 'edge-ws'
});
```

### Subscribe with Wildcards

Subscribe to topics with `+` (single-level) and `#` (multi-level) wildcards:

```typescript
import { connect } from 'edgeport/mqtt';

await using mqtt = await connect({ hostname: 'broker.example.com', clientId: 'edge' });
const sub = mqtt.subscribe('sensors/+/temp', { qos: 1 });

for await (const m of sub) {
	console.log(m.topic, m.text());
}
```

### Last Will and Persistent Sessions

Set a `will` and the broker publishes it if the client drops without a clean disconnect -
the basis for presence / offline detection. Use `cleanSession: false` with a fixed
`clientId` so queued QoS-1 messages are drained on reconnect.

```typescript
await using device = await connect({
	hostname: 'broker.example.com',
	clientId: 'device-42',
	cleanSession: false, // persistent session: queued QoS>=1 messages survive a reconnect
	will: { topic: 'devices/42/status', payload: 'offline', qos: 1, retain: true }
});
await device.publish('devices/42/status', 'online', { retain: true });

// ... later, an unexpected drop publishes the will; a clean shutdown does not:
await device.close({ graceful: false }); // abrupt -> broker fires the 'offline' will
```

### JSON Helpers

```typescript
import { connect } from 'edgeport/mqtt';

await using mqtt = await connect({ hostname: 'broker.example.com', clientId: 'edge' });
await mqtt.publishJson('sensors/1', { temp: 21.5 }, { qos: 1 });
for await (const { topic, value } of mqtt.subscribeJson<{ temp: number }>('sensors/+', {
	qos: 1
})) {
	console.log(topic, value.temp);
}
```

A plain `subscribe` message also exposes `msg.json<T>()` and `msg.text()`.

## STOMP

```typescript
import { connect } from 'edgeport/stomp';

await using stomp = await connect({
	hostname: 'mq.example.com',
	login: env.MQ_USER,
	passcode: env.MQ_PASS
});

await stomp.send('/queue/jobs', JSON.stringify({ task: 'resize' }));
const sub = stomp.subscribe('/queue/jobs', { ack: 'client' });
for await (const m of sub) {
	// process the job (m.body) here
	await m.ack?.();
}
```

### Heartbeats

Cloud messaging brokers often require heartbeats to keep the connection alive. edgeport supports STOMP heartbeats:

```typescript
import { connect } from 'edgeport/stomp';

await using stomp = await connect({
	hostname: 'mq.example.com',
	login: env.MQ_USER,
	passcode: env.MQ_PASS,
	heartBeat: [10000, 10000] // [send, expect] in ms; negotiated down with the broker
});
```

### Transactions

Stage sends in a transaction; the broker releases them only on `commit()` and discards them
on `abort()`.

```typescript
const tx = await stomp.begin();
await tx.send('/queue/orders', JSON.stringify(order));
await tx.send('/queue/audit', JSON.stringify(entry));
if (ok)
	await tx.commit(); // both messages delivered atomically
else await tx.abort(); // neither is ever delivered
```

### JSON Helpers

```typescript
import { connect } from 'edgeport/stomp';

await using stomp = await connect({
	hostname: 'mq.example.com',
	login: env.MQ_USER,
	passcode: env.MQ_PASS
});
await stomp.sendJson('/queue/jobs', { job: 'reindex', n: 7 }); // sets content-type: application/json
const sub = stomp.subscribe('/queue/jobs');
for await (const msg of sub) {
	const job = msg.json<{ job: string; n: number }>();
	// handle the job here
}
```

## FTP

Plaintext FTP, passive mode (Workers cannot accept the inbound connections active mode needs).

```typescript
import { connect, getFile, putFile } from 'edgeport/ftp';

await using ftp = await connect({
	hostname: 'files.example.com',
	username: 'u',
	password: env.FTP_PW
});
await ftp.put('reports/today.csv', 'a,b,c\n');
for (const entry of await ftp.list('reports')) console.log(entry.name, entry.size);
const bytes = await ftp.get('reports/today.csv');
```

### ASCII Mode and Resume

`get`/`put` take an options object: `type: 'ascii'` issues `TYPE A` (line-ending conversion)
vs the default `'binary'` (`TYPE I`); `offset` issues `REST <n>` to resume a download, and
`append: true` resumes an upload (`APPE`) - the practical recovery path after a dropped data
channel.

```typescript
// resume an interrupted upload from where it stopped, and download just the tail
await ftp.put('big.bin', firstChunk);
await ftp.put('big.bin', restOfFile, { append: true });
const tail = await ftp.get('big.bin', { offset: firstChunk.length });

// transfer a text file in ASCII mode
await ftp.put('records.txt', data, { type: 'ascii' });
```

### Convenience Helpers

Higher-level helpers over the raw commands; paths resolve relative to the working directory
unless absolute.

```typescript
import { connect } from 'edgeport/ftp';

await using ftp = await connect({
	hostname: 'files.example.com',
	username: 'u',
	password: env.FTP_PW
});

if (await ftp.exists('/etc/app/config.json')) {
	const cfg = await ftp.getJson<{ name: string }>('/etc/app/config.json');
}

await ftp.ensureDir('/incoming/2026/reports'); // recursive mkdir, one MKD per segment
await ftp.putText('/incoming/note.txt', 'hello world\n');
const note = await ftp.getText('/incoming/note.txt');
const when = await ftp.mtime('/incoming/note.txt'); // MDTM, parsed as UTC

await ftp.removeAll('/incoming/2026'); // recursive, client-side, non-atomic; refuses '' and '/'
```

## LDAP / LDAPS

```typescript
import { connect } from 'edgeport/ldap';
// or: import { connect } from 'edgeport/ldaps'  // implicit TLS on 636

await using ldap = await connect({
	hostname: 'ldap.example.com',
	bindDN: 'cn=svc,dc=example,dc=org',
	password: env.LDAP_PW
});

const users = await ldap.search({
	base: 'ou=people,dc=example,dc=org',
	scope: 'sub',
	filter: '(&(objectClass=person)(mail=*@example.org))',
	attributes: ['cn', 'mail']
});
for (const u of users) console.log(u.dn, u.attributes.mail);
```

### StartTLS

LDAP StartTLS is supported on the standard LDAP port (389):

```typescript
import { connect } from 'edgeport/ldap';

await using ldap = await connect({
	hostname: 'ldap.example.com',
	port: 389,
	tls: 'starttls',
	bindDN: 'cn=svc,dc=example,dc=org',
	password: env.LDAP_PW
});

const entries = await ldap.search({
	base: 'ou=people,dc=example,dc=org',
	scope: 'sub',
	filter: '(uid=jdoe)',
	attributes: ['cn', 'mail']
});
```

### LDAP Filters

LDAP search filters are expressed in RFC 4515 syntax:

```typescript
import { connect } from 'edgeport/ldap';

await using ldap = await connect({
	hostname: 'ldap.example.com',
	bindDN: 'cn=svc,dc=example,dc=org',
	password: env.LDAP_PW
});

const users = await ldap.search({
	base: 'ou=people,dc=example,dc=org',
	scope: 'sub',
	filter: '(&(objectClass=person)(mail=*@example.org))',
	attributes: ['cn', 'mail']
});
```

### Filter Builders

Build search filters from untrusted input safely. The structured builders carry values
literally, so a `*`, `(`, or `)` in user input becomes a literal byte on the wire and can
never inject filter syntax. Drop the result straight into `search({ filter })` / `findOne`.

```typescript
import { connect, and, eq, present } from 'edgeport/ldap';

await using ldap = await connect({
	hostname: 'ldap.example.com',
	bindDN: 'cn=svc,dc=example,dc=org',
	password: env.LDAP_PW
});

const users = await ldap.search({
	base: 'ou=people,dc=example,dc=org',
	filter: and(eq('objectClass', 'person'), present('mail')) // (&(objectClass=person)(mail=*))
});
const one = await ldap.findOne({
	base: 'ou=people,dc=example,dc=org',
	filter: eq('uid', userInput)
});
```

Builders: `and`, `or`, `not`, `eq`, `present`, `gte`, `lte`, `approx`, `substring`, `contains`
(also grouped under a `filters` namespace). When you assemble a filter string or DN by hand
instead, escape the interpolated value with `escapeFilterValue` / `escapeDN`.

`authenticate` does the bind-search-bind verify flow in one call:

```typescript
import { authenticate, eq } from 'edgeport/ldap';

const entry = await authenticate({
	hostname: 'ldap.example.com',
	bindDN: 'cn=svc,dc=example,dc=org',
	bindPassword: env.SVC_PW,
	base: 'ou=people,dc=example,dc=org',
	userFilter: eq('uid', username),
	password: submittedPassword
});
if (entry) {
	// authenticated; entry.dn is the bound user
}
```

## Syslog

```typescript
import { connect, Severity } from 'edgeport/syslog';

await using log = await connect({
	hostname: 'logs.example.com',
	port: 6514,
	tls: 'implicit',
	appName: 'edge-worker'
});
await log.log({
	severity: Severity.info,
	message: 'request handled',
	structuredData: [{ id: 'req@1', params: { ms: '12' } }]
});
```

### Severity Shortcuts

`info`/`notice`/`warn`/`error`/`debug` delegate to `log()` with the matching severity:

```typescript
import { connect } from 'edgeport/syslog';

await using log = await connect({ hostname: 'logs.example.com', appName: 'edge-worker' });
await log.info('request handled');
await log.warn('disk almost full', { facility: 'local0' });
await log.error('request failed', { structuredData: [{ id: 'req@1', params: { code: '500' } }] });
```

## SMPP

Send and receive SMS through a carrier's SMSC over SMPP v3.4. Bind as a transmitter, receiver,
or transceiver; submit messages; and iterate inbound `deliver_sm`s - mobile-originated messages
and delivery receipts - over the same session.

```typescript
import { connect } from 'edgeport/smpp';

await using smpp = await connect({
	hostname: 'smsc.example.com',
	port: 2775,
	systemId: 'esme',
	password: env.SMPP_PW,
	bindMode: 'transceiver'
});

// submit and get the SMSC message id back; request a delivery receipt
const id = await smpp.submit({
	source: 'EDGEPORT',
	destination: '12065550111',
	message: 'hello from the edge',
	registeredDelivery: true
});

// iterate inbound messages and delivery receipts
for await (const inbound of smpp.messages()) {
	if (inbound.isDeliveryReceipt) {
		const r = inbound.receipt();
		if (r.id === id) console.log('delivered:', r.stat); // e.g. 'DELIVRD'
	} else {
		console.log('MO from', inbound.source, inbound.text());
	}
}
```

### One-shot Send SMS

```typescript
import { sendMessage } from 'edgeport/smpp';

const id = await sendMessage({
	hostname: 'smsc.example.com',
	systemId: 'esme',
	password: env.SMPP_PW,
	source: 'EDGEPORT',
	destination: '12065550111',
	message: 'one-shot SMS from a Worker'
});
```

### Unicode and Long Messages

Pass `dataCoding: DataCoding.Ucs2` for non-GSM text (encoded UTF-16BE). A body over 254 octets
is carried in a `message_payload` TLV automatically.

```typescript
import { connect, DataCoding } from 'edgeport/smpp';

await using smpp = await connect({
	hostname: 'smsc.example.com',
	systemId: 'esme',
	password: env.SMPP_PW
});
await smpp.submit({
	destination: '12065550111',
	message: 'こんにちは',
	dataCoding: DataCoding.Ucs2
});
```

TLS is implicit-only (`tls: 'implicit'`); SMPP has no in-band STARTTLS. The session sends
periodic `enquire_link` keep-alives and answers the SMSC's, and `close()` unbinds cleanly.

## SIP (RCS)

A SIP user agent over raw TCP/TLS: register, send and receive messages, probe capabilities,
subscribe to presence, and run MSRP chat sessions. SIP + MSRP are the protocols the chat side
of **RCS** (the GSMA Universal Profile) rides on, so this is edgeport's RCS-family client - but
it targets **open SIP infrastructure** (Asterisk, FreeSWITCH, Kamailio, OpenSIPS, and cloud SIP
trunks like Twilio / Telnyx / Flowroute), not carrier RCS.

> [!NOTE]
> This is a signaling + messaging client. It does not carry voice/video media (RTP/SRTP is UDP,
> which Workers cannot open), and it does not reach carrier-RCS handsets - that path is gated
> behind IMS/SIM provisioning, and for businesses it is an HTTPS REST API (Google Jibe /
> aggregators), which a Worker already calls with `fetch`. TLS is implicit-only
> (`tls: 'implicit'`); SIP has no in-band STARTTLS.

### One-shot Message

A single `MESSAGE` needs no registration - the server challenges it, edgeport authenticates,
and the proxy routes it - so it fits a normal request-scoped Worker.

```typescript
import { sendMessage } from 'edgeport/sip';

await sendMessage({
	hostname: 'sip.example.com',
	username: 'alice',
	password: env.SIP_PW,
	to: 'bob',
	text: 'hello over SIP'
});
```

### Register and Receive

To receive inbound messages, REGISTER with RFC 5626 "outbound", which lets a listen-less Worker
receive requests on its own connection (the same trick SMPP `deliver_sm` uses). Hold the session
in a Durable Object to keep the registration open: an open socket keeps a DO alive up to ~15
minutes, and the session refreshes REGISTER on its own; reconnect on a DO alarm.

```typescript
import { connect } from 'edgeport/sip';

await using ua = await connect({
	hostname: 'sip.example.com',
	username: 'alice',
	password: env.SIP_PW
});
await ua.register();
await ua.message('bob', 'hi bob');
for await (const m of ua.messages()) {
	console.log('from', m.from, m.text());
}
```

### Capabilities and Presence

```typescript
const caps = await ua.options('bob'); // { status, allow: [...], accept: [...] }

await using sub = await ua.subscribePresence('bob');
for await (const note of sub) {
	console.log(note.state, note.text()); // Subscription-State + PIDF XML
}
```

### MSRP Chat (session mode)

`invite()` offers an MSRP message session and, on answer, opens the chat over MSRP (RFC 4975);
the Worker is always the active side and dials the peer's MSRP path.

```typescript
await using chat = await ua.invite('bob');
await chat.send('rich chat over MSRP');
for await (const m of chat.messages()) console.log(m.text());
```

Digest auth (RFC 2617 / 7616) is handled transparently, including the MD5 that Workers WebCrypto
lacks - assembled and KAT-verified in the module, the same way SSH assembles ChaCha.

## DNS

Resolve DNS over TCP (RFC 1035 + RFC 7766) from a Worker. Three levels: one-shot `resolve`
helpers, a reusable session that pipelines queries over one connection, and a raw query that
returns the full message (answer, authority, and additional sections) for tooling.

> [!IMPORTANT]
> The default resolver is `1.1.1.1` (`RESOLVERS.cloudflare`) to match ecosystem expectations,
> but a Worker's outbound TCP to Cloudflare IP ranges - which include `1.1.1.1` - is blocked by
> the runtime. **Inside a Worker, pass a non-Cloudflare resolver** (`RESOLVERS.google` /
> `RESOLVERS.quad9`). UDP is impossible on Workers, so this is DNS-over-TCP only; DNS-over-TLS is
> available with `tls: 'implicit'` (port 853).

```typescript
import { resolve, resolve4, resolveMx, reverse, RESOLVERS } from 'edgeport/dns';

const ips = await resolve4('example.com', { server: RESOLVERS.google }); // string[]
const mx = await resolveMx('example.com', { server: RESOLVERS.google }); // MxRecord[]
const names = await reverse('8.8.8.8', { server: RESOLVERS.google }); // ['dns.google']

// the overloaded resolve() narrows its return on the record type
const aaaa = await resolve('example.com', { type: 'AAAA', server: RESOLVERS.quad9 }); // string[]
```

### Session (Pipelined Queries)

```typescript
import { connect, RESOLVERS } from 'edgeport/dns';

await using dns = await connect({ hostname: RESOLVERS.google });
const [a, mx, txt] = await Promise.all([
	dns.query('example.com', 'A'),
	dns.query('example.com', 'MX'),
	dns.query('example.com', 'TXT')
]);
```

### Raw Query (Full Message)

```typescript
import { query, RESOLVERS } from 'edgeport/dns';

const res = await query(
	{ questions: [{ name: 'example.com', type: 'A' }], dnssec: true },
	{ hostname: RESOLVERS.quad9 }
);
console.log(res.rcode, res.answers, res.authority, res.additional);
```

`NXDOMAIN` and "no records" return an empty array (never a throw); a server error rcode
(`SERVFAIL`, `REFUSED`, ...) throws a `ProtocolError`. The raw `query` exposes the rcode instead
of throwing.

## XMPP

XMPP (RFC 6120 / 6121 + XEP-0060 pubsub/PEP) over the raw-TCP core. A concept-based API - you
never touch raw XML, but an escape hatch is there when you need it. Port 5222 (plaintext /
STARTTLS), 5223 (implicit TLS). SASL PLAIN and SCRAM-SHA-1/256; the strongest mechanism the
server offers is chosen.

```typescript
import { connect, el, text } from 'edgeport/xmpp';

await using xmpp = await connect({
	jid: 'juliet@example.com',
	password: env.XMPP_PW,
	tls: 'starttls' // 'off' | 'starttls' (default) | 'implicit'
});

// presence: friendly states map to XMPP (online, away, busy=dnd, xa, invisible, offline)
await xmpp.setPresence('online', { status: 'at the balcony' });

// send + receive chat
await xmpp.send({ to: 'romeo@example.com', body: 'wherefore art thou' });
for await (const msg of xmpp.messages()) {
	console.log(msg.from, msg.body);
	break;
}

// roster
await xmpp.addRosterItem('romeo@example.com', { name: 'Romeo', groups: ['Montague'] });
for (const item of await xmpp.roster()) console.log(item.jid, item.subscription, item.groups);
```

### PubSub

```typescript
import { connect, el, text } from 'edgeport/xmpp';

await using xmpp = await connect({ jid: 'sensor@example.com', password: env.XMPP_PW });

// create a node on a pubsub component, subscribe, publish, receive the event
await xmpp.createNode('pubsub.example.com', 'sensors/temp');
await xmpp.subscribeNode('pubsub.example.com', 'sensors/temp');
const events = xmpp.pubsub()[Symbol.asyncIterator]();
await xmpp.publish('sensors/temp', el('reading', { xmlns: 'urn:example' }, '21.5'), {
	service: 'pubsub.example.com'
});
const { payload } = (await events.next()).value;
console.log(text(payload!)); // '21.5'

// PEP (publish to your own account): omit the service
await xmpp.publish(
	'urn:xmpp:avatar:metadata',
	el('metadata', { xmlns: 'urn:xmpp:avatar:metadata' })
);
```

### Raw Stanzas

```typescript
await xmpp.sendXML("<presence type='unavailable'/>");
const version = await xmpp.iq('get', el('query', { xmlns: 'jabber:iq:version' }), {
	to: 'example.com'
});
```

A long-lived session (to receive inbound stanzas) belongs in a Durable Object - an open socket
keeps a DO alive up to ~15 min. For fire-once sends, `sendChat` binds, sends, and closes:

```typescript
import { sendChat } from 'edgeport/xmpp';

await sendChat({
	jid: 'bot@example.com',
	password: env.XMPP_PW,
	to: 'ops@example.com',
	body: 'deploy finished'
});
```

## IRC

RFC 1459 / 2812 with IRCv3 extensions (CAP negotiation, SASL, message-tags, server-time).
Plaintext 6667 or implicit TLS 6697.

```typescript
import { connect } from 'edgeport/irc';

await using irc = await connect({ hostname: 'irc.example.com', nick: 'edgebot' });

await irc.join('#edgeport');
await irc.say('#edgeport', 'hello from the edge');
await irc.action('#edgeport', 'waves'); // CTCP ACTION (/me)

for await (const m of irc.messages()) {
	if (m.isChannel) console.log(`<${m.from}> ${m.text}`);
	if (m.ctcp?.command === 'ACTION') console.log(`* ${m.from} ${m.ctcp.args}`);
	break;
}
```

### SASL

Pass `sasl` to run the IRCv3 CAP + SASL PLAIN exchange before registration (only the caps the
server offers are requested):

```typescript
await using irc = await connect({
	hostname: 'irc.example.com',
	nick: 'edgebot',
	sasl: { user: 'edgeacct', password: env.IRC_PASSWORD },
	caps: ['message-tags', 'server-time'] // extra caps to request alongside sasl
});
```

### Events, Names, Topic, WHOIS

`messages()` carries PRIVMSG/NOTICE (with CTCP parsed); everything else - JOIN/PART/QUIT/NICK/
KICK/MODE/TOPIC and numerics - flows through `events()`. Server `PING`s are answered automatically.

```typescript
for await (const ev of irc.events()) {
	if (ev.command === 'JOIN') console.log(`${ev.prefix?.nick} joined ${ev.params[0]}`);
}

const members = await irc.names('#edgeport'); // string[], membership prefixes stripped
await irc.topic('#edgeport', 'welcome'); // set
const current = await irc.topic('#edgeport'); // get
const who = await irc.whois('alice');
await irc.changeNick('edgebot2'); // resolves once the server echoes the NICK
```

### Raw Commands

`send(command, ...params)` applies the trailing-parameter rule to the last argument;
`sendRaw(line)` is the verbatim escape hatch.

```typescript
await irc.send('MODE', '#edgeport', '+o', 'alice'); // MODE #edgeport +o alice
await irc.sendRaw('WHO #edgeport');
```

## Utilities

`edgeport/util` is a small set of transport-free helpers the protocol modules share, published
for consumers too. Importing it never pulls in `cloudflare:sockets`.

| Helper                                     | Purpose                                                               |
| ------------------------------------------ | --------------------------------------------------------------------- |
| `toHex` / `fromHex`                        | Bytes <-> lowercase hex.                                              |
| `toBase64` / `fromBase64`                  | Bytes <-> base64 (standard or URL-safe; tolerant decode).             |
| `fromUtf8` / `toUtf8`                      | String <-> UTF-8 bytes (no more `new TextEncoder()`).                 |
| `encodeJson` / `decodeJson`                | Value <-> UTF-8 JSON bytes (tolerant parse to a `ProtocolError`).     |
| `randomHex` / `randomId`                   | CSPRNG-backed random hex tokens and prefixed ids.                     |
| `retry`                                    | Run an operation with exponential backoff, retrying transient errors. |
| `parseEmailAddress` / `formatEmailAddress` | Parse and format `Display Name <local@domain>`.                       |
| `withTimeout`                              | Race a promise against a deadline; rejects with `TimeoutError`.       |

```typescript
import {
	toBase64,
	fromUtf8,
	encodeJson,
	randomId,
	retry,
	parseEmailAddress,
	withTimeout
} from 'edgeport/util';

toBase64(bytes, { urlSafe: true }); // url-safe, unpadded
randomId('worker'); // 'worker-3f9a...'

fromUtf8('hi'); // UTF-8 bytes; toUtf8(bytes) decodes back - no TextEncoder/Decoder needed
encodeJson({ ok: true }); // bytes of '{"ok":true}'; decodeJson(bytes) parses it back

parseEmailAddress('Ada Lovelace <ada@example.com>');
// { name: 'Ada Lovelace', address: 'ada@example.com', local: 'ada', domain: 'example.com' }

const res = await withTimeout(fetch('https://example.com'), 5000, 'fetch');

// retry only transient ConnectionError / TimeoutError - never AuthError / ProtocolError
import { connect } from 'edgeport/ssh';
const ssh = await retry(() => connect({ hostname: 'box', username: 'u', password: env.PW }), {
	attempts: 4
});
```

The SSH module also gains `fingerprint(key)`, turning the raw key bytes a `HostKeyVerifier`
receives into the `SHA256:...` form `ssh-keygen -l` prints, for trust-on-first-use pinning.

## Real-World Recipes

> [!NOTE]
> For larger **multi-protocol** workflows - mail automation, secure deploy/ops, an HL7
> integration engine, device fleet management, resilience/recovery, and more - see
> [ADVANCED_USAGE.md](./ADVANCED_USAGE.md), each backed by an end-to-end integration test in
> [`test/integration/recipes/`](./test/integration/recipes/).

### A cron Worker that runs a Remote Command

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

### Email an Alert on a Webhook

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

### Poll a Mailbox and Archive Attachments to SFTP

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

### Run a Remote Command and Publish the Result to NATS

```typescript
import { connect as sshConnect } from 'edgeport/ssh';
import { connect as natsConnect } from 'edgeport/nats';

await using ssh = await sshConnect({
	hostname: env.BOX,
	username: 'deploy',
	privateKey: { pem: env.SSH_KEY }
});
const disk = await ssh.df('/'); // parsed rows: { filesystem, sizeKb, usedKb, availKb, ... }
await using nc = await natsConnect({ hostname: env.NATS, token: env.NATS_TOKEN });
await nc.publishJson('telemetry.disk', disk); // JSON-encodes the structured usage
```

### Bridge MQTT Sensor Readings to Syslog (edge observability)

```typescript
import { connect as mqttConnect } from 'edgeport/mqtt';
import { connect as syslogConnect, Severity } from 'edgeport/syslog';

await using mqtt = await mqttConnect({ hostname: env.BROKER, clientId: 'edge-bridge' });
await using log = await syslogConnect({
	hostname: env.SIEM,
	port: 6514,
	tls: 'implicit',
	appName: 'sensors'
});

for await (const reading of mqtt.subscribe('sensors/#', { qos: 1 })) {
	await log.log({
		severity: Severity.info,
		message: `${reading.topic}=${reading.text()}`
	});
}
```

### Authorize an Action via LDAP, then Alert over STOMP

```typescript
import { connect as ldapConnect } from 'edgeport/ldaps';
import { eq } from 'edgeport/ldap';
import { connect as stompConnect } from 'edgeport/stomp';

await using dir = await ldapConnect({
	hostname: env.LDAP,
	bindDN: env.SVC_DN,
	password: env.SVC_PW
});
// eq() carries the value literally, so an untrusted uid can't inject filter syntax
const allowed = await dir.search({ base: 'ou=people,dc=example,dc=org', filter: eq('uid', uid) });

if (allowed.length === 0) {
	await using mq = await stompConnect({
		hostname: env.MQ,
		login: env.MQ_USER,
		passcode: env.MQ_PW
	});
	await mq.send('/queue/security.alerts', `unauthorized action by ${uid}`);
}
```

### Pull a File over FTP and Republish to MQTT

```typescript
import { getFile } from 'edgeport/ftp';
import { connect as mqttConnect } from 'edgeport/mqtt';

const csv = await getFile({
	hostname: env.FTP,
	username: env.U,
	password: env.P,
	path: '/exports/prices.csv'
});
await using mqtt = await mqttConnect({ hostname: env.BROKER, clientId: 'price-feed' });
await mqtt.publish('feeds/prices', csv, { qos: 1, retain: true });
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
- **No agent forwarding or X11.** Local port forwarding is supported via `forwardOut`
  (`direct-tcpip` reach-through); SOCKS (`-D`) and remote (`-R`) forwarding are out of scope
  because Workers cannot accept inbound connections.
- **Encrypted private keys**: encrypted PKCS#8 (PBES2) and OpenSSH-format keys are
  supported; legacy `DEK-Info` PEM and `aes-gcm`/`chacha20-poly1305` OpenSSH key ciphers
  are not (re-encrypt with `aes256-ctr`).
- **Time-based rekey** is not triggered (byte-volume and server-initiated rekeys are).
- **FTPS is not provided.** The Workers `startTls` API exposes no TLS session export/import,
  so the FTPS data connection cannot resume the control channel's TLS session - which strict
  servers (e.g. vsftpd `require_ssl_reuse=YES`) mandate. Shipping it would only work against
  servers that disable that protection, so plain `edgeport/ftp` is provided and FTPS is
  deferred until the runtime gains TLS session control.
- **FTP is passive-mode only** (Workers cannot accept the inbound connections active mode needs).
- **LDAP SASL** is not implemented (simple bind over TLS is). The one mechanism that would add
  capability over simple bind, SASL EXTERNAL, needs a TLS client certificate, which the Workers
  socket API cannot present; PLAIN is equivalent to simple bind, and SCRAM/DIGEST/GSSAPI are
  rarely required. NATS auth is fully covered (token / user-pass / nkey / JWT); NATS does not
  use SASL. MQTT/STOMP/Syslog authenticate via TLS + username-password.
- **DNS is TCP-only, and `1.1.1.1` is unreachable from a Worker.** Workers cannot open UDP, so
  `edgeport/dns` speaks DNS-over-TCP (RFC 7766); DNS-over-TLS works via `tls: 'implicit'`. The
  default resolver `1.1.1.1` is a Cloudflare IP, which the runtime blocks outbound - pass
  `RESOLVERS.google` / `RESOLVERS.quad9` from inside a Worker.
- **XMPP and IRC over TLS are proven only against a real trusted-cert server.** workerd validates
  certificates, so the self-signed docker servers exercise the plaintext path end-to-end while
  STARTTLS / implicit-TLS for both is unit-tested; both connect fine to a public TLS server.

## Advanced: Building-Block Exports

Beyond the protocol modules, edgeport publishes the low-level transport core and the SSH
building blocks it is assembled from, for tooling that needs them directly:

| Import            | Provides                                                                                                                                                                                                                           |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `edgeport/core`   | The raw framed TCP transport (`connect`, `CoreSocket`, `FramedReader` / `FramedWriter`, `startTls`) plus the shared error vocabulary - to speak a protocol edgeport does not ship on the same buffered transport the built-ins use |
| `edgeport/wire`   | SSH binary wire codecs (`SshReader`, `SshWriter`, `toMpintBody`)                                                                                                                                                                   |
| `edgeport/crypto` | hashes/HMAC, the SSH packet ciphers (`createPacketCipher`, `cipherSizes`), host/user keys (`verifyHostSignature`, `loadUserKey`)                                                                                                   |
| `edgeport/kex`    | KEXINIT negotiation, the exchange hash + key schedule, `createKex`, and the `curve25519`/`nistp256` namespaces                                                                                                                     |
| `edgeport/auth`   | SSH user authentication (`authenticate`)                                                                                                                                                                                           |

```typescript
import { connect } from 'edgeport/core';
import { SshReader, SshWriter } from 'edgeport/wire';
import { createPacketCipher, verifyHostSignature } from 'edgeport/crypto';
import { negotiate, createKex } from 'edgeport/kex';

// a raw framed TCP client for a protocol edgeport does not ship (finger, RFC 1288)
await using sock = await connect({ hostname: 'example.com', port: 79 });
await sock.writer.writeLine('');
const line = await sock.reader.readLine();
```

These are stable but lower-level; most applications only need the protocol modules above.
`edgeport/core` is the one module that imports `cloudflare:sockets` - every protocol is built on it.

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

## License

MIT (c) Gregory Mitchell 2026. See [LICENSE](./LICENSE) file for details.
