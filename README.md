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
  OpenLDAP, an FTP server, and a WebSocket echo server) - not mocks.

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
	hostKey: {
		verify: (type, key) => type === 'ssh-ed25519' /* && key matches your pinned host key */
	}
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
const first = await pop.retrieve(1);
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

## NATS

```typescript
import { connect } from 'edgeport/nats';

await using nc = await connect({ hostname: 'nats.example.com', token: env.NATS_TOKEN });

// pub/sub
const sub = nc.subscribe('orders.*', { queue: 'workers' });
await nc.publish('orders.created', JSON.stringify({ id: 42 }));
for await (const msg of sub) {
	const order = JSON.parse(new TextDecoder().decode(msg.data));
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
	const order = JSON.parse(new TextDecoder().decode(msg.data));
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
for await (const m of sub) console.log(m.topic, new TextDecoder().decode(m.payload));

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
	console.log(m.topic, new TextDecoder().decode(m.payload));
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

## FTP

Plaintext FTP, passive mode (Workers cannot accept the inbound connections active mode needs).

```typescript
import { connect, getFile, putFile } from 'edgeport/ftp';

await using ftp = await connect({
	hostname: 'files.example.com',
	username: 'u',
	password: env.FTP_PW
});
await ftp.put('reports/today.csv', new TextEncoder().encode('a,b,c\n'));
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
import { exec } from 'edgeport/ssh';
import { connect as natsConnect } from 'edgeport/nats';

const { stdout } = await exec({
	hostname: env.BOX,
	username: 'deploy',
	privateKey: { pem: env.SSH_KEY },
	command: 'df -h /'
});
await using nc = await natsConnect({ hostname: env.NATS, token: env.NATS_TOKEN });
await nc.publish('telemetry.disk', stdout);
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
		message: `${reading.topic}=${new TextDecoder().decode(reading.payload)}`
	});
}
```

### Authorize an Action via LDAP, then Alert over STOMP

```typescript
import { connect as ldapConnect } from 'edgeport/ldaps';
import { connect as stompConnect } from 'edgeport/stomp';

await using dir = await ldapConnect({
	hostname: env.LDAP,
	bindDN: env.SVC_DN,
	password: env.SVC_PW
});
const allowed = await dir.search({ base: 'ou=people,dc=example,dc=org', filter: `(uid=${uid})` });

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

## License

MIT (c) Gregory Mitchell 2026. See [LICENSE](./LICENSE) file for details.
