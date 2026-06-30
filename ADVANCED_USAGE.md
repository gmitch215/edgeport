# Advanced Usage: Cross-Protocol Recipes

edgeport's protocols are designed to compose. This document walks through realistic,
multi-protocol workflows - the kind of "interface engine" / "edge ops" wiring that real
deployments need - with a runnable code sketch for each, and points at the integration test
that exercises it end-to-end against real servers under `workerd`.

Every recipe below has a corresponding spec in [`test/integration/recipes/`](./test/integration/recipes/)
that runs against the Dockerized servers in [`docker/compose.yml`](./docker/compose.yml).
Run them with:

```sh
docker compose -f docker/compose.yml up -d --wait
INTEGRATION=1 bunx vitest run test/integration/recipes
docker compose -f docker/compose.yml down -v
```

A shared helper, [`test/integration/recipes/_helpers.ts`](./test/integration/recipes/_helpers.ts),
provides `readSyslog()` (reads back what was sent to the syslog sink so logging can be
asserted), `artifact(n)` (a deterministic binary blob for transfer tests), `uniqueId()`,
and `waitFor()`.

> The snippets below are application-level sketches using the public API (env vars stand in
> for config). The linked spec is the exact, asserted version that runs in CI.

## Environment & Services

Every recipe reads its configuration from `env` (Worker [secrets/vars](https://developers.cloudflare.com/workers/configuration/secrets/) -
set with `wrangler secret put NAME` or in `wrangler.jsonc` `vars`). Each recipe lists the
exact variables it needs under **Prerequisites**; this is the catalog of what they are, what
the values look like, and where they come from.

| Variable                                 | Service / what it is                                 | Example value                                            | How to get it                                                                  |
| ---------------------------------------- | ---------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `BOX` / `deviceHost`                     | SSH/SFTP host (your server, bastion, or edge device) | `ssh.example.com` or `10.0.0.7`                          | the hostname/IP of a box you can reach on port 22                              |
| `SSH_KEY`                                | SSH private key (PKCS#8 or OpenSSH PEM)              | `-----BEGIN PRIVATE KEY-----\n...`                       | `ssh-keygen -t ed25519`; install the `.pub` in the box's `authorized_keys`     |
| `SSH_KEY_PASSPHRASE`                     | passphrase for an encrypted private key              | `correct horse battery staple`                           | whatever you set at `ssh-keygen` time                                          |
| `MAIL` / `SMTP` / `SMTP_HOST`            | SMTP (and IMAP/POP3) server host                     | `smtp.example.com` or `smtp.mx.cloudflare.net`           | your mail provider, or Cloudflare Email Service (see below)                    |
| `MAIL_USER` / `SMTP_USER`                | SMTP/IMAP/POP3 login                                 | `postmaster@example.com` (or literal `api_token` for CF) | provider mailbox; for CF Email Service the username is the literal `api_token` |
| `MAIL_PW` / `SMTP_PW` / `CF_EMAIL_TOKEN` | mailbox password or API token                        | a password, or `v1.0-abc...` token                       | provider; for CF, an API token with **Email Sending: Edit**                    |
| `ONCALL` / `OPS` / `STAKEHOLDERS`        | recipient email address(es)                          | `oncall@example.com`                                     | your distribution list                                                         |
| `LDAP`                                   | LDAP/LDAPS directory host                            | `ldap.example.com`                                       | your directory server (389 plaintext/StartTLS, 636 LDAPS)                      |
| `SVC_DN` / `SVC_PW`                      | service bind DN + password                           | `cn=svc,dc=example,dc=org` / a password                  | create a bind account in your directory                                        |
| `NATS`                                   | NATS server host                                     | `nats.example.com` or `connect.ngs.global`               | self-hosted NATS, or Synadia Cloud (NGS)                                       |
| `NATS_TOKEN` / `NATS_CREDS`              | NATS auth token, or a `.creds` file's contents       | `s3cr3t-token`                                           | server config; NGS issues a `.creds` file                                      |
| `BROKER`                                 | MQTT broker host                                     | `broker.example.com`                                     | self-hosted Mosquitto/EMQX, or a cloud broker                                  |
| `MQTT_USER` / `MQTT_PASS`                | MQTT credentials (or omit for anonymous)             | `device` / a password                                    | broker config                                                                  |
| `MQ` / `MQ_USER` / `MQ_PASS`             | STOMP broker host + creds (ActiveMQ/RabbitMQ)        | `mq.example.com` / `admin` / `admin`                     | broker config                                                                  |
| `FTP` / `LANDING` / `DR`                 | FTP server host(s)                                   | `files.example.com`                                      | your FTP server (passive mode; ports 21 + a passive range)                     |
| `GW`                                     | WebSocket gateway host (for `wss://`)                | `gateway.example.com`                                    | your realtime/WS endpoint                                                      |
| `SIEM`                                   | syslog collector host (RFC 5424 over TLS)            | `logs.example.com`                                       | your SIEM/log aggregator (Datadog, Splunk, rsyslog, ...) listening on 6514     |

**Cloudflare Email Service (SMTP):** set `SMTP`/`MAIL` to `smtp.mx.cloudflare.net`, `tls: 'implicit'`
(port 465), the username to the literal string `api_token`, and the password to a Cloudflare API
token scoped **Email Sending: Edit**; the `from` domain must be onboarded to Email Sending. See
the [Cloudflare Email Service SMTP docs](https://developers.cloudflare.com/email-service/api/send-emails/smtp/).

## Recipe Index

| Recipe                                                          | Modules                                  | What it proves                                                   |
| --------------------------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------------- |
| [Mail Service Stack](#mail-service-stack)                       | SMTP + IMAP + POP3 + LDAP + Syslog       | LDAP recipient validation, cross-protocol consistency, audit     |
| [Secure Deploy/Ops](#secure-deployops)                          | SSH + SFTP                               | Exec, upload+resume, shell tail, clean disconnect                |
| [CI / Observability](#ci--observability)                        | Syslog + SMTP + IMAP                     | Structured logs -> error alert -> verified email                 |
| [Realtime Chat](#realtime-chat)                                 | WebSocket + NATS + LDAP + MQTT           | Auth, routing, presence, reconnect/ordering                      |
| [Resilience & Recovery](#resilience--recovery)                  | NATS (JetStream) + MQTT + Syslog         | Durable continuity, persistent-session drain                     |
| [Device Fleet Management](#device-fleet-management)             | SSH + SFTP + MQTT + Syslog               | Telemetry, LWT offline, firmware push+resume                     |
| [HL7 Integration Engine](#hl7-integration-engine)               | FTP + SFTP + MQTT + STOMP + Syslog       | Parse, fan-out, ack semantics, audit                             |
| [Mainframe Nightly Batch](#mainframe-nightly-batch)             | FTP + SFTP + Syslog + SMTP               | Insecure-inside / secure-outside transfer                        |
| [Passive-FTP Monitoring](#passive-ftp-monitoring)               | FTP + Syslog + SMTP                      | PASV/EPSV, port pressure, failure alerting                       |
| [Scheduled Reports](#scheduled-reports)                         | SSH + SFTP + SMTP + Syslog               | Exec job, checksum, email attachment, failure alert              |
| [Transactional Messaging](#transactional-messaging)             | STOMP + MQTT + NATS + Syslog             | STOMP commit/abort, ack modes, cross-broker bridge               |
| [Centralized Authentication](#centralized-authentication)       | LDAP + SSH + SFTP + Syslog               | LDAP bind + group gate for SSH/SFTP, audit                       |
| [Notification Fan-Out](#notification-fan-out)                   | NATS + WebSocket + MQTT + STOMP + Syslog | One event -> three transports, ordering, slow-consumer isolation |
| [Credential-Protecting Gateway](#credential-protecting-gateway) | LDAPS + SSH + SFTP + Syslog              | LDAPS fail-closed, no downgrade, server-identity gate            |
| [Certificate Lifecycle](#certificate-lifecycle)                 | LDAPS + Syslog + SMTP                    | Cert validation fails closed -> alert + audit                    |

---

## Mail Service Stack

**Modules:** SMTP + IMAP + POP3 + LDAP + Syslog: [`mail.spec.ts`](./test/integration/recipes/mail.spec.ts)

### Prerequisites

- **Mail server** `MAIL` + `MAIL_USER`/`MAIL_PW`: a host speaking SMTP+IMAP+POP3 (a mailbox provider, or `smtp.mx.cloudflare.net` via the Cloudflare Email Service).
- **Directory** `LDAP` + `SVC_DN`/`SVC_PW`: for recipient validation (e.g. `cn=svc,dc=example,dc=org`).
- **Syslog collector** `SIEM`: for the audit trail.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

A complete mail server: recipients are validated against LDAP before send, mail is submitted
via SMTP and read back via both IMAP (multi-device) and POP3 (download), cross-protocol
mailbox consistency holds (a POP3 read without delete leaves the IMAP view intact), and every
transaction is audited to Syslog. An unknown recipient is rejected at the directory gate.

```typescript
import { send } from 'edgeport/smtp';
import { connect as imapConnect } from 'edgeport/imap';
import { search as ldapSearch, eq } from 'edgeport/ldap';
import { connect as syslogConnect } from 'edgeport/syslog';

const auth = { username: env.MAIL_USER, password: env.MAIL_PW };
await using audit = await syslogConnect({
	hostname: env.SIEM,
	port: 6514,
	tls: 'implicit',
	appName: 'mta'
});

// 1. validate the recipient against the directory (reject unknown addresses).
// eq() carries the address literally, so an untrusted recipient can't inject filter syntax
const found = await ldapSearch({
	hostname: env.LDAP,
	bindDN: env.SVC_DN,
	password: env.SVC_PW,
	base: 'ou=people,dc=example,dc=org',
	filter: eq('mail', recipient)
});
if (found.length === 0) {
	await audit.warn(`rejected unknown recipient ${recipient}`);
	throw new Error('unknown recipient');
}

// 2. submit (tls:'off' for a trusted internal relay; or 587/STARTTLS, 465/implicit)
await send({
	hostname: env.MAIL,
	tls: 'off',
	auth,
	from: 'bot@example.org',
	to: recipient,
	subject: 'Hi',
	text: 'body'
});
await audit.info(`delivered to ${recipient}`);

// 3. the same message is visible via IMAP and POP3; a POP3 read (no DELE) doesn't disturb IMAP
await using imap = await imapConnect({ hostname: env.MAIL, tls: 'off', auth });
await imap.select('INBOX');
const uids = await imap.search({ subject: 'Hi' });
const messages = await imap.fetch(uids, { body: true });
```

**Use case:** a full mail-handling service with directory-validated recipients and a
compliance audit trail.

## Secure Deploy/Ops

**Modules:** SSH + SFTP, [`secure.spec.ts`](./test/integration/recipes/secure.spec.ts)

### Prerequisites

- **SSH host** `BOX` + **private key** `SSH_KEY`; a box reachable on port 22 with your public key in `authorized_keys`.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

A deploy/ops loop over one connection: read free space with the `df('/')` helper (parsed rows,
no text munging), upload a build artifact over an SFTP session **reused from the SSH connection**,
resume an interrupted upload with `writeFile(path, data, { offset })`, `chmod()` + restart, tail
logs over an interactive `shell()` channel, and verify a clean `await using` disconnect.

```typescript
import { connect as sshConnect } from 'edgeport/ssh';
import { connect as sftpConnect } from 'edgeport/sftp';

await using ssh = await sshConnect({
	hostname: env.BOX,
	username: 'deploy',
	privateKey: { pem: env.SSH_KEY }
});

// check disk before shipping (df() returns parsed rows, no text munging)
const [root] = await ssh.df('/'); // { filesystem, sizeKb, usedKb, availKb, usePercent, mountedOn }

// upload over a REUSED session, resuming if the first attempt was cut short
await using sftp = await sftpConnect({ session: ssh });
try {
	await sftp.writeFile('/srv/app.tar', artifact);
} catch {
	const { size } = await sftp.stat('/srv/app.tar'); // resume from the partial size
	await sftp.writeFile('/srv/app.tar', artifact.subarray(size), { offset: size });
}

// apply + restart, then tail the log over an interactive shell
await ssh.chmod('/srv/app.tar', 0o600);
await ssh.exec('systemctl restart app');
await using shell = await ssh.shell();
await shell.write(new TextEncoder().encode('tail -n 20 /var/log/app.log\n'));
for await (const chunk of shell.stdout) {
	console.log(new TextDecoder().decode(chunk));
	break;
}
// the `await using` scope closes both channels cleanly on exit
```

**Use case:** CI/CD deploy steps, remote maintenance, log inspection from a Worker.

## CI / Observability

**Modules:** Syslog + SMTP + IMAP, [`ci.spec.ts`](./test/integration/recipes/ci.spec.ts)

### Prerequisites

- **Syslog collector** `SIEM`: ingests the RFC 5424 logs (TLS on 6514).
- **SMTP + IMAP** `SMTP` + `SMTP_USER`/`SMTP_PW`, alerting to `ONCALL`: sends and verifies the alert email.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

A service emits high-volume RFC 5424 structured-data logs over Syslog; ingestion and the
structured-data wire format are verified; an error-severity event triggers an alert email
over SMTP, confirmed to land via IMAP. Ingestion + parsing + downstream notification together.

```typescript
import { connect as syslogConnect, Severity } from 'edgeport/syslog';
import { send } from 'edgeport/smtp';

await using log = await syslogConnect({
	hostname: env.SIEM,
	port: 6514,
	tls: 'implicit',
	appName: 'api'
});

for (const event of requestLog) {
	await log.log({
		severity: event.level,
		message: event.msg,
		structuredData: [{ id: 'req@1', params: { ms: String(event.ms), path: event.path } }]
	});

	// an error escalates to an alert email
	if (event.level === Severity.error) {
		await send({
			hostname: env.SMTP,
			port: 587,
			auth: { username: env.SMTP_USER, password: env.SMTP_PW },
			from: 'alerts@example.com',
			to: env.ONCALL,
			subject: `ALERT ${event.msg}`,
			text: event.detail
		});
	}
}
// an IMAP poll later confirms the alert was delivered (see the spec)
```

**Use case:** shipping Worker logs to a SIEM/collector and alerting on errors.

## Realtime Chat

**Modules:** WebSocket + NATS + LDAP + MQTT, [`chat.spec.ts`](./test/integration/recipes/chat.spec.ts)

### Prerequisites

- **Directory** `LDAP` (+ a user DN/password at runtime); the login gate.
- **NATS** `NATS` + `NATS_TOKEN`; message routing with queue groups.
- **MQTT broker** `BROKER`; presence via Last Will.
- **WebSocket gateway** `GW`; the client transport (`wss://`).

See [Environment & Services](#environment--services) for value formats and how to obtain each.

A realtime chat app with presence: authenticate with an LDAP bind, open a WebSocket carrying
a session token, route messages through NATS pub/sub with **queue groups** for multi-server
fan-out, and track presence with an MQTT **Last Will** that fires on an ungraceful disconnect.

```typescript
import { connect as ldapConnect } from 'edgeport/ldaps';
import { escapeDN } from 'edgeport/ldap';
import { connect as wsConnect } from 'edgeport/ws';
import { connect as natsConnect } from 'edgeport/nats';
import { connect as mqttConnect } from 'edgeport/mqtt';

// 1. authenticate the user (LDAP bind is the login gate; escapeDN guards the RDN value)
await using dir = await ldapConnect({
	hostname: env.LDAP,
	bindDN: `uid=${escapeDN(user)},ou=people,dc=example,dc=org`,
	password
});

// 2. presence via an MQTT last-will: if this client drops, the broker announces 'offline'
await using presence = await mqttConnect({
	hostname: env.BROKER,
	clientId: user,
	will: { topic: `presence/${user}`, payload: 'offline', qos: 1, retain: true }
});
await presence.publish(`presence/${user}`, 'online', { retain: true });

// 3. fan messages out across chat servers with a queue group (one server handles each)
await using nc = await natsConnect({ hostname: env.NATS, token: env.NATS_TOKEN });
const room = nc.subscribe('room.general', { queue: 'chat-servers' });

// 4. bridge the client's WebSocket into the bus
const ws = await wsConnect(`wss://${env.GW}/chat?token=${sessionToken}`);
for await (const frame of ws) {
	if (frame.type === 'text') await nc.publish('room.general', frame.data);
}
```

**Use case:** authenticated realtime messaging with horizontal fan-out and presence.

## Resilience & Recovery

**Modules:** NATS (JetStream) + MQTT + Syslog, [`recovery.spec.ts`](./test/integration/recipes/recovery.spec.ts)

### Prerequisites

- **NATS with JetStream** `NATS` + `NATS_TOKEN`; the server must be started with `-js`.
- **MQTT broker** `BROKER`; with persistence enabled for `cleanSession: false` drains.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

Resilience across the stack: NATS JetStream durable streams + consumers verify message
continuity (no loss / no duplication) across a client reconnect, and MQTT persistent sessions
(`cleanSession: false` + a fixed `clientId`) reconnect and **drain** QoS-1 messages queued
while the subscriber was offline.

```typescript
import { connect as mqttConnect } from 'edgeport/mqtt';
import { connect as natsConnect } from 'edgeport/nats';

// MQTT persistent session: messages published while we were gone are waiting on reconnect
await using sub = await mqttConnect({
	hostname: env.BROKER,
	clientId: 'ingest-1',
	cleanSession: false
});
for await (const m of sub.subscribe('ingest/#', { qos: 1 })) {
	// process m here; QoS-1 delivery survives a disconnect/reconnect
}

// NATS JetStream durable continuity is driven over core request-reply to $JS.API.*:
await using nc = await natsConnect({ hostname: env.NATS, token: env.NATS_TOKEN });
const enc = new TextEncoder();
await nc.request(
	'$JS.API.STREAM.CREATE.EVENTS',
	enc.encode(JSON.stringify({ name: 'EVENTS', subjects: ['events.>'] }))
);
await nc.publishJson('events.created', { id: 1 }); // acked + persisted by the stream
// a durable consumer replays un-acked messages after a reconnect - see the spec for the full dance
```

> Tests run under `workerd` and cannot restart Docker, so "failover" is modeled as a client
> reconnect rather than a server-node kill - the message-continuity guarantees are what matter
> and are fully asserted.

**Use case:** at-least-once pipelines that must survive disconnects without losing messages.

## Device Fleet Management

**Modules:** SSH + SFTP + MQTT + Syslog, [`recovery-agent.spec.ts`](./test/integration/recipes/recovery-agent.spec.ts)

### Prerequisites

- **MQTT broker** `BROKER`; device telemetry + Last Will.
- **SSH/SFTP host** `deviceHost` + **private key** `SSH_KEY`; the device the operator reaches.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

The IoT/edge ops loop: devices report telemetry over MQTT (QoS 1) with a **Last Will** for
offline detection; an operator SSHes in and pushes a firmware blob over SFTP with a SHA-256
checksum verified on the device and **resume-on-drop** via `{ offset }`; SSH exec applies and
restarts; the device's Syslog confirms.

```typescript
import { connect as mqttConnect } from 'edgeport/mqtt';
import { connect as sshConnect } from 'edgeport/ssh';
import { connect as sftpConnect } from 'edgeport/sftp';

// device side: telemetry + last-will so the fleet sees it drop
await using device = await mqttConnect({
	hostname: env.BROKER,
	clientId: deviceId,
	will: { topic: `devices/${deviceId}/status`, payload: 'offline', qos: 1 }
});
await device.publishJson(`devices/${deviceId}/telemetry`, { cpu: 0.31 }, { qos: 1 });

// operator side: push firmware, verify the checksum on the box, apply, restart
await using ssh = await sshConnect({
	hostname: deviceHost,
	username: 'ops',
	privateKey: { pem: env.SSH_KEY }
});
await using sftp = await sftpConnect({ session: ssh });
await sftp.writeFile('/tmp/fw.bin', firmware);

const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', firmware))]
	.map((b) => b.toString(16).padStart(2, '0'))
	.join('');
const { stdout } = await ssh.exec('sha256sum /tmp/fw.bin');
if (!stdout.includes(digest)) throw new Error('firmware checksum mismatch');
await ssh.exec('fwupdate /tmp/fw.bin && reboot');
```

**Use case:** remote device/firmware management and health monitoring.

## HL7 Integration Engine

**Modules:** FTP + SFTP + MQTT + STOMP + Syslog, [`healthcare.spec.ts`](./test/integration/recipes/healthcare.spec.ts)

### Prerequisites

- **FTP server** `FTP` (+ username/password at runtime); the lab drop zone.
- **MQTT broker** `BROKER` and **STOMP broker** `MQ` + `MQ_USER`/`MQ_PASS`; the two downstream consumers.
- **Syslog collector** `SIEM`; the audit trail.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

A healthcare interface engine (Mirth/Rhapsody-class): a lab drops an HL7 batch over FTP, the
engine parses it into messages/segments (MSH/PID) and republishes events to **two** downstream
consumers - MQTT and STOMP. The STOMP (EHR) subscriber uses `ack: 'client'`; an acked message
is not redelivered. Every stage writes an audited Syslog trail.

```typescript
import { getFile } from 'edgeport/ftp';
import { connect as mqttConnect } from 'edgeport/mqtt';
import { connect as stompConnect } from 'edgeport/stomp';
import { connect as syslogConnect } from 'edgeport/syslog';

// pick up the batch the lab dropped (plain FTP; FTPS is not supported - see note)
const batch = new TextDecoder().decode(
	await getFile({ hostname: env.FTP, username, password, path: '/in/lab.hl7' })
);
const messages = batch.split('\r\r'); // one HL7 message per block

await using mqtt = await mqttConnect({ hostname: env.BROKER, clientId: 'hl7-engine' });
await using mq = await stompConnect({ hostname: env.MQ, login: env.MQ_USER, passcode: env.MQ_PW });
await using audit = await syslogConnect({
	hostname: env.SIEM,
	port: 6514,
	tls: 'implicit',
	appName: 'hl7'
});

for (const hl7 of messages) {
	const pid = hl7.split('\r').find((s) => s.startsWith('PID'));
	await mqtt.publish('hl7/adt', hl7, { qos: 1 }); // downstream consumer A
	await mq.send('/queue/hl7.ehr', hl7); // downstream consumer B (acks delivery)
	await audit.info(`routed ${pid}`);
}

// the EHR side acks what it has durably stored:
const ehr = mq.subscribe('/queue/hl7.ehr', { ack: 'client' });
for await (const m of ehr) {
	// persist m.body (the EHR write) here
	await m.ack?.();
}
```

> The recipe calls for FTPS; edgeport doesn't provide FTPS (Workers `startTls` can't reuse the
> control channel's TLS session), so plain `edgeport/ftp` is used - noted in the spec.

**Use case:** transactional message routing with delivery acks and a full audit trail.

## Mainframe Nightly Batch

**Modules:** FTP + SFTP + Syslog + SMTP, [`mainframe.spec.ts`](./test/integration/recipes/mainframe.spec.ts)

### Prerequisites

- **Landing FTP** `LANDING` and **secure SFTP** `DR` (+ username/password at runtime); the insecure-in / secure-out legs.
- **Syslog collector** `SIEM` and **SMTP** `SMTP` + `SMTP_USER`/`SMTP_PW` to `OPS`; per-leg audit + the job-summary email.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

The classic "insecure-inside, secure-outside" hybrid: a legacy system pushes fixed-width,
CRLF-terminated records over **plain FTP** into a landing zone; a transfer agent re-sends them
**securely over SFTP** (with resume-on-interruption); each leg emits Syslog; a job-summary
email goes out over SMTP at the end.

```typescript
import { connect as ftpConnect } from 'edgeport/ftp';
import { connect as sftpConnect } from 'edgeport/sftp';
import { connect as syslogConnect } from 'edgeport/syslog';
import { send } from 'edgeport/smtp';

await using audit = await syslogConnect({
	hostname: env.SIEM,
	port: 6514,
	tls: 'implicit',
	appName: 'erp-batch'
});

// 1. pull the fixed-width file the mainframe dropped over plain FTP
await using ftp = await ftpConnect({ hostname: env.LANDING, username, password });
const file = await ftp.get('NIGHTLY.DAT');
await audit.info('landed NIGHTLY.DAT');

// 2. forward it securely over SFTP (byte-exact; resumes if interrupted)
await using sftp = await sftpConnect({ hostname: env.DR, username, password });
await sftp.writeFile('/incoming/nightly.dat', file);
await audit.info('forwarded NIGHTLY.DAT');

// 3. job-summary email
await send({
	hostname: env.SMTP,
	port: 587,
	auth: { username: env.SMTP_USER, password: env.SMTP_PW },
	from: 'batch@example.com',
	to: env.OPS,
	subject: 'nightly batch complete',
	text: `${file.length} bytes transferred`
});
```

> The recipe calls for active-mode + ASCII (TYPE A) FTP; edgeport FTP is passive-only (Workers
> can't accept inbound connections) and byte-verbatim, so passive mode is used and ASCII
> correctness is proven by round-tripping CRLF records byte-exact - noted in the spec.

**Use case:** legacy ERP/mainframe file exchange bridged to modern secure transfer.

## Passive-FTP Monitoring

**Modules:** FTP + Syslog + SMTP, [`monitoring.spec.ts`](./test/integration/recipes/monitoring.spec.ts)

### Prerequisites

- **FTP server** `FTP` (+ username/password at runtime); passive mode, ports 21 + a passive range.
- **Syslog collector** `SIEM` and **SMTP** `SMTP` + `SMTP_USER`/`SMTP_PW` to `ONCALL`; failure audit + alert.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

The parts of passive FTP that actually break in production: EPSV-first/PASV-fallback
negotiation, passive-port-range pressure (sequential transfers forcing port reuse),
control-connection survival during a large transfer, and failure handling - a failed transfer
is caught, logged to Syslog, and alerted over SMTP.

```typescript
import { connect as ftpConnect } from 'edgeport/ftp';
import { connect as syslogConnect, Severity } from 'edgeport/syslog';
import { send } from 'edgeport/smtp';

await using audit = await syslogConnect({
	hostname: env.SIEM,
	port: 6514,
	tls: 'implicit',
	appName: 'ftp-mon'
});
await using ftp = await ftpConnect({ hostname: env.FTP, username, password }); // EPSV-first, PASV fallback

try {
	const data = await ftp.get('exports/large.csv');
	await audit.info(`transfer ok ${data.length}b`);
	await ftp.list('exports'); // control connection still healthy after a large data transfer
} catch (err) {
	// the data channel stalled/failed - log it and page on-call
	await audit.log({ severity: Severity.alert, message: `FTP transfer failed: ${err}` });
	await send({
		hostname: env.SMTP,
		port: 587,
		auth: { username: env.SMTP_USER, password: env.SMTP_PW },
		from: 'mon@example.com',
		to: env.ONCALL,
		subject: 'FTP transfer failed',
		text: String(err)
	});
}
```

Resume uses real RFC 959 `REST` offset resume - `put(path, rest, { append: true })` to
continue an upload and `get(path, { offset })` to fetch just the tail.

**Use case:** monitoring and alerting for passive-FTP-behind-NAT deployments.

## Scheduled Reports

**Modules:** SSH + SFTP + SMTP + Syslog, [`report.spec.ts`](./test/integration/recipes/report.spec.ts)

### Prerequisites

- **SSH/SFTP host** `BOX` + **private key** `SSH_KEY`; runs and serves the report.
- **SMTP** `SMTP` to `ONCALL`/`STAKEHOLDERS`; distributes the report (attachment) and failure alerts.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

The classic reporting cron: a scheduler SSHes into a host to run a report job, pulls the
output over SFTP with a SHA-256 integrity check, emails it to stakeholders as a MIME
attachment, logs the run to Syslog, and alerts on failure.

```typescript
import { connect as sshConnect } from 'edgeport/ssh';
import { connect as sftpConnect } from 'edgeport/sftp';
import { send } from 'edgeport/smtp';

await using ssh = await sshConnect({
	hostname: env.BOX,
	username: 'reports',
	privateKey: { pem: env.SSH_KEY }
});
const { code } = await ssh.exec('generate-daily-report > /var/reports/today.csv');
if (code !== 0) {
	await send({
		hostname: env.SMTP,
		tls: 'off',
		from: 'cron@x',
		to: env.ONCALL,
		subject: 'report FAILED',
		text: 'job exited nonzero'
	});
	throw new Error('report job failed');
}

// pull + verify integrity
await using sftp = await sftpConnect({ session: ssh });
const csv = await sftp.readFile('/var/reports/today.csv');
const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', csv))]
	.map((b) => b.toString(16).padStart(2, '0'))
	.join('');
if (!(await ssh.exec('sha256sum /var/reports/today.csv')).stdout.includes(digest))
	throw new Error('checksum mismatch');

// distribute as an attachment
await send({
	hostname: env.SMTP,
	tls: 'off',
	from: 'cron@x',
	to: env.STAKEHOLDERS,
	subject: 'Daily report',
	text: 'Attached.',
	attachments: [{ filename: 'today.csv', content: csv, contentType: 'text/csv' }]
});
```

**Use case:** ops/reporting cron jobs that generate, fetch, and distribute artifacts.

## Transactional Messaging

**Modules:** STOMP + MQTT + NATS + Syslog, [`messaging.spec.ts`](./test/integration/recipes/messaging.spec.ts)

### Prerequisites

- **STOMP broker** `MQ` + `MQ_USER`/`MQ_PASS`; the transactional producer/consumer (ActiveMQ/RabbitMQ).
- **MQTT broker** `BROKER` and **NATS** `NATS` + `NATS_TOKEN`; the bridged downstream consumers.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

Transactional produce with multiple consumers: a producer stages sends in a STOMP
transaction (a rolled-back transaction never reaches subscribers), ack modes (`client` vs
`client-individual`) behave correctly, and committed messages are bridged - at the
application level, since the brokers are separate - to MQTT and NATS subscribers byte-for-byte.

```typescript
import { connect as stompConnect } from 'edgeport/stomp';
import { connect as mqttConnect } from 'edgeport/mqtt';
import { connect as natsConnect } from 'edgeport/nats';

await using mq = await stompConnect({ hostname: env.MQ, login: env.MQ_USER, passcode: env.MQ_PW });
await using mqtt = await mqttConnect({ hostname: env.BROKER, clientId: 'bridge' });
await using nc = await natsConnect({ hostname: env.NATS, token: env.NATS_TOKEN });

// stage two sends; commit releases both atomically (abort would deliver neither)
const tx = await mq.begin();
await tx.send('/queue/orders', payload);
await tx.send('/queue/audit', entry);
await tx.commit();

// a subscriber consumes the committed message and the worker bridges it to other transports
for await (const m of mq.subscribe('/queue/orders', { ack: 'client' })) {
	await mqtt.publish('orders', m.body, { qos: 1 });
	await nc.publish('orders', m.body);
	await m.ack();
	break;
}
```

**Use case:** transactional pipelines whose events must reach heterogeneous consumers.

## Centralized Authentication

**Modules:** LDAP + SSH + SFTP + Syslog, [`auth.spec.ts`](./test/integration/recipes/auth.spec.ts)

### Prerequisites

- **Directory** `LDAP` + `SVC_DN`/`SVC_PW`; identity + group membership (with `ou=people` / `ou=groups`).
- **SSH/SFTP host** `BOX` + **private key** `SSH_KEY`; the gated action target.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

LDAP as the single identity source for a fleet: a bind verifies the password, a group lookup
authorizes the action, locked accounts are denied, and only then does the SSH/SFTP action run -
every decision and command audited to Syslog.

```typescript
import { authenticate, search as ldapSearch, eq } from 'edgeport/ldap';
import { connect as sshConnect } from 'edgeport/ssh';

async function authorize(uid: string, password: string): Promise<boolean> {
	// 1. authenticate via bind-search-bind in one call; eq() keeps an untrusted uid from
	// injecting filter syntax. returns the located entry, or null on bad password / no match
	const entry = await authenticate({
		hostname: env.LDAP,
		bindDN: env.SVC_DN,
		bindPassword: env.SVC_PW,
		base: 'ou=people,dc=example,dc=org',
		userFilter: eq('uid', uid),
		password
	});
	if (!entry) return false;
	// 2. authorize: not locked, and a member of cn=admins
	if (entry.attributes.employeeType?.includes('locked')) return false;
	const admins = await ldapSearch({
		hostname: env.LDAP,
		bindDN: env.SVC_DN,
		password: env.SVC_PW,
		base: 'cn=admins,ou=groups,dc=example,dc=org',
		filter: '(objectClass=*)'
	});
	return admins[0]?.attributes.member?.some((m) => m.startsWith(`uid=${uid},`)) ?? false;
}

if (await authorize(uid, password)) {
	await using ssh = await sshConnect({
		hostname: env.BOX,
		username: 'svc',
		privateKey: { pem: env.SSH_KEY }
	});
	await ssh.exec('systemctl restart app'); // gated action
}
```

> The SSH box authenticates its own service account; the LDAP bind + group check is the
> application authorization gate in front of it (the standard "LDAP-backed fleet" pattern).
> The edgeport LDAP module is bind+search, so access changes are shown via seeded membership.

**Use case:** centralized, audited authorization for a fleet of hosts.

## Notification Fan-Out

**Modules:** NATS + WebSocket + MQTT + STOMP + Syslog, [`notifications.spec.ts`](./test/integration/recipes/notifications.spec.ts)

### Prerequisites

- **NATS** `NATS` + `NATS_TOKEN`; the notification core.
- **WebSocket gateway** `GW`, **MQTT broker** `BROKER`, **STOMP broker** `MQ` + `MQ_USER`/`MQ_PASS`; the three fan-out transports.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

One event, many transports: a notification core on NATS fans each event out to browsers (WS),
mobile/IoT (MQTT QoS 1), and JVM/legacy consumers (STOMP client-ack) - bridged at the
application level. Ordering is preserved per transport, per-protocol ack/QoS is respected, and
a slow consumer on one transport does not stall the others.

```typescript
import { connect as natsConnect } from 'edgeport/nats';
import { connect as wsConnect } from 'edgeport/ws';
import { connect as mqttConnect } from 'edgeport/mqtt';
import { connect as stompConnect } from 'edgeport/stomp';

await using nc = await natsConnect({ hostname: env.NATS, token: env.NATS_TOKEN });
await using mqtt = await mqttConnect({ hostname: env.BROKER, clientId: 'notify' });
await using mq = await stompConnect({ hostname: env.MQ, login: env.MQ_USER, passcode: env.MQ_PW });
const ws = await wsConnect(`wss://${env.GW}/notify`);

// the core publishes once on NATS; the worker is the fan-out bridge to every transport
for await (const event of nc.subscribe('notifications.>')) {
	ws.send(event.data); // browsers
	await mqtt.publish('notifications', event.data, { qos: 1 }); // mobile / IoT
	await mq.send('/topic/notifications', event.data); // JVM / legacy
}
```

**Use case:** product notification hubs delivering one event to heterogeneous clients.

## Credential-Protecting Gateway

**Modules:** LDAPS + SSH + SFTP + Syslog, [`credentials.spec.ts`](./test/integration/recipes/credentials.spec.ts)

### Prerequisites

- **LDAPS directory** `LDAP` + `SVC_DN`/`SVC_PW`; connect via `edgeport/ldaps` (TLS on 636); the server cert must chain to a CA the runtime trusts.
- **SSH/SFTP host** `BOX` + **private key** `SSH_KEY`; the gated action target.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

An auth gateway binds over LDAPS so the simple-bind password never crosses the wire in
cleartext. The security guarantees live in the TLS layer: an untrusted/self-signed/expired or
hostname-mismatched server certificate makes the bind **fail closed** before any credential is
sent, the client never silently downgrades to plaintext LDAP, and `expectedServerHostname`
pins the server identity. Only after the directory check passes does the gated SSH/SFTP action
run, with every decision audited to Syslog.

```typescript
import { connect as ldapsConnect } from 'edgeport/ldaps';
import { connect as sshConnect } from 'edgeport/ssh';
import { ConnectionError } from 'edgeport';

// fail closed: an untrusted directory cert is rejected before the bind, so no password leaks
try {
	await using dir = await ldapsConnect({
		hostname: env.LDAP,
		expectedServerHostname: env.LDAP, // the cert must match this identity
		bindDN: env.SVC_DN,
		password: env.SVC_PW
	});
	// ... bind succeeded over a verified TLS channel; gate the action here
	await using ssh = await sshConnect({
		hostname: env.BOX,
		username: 'svc',
		privateKey: { pem: env.SSH_KEY }
	});
	await ssh.exec('systemctl restart app');
} catch (err) {
	if (err instanceof ConnectionError) {
		// TLS/cert validation failed - do NOT fall back to plaintext LDAP; deny the action
	}
}
```

> Workers runtime limits (documented in the spec): workerd validates the server cert but cannot
> be made to trust a private CA, so a trusted-CA happy-path bind and on-wire packet capture are
> not testable locally - the recipe asserts the fail-closed gate and no-downgrade behavior.

**Use case:** an identity gateway where credentials must never traverse an unverified channel.

## Certificate Lifecycle

**Modules:** LDAPS + Syslog + SMTP, [`certificates.spec.ts`](./test/integration/recipes/certificates.spec.ts)

### Prerequisites

- **LDAPS directory** `LDAP` + `SVC_DN`/`SVC_PW`; `edgeport/ldaps` on 636; the monitored server certificate.
- **Syslog collector** `SIEM` and **SMTP** `SMTP` to `ONCALL`; cert-failure audit + alert.

See [Environment & Services](#environment--services) for value formats and how to obtain each.

The operational failure mode that breaks LDAPS in production: the directory server's
certificate is untrusted (expired / self-signed / wrong hostname), so binds start failing
closed. The deployment detects it, audits the failure to Syslog, and alerts on-call over SMTP -
and keeps failing closed on retry until the cert is fixed.

```typescript
import { connect as ldapsConnect } from 'edgeport/ldaps';
import { connect as syslogConnect } from 'edgeport/syslog';
import { send } from 'edgeport/smtp';
import { ConnectionError } from 'edgeport';

await using audit = await syslogConnect({
	hostname: env.SIEM,
	port: 6514,
	tls: 'implicit',
	appName: 'ldaps-mon'
});

try {
	await using dir = await ldapsConnect({
		hostname: env.LDAP,
		bindDN: env.SVC_DN,
		password: env.SVC_PW
	});
	// ... bind ok
} catch (err) {
	if (err instanceof ConnectionError) {
		await audit.error('ldaps cert validation failed');
		await send({
			hostname: env.SMTP,
			tls: 'off',
			from: 'ldaps-mon@example.org',
			to: env.ONCALL,
			subject: 'CERT: directory TLS validation failing',
			text: String(err)
		});
	}
}
```

> Workers surfaces one opaque error for all cert problems (it does not distinguish expired vs
> hostname-mismatch vs self-signed vs broken-chain), and a successful post-renewal bind can't be
> shown locally (no trusted cert validates) - the recipe asserts one representative
> fail-closed -> alert + audit path.

**Use case:** detecting and alerting on directory-certificate expiry/rotation failures.

---

## Notes on Test Infrastructure

- **Syslog readback:** the Dockerized syslog service ingests on `:5514` and serves the
  captured log back on `:5515`, so tests can assert exactly what was logged (`readSyslog()`).
- **Plaintext transports:** GreenMail's plaintext mail ports are used with `tls: 'off'`
  (workerd rejects GreenMail's self-signed cert on the implicit-TLS ports).
- **Port forwarding:** SSH `forwardOut` (direct-tcpip) is verified against Dropbear, which
  permits TCP forwarding (`linuxserver/openssh` disables it by default).
- **JetStream:** the NATS server runs with `-js` enabled for the recovery recipe.
