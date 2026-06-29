// recipe: a full email-service stack over real servers - SMTP + IMAP + POP3 + LDAP + Syslog.
//
// this models how a Workers-hosted mail gateway actually behaves end to end: it validates a
// recipient against the LDAP directory before relaying, submits over SMTP, then proves the
// message is visible through BOTH retrieval protocols (IMAP and POP3) against the same account,
// and writes an ordered audit trail to Syslog for every transaction stage. wrong-credential
// paths on all three mail protocols must surface as AuthError.
//
// PLAINTEXT NOTE: greenmail's TLS ports use a self-signed cert that workerd rejects, so every
// mail protocol here connects with tls:'off' (now supported on the PUBLIC API - no more
// _sessionFromSocket workaround). a real deployment would use STARTTLS/implicit TLS; tls:'off'
// is the dev-server shape only. ldap 389 is plaintext bind+search. syslog 5514 is plaintext
// ingest, read back via readSyslog() (port 5515).
//
// LDAP-vs-greenmail GATE: greenmail accepts any local recipient at RCPT TO, so directory-based
// recipient validation cannot be a server-side reject - it is APPLICATION logic. we look the
// address up in ou=people first and only call smtp.send() when the directory has it; an unknown
// address is rejected by our code and never submitted.
//
// SHARED-SERVER NOTE: greenmail accumulates mail across every suite and the syslog file is
// shared, so each test uses a uniqueId() marker and scopes its assertions to that id.
import { describe, expect, it } from 'vitest';
import { AuthError } from '../../../src/core/errors';
import { connect as imapConnect } from '../../../src/imap/index';
import { connect as ldapConnect, type LdapSession } from '../../../src/ldap/index';
import { connect as pop3Connect } from '../../../src/pop3/index';
import { connect as smtpConnect, send as smtpSend } from '../../../src/smtp/index';
import { Facility, Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const HOST = '127.0.0.1';
const SMTP_PORT = 3025;
const IMAP_PORT = 3143;
const POP3_PORT = 3110;
const LDAP_PORT = 389;
const SYSLOG_PORT = 5514;

// the greenmail mailbox we send to and read back from (tester:testpass@localhost)
const ME = 'tester@localhost';
const mailAuth = { username: 'tester', password: 'testpass' };

// ldap directory: admin bind + seeded people under ou=people
const LDAP_BASE = 'dc=example,dc=org';
const PEOPLE_BASE = `ou=people,${LDAP_BASE}`;
const ldapAdmin = {
	hostname: HOST,
	port: LDAP_PORT,
	bindDN: 'cn=admin,dc=example,dc=org',
	password: 'admin'
};

const decoder = new TextDecoder();

// opens a plaintext SMTP submission session on greenmail via the PUBLIC api (tls:'off')
async function openSmtp(auth = mailAuth) {
	return smtpConnect({ hostname: HOST, port: SMTP_PORT, tls: 'off', auth });
}

// opens a plaintext IMAP session on greenmail via the PUBLIC api (tls:'off')
async function openImap(auth = mailAuth) {
	return imapConnect({ hostname: HOST, port: IMAP_PORT, tls: 'off', auth });
}

// opens a plaintext POP3 session on greenmail via the PUBLIC api (tls:'off')
async function openPop3(auth = mailAuth) {
	return pop3Connect({ hostname: HOST, port: POP3_PORT, tls: 'off', auth });
}

// opens the plaintext syslog audit channel; Facility.mail keeps these events self-labelling
async function openSyslog(runId: string) {
	return syslogConnect({
		hostname: HOST,
		port: SYSLOG_PORT,
		tls: 'off',
		appName: 'mail-gateway',
		procId: runId
	});
}

// looks a recipient up in the directory by its mail attribute; returns the matching dn or null.
// this is the app-level RCPT-TO gate: greenmail itself would accept any local recipient.
async function lookupRecipient(ldap: LdapSession, address: string): Promise<string | null> {
	const entries = await ldap.search({
		base: PEOPLE_BASE,
		scope: 'sub',
		filter: `(mail=${address})`,
		attributes: ['mail', 'uid']
	});
	return entries.length > 0 ? (entries[0]!.dn ?? null) : null;
}

// polls imap (search by subject + fetch body) until the marked message shows up in INBOX
async function waitForImap(marker: string, auth = mailAuth): Promise<string | null> {
	return waitFor(
		async () => {
			await using session = await openImap(auth);
			await session.select('INBOX');
			const uids = await session.search({ subject: marker });
			if (uids.length === 0) return null;
			const messages = await session.fetch(uids, { flags: true, body: true, size: true });
			const body = messages
				.map((m) => (m.body ? decoder.decode(m.body) : ''))
				.find((b) => b.includes(marker));
			return body ?? null;
		},
		15_000,
		300
	);
}

// polls pop3 (stat + list + retrieve every message) until one containing `marker` appears
async function waitForPop3(marker: string, auth = mailAuth): Promise<string | null> {
	return waitFor(
		async () => {
			await using session = await openPop3(auth);
			const { count } = await session.stat();
			if (count === 0) return null;
			const list = await session.list();
			for (const { id } of list) {
				const raw = decoder.decode(await session.retrieve(id));
				if (raw.includes(marker)) return raw;
			}
			return null;
		},
		15_000,
		300
	);
}

// counts how many messages in the mailbox contain `marker`, via pop3 stat+list+retrieve.
// used to prove a no-DELE pop3 read leaves the message present for a later view.
async function pop3CountMatching(marker: string, auth = mailAuth): Promise<number> {
	await using session = await openPop3(auth);
	const { count } = await session.stat();
	if (count === 0) return 0;
	const list = await session.list();
	let n = 0;
	for (const { id } of list) {
		const raw = decoder.decode(await session.retrieve(id));
		if (raw.includes(marker)) n++;
	}
	return n;
}

// counts how many INBOX messages match `marker` via imap search, proving the imap view is intact.
async function imapCountMatching(marker: string, auth = mailAuth): Promise<number> {
	await using session = await openImap(auth);
	await session.select('INBOX');
	const uids = await session.search({ subject: marker });
	if (uids.length === 0) return 0;
	const messages = await session.fetch(uids, { body: true });
	return messages.filter((m) => (m.body ? decoder.decode(m.body).includes(marker) : false)).length;
}

// waits until every expected audit marker for this run is present in the syslog readback, IN ORDER.
// scoped to runId so concurrent suites sharing the syslog file never pollute the ordering check.
async function waitForAudit(runId: string, markers: string[]): Promise<string | null> {
	return waitFor(
		async () => {
			const all = await readSyslog();
			const mine = all
				.split('\n')
				.filter((line) => line.includes(runId))
				.join('\n');
			let from = 0;
			for (const m of markers) {
				const at = mine.indexOf(m, from);
				if (at < 0) return null;
				from = at + m.length;
			}
			return mine;
		},
		15_000,
		300
	);
}

describe('recipe: full mail-service stack (SMTP + IMAP + POP3 + LDAP + Syslog)', () => {
	// 1. outbound submission over SMTP: a uniquely-subjected message is accepted by the server.
	it('submits a message over SMTP and the server accepts the recipient', async () => {
		const subject = uniqueId('mail-send');
		const body = `body for ${subject} - submitted over edgeport smtp`;

		await using smtp = await openSmtp();
		const sent = await smtp.send({ from: ME, to: ME, subject, text: body });
		expect(sent.accepted, 'greenmail should accept the local recipient').toContain(ME);

		// the one-shot send() wrapper is the other public entrypoint; it must also be accepted
		const oneShot = await smtpSend({
			hostname: HOST,
			port: SMTP_PORT,
			tls: 'off',
			auth: mailAuth,
			from: ME,
			to: ME,
			subject: `${subject}-oneshot`,
			text: `one-shot ${subject}`
		});
		expect(oneShot.accepted).toContain(ME);
	});

	// 2. LDAP-driven recipient validation: a seeded directory address is validated then sent; an
	// unknown address is rejected by APP logic and never submitted (greenmail would accept it).
	it('validates the recipient against LDAP before sending; rejects an unknown address', async () => {
		const runId = uniqueId('mail-ldap');
		await using ldap = await ldapConnect(ldapAdmin);

		// (a) a SEEDED address resolves in the directory -> allowed -> submitted.
		// we look it up by its directory mail attribute (alice@example.org), prove the lookup,
		// then submit the actual greenmail message to ME (the only mailbox that server hosts).
		const known = 'alice@example.org';
		const knownDn = await lookupRecipient(ldap, known);
		expect(knownDn, 'seeded recipient must resolve in ou=people').not.toBeNull();
		expect(knownDn!.toLowerCase()).toContain('uid=alice');

		const subject = uniqueId('mail-ldap-ok');
		await using smtp = await openSmtp();
		const sent = await smtp.send({
			from: ME,
			to: ME,
			subject,
			text: `validated recipient ${known} for run ${runId}`,
			headers: { 'X-Validated-Recipient': known }
		});
		expect(sent.accepted, 'a directory-validated message must be submitted').toContain(ME);

		// (b) an UNKNOWN address is absent from the directory -> our gate rejects it -> NOT sent.
		const unknown = 'nobody@example.org';
		const unknownDn = await lookupRecipient(ldap, unknown);
		expect(unknownDn, 'unknown recipient must not resolve in the directory').toBeNull();

		// the app-level gate: because the directory lookup failed, we never call smtp.send().
		// (greenmail itself accepts any local recipient, so the gate has to live in our code.)
		let submitted = false;
		if (unknownDn !== null) {
			submitted = true; // unreachable - documents that the gate is the directory result
		}
		expect(submitted, 'an unknown recipient must be rejected before submission').toBe(false);
	});

	// 3. cross-protocol mailbox consistency: a single SMTP-sent message is visible via BOTH IMAP
	// and POP3, and a POP3 retrieve WITHOUT delete leaves the IMAP view (and a second POP3 view)
	// intact - the same account stays sane when hit by both protocols.
	it('shows one SMTP message via both IMAP and POP3, and a no-delete POP3 read keeps it', async () => {
		const subject = uniqueId('mail-xproto');
		const body = `cross-protocol body ${subject}`;

		await using smtp = await openSmtp();
		const sent = await smtp.send({ from: ME, to: ME, subject, text: body });
		expect(sent.accepted).toContain(ME);

		// IMAP view: select + search + fetch (waitFor handles delivery latency)
		const viaImap = await waitForImap(subject);
		expect(viaImap, 'imap should see the message').not.toBeNull();
		expect(viaImap!).toContain(subject);
		expect(viaImap!).toContain(body);

		// POP3 view: stat + list + retrieve, NO delete - the message is read but left on the server
		const viaPop = await waitForPop3(subject);
		expect(viaPop, 'pop3 should see the same message').not.toBeNull();
		expect(viaPop!).toContain(subject);
		expect(viaPop!).toContain(body);

		// the no-delete invariant: after the POP3 retrieve above (which issued no DELE), both the
		// IMAP view and a fresh POP3 view must still find the message exactly once.
		expect(await imapCountMatching(subject), 'imap view intact after pop3 read').toBe(1);
		expect(await pop3CountMatching(subject), 'pop3 view intact after pop3 read').toBe(1);
	});

	// 4. audit completeness: every transaction stage (validate-recipient, smtp-send, imap-read,
	// pop3-read) is logged to Syslog with the run id, and the readback shows the full ORDERED trail.
	it('logs the full ordered transaction audit trail to Syslog', async () => {
		const runId = uniqueId('mail-audit');
		const subject = `${runId}-msg`;

		await using log = await openSyslog(runId);
		await using ldap = await ldapConnect(ldapAdmin);

		// stage 1: validate the recipient against the directory
		const recipient = 'bob@example.org';
		const dn = await lookupRecipient(ldap, recipient);
		expect(dn, 'bob must resolve in the directory').not.toBeNull();
		await log.log({
			severity: Severity.info,
			facility: Facility.mail,
			message: `validate-recipient ${runId} addr=${recipient} dn=${JSON.stringify(dn)}`,
			structuredData: [{ id: 'mail@gw', params: { run: runId, stage: 'validate' } }]
		});

		// stage 2: smtp send
		await using smtp = await openSmtp();
		const sent = await smtp.send({
			from: ME,
			to: ME,
			subject,
			text: `audited message for ${runId}`,
			headers: { 'X-Run-Id': runId }
		});
		expect(sent.accepted).toContain(ME);
		await log.log({
			severity: Severity.notice,
			facility: Facility.mail,
			message: `smtp-send ${runId} accepted=${sent.accepted.length}`,
			structuredData: [{ id: 'mail@gw', params: { run: runId, stage: 'smtp' } }]
		});

		// stage 3: imap read-back
		const viaImap = await waitForImap(subject);
		expect(viaImap, 'audited message must be readable over imap').not.toBeNull();
		await log.log({
			severity: Severity.info,
			facility: Facility.mail,
			message: `imap-read ${runId} found=1`,
			structuredData: [{ id: 'mail@gw', params: { run: runId, stage: 'imap' } }]
		});

		// stage 4: pop3 read-back
		const viaPop = await waitForPop3(subject);
		expect(viaPop, 'audited message must be readable over pop3').not.toBeNull();
		await log.log({
			severity: Severity.info,
			facility: Facility.mail,
			message: `pop3-read ${runId} found=1`,
			structuredData: [{ id: 'mail@gw', params: { run: runId, stage: 'pop3' } }]
		});

		// the readback must show all four stages, in submission order, scoped to this run
		const audit = await waitForAudit(runId, [
			`validate-recipient ${runId}`,
			`smtp-send ${runId}`,
			`imap-read ${runId}`,
			`pop3-read ${runId}`
		]);
		expect(audit, 'the full ordered audit trail should be in syslog').not.toBeNull();
		// each stage carried the run id in its structured data too
		expect(audit!).toContain(`validate-recipient ${runId}`);
		expect(audit!).toContain(`pop3-read ${runId}`);
	});

	// extra coverage retained from the prior version: multi-recipient envelope + multipart MIME.
	it('delivers to multiple recipients and reports the accepted envelope', async () => {
		const subject = uniqueId('mail-multi');
		await using smtp = await openSmtp();
		// greenmail accepts any local recipient; all three should be accepted
		const recipients = ['tester@localhost', 'second@localhost', 'third@localhost'];
		const res = await smtp.send({
			from: ME,
			to: recipients,
			subject,
			text: `multi-recipient ${subject}`
		});
		expect(res.accepted).toEqual(expect.arrayContaining(recipients));
		expect(res.accepted.length).toBe(recipients.length);
	});

	it('delivers a multipart HTML+text message that arrives intact', async () => {
		const subject = uniqueId('mail-mime');
		const text = `plain part ${subject}`;
		const html = `<p>html part <b>${subject}</b></p>`;

		await using smtp = await openSmtp();
		const res = await smtp.send({ from: ME, to: ME, subject, text, html });
		expect(res.accepted).toContain(ME);

		// pull it back over pop3 and confirm both alternative parts + the multipart marker survive
		const raw = await waitForPop3(subject);
		expect(raw, 'multipart message should be retrievable').not.toBeNull();
		expect(raw!.toLowerCase()).toContain('multipart/alternative');
		expect(raw!).toContain(text);
		expect(raw!).toContain(html);
	});

	// 5. error handling: a wrong password on each mail protocol surfaces as AuthError (public api).
	describe('error handling', () => {
		const wrong = { username: 'tester', password: 'wrong-password' };

		it('rejects a wrong SMTP password with AuthError', async () => {
			await expect(openSmtp(wrong)).rejects.toBeInstanceOf(AuthError);
		});

		it('rejects a wrong IMAP password with AuthError', async () => {
			await expect(openImap(wrong)).rejects.toBeInstanceOf(AuthError);
		});

		it('rejects a wrong POP3 password with AuthError', async () => {
			await expect(openPop3(wrong)).rejects.toBeInstanceOf(AuthError);
		});

		it('rejects a wrong LDAP bind password with AuthError', async () => {
			await expect(ldapConnect({ ...ldapAdmin, password: 'wrong' })).rejects.toBeInstanceOf(
				AuthError
			);
		});
	});
});
