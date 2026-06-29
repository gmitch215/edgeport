// recipe: certificate-lifecycle / rotation resilience over LDAPS (LDAPS + Syslog + SMTP).
//
// this is the operational failure that breaks directory-backed auth in production: the LDAPS
// server's certificate stops validating (expired, rotated to a chain the client doesn't trust,
// or a hostname mismatch after a move) and every bind fails closed until someone fixes the cert.
// the recipe proves the deployment's RESPONSE to that: it detects the fail-closed bind, writes an
// audit trail to Syslog, and fires an SMTP alert so an operator renews the cert.
//
// CRITICAL runtime fact (confirmed under local workerd): workerd VALIDATES outbound TLS and
// REJECTS untrusted certificates. the docker openldap on 636 serves a self-signed cert that is
// ALSO expired and ALSO hostname-mismatched (CN does not match 127.0.0.1) - three distinct
// failure modes on one cert. workerd surfaces ONE opaque error for all of them: it does NOT
// distinguish expired vs hostname-mismatch vs self-signed vs broken-chain, cannot be told to
// trust a private CA, and there is therefore NO trusted cert that ever validates locally. so:
//   - the distinct cert failure modes are NOT separately observable here (workerd collapses them).
//   - a "successful renewal -> bind succeeds" path is NOT observable here (no cert ever validates).
// this spec asserts the ONE representative path that IS observable: untrusted cert -> fail-closed
// LDAPS connect -> operational response (Syslog audit + SMTP alert) -> repeated attempts stay
// fail-closed. the surfaced failure is a ConnectionError because the TLS handshake is what fails,
// before any LDAP bytes are exchanged (ldap.connect opens the core socket with tls:'on' first).
//
// SMTP: greenmail 3025 is plaintext. the public smtp.send({ tls:'off' }) opens a tls:'off' core
// socket and skips the STARTTLS upgrade, which is exactly what greenmail wants; we use that public
// path. Syslog ingest is plaintext on 5514 (tls:'off'); readback via readSyslog(). the optional
// IMAP confirmation reads greenmail's plaintext store on 3143 (tls:'off').
import { describe, expect, it } from 'vitest';
import { ConnectionError } from '../../../src/core/errors';
import { connect as imapConnect } from '../../../src/imap/index';
import { connect as ldapsConnect } from '../../../src/ldaps/index';
import { send as smtpSend } from '../../../src/smtp/index';
import { Facility, Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const HOST = '127.0.0.1';
const LDAPS_PORT = 636; // openldap implicit-TLS; serves a self-signed + expired + mismatched cert
const SYSLOG_PORT = 5514;
const SMTP_PORT = 3025;
const IMAP_PORT = 3143;
const ME = 'tester@localhost';
const smtpAuth = { username: 'tester', password: 'testpass' };
const imapAuth = { username: 'tester', password: 'testpass' };

// the admin bind we WOULD use if the cert validated; binding is moot because the handshake fails
// first, but passing it proves the connect can't reach a bound session even with valid creds
const bindDN = 'cn=admin,dc=example,dc=org';
const bindPassword = 'admin';

// opens the plaintext syslog audit channel; Facility.auth labels these as directory-auth events
async function openSyslog(runId: string) {
	return syslogConnect({
		hostname: HOST,
		port: SYSLOG_PORT,
		appName: 'cert-monitor',
		procId: runId
	});
}

// attempts an LDAPS bind against the untrusted cert; returns the thrown error (always fails closed)
async function attemptLdapsBind(): Promise<unknown> {
	try {
		const session = await ldapsConnect({
			hostname: HOST,
			port: LDAPS_PORT,
			bindDN,
			password: bindPassword,
			timeoutMs: 10_000
		});
		// if we ever reach here a cert validated, which cannot happen locally; close and signal it
		await session.close().catch(() => {});
		return null;
	} catch (err) {
		return err;
	}
}

// polls the syslog readback until every expected marker for this run is present, in order
async function waitForAudit(runId: string, markers: string[]): Promise<string | null> {
	return waitFor(
		async () => {
			const all = await readSyslog();
			// keep only this run's lines so concurrent suites don't pollute the ordering check
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

describe('recipe: certificate-lifecycle / rotation resilience over LDAPS (LDAPS + Syslog + SMTP)', () => {
	// 1. the directory cert fails validation: an LDAPS bind to 636 rejects fail-closed.
	//
	// this one cert exhibits expired + self-signed + hostname-mismatch SIMULTANEOUSLY, and workerd
	// collapses all of them to a single opaque TLS-handshake failure - it does NOT tell us which
	// mode tripped. ldap.connect dials the core socket with tls:'on' before any LDAP byte, so the
	// failure is a ConnectionError (handshake), not an AuthError, even though we passed valid creds.
	it('rejects an LDAPS bind against the untrusted/expired cert with ConnectionError', async () => {
		const err = await attemptLdapsBind();
		expect(err, 'an untrusted cert must make the LDAPS connect throw, never resolve').toBeTruthy();
		// fail-closed surfaces as a ConnectionError: the TLS handshake failed before LDAP started.
		// note: we cannot assert WHICH cert defect (expired/self-signed/mismatch) - workerd hides it.
		expect(err).toBeInstanceOf(ConnectionError);
	});

	// 2. the operational response (the point of the recipe): on the cert failure the deployment
	// (a) logs an error/alert event to Syslog with the run id + structured data, and (b) sends an
	// SMTP alert email whose subject carries the run id + 'CERT'. assert the send is accepted and
	// the syslog audit shows the ordered cert-failure -> alert-sent trail.
	it('audits the cert failure and fires an SMTP alert, in order', async () => {
		const runId = uniqueId('cert-alert');
		await using log = await openSyslog(runId);

		// the bind fails closed against the untrusted cert
		const err = await attemptLdapsBind();
		expect(err, 'the cert failure must be observable as a thrown error').toBeInstanceOf(
			ConnectionError
		);
		const detail = (err as Error).message;

		// (a) audit the validation failure at error severity (Facility.auth: directory auth)
		await log.log({
			severity: Severity.error,
			facility: Facility.auth,
			message: `ldaps cert validation failed ${runId} host=${HOST}:${LDAPS_PORT}`,
			structuredData: [
				{
					id: 'cert@mon',
					params: {
						run: runId,
						event: 'cert-validation-failed',
						// workerd gives one opaque reason; record it verbatim rather than guessing the mode
						mode: 'opaque',
						detail: detail.slice(0, 200)
					}
				}
			]
		});

		// (b) alert by email; the subject carries the run id and the required 'CERT' marker
		const subject = `${runId} LDAPS CERT validation failed`;
		const sent = await smtpSend({
			hostname: HOST,
			port: SMTP_PORT,
			tls: 'off',
			auth: smtpAuth,
			from: ME,
			to: ME,
			subject,
			text: `LDAPS bind to ${HOST}:${LDAPS_PORT} failed closed for run ${runId}: ${detail}. directory binds will keep failing until the certificate is renewed.`
		});
		expect(sent.accepted, 'the cert-failure alert email must be accepted').toContain(ME);

		// record that the alert went out so the audit shows the full lifecycle
		await log.log({
			severity: Severity.notice,
			facility: Facility.auth,
			message: `alert-sent ${runId} subject=${JSON.stringify(subject)}`
		});

		const audit = await waitForAudit(runId, [
			`ldaps cert validation failed ${runId}`,
			`alert-sent ${runId}`
		]);
		expect(
			audit,
			'cert-failure -> alert-sent must appear in the syslog audit, in order'
		).not.toBeNull();
		// the alert line names this run, tying the email back to the cert event
		expect(audit!).toContain(`alert-sent ${runId}`);
	});

	// 3. no-downgrade safety: the failed LDAPS connect must NOT silently fall back to plaintext.
	// it throws and never hands back a bound session - a directory client that quietly downgraded
	// to cleartext on a cert error would leak credentials, so this is the security-critical check.
	it('never silently downgrades to plaintext when the cert fails', async () => {
		let session: unknown = 'unset';
		let threw = false;
		try {
			session = await ldapsConnect({
				hostname: HOST,
				port: LDAPS_PORT,
				bindDN,
				password: bindPassword,
				timeoutMs: 10_000
			});
		} catch (err) {
			threw = true;
			expect(err).toBeInstanceOf(ConnectionError);
		}
		expect(threw, 'a cert failure must throw, not resolve to a (plaintext) session').toBe(true);
		// the session binding was never reassigned to a real session object
		expect(session).toBe('unset');
	});

	// 4. repeated attempts stay fail-closed: a retry against the still-untrusted cert fails the same
	// way. this models 'binds keep failing until the cert is fixed' - the steady state that keeps
	// triggering the alert in test 2 until an operator renews the cert (a success we can't show here).
	it('keeps failing closed on repeated binds against the unchanged cert', async () => {
		const attempts = 3;
		for (let i = 0; i < attempts; i++) {
			const err = await attemptLdapsBind();
			expect(err, `attempt ${i} must fail closed`).toBeInstanceOf(ConnectionError);
		}
	});

	// 5. (optional) confirm the alert actually landed: read greenmail over plaintext IMAP and find
	// the message whose subject carries this run's id + 'CERT'. ties the SMTP send to a delivered mail.
	it('delivers the cert alert (verified via IMAP)', async () => {
		const runId = uniqueId('cert-imap');
		const subject = `${runId} LDAPS CERT validation failed`;

		// re-confirm the failure so the alert we send is genuinely a response to a fail-closed bind
		const err = await attemptLdapsBind();
		expect(err).toBeInstanceOf(ConnectionError);

		const sent = await smtpSend({
			hostname: HOST,
			port: SMTP_PORT,
			tls: 'off',
			auth: smtpAuth,
			from: ME,
			to: ME,
			subject,
			text: `cert alert for ${runId}`
		});
		expect(sent.accepted).toContain(ME);

		// greenmail delivers near-instantly but poll to avoid a race on the store. server-side
		// SEARCH by the spaceless runId narrows to this run's mail (the proven mail.spec pattern -
		// fetchRecent over the whole mailbox trips greenmail's fetch), then confirm the full subject.
		const decoder = new TextDecoder();
		const found = await waitFor(
			async () => {
				await using session = await imapConnect({
					hostname: HOST,
					port: IMAP_PORT,
					tls: 'off',
					auth: imapAuth
				});
				await session.select('INBOX');
				const uids = await session.search({ subject: runId });
				if (uids.length === 0) return null;
				const messages = await session.fetch(uids, { body: true });
				const body = messages
					.map((m) => (m.body ? decoder.decode(m.body) : ''))
					.find((b) => b.includes(subject));
				return body ?? null;
			},
			15_000,
			300
		);
		expect(found, 'the cert alert email should be retrievable from the mailbox').not.toBeNull();
		expect(found!).toContain(subject);
	});
});
