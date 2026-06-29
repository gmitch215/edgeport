// recipe: CI/observability pipeline -> Syslog ingest + parse, error-severity alert via SMTP,
// verified via IMAP. exercises three protocols end to end against the dockerized servers.
import { expect, it } from 'vitest';
import { connect as coreConnect } from '../../../src/core/socket';
import { _imapSessionFromSocket } from '../../../src/imap/index';
import { _sessionFromSocket as smtpSession } from '../../../src/smtp/index';
import { Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const auth = { username: 'tester', password: 'testpass' };
const MAILBOX = 'tester@localhost';

// greenmail SMTP/IMAP are plaintext on 3025/3143; the public connect() only offers
// starttls|implicit, so (matching smtp.spec.ts / imap.spec.ts) we open a plaintext core
// socket and hand it to _sessionFromSocket with tls:'implicit' meaning "no upgrade, socket
// already usable". real deployments use 587/STARTTLS or 465/implicit + 993 imaps.
async function openSmtp() {
	const socket = await coreConnect({ hostname: '127.0.0.1', port: 3025, tls: 'off' });
	return smtpSession(socket, { hostname: '127.0.0.1', tls: 'implicit', auth });
}

async function openImap() {
	const socket = await coreConnect({ hostname: '127.0.0.1', port: 3143, tls: 'off' });
	return _imapSessionFromSocket(socket, { hostname: '127.0.0.1', tls: 'implicit', auth });
}

// the syslog sink (port 5514) is a plaintext capture; real syslog/TLS would be 6514/implicit.
async function openSyslog() {
	return syslogConnect({ hostname: '127.0.0.1', port: 5514, tls: 'off', appName: 'edge-svc' });
}

it('emits high-volume structured syslog, alerts on error via SMTP, verifies via IMAP', async () => {
	const tag = uniqueId('ci');
	const VOLUME = 50;
	const errorMsg = `boom: upstream 503 [${tag}]`;

	// 1. emit a high-volume batch of RFC 5424 structured-data logs, all tagged with `tag`.
	// every line carries a req@1 SD element; one info line carries NO structured data (NIL '-').
	await using log = await openSyslog();
	const severities: Severity[] = [Severity.info, Severity.warning, Severity.notice, Severity.debug];
	for (let i = 0; i < VOLUME; i++) {
		const noSd = i === 0; // first line intentionally has no structured data -> renders '-'
		await log.log({
			severity: severities[i % severities.length]!,
			message: `req ${i} handled [${tag}]`,
			structuredData: noSd
				? undefined
				: [{ id: 'req@1', params: { ms: String(10 + (i % 90)), path: `/x/${i}` } }]
		});
	}

	// 3. an ERROR-severity event: log it AND fire an alert email. log first so the SD with the
	// quoted message (escaping per RFC 5424) is captured, then send the SMTP alert.
	await log.log({
		severity: Severity.error,
		message: errorMsg,
		structuredData: [{ id: 'req@1', params: { ms: '999', path: '/checkout', err: errorMsg } }]
	});

	// edge case: an oversized line should not blow up the rest of the batch. syslog over TCP is
	// fire-and-forget (no server reply), so a large frame is just more bytes; assert it resolves.
	const oversized = `oversized ${'A'.repeat(4096)} [${tag}]`;
	await expect(log.log({ severity: Severity.debug, message: oversized })).resolves.toBeUndefined();

	const alertSubject = `[${tag}] ALERT service degraded`;
	{
		await using smtp = await openSmtp();
		const res = await smtp.send({
			from: MAILBOX,
			to: MAILBOX,
			subject: alertSubject,
			text: `An error-severity event fired:\n\n${errorMsg}\n\ntag=${tag}`
		});
		expect(res.accepted).toContain(MAILBOX);
	}

	// close the syslog socket so the sink flushes the captured file before we read it back.
	await log.close();

	// 2. verify ingestion + parsing of the captured raw framed bytes.
	// the tag appears: once per VOLUME line, twice in the error line (message + err= SD param),
	// once in the oversized line => VOLUME + 3 total occurrences.
	const EXPECTED_TAGS = VOLUME + 3;
	const captured = await waitFor(async () => {
		const text = await readSyslog();
		const n = text.split(tag).length - 1;
		return n >= EXPECTED_TAGS ? text : null;
	});
	expect(captured, 'syslog readback did not contain the expected tagged lines').not.toBeNull();
	const text = captured!;

	// exact occurrence count proves every line of the high-volume batch was captured
	// (octet-counting framing has no newline separators, so we count tag occurrences, not lines)
	const tagCount = text.split(tag).length - 1;
	expect(tagCount).toBe(EXPECTED_TAGS);
	// octet-counting framing: each record is "<len> <PRI>VERSION TIMESTAMP ...". assert a framed
	// byte-length prefix immediately precedes a PRI on a record carrying our tag.
	expect(
		new RegExp(`\\d+ <\\d+>1 \\S+ - edge-svc - - .* req 0 handled \\[${tag}\\]`).test(text)
	).toBe(true);

	// RFC 5424 structured-data syntax rendered correctly on the wire
	expect(text).toContain('[req@1 ms=');
	expect(text).toContain('path="/x/1"');
	// app-name from the session default is present
	expect(text).toContain('edge-svc');
	// NIL structured-data ('-') is present for the no-SD line; PRI for user.info = <14>
	expect(text).toContain('<14>1 ');
	// SD value escaping per RFC 5424 6.3.3: only " \ and ] are backslash-escaped inside a
	// PARAM-VALUE; a '[' is legal unescaped. so the embedded error renders as ...[tag\]"
	expect(text).toContain('err="boom: upstream 503 [' + tag + '\\]"');
	// octet-counting framing: a decimal length + space precedes a known short line.
	// PRI for user.error = 3, so "<11>1 " appears for the error record.
	expect(text).toContain('<11>1 ');
	// the oversized line was captured intact (framing held for a big frame)
	expect(text).toContain('A'.repeat(4096));

	// 4. verify the alert email lands via IMAP. poll for delivery, then search + fetch.
	const found = await waitFor(
		async () => {
			await using imap = await openImap();
			const status = await imap.select('INBOX');
			if (status.exists === 0) return null;
			const uids = await imap.search({ subject: tag });
			if (uids.length === 0) return null;
			const msgs = await imap.fetch(uids, { flags: true, body: true, size: true });
			const hit = msgs.find((m) => {
				const body = m.body ? new TextDecoder().decode(m.body) : '';
				return body.includes(tag) && body.includes('ALERT');
			});
			return hit ?? null;
		},
		15000,
		250
	);

	expect(found, 'alert email with the unique tag was not delivered to INBOX').not.toBeNull();
	const body = new TextDecoder().decode(found!.body!);
	// the alert carries the subject (tag + ALERT) and the original error message in the body
	expect(body).toContain('ALERT');
	expect(body).toContain(tag);
	expect(body).toContain(errorMsg);
});
