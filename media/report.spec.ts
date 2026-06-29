// recipe: scheduled report generation + distribution (the ops/reporting cron pattern).
// SSH runs a report-generation job on the host, SFTP pulls the output back over the SAME ssh
// session, SHA-256 verifies the bytes against the host's own sha256sum, SMTP mails the file as
// a MIME attachment to stakeholders, IMAP retrieves it and proves the attachment round-trips,
// and Syslog records the ordered run trail. the failure path (a job that exits non-zero) fires
// a failure-alert email and an error-severity syslog line.
//
// greenmail SMTP (3025) / IMAP (3143) are plaintext, so we drive the public connect()/send()
// with tls:'off' (which maps to a plaintext core socket - no STARTTLS, no implicit TLS). the
// syslog sink (5514) is a plaintext capture read back via readSyslog(); real deployments use
// 587/STARTTLS or 465/implicit, 993 imaps, and 6514 syslog-over-TLS.
import { describe, expect, it } from 'vitest';
import { connect as imapConnect } from '../../../src/imap/index';
import { connect as sftpConnect } from '../../../src/sftp/index';
import { connect as smtpConnect } from '../../../src/smtp/index';
import { connect as sshConnect } from '../../../src/ssh/index';
import { Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const HOST = '127.0.0.1';
const SSH_PORT = 2222;
const SMTP_PORT = 3025;
const IMAP_PORT = 3143;
const SYSLOG_PORT = 5514;
const ME = 'tester@localhost';
const sshBase = { hostname: HOST, port: SSH_PORT, username: 'tester', password: 'testpass' };
const mailAuth = { username: 'tester', password: 'testpass' };
const APP = 'report-cron';

const dec = (b: Uint8Array) => new TextDecoder().decode(b);

// base64 of `data` as one unwrapped line (the MIME builder wraps at 76 cols, so we compare
// against the retrieved body with all whitespace stripped)
function base64(data: Uint8Array): string {
	let bin = '';
	for (const b of data) bin += String.fromCharCode(b);
	return btoa(bin);
}

// lowercase hex sha-256 of `data`, computed in-worker via WebCrypto
async function sha256Hex(data: Uint8Array): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', data as BufferSource);
	let hex = '';
	for (const b of new Uint8Array(digest)) hex += b.toString(16).padStart(2, '0');
	return hex;
}

async function openSmtp() {
	return smtpConnect({ hostname: HOST, port: SMTP_PORT, tls: 'off', auth: mailAuth });
}

async function openImap() {
	return imapConnect({ hostname: HOST, port: IMAP_PORT, tls: 'off', auth: mailAuth });
}

async function openSyslog() {
	return syslogConnect({ hostname: HOST, port: SYSLOG_PORT, tls: 'off', appName: APP });
}

// polls imap (search by unique subject + fetch full body) until a matching message arrives
async function waitForMail(subject: string): Promise<Uint8Array | null> {
	return waitFor(
		async () => {
			await using imap = await openImap();
			const status = await imap.select('INBOX');
			if (status.exists === 0) return null;
			const uids = await imap.search({ subject });
			if (uids.length === 0) return null;
			const msgs = await imap.fetch(uids, { flags: true, body: true });
			const hit = msgs.find((m) => m.body && dec(m.body).includes(subject));
			return hit?.body ?? null;
		},
		15_000,
		250
	);
}

describe('recipe: scheduled report generation + distribution', () => {
	it('generates -> pulls -> verifies checksum -> emails as attachment -> logs the trail', async () => {
		const id = uniqueId('report');
		const csvPath = `/config/${id}.csv`;
		const subject = `Daily Report ${id}`;

		await using ssh = await sshConnect(sshBase);

		// 1. SSH exec the report-generation job on the host. it builds a 200-row CSV and prints
		// a 'generated' marker on success. assert exit code 0 and the marker.
		const gen = await ssh.exec(`seq 1 200 > ${csvPath} && echo generated`);
		expect(gen.code, dec(gen.stderr)).toBe(0);
		expect(dec(gen.stdout)).toContain('generated');

		await using syslog = await openSyslog();
		await syslog.log({
			severity: Severity.info,
			message: `job-generated ${id}`,
			structuredData: [{ id: 'run@1', params: { step: 'generate', file: csvPath } }]
		});

		// 2. pull the output over SFTP, REUSING the open ssh session (connect({ session })).
		await using sftp = await sftpConnect({ session: ssh });
		const attrs = await sftp.stat(csvPath);
		const pulled = await sftp.readFile(csvPath);
		expect(pulled.length).toBe(attrs.size);
		// the report has exactly 200 lines (seq 1..200), each terminated by a newline
		expect(dec(pulled).trimEnd().split('\n').length).toBe(200);
		await syslog.log({
			severity: Severity.info,
			message: `pulled ${id}`,
			structuredData: [{ id: 'run@1', params: { step: 'pull', bytes: String(pulled.length) } }]
		});

		// 2b. INTEGRITY: compute SHA-256 of the pulled bytes here, and the host's own sha256sum
		// over the same file via ssh. they must match - proves SFTP delivered the file intact.
		const localHash = await sha256Hex(pulled);
		const remote = await ssh.exec(`sha256sum ${csvPath}`);
		expect(remote.code, dec(remote.stderr)).toBe(0);
		const remoteHash = dec(remote.stdout).trim().split(/\s+/)[0];
		expect(remoteHash).toBe(localHash);
		await syslog.log({
			severity: Severity.info,
			message: `checksum-ok ${id}`,
			structuredData: [{ id: 'run@1', params: { step: 'checksum', sha256: localHash } }]
		});

		// 3. email the report to stakeholders with the CSV as a MIME ATTACHMENT.
		const filename = `${id}.csv`;
		{
			await using smtp = await openSmtp();
			const res = await smtp.send({
				from: ME,
				to: ME,
				subject,
				text: `Attached is the daily report (${id}). sha256=${localHash}`,
				attachments: [{ filename, content: pulled, contentType: 'text/csv' }]
			});
			expect(res.accepted).toContain(ME);
		}
		await syslog.log({
			severity: Severity.info,
			message: `emailed ${id}`,
			structuredData: [{ id: 'run@1', params: { step: 'email', to: ME, file: filename } }]
		});

		// 3b. retrieve via IMAP and prove the attachment round-trips: the message must be
		// multipart/mixed, declare the attachment, and carry the base64 of the report bytes.
		const raw = await waitForMail(subject);
		expect(raw, 'report email with the attachment was not delivered').not.toBeNull();
		const body = dec(raw!);
		expect(body.toLowerCase()).toContain('multipart/mixed');
		expect(body).toContain(`filename="${filename}"`);
		expect(body.toLowerCase()).toContain('content-transfer-encoding: base64');
		// the builder wraps base64 at 76 cols; strip all whitespace, then assert our exact
		// unwrapped base64 of the pulled bytes is present -> the encoding round-trips byte-exact
		const flat = body.replace(/\s+/g, '');
		expect(flat).toContain(base64(pulled));

		// 4. close the syslog socket so the sink flushes, then assert the ORDERED run trail.
		await syslog.close();
		const captured = await waitFor(async () => {
			const text = await readSyslog();
			return text.includes(`emailed ${id}`) ? text : null;
		});
		expect(captured, 'syslog readback missing the report trail').not.toBeNull();
		const text = captured!;
		// each step is present, tagged with the unique id and the report-cron app-name
		expect(text).toContain(APP);
		for (const step of [
			`job-generated ${id}`,
			`pulled ${id}`,
			`checksum-ok ${id}`,
			`emailed ${id}`
		]) {
			expect(text).toContain(step);
		}
		// ORDER: generate -> pull -> checksum -> email, in that sequence on the wire
		const order = [`job-generated ${id}`, `pulled ${id}`, `checksum-ok ${id}`, `emailed ${id}`];
		let cursor = -1;
		for (const step of order) {
			const at = text.indexOf(step);
			expect(at, `step out of order: ${step}`).toBeGreaterThan(cursor);
			cursor = at;
		}
		// the checksum SD param made it onto the wire intact
		expect(text).toContain(`sha256="${localHash}"`);
	});

	it('detects a failed report job: captures the non-zero exit, alerts via email + error syslog', async () => {
		const id = uniqueId('report-fail');
		const subject = `report FAILED ${id}`;

		await using ssh = await sshConnect(sshBase);

		// 1 (failure path). a report job that errors out then exits non-zero. assert the exit
		// code is captured and the 'generated' success marker is absent.
		const failed = await ssh.exec(`echo "report build error [${id}]" 1>&2; exit 3`);
		expect(failed.code).toBe(3);
		expect(dec(failed.stdout)).not.toContain('generated');
		expect(dec(failed.stderr)).toContain(id);

		// 5. failure alerting: log an error-severity line AND send a failure-alert email.
		await using syslog = await openSyslog();
		await syslog.log({
			severity: Severity.error,
			message: `report FAILED ${id} exit=${failed.code}`,
			structuredData: [{ id: 'run@1', params: { step: 'failed', exit: String(failed.code) } }]
		});

		{
			await using smtp = await openSmtp();
			const res = await smtp.send({
				from: ME,
				to: ME,
				subject,
				text: `The scheduled report job failed.\n\nid=${id}\nexit=${failed.code}\nstderr=${dec(failed.stderr).trim()}`
			});
			expect(res.accepted).toContain(ME);
		}

		// the alert email lands via IMAP, carrying the unique id and the 'report FAILED' marker
		const raw = await waitForMail(subject);
		expect(raw, 'failure-alert email was not delivered').not.toBeNull();
		const body = dec(raw!);
		expect(body).toContain(id);
		expect(body).toContain('report FAILED');
		expect(body).toContain('exit=3');

		// the error-severity line is in the syslog readback (PRI for user.error = 3 -> <11>1)
		await syslog.close();
		const captured = await waitFor(async () => {
			const text = await readSyslog();
			return text.includes(`report FAILED ${id}`) ? text : null;
		});
		expect(captured, 'error-severity syslog line was not captured').not.toBeNull();
		expect(captured!).toContain(`report FAILED ${id} exit=3`);
		expect(captured!).toContain('<11>1 ');
	});
});
