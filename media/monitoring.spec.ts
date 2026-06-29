// recipe: passive-FTP-behind-NAT monitoring - the parts of passive FTP that actually break
// in production, wired to Syslog (audit trail) and SMTP (failure alerting).
//
// passive FTP is the only mode the Workers runtime can speak (no inbound sockets, so no PORT),
// and the module proves it: openPassive() prefers EPSV (RFC 2428) and falls back to PASV (RFC
// 959). that negotiation is INTERNAL - the public FtpSession exposes no PASV-vs-EPSV switch and
// no transfer-mode observable - so we cannot assert which one fired from the public surface; we
// exercise the real round-trips it produces and note the EPSV-first behavior in comments where
// it matters. there is likewise NO REST/offset resume on the public API (no offset param on
// get/getStream/put), so the "resume after a dropped data channel" case is simulated at the
// application level (re-store the whole object) and clearly marked.
//
// the docker passive data-port range is 40000-40009 (10 ports) and is SHARED with every other
// suite, so this file drives data transfers SEQUENTIALLY and never fans out concurrent data
// channels. limited concurrency, where attempted, treats a data-connection failure as an alert,
// not a test failure.
//
// SMTP: greenmail 3025 is plaintext, which the public smtp.connect() cannot produce (it only
// maps tls to 'on'/'starttls'); we drive _sessionFromSocket over a tls:'off' core socket with
// tls:'implicit' (skip the STARTTLS upgrade) - the same pattern mail.spec.ts uses.
import { describe, expect, it } from 'vitest';
import { connect as coreConnect } from '../../../src/core/socket';
import { connect as ftpConnect } from '../../../src/ftp/index';
import { _sessionFromSocket as smtpSessionFromSocket } from '../../../src/smtp/index';
import { Facility, Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { artifact, readSyslog, uniqueId, waitFor } from './_helpers';

const HOST = '127.0.0.1';
const FTP_PORT = 21;
const SYSLOG_PORT = 5514;
const SMTP_PORT = 3025;
const ME = 'tester@localhost';
const ftpAuth = { username: 'tester', password: 'testpass' };
const smtpAuth = { username: 'tester', password: 'testpass' };

// opens the plaintext syslog audit channel; Facility.ftp keeps these events self-labelling
async function openSyslog(runId: string) {
	return syslogConnect({
		hostname: HOST,
		port: SYSLOG_PORT,
		appName: 'ftp-monitor',
		procId: runId
	});
}

// opens a plaintext SMTP submission session on greenmail (see header note on why _sessionFromSocket)
async function openSmtp() {
	const socket = await coreConnect({ hostname: HOST, port: SMTP_PORT, tls: 'off' });
	return smtpSessionFromSocket(socket, { hostname: HOST, tls: 'implicit', auth: smtpAuth });
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

describe('recipe: passive-FTP-behind-NAT monitoring (FTP + Syslog + SMTP)', () => {
	// 1. PASV/EPSV negotiation: a byte-exact passive upload+download round-trip.
	it('round-trips a file over a passive data channel and audits it', async () => {
		const runId = uniqueId('mon-pasv');
		await using log = await openSyslog(runId);
		await using ftp = await ftpConnect({ ...ftpAuth, hostname: HOST, port: FTP_PORT });

		const path = `${runId}.bin`;
		const payload = artifact(4096);

		// upload then download; openPassive() negotiates EPSV-first, PASV-fallback internally.
		// the public API exposes no mode observable, so we assert the transfer is byte-exact
		// (which is what NAT/ALG breakage would corrupt or stall in production) rather than the mode.
		await ftp.put(path, payload);
		const got = await ftp.get(path);
		expect(got.length).toBe(payload.length);
		expect(got).toEqual(payload);

		await ftp.delete(path);
		await log.log({
			severity: Severity.info,
			facility: Facility.ftp,
			message: `pasv-transfer-ok ${runId} bytes=${payload.length}`,
			structuredData: [{ id: 'ftp@mon', params: { run: runId, op: 'roundtrip' } }]
		});

		const audit = await waitForAudit(runId, ['pasv-transfer-ok']);
		expect(audit, 'pasv round-trip should be audited').not.toBeNull();
	});

	// 2. passive port-range pressure: SEVERAL sequential transfers exercise port reuse/cycling
	// across the 10-port range (40000-40009) without ever opening concurrent data channels.
	it('survives sequential transfers that cycle the shared passive port range', async () => {
		const runId = uniqueId('mon-cycle');
		await using log = await openSyslog(runId);
		await using ftp = await ftpConnect({ ...ftpAuth, hostname: HOST, port: FTP_PORT });

		const rounds = 8;
		const paths: string[] = [];
		for (let i = 0; i < rounds; i++) {
			const path = `${runId}-${i}.bin`;
			// vary the size so each cycle is a distinct payload, not a cached no-op
			const payload = artifact(512 + i * 37);
			await ftp.put(path, payload);
			const got = await ftp.get(path);
			expect(got, `round ${i} should round-trip byte-exact`).toEqual(payload);
			paths.push(path);
			await log.log({
				severity: Severity.info,
				facility: Facility.ftp,
				message: `cycle-transfer-ok ${runId} round=${i}`,
				structuredData: [{ id: 'ftp@mon', params: { run: runId, round: String(i) } }]
			});
		}

		// cleanup; tolerate a missing file so cleanup never fails the assertion above
		for (const path of paths) await ftp.delete(path).catch(() => {});

		// every round must have been audited, in order, all of them
		const markers = Array.from(
			{ length: rounds },
			(_, i) => `cycle-transfer-ok ${runId} round=${i}`
		);
		const audit = await waitForAudit(runId, markers);
		expect(audit, 'all sequential cycles should be audited in order').not.toBeNull();
	});

	// 3. REST/resume after a dropped data channel, using real RFC 959 REST offset resume.
	it('recovers a dropped transfer via REST offset resume', async () => {
		const runId = uniqueId('mon-resume');
		await using log = await openSyslog(runId);
		await using ftp = await ftpConnect({ ...ftpAuth, hostname: HOST, port: FTP_PORT });

		const path = `${runId}.bin`;
		const full = artifact(8192);
		const cut = 3000; // where the data channel "dropped"

		// 1) a transfer that "drops" mid-stream - model the drop as a partial upload
		await ftp.put(path, full.subarray(0, cut));
		const afterDrop = await ftp.get(path);
		expect(afterDrop.length).toBe(cut);
		await log.log({
			severity: Severity.warning,
			facility: Facility.ftp,
			message: `transfer-dropped ${runId} at=${cut}`
		});

		// 2) resume the upload from the partial size via REST (append the remaining bytes), then
		// verify the recovered file is byte-exact - the real production resume, not a full re-store
		await ftp.put(path, full.subarray(cut), { append: true });
		const resumed = await ftp.get(path);
		expect(resumed.length).toBe(full.length);
		expect(resumed).toEqual(full);
		// and a partial download via REST offset returns exactly the tail
		const tail = await ftp.get(path, { offset: cut });
		expect(tail).toEqual(full.subarray(cut));

		await ftp.delete(path).catch(() => {});
		await log.log({
			severity: Severity.notice,
			facility: Facility.ftp,
			message: `resume-ok ${runId} bytes=${full.length}`
		});

		const audit = await waitForAudit(runId, ['transfer-dropped', 'resume-ok']);
		expect(audit, 'drop + resume should both be audited in order').not.toBeNull();
	});

	// 4. control-connection behavior during a large transfer: a larger payload must not wedge the
	// control channel - after it completes, a follow-up command on the SAME session must succeed.
	it('keeps the control connection usable after a large data transfer', async () => {
		const runId = uniqueId('mon-large');
		await using log = await openSyslog(runId);
		await using ftp = await ftpConnect({
			...ftpAuth,
			hostname: HOST,
			port: FTP_PORT,
			timeoutMs: 30_000
		});

		const path = `${runId}.bin`;
		const big = artifact(200_000);
		await ftp.put(path, big);

		// SIZE + a streamed download exercise the control channel both before and around a second
		// data channel; getStream() is the module's large-payload path (it owns its data conn).
		const reported = await ftp.size(path);
		expect(reported).toBe(big.length);

		const stream = await ftp.getStream(path);
		let received = 0;
		const reader = stream.getReader();
		for (;;) {
			const { value, done } = await reader.read();
			if (done) break;
			if (value) received += value.length;
		}
		expect(received).toBe(big.length);

		// the decisive assertion: the control connection is still alive and answers a fresh command
		const listing = await ftp.list();
		expect(listing.some((e) => e.name === path)).toBe(true);

		await ftp.delete(path).catch(() => {});
		await log.log({
			severity: Severity.info,
			facility: Facility.ftp,
			message: `large-transfer-ok ${runId} bytes=${big.length} control=alive`
		});

		const audit = await waitForAudit(runId, ['large-transfer-ok']);
		expect(audit, 'large transfer + live control should be audited').not.toBeNull();
	});

	// 5. failure alerting: a stalled/failed transfer (GET of a path that does not exist) is caught,
	// logged to Syslog at alert severity, and emailed via SMTP. the email send must succeed.
	it('catches a failed transfer, audits it, and sends an SMTP alert', async () => {
		const runId = uniqueId('mon-fail');
		await using log = await openSyslog(runId);
		await using ftp = await ftpConnect({ ...ftpAuth, hostname: HOST, port: FTP_PORT });

		const missing = `${runId}-does-not-exist.bin`;
		let failure: unknown;
		try {
			// RETR on a nonexistent path -> the server rejects with a 5xx the module maps to an error
			await ftp.get(missing);
		} catch (err) {
			failure = err;
		}
		expect(failure, 'GET of a missing path must throw').toBeTruthy();

		// audit the failure at alert severity
		await log.log({
			severity: Severity.alert,
			facility: Facility.ftp,
			message: `transfer-failed ${runId} path=${missing} err=${(failure as Error).message}`,
			structuredData: [{ id: 'ftp@mon', params: { run: runId, op: 'retr', outcome: 'failed' } }]
		});

		// alert by email; subject carries the runId + the required phrase. the control connection
		// is still healthy after the failure, so we can keep using ftp below the alert if needed.
		const subject = `${runId} FTP transfer failed`;
		await using smtp = await openSmtp();
		const sent = await smtp.send({
			from: ME,
			to: ME,
			subject,
			text: `Passive FTP transfer failed for run ${runId}: ${missing}. control connection still alive.`
		});
		expect(sent.accepted, 'alert email must be accepted by the server').toContain(ME);

		// record that the alert went out
		await log.log({
			severity: Severity.notice,
			facility: Facility.ftp,
			message: `alert-sent ${runId} subject=${JSON.stringify(subject)}`
		});

		const audit = await waitForAudit(runId, ['transfer-failed', 'alert-sent']);
		expect(audit, 'failure + alert should both be audited in order').not.toBeNull();
	});

	// 6. end-to-end audit: one run does an ok transfer, a failure + alert, and the syslog audit
	// must show the monitoring lifecycle in order: transfer-ok -> failure -> alert-sent.
	it('produces an ordered transfer-ok -> failure -> alert-sent audit trail', async () => {
		const runId = uniqueId('mon-audit');
		await using log = await openSyslog(runId);
		await using ftp = await ftpConnect({ ...ftpAuth, hostname: HOST, port: FTP_PORT });

		// (a) a good transfer
		const okPath = `${runId}.bin`;
		const payload = artifact(2048);
		await ftp.put(okPath, payload);
		const got = await ftp.get(okPath);
		expect(got).toEqual(payload);
		await ftp.delete(okPath).catch(() => {});
		await log.log({
			severity: Severity.info,
			facility: Facility.ftp,
			message: `transfer-ok ${runId}`
		});

		// (b) a failure
		let failed = false;
		try {
			await ftp.get(`${runId}-missing.bin`);
		} catch {
			failed = true;
		}
		expect(failed).toBe(true);
		await log.log({
			severity: Severity.alert,
			facility: Facility.ftp,
			message: `failure ${runId}`
		});

		// (c) the alert email
		const subject = `${runId} FTP transfer failed`;
		await using smtp = await openSmtp();
		const sent = await smtp.send({
			from: ME,
			to: ME,
			subject,
			text: `monitoring alert for ${runId}`
		});
		expect(sent.accepted).toContain(ME);
		await log.log({
			severity: Severity.notice,
			facility: Facility.ftp,
			message: `alert-sent ${runId}`
		});

		// the ordered lifecycle must appear in the syslog audit, scoped to this run
		const audit = await waitForAudit(runId, [
			`transfer-ok ${runId}`,
			`failure ${runId}`,
			`alert-sent ${runId}`
		]);
		expect(audit, 'ordered monitoring lifecycle should be in the audit').not.toBeNull();
		// the alert line names the failed run id, tying the email back to the event
		expect(audit!).toContain(`alert-sent ${runId}`);
	});
});
