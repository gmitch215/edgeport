// recipe: an automatic DNS recovery agent. a scheduled Worker discovers a service endpoint over
// DNS (edgeport/dns), probes its health over SSH, runs a recovery command when it is down,
// re-confirms it is up, writes an ordered audit trail to Syslog, and emails ops the before/after
// over SMTP (verified here by reading it back over IMAP). uses DNS + SSH + Syslog + SMTP together.
//
// PLAINTEXT NOTE: coredns answers over tcp on 5354; openssh is password auth on 2222; greenmail
// smtp/imap use tls:'off' (workerd rejects the self-signed tls cert); syslog 5514 ingest / 5515
// readback. SHARED-SERVER NOTE: the openssh box, greenmail, and the syslog file are shared across
// suites, so every test scopes its state (marker file, subject, log line) to a uniqueId().
import { describe, expect, it } from 'vitest';
import { resolve4, resolveMx, resolveSrv } from '../../../src/dns/index';
import { send as smtpSend } from '../../../src/smtp/index';
import { connect as sshConnect } from '../../../src/ssh/index';
import { Facility, Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { uniqueId, waitForLog, waitForMail } from './_helpers';

const HOST = '127.0.0.1';
const DNS = { server: HOST, port: 5354 };
const SSH = { hostname: HOST, port: 2222, username: 'tester', password: 'testpass' };
const SMTP_PORT = 3025;
const SYSLOG_PORT = 5514;
const OPS = 'tester@localhost';
const mailAuth = { username: 'tester', password: 'testpass' };

describe('recipe: automatic DNS recovery agent (DNS + SSH + Syslog + SMTP)', () => {
	// 1. service discovery: the agent resolves where the service lives before touching it
	it('discovers the service endpoint over DNS', async () => {
		const ips = await resolve4('host.edgeport.test', DNS);
		expect(ips).toContain('93.184.216.34');

		const mx = await resolveMx('edgeport.test', DNS);
		expect(mx.some((r) => r.exchange.includes('mail.edgeport.test'))).toBe(true);

		const srv = await resolveSrv('_sip._tcp.edgeport.test', DNS);
		expect(srv[0]?.port).toBe(5060);
	});

	// 2. the recovery loop: probe health over ssh (down) -> run recovery -> re-probe (up), with an
	// ordered audit trail landing in syslog for every stage.
	it('detects a down service over SSH, recovers it, confirms healthy, and audits to syslog', async () => {
		const runId = uniqueId('dns-recover');
		const marker = `/tmp/edgeport-health-${runId}`;
		const probe = `test -f ${marker} && echo UP || echo DOWN`;

		const [ip] = await resolve4('host.edgeport.test', DNS);
		expect(ip).toBe('93.184.216.34');

		await using log = await syslogConnect({
			hostname: HOST,
			port: SYSLOG_PORT,
			tls: 'off',
			appName: 'dns-recovery',
			procId: runId
		});
		await using ssh = await sshConnect(SSH);

		// health probe: the marker is absent, so the service reports DOWN
		const before = await ssh.exec(probe);
		expect(before.stdoutText.trim()).toBe('DOWN');
		await log.log({
			severity: Severity.warning,
			facility: Facility.daemon,
			message: `health-down ${runId} host=host.edgeport.test ip=${ip}`
		});

		// recovery action (a real agent would re-apply config / restart the unit; here: touch the marker)
		const fix = await ssh.exec(`touch ${marker}`);
		expect(fix.code).toBe(0);
		await log.log({
			severity: Severity.notice,
			facility: Facility.daemon,
			message: `recovery-run ${runId} action=touch`
		});

		// confirm healthy
		const after = await ssh.exec(probe);
		expect(after.stdoutText.trim()).toBe('UP');
		await log.log({
			severity: Severity.info,
			facility: Facility.daemon,
			message: `health-up ${runId} recovered=1`
		});

		const audit = await waitForLog(runId, [
			`health-down ${runId}`,
			`recovery-run ${runId}`,
			`health-up ${runId}`
		]);
		expect(audit, 'the full recovery audit trail should be in syslog').not.toBeNull();

		// leave the shared box as we found it
		await ssh.exec(`rm -f ${marker}`);
	});

	// 3. the notification: ops gets an emailed before/after report, delivered for real
	it('emails ops a recovery report that is delivered (verified over IMAP)', async () => {
		const runId = uniqueId('dns-recover-mail');
		const [ip] = await resolve4('host.edgeport.test', DNS);
		await smtpSend({
			hostname: HOST,
			port: SMTP_PORT,
			tls: 'off',
			auth: mailAuth,
			from: OPS,
			to: OPS,
			subject: `${runId} recovery report`,
			text: `service host.edgeport.test (${ip}) was DOWN and has been recovered to UP for run ${runId}`
		});

		const body = await waitForMail(runId);
		expect(body, 'the recovery report should be delivered').not.toBeNull();
		expect(body!).toContain(ip);
		expect(body!).toContain('recovered');
	});
});
