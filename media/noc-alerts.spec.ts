// recipe: an IRC NOC alert bridge. a monitor bot discovers a service endpoint over DNS
// (edgeport/dns), announces its status to an IRC ops channel where on-call sees it live, audits
// the alert to Syslog, and emails a digest over SMTP (verified over IMAP). uses IRC + DNS + Syslog
// + SMTP together.
//
// PLAINTEXT NOTE: ergo is plaintext on 6667 (workerd rejects self-signed tls); coredns answers over
// tcp on 5354; greenmail smtp/imap use tls:'off'; syslog 5514 ingest / 5515 readback. SHARED-SERVER
// NOTE: ergo, greenmail, and the syslog file are shared, so nicks/channels/subjects are per-run.
import { describe, expect, it } from 'vitest';
import { resolve4, resolveSrv } from '../../../src/dns/index';
import { connect as ircConnect, type IrcSession } from '../../../src/irc/index';
import { send as smtpSend } from '../../../src/smtp/index';
import { connect as syslogConnect } from '../../../src/syslog/index';
import { uniqueId, waitForLog, waitForMail } from './_helpers';

const HOST = '127.0.0.1';
const DNS = { server: HOST, port: 5354 };
const IRC_PORT = 6667;
const SMTP_PORT = 3025;
const SYSLOG_PORT = 5514;
const OPS = 'tester@localhost';
const mailAuth = { username: 'tester', password: 'testpass' };

function uniqNick(prefix: string): string {
	return `${prefix}${Math.floor(Math.random() * 1e6).toString(36)}`;
}

function client(nick: string): Promise<IrcSession> {
	return ircConnect({ hostname: HOST, port: IRC_PORT, tls: 'off', nick, timeoutMs: 10_000 });
}

// polls fn until predicate holds (or tries run out); returns the last value
async function until<T>(fn: () => Promise<T>, ok: (v: T) => boolean, tries = 20): Promise<T> {
	let last!: T;
	for (let i = 0; i < tries; i++) {
		last = await fn();
		if (ok(last)) return last;
		await new Promise((r) => setTimeout(r, 250));
	}
	return last;
}

describe('recipe: IRC NOC alert bridge (IRC + DNS + Syslog + SMTP)', () => {
	// 1. a DNS-discovered service status is announced to the ops channel; on-call receives it live
	it('announces a DNS-discovered endpoint to an IRC ops channel that on-call receives', async () => {
		const runId = uniqueId('noc');
		const chan = `#noc-${runId}`;
		const botNick = uniqNick('noc');
		const oncallNick = uniqNick('oncall');
		await using bot = await client(botNick);
		await using oncall = await client(oncallNick);

		await bot.join(chan);
		await oncall.join(chan);
		await until(
			() => bot.names(chan),
			(m) => m.includes(botNick) && m.includes(oncallNick)
		);

		// discovery over dns drives what the bot reports
		const [ip] = await resolve4('sip.edgeport.test', DNS);
		expect(ip).toBe('10.0.1.60');
		const srv = await resolveSrv('_sip._tcp.edgeport.test', DNS);
		const port = srv[0]?.port;

		const inbox = oncall.messages()[Symbol.asyncIterator]();
		const alert = `ALERT ${runId} sip.edgeport.test -> ${ip}:${port} DEGRADED`;
		await bot.say(chan, alert);

		const { value } = await inbox.next();
		expect(value!.text).toBe(alert);
		expect(value!.text).toContain(ip);
		expect(value!.isChannel).toBe(true);
	});

	// 2. the same alert is audited to syslog and an email digest is delivered to ops (over IMAP)
	it('audits the alert to syslog and emails a digest delivered to ops', async () => {
		const runId = uniqueId('noc-digest');
		const [ip] = await resolve4('sip.edgeport.test', DNS);

		await using log = await syslogConnect({
			hostname: HOST,
			port: SYSLOG_PORT,
			tls: 'off',
			appName: 'noc-bridge',
			procId: runId
		});
		await log.error(`noc-alert ${runId} sip.edgeport.test ip=${ip} state=DEGRADED`);

		const audit = await waitForLog(runId, [`noc-alert ${runId}`]);
		expect(audit, 'the alert should be audited to syslog').not.toBeNull();

		await smtpSend({
			hostname: HOST,
			port: SMTP_PORT,
			tls: 'off',
			auth: mailAuth,
			from: OPS,
			to: OPS,
			subject: `${runId} NOC digest`,
			text: `NOC digest for ${runId}: sip.edgeport.test at ${ip} is DEGRADED`
		});

		const body = await waitForMail(runId);
		expect(body, 'the NOC digest should be delivered').not.toBeNull();
		expect(body!).toContain(ip);
	});
});
