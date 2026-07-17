// recipe: an XMPP chatops deploy bot. an operator sends a chat command to the bot's JID; the bot
// runs it over SSH on the target box, streams the result back over XMPP, audits the action to
// Syslog, and emails ops over SMTP when the command fails (verified over IMAP). uses XMPP + SSH +
// Syslog + SMTP together.
//
// PLAINTEXT NOTE: ejabberd c2s is plaintext SASL PLAIN on 5222 (workerd rejects the self-signed
// STARTTLS cert); openssh is password auth on 2222; greenmail smtp/imap use tls:'off'; syslog 5514.
// SHARED-SERVER NOTE: tester/tester2 accounts, the openssh box, and greenmail are shared, so each
// test uses distinct resources and a uniqueId() marker.
import { describe, expect, it } from 'vitest';
import { send as smtpSend } from '../../../src/smtp/index';
import { connect as sshConnect } from '../../../src/ssh/index';
import { connect as syslogConnect } from '../../../src/syslog/index';
import { connect as xmppConnect, type XmppSession } from '../../../src/xmpp/index';
import { uniqueId, waitForLog, waitForMail } from './_helpers';

const HOST = '127.0.0.1';
const DOMAIN = 'localhost';
const XMPP_PORT = 5222;
const SSH = { hostname: HOST, port: 2222, username: 'tester', password: 'testpass' };
const SMTP_PORT = 3025;
const SYSLOG_PORT = 5514;
const OPS = 'tester@localhost';
const mailAuth = { username: 'tester', password: 'testpass' };

// SASL PLAIN over the plaintext c2s stream (mirrors the xmpp integration spec)
function login(user: string, resource: string): Promise<XmppSession> {
	return xmppConnect({
		hostname: HOST,
		port: XMPP_PORT,
		domain: DOMAIN,
		jid: `${user}@${DOMAIN}`,
		password: 'testpass',
		resource,
		mechanisms: 'PLAIN',
		tls: 'off',
		timeoutMs: 10_000
	});
}

// reads the next stanza from an async iterator with a deadline so a miss fails fast
async function nextWithin<T>(iter: AsyncIterator<T>, ms: number): Promise<T> {
	const timeout = new Promise<never>((_, reject) =>
		setTimeout(() => reject(new Error('timed out waiting for stanza')), ms)
	);
	const { value, done } = await Promise.race([iter.next(), timeout]);
	if (done) throw new Error('iterator ended');
	return value;
}

describe('recipe: XMPP chatops deploy bot (XMPP + SSH + Syslog + SMTP)', () => {
	// 1. a chat command drives an SSH exec; the bot replies with the output and audits it
	it('runs an SSH command from an XMPP chat command and replies with the output', async () => {
		const runId = uniqueId('chatops');
		await using bot = await login('tester', `bot-${runId}`);
		await using op = await login('tester2', `op-${runId}`);
		await bot.setPresence('online');
		await op.setPresence('online');

		await using log = await syslogConnect({
			hostname: HOST,
			port: SYSLOG_PORT,
			tls: 'off',
			appName: 'chatops',
			procId: runId
		});
		await using ssh = await sshConnect(SSH);

		// the bot handles one `run: <cmd>` command: exec over ssh, audit, reply to the sender
		const botLoop = (async () => {
			for await (const msg of bot.messages()) {
				if (!msg.body.startsWith('run:')) continue;
				const cmd = msg.body.slice('run:'.length).trim();
				const res = await ssh.exec(cmd);
				await log.info(`chatops ${runId} from=${msg.from} code=${res.code}`);
				await bot.send({
					to: msg.from,
					body: `exit ${res.code}: ${res.stdoutText.trim()}`
				});
				return;
			}
		})();

		const inbox = op.messages()[Symbol.asyncIterator]();
		await op.send({ to: `tester@${DOMAIN}`, body: `run: echo deployed-${runId}` });

		const reply = await nextWithin(inbox, 10_000);
		expect(reply.body).toContain('exit 0');
		expect(reply.body).toContain(`deployed-${runId}`);
		await botLoop;

		const audit = await waitForLog(runId, [`chatops ${runId}`]);
		expect(audit, 'the chatops action should be audited to syslog').not.toBeNull();
	});

	// 2. a failing command triggers an emailed alert to ops (delivered over IMAP)
	it('emails ops when the SSH command fails', async () => {
		const runId = uniqueId('chatops-fail');
		await using bot = await login('tester', `bot2-${runId}`);
		await using op = await login('tester2', `op2-${runId}`);
		await bot.setPresence('online');
		await op.setPresence('online');
		await using ssh = await sshConnect(SSH);

		const botLoop = (async () => {
			for await (const msg of bot.messages()) {
				if (!msg.body.startsWith('run:')) continue;
				const cmd = msg.body.slice('run:'.length).trim();
				const res = await ssh.exec(cmd);
				if (res.code !== 0) {
					await smtpSend({
						hostname: HOST,
						port: SMTP_PORT,
						tls: 'off',
						auth: mailAuth,
						from: OPS,
						to: OPS,
						subject: `${runId} deploy failed`,
						text: `command "${cmd}" failed with code ${res.code} for run ${runId}`
					});
				}
				await bot.send({ to: msg.from, body: `exit ${res.code}` });
				return;
			}
		})();

		const inbox = op.messages()[Symbol.asyncIterator]();
		await op.send({ to: `tester@${DOMAIN}`, body: `run: sh -c "exit 3"` });

		const reply = await nextWithin(inbox, 10_000);
		expect(reply.body).toContain('exit 3');
		await botLoop;

		const body = await waitForMail(runId);
		expect(body, 'the failure alert should be delivered to ops').not.toBeNull();
		expect(body!).toContain('failed with code 3');
	});
});
