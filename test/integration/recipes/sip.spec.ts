// recipe: SIP messaging with an audit trail
import { describe, expect, it } from 'vitest';
import { connect as sipConnect, type SipScheduler } from '../../../src/sip/index';
import { connect as syslogConnect } from '../../../src/syslog/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const HOST = '127.0.0.1';
const SIP_PORT = 5060;
const SIP_DOMAIN = 'edgeport.test';
const SYSLOG_PORT = 5514;
const PASSWORD = 'testpass';

// no real refresh/keep-alive timers during the test
const noScheduler: SipScheduler = { set: () => 0, clear: () => {} };

function ua(username: string) {
	return sipConnect({
		hostname: HOST,
		port: SIP_PORT,
		domain: SIP_DOMAIN,
		username,
		password: PASSWORD,
		scheduler: noScheduler,
		timeoutMs: 10_000
	});
}

async function openSyslog(runId: string) {
	return syslogConnect({ hostname: HOST, port: SYSLOG_PORT, appName: 'sip-alerts', procId: runId });
}

async function waitForAudit(runId: string, markers: string[]): Promise<string | null> {
	return waitFor(
		async () => {
			const mine = (await readSyslog())
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

describe('recipe: SIP messaging with audit (SIP + Syslog)', () => {
	it('registers two endpoints, routes a MESSAGE, and audits the delivery', async () => {
		const runId = uniqueId('sip-alert');
		await using audit = await openSyslog(runId);
		await using oncall = await ua('alert-oncall');
		await using sender = await ua('alert-sender');

		await oncall.register();
		await sender.register();
		const inbox = oncall.messages()[Symbol.asyncIterator]();
		await audit.info(`sip-registered ${runId}`);

		// deliver the alert over SIP MESSAGE (digest-authenticated + routed by the proxy)
		const text = `ALERT ${runId} disk almost full`;
		const resp = await sender.message('alert-oncall', text);
		expect(resp.status).toBeGreaterThanOrEqual(200);
		expect(resp.status).toBeLessThan(300);
		await audit.info(`sip-sent ${runId}`);

		// the on-call endpoint receives it on its registered flow
		const { value } = await inbox.next();
		expect(value).toBeDefined();
		expect(value!.text()).toBe(text);
		expect(value!.from).toContain('alert-sender@edgeport.test');
		await audit.info(`sip-received ${runId}`);

		const trail = await waitForAudit(runId, [
			`sip-registered ${runId}`,
			`sip-sent ${runId}`,
			`sip-received ${runId}`
		]);
		expect(trail, 'register -> send -> receive should be audited in order').not.toBeNull();
	});
});
