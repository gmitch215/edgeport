import { describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/errors';
import { connect, sendMessage, type SipScheduler } from '../../src/sip/index';

const HOST = '127.0.0.1';
const PORT = 5060;
const DOMAIN = 'edgeport.test';
const PASSWORD = 'testpass';

// no real refresh/keep-alive timers during the short tests
const noScheduler: SipScheduler = { set: () => 0, clear: () => {} };

function ua(username: string, password = PASSWORD) {
	return connect({
		hostname: HOST,
		port: PORT,
		domain: DOMAIN,
		username,
		password,
		scheduler: noScheduler,
		timeoutMs: 10_000
	});
}

describe('sip against kamailio', () => {
	it('registers with digest auth (RFC 5626 outbound)', async () => {
		await using alice = await ua('alice');
		await alice.register();
		expect(alice.localUri).toBe('sip:alice@edgeport.test');
	});

	it('rejects a bad password with AuthError', async () => {
		await using bad = await ua('mallory', 'wrongpass');
		await expect(bad.register()).rejects.toBeInstanceOf(AuthError);
	});

	it('routes a MESSAGE between two registered users (send + receive)', async () => {
		await using sender = await ua('sender');
		await using recipient = await ua('recipient');
		await sender.register();
		await recipient.register();

		const inbox = recipient.messages()[Symbol.asyncIterator]();
		const text = `hello recipient ${Date.now()}`;
		const resp = await sender.message('recipient', text);
		expect(resp.status).toBeGreaterThanOrEqual(200);
		expect(resp.status).toBeLessThan(300);

		const { value } = await inbox.next();
		expect(value).toBeDefined();
		expect(value!.text()).toBe(text);
		expect(value!.from).toContain('sender@edgeport.test');
	});

	it('probes capabilities with OPTIONS', async () => {
		await using alice = await ua('optprobe');
		await alice.register();
		const res = await alice.options();
		expect(res.status).toBeGreaterThanOrEqual(200);
		expect(res.status).toBeLessThan(700);
	});

	it('sends a one-shot MESSAGE to a registered peer', async () => {
		// keep a registered recipient open so the proxy has a flow to route to
		await using peer = await ua('oneshotpeer');
		await peer.register();
		const inbox = peer.messages()[Symbol.asyncIterator]();

		const text = `one-shot ${Date.now()}`;
		const resp = await sendMessage({
			hostname: HOST,
			port: PORT,
			domain: DOMAIN,
			username: 'oneshotsender',
			password: PASSWORD,
			scheduler: noScheduler,
			timeoutMs: 10_000,
			to: 'oneshotpeer',
			text
		});
		expect(resp.status).toBeGreaterThanOrEqual(200);
		expect(resp.status).toBeLessThan(300);

		const { value } = await inbox.next();
		expect(value!.text()).toBe(text);
	});
});
