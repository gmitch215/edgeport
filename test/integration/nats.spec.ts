import { expect, it } from 'vitest';
import { connect } from '../../src/nats/index';

const base = { hostname: '127.0.0.1', port: 4222, username: 'tester', password: 'testpass' };
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

it('publishes and receives on a subscription', async () => {
	await using nc = await connect(base);
	const sub = nc.subscribe('greet');
	const it = sub[Symbol.asyncIterator]();
	await nc.publish('greet', 'hello-nats');
	const { value } = await it.next();
	expect(dec(value!.data)).toBe('hello-nats');
});

it('request-reply round-trips through an inbox', async () => {
	await using nc = await connect(base);
	const svc = nc.subscribe('svc.echo');

	// responder loop
	void (async () => {
		for await (const m of svc) {
			if (m.reply) await nc.publish(m.reply, m.data);
			break;
		}
	})();
	const reply = await nc.request('svc.echo', 'ping', { timeoutMs: 3000 });
	expect(dec(reply.data)).toBe('ping');
});

it('rejects bad credentials with AuthError', async () => {
	await expect(connect({ ...base, password: 'wrong' })).rejects.toBeTruthy();
});
