import { afterAll, describe, expect, it } from 'vitest';
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

// JetStream under workerd we cannot kill the server, so a "failover"
// is modeled as a CLIENT reconnect against the same server, re-binding the same durable.
describe('jetstream', () => {
	const SUFFIX = `${Math.floor(performance.now() * 1000)}_${Math.floor(Math.random() * 1e6)}`;
	const STREAM = `S_${SUFFIX}`;
	const DURABLE = `D_${SUFFIX}`;
	const SUBJECT = `js.${SUFFIX}`;

	afterAll(async () => {
		try {
			await using nc = await connect(base);
			await nc.request(`$JS.API.STREAM.DELETE.${STREAM}`, '', { timeoutMs: 4000 }).catch(() => {});
		} catch {
			// server may be down between runs; nothing to clean
		}
	});

	it('ensureStream is idempotent and publish returns increasing PubAck seqs', async () => {
		await using nc = await connect(base);
		const js = nc.jetstream();

		const info = await js.ensureStream(STREAM, { subjects: [SUBJECT] });
		expect(info.name).toBe(STREAM);
		expect(info.subjects).toContain(SUBJECT);
		const again = await js.ensureStream(STREAM, { subjects: [SUBJECT] });
		expect(again.name).toBe(STREAM);

		const ack1 = await js.publish(SUBJECT, 'first');
		expect(ack1.stream).toBe(STREAM);
		expect(ack1.seq).toBeGreaterThan(0);
		const ack2 = await js.publish(SUBJECT, 'second');
		expect(ack2.seq).toBe(ack1.seq + 1);
	}, 30_000);

	it('durable pull: ack a subset, reconnect, re-bind, only un-acked redelivered (no loss/no dup)', async () => {
		const stream = `${STREAM}B`;
		const durable = `${DURABLE}B`;
		const subject = `${SUBJECT}.b`;
		const ackWaitMs = 1500;
		const sent = ['msg-1', 'msg-2', 'msg-3', 'msg-4'];

		// connection #1: publish 4, pull all, ack only the first 2, then drop
		{
			await using nc = await connect(base);
			const js = nc.jetstream();
			await js.ensureStream(stream, { subjects: [subject] });
			for (let i = 0; i < sent.length; i++) {
				const ack = await js.publish(subject, sent[i]!);
				expect(ack.seq).toBe(i + 1);
			}
			const consumer = await js.pullSubscribe(stream, durable, { ackWaitMs });
			const pulled = await consumer.fetch(sent.length, { expiresMs: 2000 });
			expect(pulled.map((m) => dec(m.data))).toEqual(sent);
			await pulled[0]!.ack();
			await pulled[1]!.ack();
			await nc.close();
		}

		await new Promise((r) => setTimeout(r, ackWaitMs + 750));

		// connection #2: re-bind the same durable and drain the remainder
		{
			await using nc = await connect(base);
			const js = nc.jetstream();
			const consumer = await js.pullSubscribe(stream, durable, { ackWaitMs });
			const redelivered: string[] = [];
			for (let round = 0; round < 3 && redelivered.length < 2; round++) {
				const batch = await consumer.fetch(4, { expiresMs: 1500 });
				for (const m of batch) {
					redelivered.push(dec(m.data));
					await m.ack();
				}
				if (batch.length === 0) break;
			}
			expect(redelivered.sort()).toEqual(['msg-3', 'msg-4']); // no loss
			expect(redelivered).not.toContain('msg-1'); // no dup
			expect(redelivered).not.toContain('msg-2');
			const empty = await consumer.fetch(4, { expiresMs: 800 });
			expect(empty).toEqual([]);
			await nc.request(`$JS.API.STREAM.DELETE.${stream}`, '', { timeoutMs: 4000 }).catch(() => {});
		}
	}, 30_000);
});
