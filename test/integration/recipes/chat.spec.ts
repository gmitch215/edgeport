// recipe: realtime chat app combining ldap auth + wss handshake + nats routing + mqtt presence.
// no real chat server exists in docker, so the app layer is simulated in-test: ldap is the login
// gate, the ws-echo box stands in for a handshake/ack endpoint (it echoes our token frame back),
// nats core pub/sub with queue groups fans messages across chat servers, and an mqtt last-will
// models user presence going offline on an abrupt drop.
import { describe, expect, it } from 'vitest';
import { AuthError } from '../../../src/core/errors';
import { connect as ldapConnect } from '../../../src/ldap/index';
import { connect as mqttConnect } from '../../../src/mqtt/index';
import { connect as natsConnect } from '../../../src/nats/index';
import { connect as wsConnect } from '../../../src/ws/index';
import { uniqueId, waitFor } from './_helpers';

const dec = (b: Uint8Array) => new TextDecoder().decode(b);

const ldapAdmin = {
	hostname: '127.0.0.1',
	port: 389,
	bindDN: 'cn=admin,dc=example,dc=org',
	password: 'admin'
};
const natsBase = { hostname: '127.0.0.1', port: 4222, username: 'tester', password: 'testpass' };
const mqttBase = { hostname: '127.0.0.1', port: 1883 };
const WS_ECHO = 'ws://127.0.0.1:8081/.ws';

// derives a deterministic session token from a login id (the app would sign this; here it is plain)
function deriveToken(loginId: string): string {
	return `token:${loginId}`;
}

// scans the echo stream for a frame containing `needle`; the jmalloc echo box greets first
async function awaitEcho(
	ws: AsyncIterator<{ type: string; data: string | Uint8Array }>,
	needle: string,
	maxFrames = 6
): Promise<boolean> {
	for (let i = 0; i < maxFrames; i++) {
		const { value, done } = await ws.next();
		if (done || !value) return false;
		if (value.type === 'text' && (value.data as string).includes(needle)) return true;
	}
	return false;
}

describe('realtime chat: ldap auth + wss handshake + nats routing + mqtt presence', () => {
	// 1. login gate: a real ldap bind authenticates the user; a wrong password is rejected
	it('authenticates a user via ldap bind and rejects bad credentials', async () => {
		await using session = await ldapConnect(ldapAdmin);
		// a bound session can read the directory (proves the bind succeeded)
		const entries = await session.search({
			base: 'dc=example,dc=org',
			scope: 'base',
			filter: '(objectClass=*)'
		});
		expect(entries.length).toBeGreaterThan(0);

		// wrong password is an auth failure, not a transport one
		await expect(
			ldapConnect({ ...ldapAdmin, password: 'not-the-password' })
		).rejects.toBeInstanceOf(AuthError);
	});

	// 2. token handshake over ws: after ldap auth, send a hello frame carrying the session token and
	// assert the (echoed) ack returns it. the echo box has no real auth, so the echo stands in for
	// a server-side handshake/ack of the token.
	it('completes a token handshake over the websocket after login', async () => {
		await using login = await ldapConnect(ldapAdmin);
		expect(login).toBeTruthy(); // bound (login gate passed)

		const loginId = uniqueId('user');
		const token = deriveToken(loginId);
		const ws = await wsConnect(WS_ECHO);
		try {
			const hello = JSON.stringify({ type: 'hello', token });
			ws.send(hello);
			const acked = await awaitEcho(ws[Symbol.asyncIterator](), token);
			expect(acked).toBe(true);
		} finally {
			ws.close(1000, 'handshake done');
		}
	});

	// 3. message routing: two subscribers in the same queue group split the messages (each goes to
	// exactly one member, no duplication) with per-subscriber ordering preserved; a plain subscriber
	// on the same subject still sees every message.
	it('routes chat messages through nats queue groups with no duplication and ordered delivery', async () => {
		await using nc = await natsConnect(natsBase);
		const subject = `chat.room.${uniqueId('rm')}`;
		const queue = 'chat-servers';

		const qa = nc.subscribe(subject, { queue });
		const qb = nc.subscribe(subject, { queue });
		const plain = nc.subscribe(subject); // observer: not in the queue group

		const N = 12;
		// collectors record arrival order per subscriber so we can check ordering
		const aGot: number[] = [];
		const bGot: number[] = [];
		const plainGot: number[] = [];

		const collect = async (
			sub: AsyncIterable<{ data: Uint8Array }>,
			into: number[],
			want: number
		) => {
			for await (const m of sub) {
				into.push(Number(dec(m.data)));
				if (into.length >= want) break;
			}
		};

		const qaDone = collect(qa, aGot, N); // may stop early; guarded by waitFor below
		const qbDone = collect(qb, bGot, N);
		const plainDone = collect(plain, plainGot, N);

		// give the SUBs time to register on the server before publishing
		await new Promise((r) => setTimeout(r, 200));

		for (let i = 0; i < N; i++) {
			await nc.publish(subject, String(i));
		}

		// queue group: union of both members covers all N, with none delivered twice
		await waitFor(() => aGot.length + bGot.length >= N, 5000, 50);
		const union = [...aGot, ...bGot].sort((x, y) => x - y);
		expect(union).toEqual([...Array(N).keys()]);
		const seen = new Set(union);
		expect(seen.size).toBe(N); // no duplication across the group

		// per-subscriber ordering: each member's own messages arrive in publish order
		expect(aGot).toEqual([...aGot].sort((x, y) => x - y));
		expect(bGot).toEqual([...bGot].sort((x, y) => x - y));

		// the plain observer receives every message (full fan-out, ordered)
		await waitFor(() => plainGot.length >= N, 5000, 50);
		expect(plainGot).toEqual([...Array(N).keys()]);

		await qa.unsubscribe();
		await qb.unsubscribe();
		await plain.unsubscribe();
		await Promise.allSettled([qaDone, qbDone, plainDone]);
	});

	// 4. presence via mqtt last will: a user client registers an offline will; a presence subscriber
	// gets that will published when the user drops abruptly (close graceful:false).
	it('publishes an offline presence message via the mqtt last will on an abrupt disconnect', async () => {
		const presenceTopic = `presence/${uniqueId('user')}`;

		// subscriber watches the presence topic
		await using watcher = await mqttConnect({ ...mqttBase, clientId: uniqueId('watch') });
		const presenceSub = watcher.subscribe(presenceTopic, { qos: 1 });
		const offline: string[] = [];
		void (async () => {
			for await (const m of presenceSub) {
				offline.push(dec(m.payload));
			}
		})();

		// user connects with an offline will; let the SUBSCRIBE settle before we drop the user
		const user = await mqttConnect({
			...mqttBase,
			clientId: uniqueId('user-client'),
			will: { topic: presenceTopic, payload: 'offline', qos: 1, retain: false }
		});
		await new Promise((r) => setTimeout(r, 300));

		// abrupt drop (no DISCONNECT) makes the broker fire the will
		await user.close({ graceful: false });

		const got = await waitFor(() => (offline.includes('offline') ? offline : null), 8000, 100);
		expect(got).not.toBeNull();
		expect(offline).toContain('offline');

		await presenceSub.unsubscribe();
	});

	// 5. resilience: a resubscribed nats subscription still receives new messages, ordering holds
	// under several concurrent publishers, and the iterator drains under backpressure.
	it('survives a nats resubscribe, keeps order under concurrent publishers, and drains backpressure', async () => {
		await using nc = await natsConnect(natsBase);

		// 5a. reconnect a subscription: close the first, resubscribe, verify it gets new messages
		const subject = `chat.resilience.${uniqueId('rs')}`;
		const first = nc.subscribe(subject);
		await first.unsubscribe(); // simulate a dropped subscriber
		const second = nc.subscribe(subject);
		const secondIt = second[Symbol.asyncIterator]();
		await nc.publish(subject, 'after-resub');
		const reMsg = await secondIt.next();
		expect(reMsg.done).toBe(false);
		expect(dec(reMsg.value!.data)).toBe('after-resub');
		await second.unsubscribe();

		// 5b. ordering under several concurrent publishers: each publisher tags its own stream; a
		// single subject subscriber must see each publisher's own messages in order.
		const burst = `chat.burst.${uniqueId('bz')}`;
		const sub = nc.subscribe(burst);
		const perPublisher = 8;
		const publishers = 4;
		const total = perPublisher * publishers;

		const byPublisher = new Map<string, number[]>();
		const drain = (async () => {
			let count = 0;
			for await (const m of sub) {
				const [p, n] = dec(m.data).split(':');
				const arr = byPublisher.get(p!) ?? [];
				arr.push(Number(n));
				byPublisher.set(p!, arr);
				if (++count >= total) break;
			}
		})();

		// publishers run concurrently; per single writer the per-publisher order is preserved
		await Promise.all(
			Array.from({ length: publishers }, (_, p) =>
				(async () => {
					for (let n = 0; n < perPublisher; n++) {
						await nc.publish(burst, `p${p}:${n}`);
					}
				})()
			)
		);
		await drain;

		expect([...byPublisher.values()].reduce((a, v) => a + v.length, 0)).toBe(total);
		for (const [, seq] of byPublisher) {
			expect(seq).toEqual([...seq].sort((x, y) => x - y)); // each publisher's stream stays ordered
		}
		await sub.unsubscribe();

		// 5c. backpressure: publish a burst, then drain the iterator after the fact (queue buffers it)
		const bp = `chat.backpressure.${uniqueId('bp')}`;
		const bpSub = nc.subscribe(bp);
		const M = 20;
		for (let i = 0; i < M; i++) await nc.publish(bp, String(i));
		const bpIt = bpSub[Symbol.asyncIterator]();
		const drained: number[] = [];
		for (let i = 0; i < M; i++) {
			const { value, done } = await bpIt.next();
			if (done) break;
			drained.push(Number(dec(value!.data)));
		}
		expect(drained).toEqual([...Array(M).keys()]);
		await bpSub.unsubscribe();
	});
});
