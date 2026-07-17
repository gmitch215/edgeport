import { describe, expect, it } from 'vitest';
import { connect, type IrcSession } from '../../src/irc/index';

const HOST = '127.0.0.1';
const PORT = 6667;

// unique nicks per test avoid a 433 if a prior client's QUIT has not fully drained
function uniq(prefix: string): string {
	return `${prefix}${Math.floor(Math.random() * 1e6).toString(36)}`;
}

function client(nick: string): Promise<IrcSession> {
	return connect({ hostname: HOST, port: PORT, tls: 'off', nick, timeoutMs: 10_000 });
}

// polls fn until predicate holds (or tries run out); returns the last value
async function until<T>(
	fn: () => Promise<T>,
	ok: (v: T) => boolean,
	tries = 20,
	delayMs = 250
): Promise<T> {
	let last!: T;
	for (let i = 0; i < tries; i++) {
		last = await fn();
		if (ok(last)) return last;
		await new Promise((r) => setTimeout(r, delayMs));
	}
	return last;
}

describe('irc against ergo', () => {
	it('registers, joins, and relays a channel message between two clients', async () => {
		const nickA = uniq('alice');
		const nickB = uniq('bob');
		await using a = await client(nickA);
		await using b = await client(nickB);
		expect(a.nick).toBe(nickA);

		await a.join('#edgeport');
		await b.join('#edgeport');

		// wait until both are seen in the channel before relying on delivery
		const members = await until(
			() => a.names('#edgeport'),
			(m) => m.includes(nickA) && m.includes(nickB)
		);
		expect(members).toContain(nickA);
		expect(members).toContain(nickB);

		const inbox = b.messages()[Symbol.asyncIterator]();
		const text = `hello channel ${Date.now()}`;
		await a.say('#edgeport', text);

		const { value } = await inbox.next();
		expect(value).toBeDefined();
		expect(value!.text).toBe(text);
		expect(value!.from).toBe(nickA);
		expect(value!.target).toBe('#edgeport');
		expect(value!.isChannel).toBe(true);
	});

	it('sets a topic with one client and reads it with another', async () => {
		const chan = '#edgeport-topic';
		const nickA = uniq('setter');
		await using a = await client(nickA);
		await using b = await client(uniq('getter'));
		// A must create the channel first so it holds +o and can set the topic under +t
		await a.join(chan);
		await until(
			() => a.names(chan),
			(m) => m.includes(nickA)
		);
		await b.join(chan);
		await until(
			() => a.names(chan),
			(m) => m.length >= 2
		);

		const topic = `edge topic ${Date.now()}`;
		await a.topic(chan, topic);

		const seen = await until(
			() => b.topic(chan) as Promise<string>,
			(t) => t === topic
		);
		expect(seen).toBe(topic);
	});

	it('delivers a direct private message between two clients', async () => {
		const nickA = uniq('pmfrom');
		const nickB = uniq('pmto');
		await using a = await client(nickA);
		await using b = await client(nickB);

		const inbox = b.messages()[Symbol.asyncIterator]();
		const text = `direct ${Date.now()}`;
		// give the server a beat to finish registering both before routing a PM
		await until(
			() => a.whois(nickB).then((w) => w.nick),
			(n) => n === nickB
		);
		await a.say(nickB, text);

		const { value } = await inbox.next();
		expect(value!.text).toBe(text);
		expect(value!.from).toBe(nickA);
		expect(value!.target).toBe(nickB);
		expect(value!.isChannel).toBe(false);
	});

	it('leaves a channel with part()', async () => {
		const chan = '#edgeport-part';
		const nickA = uniq('leaver');
		await using a = await client(nickA);
		await using b = await client(uniq('watcher'));
		await a.join(chan);
		await b.join(chan);
		await until(
			() => b.names(chan),
			(m) => m.includes(nickA)
		);

		await a.part(chan, 'bye');

		const after = await until(
			() => b.names(chan),
			(m) => !m.includes(nickA)
		);
		expect(after).not.toContain(nickA);
	});
});
