import { beforeAll, describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/errors';
import { command, connect, publish, type RedisSession } from '../../src/redis/index';

const HOST = '127.0.0.1';
const PORT = 6379;
const PASSWORD = 'testpass';

// unique key prefixes keep the tests independent without flushing the shared database
function uniq(prefix: string): string {
	return `${prefix}:${Math.floor(Math.random() * 1e9).toString(36)}`;
}

function client(overrides: Record<string, unknown> = {}): Promise<RedisSession> {
	return connect({
		hostname: HOST,
		port: PORT,
		password: PASSWORD,
		timeoutMs: 10_000,
		...overrides
	});
}

beforeAll(async () => {
	// the compose healthcheck already gates readiness; this is a cheap belt-and-braces poll
	for (let i = 0; i < 20; i++) {
		try {
			await using redis = await client();
			if ((await redis.ping()) === 'PONG') return;
		} catch {
			await new Promise((r) => setTimeout(r, 250));
		}
	}
	throw new Error('redis did not become ready');
}, 20_000);

describe('redis handshake against redis 8.8', () => {
	it('authenticates with requirepass as the default user', async () => {
		await using redis = await client();
		expect(redis.protocol).toBe(2);
		expect(redis.serverInfo).toBeUndefined();
		expect(await redis.ping()).toBe('PONG');
		expect(await redis.ping('echo me')).toBe('echo me');
	});

	it('authenticates with an ACL username and password', async () => {
		await using redis = await client({ username: 'tester' });
		expect(await redis.ping()).toBe('PONG');
	});

	it('negotiates RESP3 with HELLO and reports the server properties', async () => {
		await using redis = await client({ protocol: 3, clientName: 'edgeport-e2e' });
		expect(redis.protocol).toBe(3);
		expect(redis.serverInfo?.server).toBe('redis');
		expect(redis.serverInfo?.proto).toBe(3);
		expect(typeof redis.serverInfo?.version).toBe('string');
	});

	it('rejects a bad password with AuthError on both protocol versions', async () => {
		await expect(client({ password: 'wrong' })).rejects.toThrow(AuthError);
		await expect(client({ password: 'wrong', protocol: 3 })).rejects.toThrow(AuthError);
	});

	it('selects a database and keeps the keyspaces apart', async () => {
		const key = uniq('db');
		await using five = await client({ db: 5 });
		await using zero = await client();
		await five.set(key, 'in-five');
		expect(await five.getText(key)).toBe('in-five');
		expect(await zero.getText(key)).toBeNull();
		await five.del(key);
	});

	it('reads the INFO report', async () => {
		await using redis = await client();
		const info = await redis.info('server');
		expect(info.redis_version).toMatch(/^\d+\.\d+/);
	});
});

describe('redis strings, keys, and expiry', () => {
	it('round-trips a value as text and as bytes, then deletes it', async () => {
		const key = uniq('str');
		await using redis = await client();
		expect(await redis.set(key, 'hello')).toBe(true);
		expect(await redis.getText(key)).toBe('hello');
		expect(Array.from((await redis.get(key))!)).toEqual([104, 101, 108, 108, 111]);
		expect(await redis.exists(key)).toBe(1);
		expect(await redis.del(key)).toBe(1);
		expect(await redis.getText(key)).toBeNull();
		expect(await redis.get(key)).toBeNull();
	});

	it('keeps a binary value byte-exact through the server', async () => {
		const key = uniq('bin');
		const raw = new Uint8Array([0x00, 0xff, 0x0d, 0x0a, 0x80, 0x7f]);
		await using redis = await client();
		await redis.set(key, raw);
		expect(Array.from((await redis.get(key))!)).toEqual(Array.from(raw));
		await redis.del(key);
	});

	it('honours NX, XX, and EX', async () => {
		const key = uniq('opt');
		await using redis = await client();
		expect(await redis.set(key, 'first', { nx: true })).toBe(true);
		expect(await redis.set(key, 'second', { nx: true })).toBe(false);
		expect(await redis.getText(key)).toBe('first');
		expect(await redis.set(key, 'third', { xx: true, ex: 60 })).toBe(true);
		expect(await redis.ttl(key)).toBeGreaterThan(0);
		expect(await redis.set(uniq('absent'), 'x', { xx: true })).toBe(false);
		await redis.del(key);
	});

	it('sets and reads a time to live, and reports the no-key and no-ttl cases', async () => {
		const key = uniq('ttl');
		await using redis = await client();
		expect(await redis.ttl(key)).toBe(-2); // missing
		await redis.set(key, 'v');
		expect(await redis.ttl(key)).toBe(-1); // no expiry
		expect(await redis.expire(key, 60)).toBe(true);
		expect(await redis.ttl(key)).toBeGreaterThan(0);
		expect(await redis.expire(uniq('absent'), 60)).toBe(false);
		await redis.del(key);
	});

	it('increments and decrements a counter', async () => {
		const key = uniq('ctr');
		await using redis = await client();
		expect(await redis.incr(key)).toBe(1);
		expect(await redis.incrBy(key, 10)).toBe(11);
		expect(await redis.decr(key)).toBe(10);
		expect(await redis.incrBy(key, -4)).toBe(6);
		await redis.del(key);
	});

	it('reads and writes several keys in one command', async () => {
		const a = uniq('m');
		const b = uniq('m');
		await using redis = await client();
		await redis.mset({ [a]: 'A', [b]: 2 });
		expect(await redis.mget([a, b, uniq('absent')])).toEqual(['A', '2', null]);
		await redis.del(a, b);
	});

	it('finds keys by pattern and walks them all through scanIterator', async () => {
		const prefix = uniq('scan');
		await using redis = await client();
		const entries = Object.fromEntries(
			Array.from({ length: 25 }, (_, i) => [`${prefix}:${i}`, String(i)])
		);
		await redis.mset(entries);

		expect((await redis.keys(`${prefix}:*`)).sort()).toEqual(Object.keys(entries).sort());

		const walked: string[] = [];
		for await (const key of redis.scanIterator({ match: `${prefix}:*`, count: 5 })) {
			walked.push(key);
		}
		expect([...new Set(walked)].sort()).toEqual(Object.keys(entries).sort());

		// a single page also reports a usable cursor
		const page = await redis.scan({ match: `${prefix}:*`, count: 5 });
		expect(typeof page.cursor).toBe('string');
		await redis.del(...Object.keys(entries));
	});
});

describe('redis hashes, lists, sets, and sorted sets', () => {
	it('drives a hash and normalizes HGETALL across both protocol versions', async () => {
		const key = uniq('hash');
		await using two = await client();
		await using three = await client({ protocol: 3 });
		expect(await two.hset(key, { name: 'ada', year: 1815 })).toBe(2);
		expect(await two.hgetText(key, 'name')).toBe('ada');
		expect(Array.from((await two.hget(key, 'name'))!)).toEqual([97, 100, 97]);
		expect(await two.hgetText(key, 'missing')).toBeNull();
		expect(await two.hget(key, 'missing')).toBeNull();

		const expected = { name: 'ada', year: '1815' };
		expect(await two.hgetall(key)).toEqual(expected);
		// RESP3 answers with a map instead of a flat array; the helper hides the difference
		expect(await three.hgetall(key)).toEqual(expected);

		expect(await two.hdel(key, 'year')).toBe(1);
		expect(await two.hgetall(key)).toEqual({ name: 'ada' });
		await two.del(key);
	});

	it('drives a list from both ends', async () => {
		const key = uniq('list');
		await using redis = await client();
		expect(await redis.rpush(key, 'b', 'c')).toBe(2);
		expect(await redis.lpush(key, 'a')).toBe(3);
		expect(await redis.lrange(key, 0, -1)).toEqual(['a', 'b', 'c']);
		expect(await redis.llen(key)).toBe(3);
		expect(await redis.lpop(key)).toBe('a');
		expect(await redis.rpop(key)).toBe('c');
		expect(await redis.lrange(key, 0, -1)).toEqual(['b']);
		await redis.del(key);
		expect(await redis.lpop(key)).toBeNull();
		expect(await redis.llen(key)).toBe(0);
	});

	it('drives a set, reading the RESP3 set reply as members', async () => {
		const key = uniq('set');
		await using two = await client();
		await using three = await client({ protocol: 3 });
		expect(await two.sadd(key, 'x', 'y', 'z')).toBe(3);
		expect((await two.smembers(key)).sort()).toEqual(['x', 'y', 'z']);
		expect((await three.smembers(key)).sort()).toEqual(['x', 'y', 'z']);
		expect(await two.sismember(key, 'x')).toBe(true);
		expect(await three.sismember(key, 'nope')).toBe(false);
		expect(await two.srem(key, 'z')).toBe(1);
		expect((await two.smembers(key)).sort()).toEqual(['x', 'y']);
		await two.del(key);
	});

	it('drives a sorted set and normalizes WITHSCORES across both protocol versions', async () => {
		const key = uniq('zset');
		await using two = await client();
		await using three = await client({ protocol: 3 });
		expect(await two.zadd(key, { low: 1, mid: 2.5, high: 10 })).toBe(3);
		expect(await two.zrange(key, 0, -1)).toEqual(['low', 'mid', 'high']);
		expect(await two.zrange(key, 0, -1, { rev: true })).toEqual(['high', 'mid', 'low']);

		const expected = [
			{ member: 'low', score: 1 },
			{ member: 'mid', score: 2.5 },
			{ member: 'high', score: 10 }
		];
		// RESP2 returns one flat member/score list, RESP3 returns member/score pairs
		expect(await two.zrangeWithScores(key, 0, -1)).toEqual(expected);
		expect(await three.zrangeWithScores(key, 0, -1)).toEqual(expected);
		expect(await three.zrangeWithScores(key, 0, -1, { rev: true })).toEqual(
			[...expected].reverse()
		);

		expect(await two.zrem(key, 'mid')).toBe(1);
		expect(await two.zrange(key, 0, -1)).toEqual(['low', 'high']);
		await two.del(key);
	});
});

describe('redis pipelining, transactions, and scripting', () => {
	it('runs a pipeline in one round trip, keeping replies in order', async () => {
		const key = uniq('pipe');
		await using redis = await client();
		const replies = await redis.pipeline([
			['SET', key, 'v'],
			['INCR', `${key}:n`],
			['GET', key],
			['GET', `${key}:absent`]
		]);
		expect(replies.map((r) => r.value)).toEqual(['OK', 1, 'v', null]);
		await redis.del(key, `${key}:n`);
	});

	it('reports a per-command pipeline failure without discarding the other replies', async () => {
		const key = uniq('pipe-err');
		await using redis = await client();
		await redis.set(key, 'a string');
		const [ok, bad] = await redis.pipeline([
			['GET', key],
			['LPUSH', key, 'x']
		]);
		expect(ok!.text()).toBe('a string');
		expect(bad!.error).toMatch(/^WRONGTYPE/);
		expect(() => bad!.text()).toThrow();
		await redis.del(key);
	});

	it('applies a transaction atomically', async () => {
		const key = uniq('tx');
		await using redis = await client();
		const replies = await redis.multi([
			['SET', key, '1'],
			['INCR', key],
			['GET', key]
		]);
		expect(replies.map((r) => r.value)).toEqual(['OK', 2, '2']);
		expect(await redis.getText(key)).toBe('2');
		await redis.del(key);
	});

	it('keeps a per-command failure inside the EXEC array', async () => {
		const key = uniq('tx-err');
		await using redis = await client();
		await redis.set(key, 'a string');
		const replies = await redis.multi([
			['INCR', `${key}:n`],
			['LPUSH', key, 'x']
		]);
		expect(replies[0]!.number()).toBe(1);
		expect(replies[1]!.error).toMatch(/^WRONGTYPE/);
		await redis.del(key, `${key}:n`);
	});

	it('aborts the transaction when a queued command is unknown', async () => {
		await using redis = await client();
		await expect(redis.multi([['NOSUCHCOMMAND']])).rejects.toThrow(/EXECABORT|unknown command/);
	});

	it('runs a Lua script with keys and args, then again by its sha', async () => {
		const key = uniq('lua');
		await using redis = await client();
		const script = 'return redis.call("SET", KEYS[1], ARGV[1])';
		expect((await redis.eval(script, { keys: [key], args: ['scripted'] })).text()).toBe('OK');
		expect(await redis.getText(key)).toBe('scripted');

		const sha = (await redis.send('SCRIPT', 'LOAD', script)).text();
		expect((await redis.evalSha(sha, { keys: [key], args: ['again'] })).text()).toBe('OK');
		expect(await redis.getText(key)).toBe('again');
		await redis.del(key);
	});

	it('surfaces a script error as a rejection', async () => {
		await using redis = await client();
		await expect(redis.eval('return redis.error_reply("boom")')).rejects.toThrow(/boom/);
		await expect(redis.evalSha('0'.repeat(40))).rejects.toThrow(/NOSCRIPT/);
	});

	it('reaches an uncovered command through the raw send escape hatch', async () => {
		const key = uniq('raw');
		await using redis = await client();
		await redis.send('SETRANGE', key, 0, 'hello');
		expect((await redis.send('STRLEN', key)).number()).toBe(5);
		expect((await redis.send('TYPE', key)).text()).toBe('string');
		await redis.del(key);
	});
});

describe('redis pub/sub', () => {
	it('delivers a published message to a RESP2 subscriber', async () => {
		const channel = uniq('chan');
		await using subscriber = await client();
		await using publisher = await client();
		await using sub = await subscriber.subscribe(channel);
		expect(subscriber.subscriptionCount).toBe(1);

		expect(await publisher.publish(channel, 'hello edge')).toBe(1);
		const { value } = await sub[Symbol.asyncIterator]().next();
		expect(value!.channel).toBe(channel);
		expect(value!.text()).toBe('hello edge');
	});

	it('delivers a JSON payload and parses it back', async () => {
		const channel = uniq('json');
		await using subscriber = await client();
		await using publisher = await client();
		await using sub = await subscriber.subscribe(channel);

		await publisher.publishJson(channel, { sha: '9f2c1ab', ok: true });
		const { value } = await sub[Symbol.asyncIterator]().next();
		expect(value!.json()).toEqual({ sha: '9f2c1ab', ok: true });
	});

	it('delivers a pattern match with the pattern that caught it', async () => {
		const prefix = uniq('news');
		await using subscriber = await client();
		await using publisher = await client();
		await using sub = await subscriber.psubscribe(`${prefix}.*`);

		await publisher.publish(`${prefix}.jazz`, 'a tune');
		const { value } = await sub[Symbol.asyncIterator]().next();
		expect(value!.pattern).toBe(`${prefix}.*`);
		expect(value!.channel).toBe(`${prefix}.jazz`);
		expect(value!.text()).toBe('a tune');
	});

	it('subscribes to several channels at once and routes each delivery', async () => {
		const a = uniq('multi');
		const b = uniq('multi');
		await using subscriber = await client();
		await using publisher = await client();
		await using sub = await subscriber.subscribe(a, b);
		expect(subscriber.subscriptionCount).toBe(2);

		const iter = sub[Symbol.asyncIterator]();
		await publisher.publish(a, 'from-a');
		expect((await iter.next()).value!.channel).toBe(a);
		await publisher.publish(b, 'from-b');
		expect((await iter.next()).value!.channel).toBe(b);
	});

	it('refuses a data command while a RESP2 connection is subscribed, then allows it again', async () => {
		const channel = uniq('guard');
		await using subscriber = await client();
		const sub = await subscriber.subscribe(channel);
		await expect(subscriber.getText('any-key')).rejects.toThrow(/not allowed while a RESP2/);
		// PING stays legal in subscriber mode
		expect(await subscriber.ping()).toBe('PONG');

		await sub.unsubscribe();
		expect(subscriber.subscriptionCount).toBe(0);
		await expect(subscriber.getText('any-key')).resolves.toBeNull();
	});

	it('runs ordinary commands while subscribed on RESP3', async () => {
		const channel = uniq('resp3');
		const key = uniq('resp3-key');
		await using subscriber = await client({ protocol: 3 });
		await using publisher = await client();
		await using sub = await subscriber.subscribe(channel);

		// the RESP3 payoff: a subscribed connection is still a working command connection
		await subscriber.set(key, 'while-subscribed');
		expect(await subscriber.getText(key)).toBe('while-subscribed');

		await publisher.publish(channel, 'delivered');
		const { value } = await sub[Symbol.asyncIterator]().next();
		expect(value!.text()).toBe('delivered');

		// and the command replies stay correlated after the push
		expect(await subscriber.incr(`${key}:n`)).toBe(1);
		await subscriber.del(key, `${key}:n`);
	});

	it('ends the iterator when the subscription is released', async () => {
		const channel = uniq('release');
		await using subscriber = await client({ protocol: 3 });
		const sub = await subscriber.subscribe(channel);
		const iter = sub[Symbol.asyncIterator]();
		const pending = iter.next();
		await sub.unsubscribe();
		expect((await pending).done).toBe(true);
		expect(subscriber.subscriptionCount).toBe(0);
	});

	it('reports zero receivers when nobody is listening', async () => {
		await using redis = await client();
		expect(await redis.publish(uniq('nobody'), 'unheard')).toBe(0);
	});
});

describe('redis one-shots', () => {
	it('command connects, runs one command, and closes', async () => {
		const key = uniq('one');
		await using redis = await client();
		await redis.set(key, 'from-session');

		const reply = await command({
			hostname: HOST,
			port: PORT,
			password: PASSWORD,
			args: ['GET', key]
		});
		expect(reply.text()).toBe('from-session');

		const missing = await command({
			hostname: HOST,
			port: PORT,
			password: PASSWORD,
			args: ['GET', uniq('absent')]
		});
		expect(missing.isNull).toBe(true);
		await redis.del(key);
	});

	it('publish delivers to a live subscriber and reports the receiver count', async () => {
		const channel = uniq('one-shot');
		await using subscriber = await client();
		await using sub = await subscriber.subscribe(channel);

		const received = await publish({
			hostname: HOST,
			port: PORT,
			password: PASSWORD,
			channel,
			message: 'one-shot payload'
		});
		expect(received).toBe(1);
		const { value } = await sub[Symbol.asyncIterator]().next();
		expect(value!.text()).toBe('one-shot payload');
	});
});
