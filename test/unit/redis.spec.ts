import { beforeEach, describe, expect, it, vi } from 'vitest';
import { connect as coreConnect } from '../../src/core';
import { AuthError, ConnectionError, ProtocolError } from '../../src/core/errors';
import {
	_connectOverSocket,
	command,
	makeReply,
	publish,
	type RedisConnectOptions,
	type RedisSession,
	type RespValue
} from '../../src/redis';
import { mockConnection, type MockServerEnd } from '../mock-socket';

// stub only the core dial so the one-shots can be driven over a mock socket; the error vocabulary
// the redis module imports from the same barrel stays real
vi.mock('../../src/core', async (importOriginal) => {
	const actual = await importOriginal<typeof import('../../src/core')>();
	return { ...actual, connect: vi.fn() };
});

// latin1 so a RESP vector written as a JS string maps one char to one byte
function bytesOf(wire: string): Uint8Array {
	const out = new Uint8Array(wire.length);
	for (let i = 0; i < wire.length; i++) out[i] = wire.charCodeAt(i) & 0xff;
	return out;
}

const decoder = new TextDecoder();

// reads one command the client sent, as its argument list
async function readCommand(server: MockServerEnd): Promise<string[]> {
	const header = await server.readLine();
	expect(header[0]).toBe('*');
	const count = Number(header.slice(1));
	const args: string[] = [];
	for (let i = 0; i < count; i++) {
		const len = Number((await server.readLine()).slice(1));
		args.push(decoder.decode(await server.readN(len)));
		await server.readN(2);
	}
	return args;
}

const HELLO_MAP =
	'%3\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n8.8.2\r\n$5\r\nproto\r\n:3\r\n';

interface Ctx {
	session: RedisSession;
	server: MockServerEnd;
}

// opens a session over a mock socket, answering whatever handshake the options imply
async function connected(opts: Partial<RedisConnectOptions> = {}): Promise<Ctx> {
	const { socket, server } = mockConnection();
	const pending = _connectOverSocket(socket, { hostname: 'redis.test', ...opts });
	if ((opts.protocol ?? 2) === 3) {
		await readCommand(server);
		await server.write(bytesOf(HELLO_MAP));
	} else {
		if (opts.password !== undefined) {
			await readCommand(server);
			await server.writeLine('+OK');
		}
		if (opts.clientName !== undefined) {
			await readCommand(server);
			await server.writeLine('+OK');
		}
	}
	if (opts.db !== undefined) {
		await readCommand(server);
		await server.writeLine('+OK');
	}
	return { session: await pending, server };
}

// runs one command against the session, asserting what went out and scripting the reply
async function exchange(
	ctx: Ctx,
	run: () => Promise<unknown>,
	expected: string[],
	reply: string
): Promise<unknown> {
	const pending = run();
	expect(await readCommand(ctx.server)).toEqual(expected);
	await ctx.server.write(bytesOf(reply));
	return await pending;
}

beforeEach(() => {
	vi.mocked(coreConnect).mockReset();
});

describe('redis handshake', () => {
	it('sends nothing for an unauthenticated RESP2 connection', async () => {
		const { session } = await connected();
		expect(session.protocol).toBe(2);
		expect(session.serverInfo).toBeUndefined();
		expect(session.subscriptionCount).toBe(0);
	});

	it('authenticates a RESP2 connection with a bare password', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, { hostname: 'redis.test', password: 'testpass' });
		expect(await readCommand(server)).toEqual(['AUTH', 'testpass']);
		await server.writeLine('+OK');
		await expect(pending).resolves.toBeDefined();
	});

	it('authenticates a RESP2 connection with an ACL username and password', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, {
			hostname: 'redis.test',
			username: 'tester',
			password: 'testpass'
		});
		expect(await readCommand(server)).toEqual(['AUTH', 'tester', 'testpass']);
		await server.writeLine('+OK');
		await expect(pending).resolves.toBeDefined();
	});

	it('raises AuthError on a WRONGPASS reply', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, { hostname: 'redis.test', password: 'nope' });
		await readCommand(server);
		await server.writeLine('-WRONGPASS invalid username-password pair or user is disabled.');
		await expect(pending).rejects.toThrow(AuthError);
	});

	it('raises AuthError when a password is sent to a server that has none', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, { hostname: 'redis.test', password: 'x' });
		await readCommand(server);
		await server.writeLine('-ERR Client sent AUTH, but no password is set.');
		await expect(pending).rejects.toThrow(AuthError);
	});

	it('registers a connection name on RESP2 with CLIENT SETNAME', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, { hostname: 'redis.test', clientName: 'edgeport' });
		expect(await readCommand(server)).toEqual(['CLIENT', 'SETNAME', 'edgeport']);
		await server.writeLine('+OK');
		await expect(pending).resolves.toBeDefined();
	});

	it('raises ProtocolError when CLIENT SETNAME is rejected', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, { hostname: 'redis.test', clientName: 'bad name' });
		await readCommand(server);
		await server.writeLine('-ERR Client names cannot contain spaces');
		await expect(pending).rejects.toThrow(ProtocolError);
	});

	it('runs HELLO 3 and captures the server properties', async () => {
		const { session } = await connected({ protocol: 3 });
		expect(session.protocol).toBe(3);
		expect(session.serverInfo).toEqual({ server: 'redis', version: '8.8.2', proto: 3 });
	});

	it('folds auth and the connection name into the HELLO clauses', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, {
			hostname: 'redis.test',
			protocol: 3,
			username: 'tester',
			password: 'testpass',
			clientName: 'edgeport'
		});
		expect(await readCommand(server)).toEqual([
			'HELLO',
			'3',
			'AUTH',
			'tester',
			'testpass',
			'SETNAME',
			'edgeport'
		]);
		await server.write(bytesOf(HELLO_MAP));
		await expect(pending).resolves.toBeDefined();
	});

	it('defaults the HELLO auth username to default when only a password is given', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, {
			hostname: 'redis.test',
			protocol: 3,
			password: 'testpass'
		});
		expect(await readCommand(server)).toEqual(['HELLO', '3', 'AUTH', 'default', 'testpass']);
		await server.write(bytesOf(HELLO_MAP));
		await expect(pending).resolves.toBeDefined();
	});

	it('points at protocol: 2 when the server answers NOPROTO', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, { hostname: 'redis.test', protocol: 3 });
		await readCommand(server);
		await server.writeLine('-NOPROTO unsupported protocol version');
		await expect(pending).rejects.toThrow(/does not support RESP3.*protocol: 2/s);
	});

	it('points at protocol: 2 when the server predates HELLO', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, { hostname: 'redis.test', protocol: 3 });
		await readCommand(server);
		await server.writeLine("-ERR unknown command 'HELLO'");
		await expect(pending).rejects.toThrow(/does not support RESP3/);
	});

	it('raises AuthError when the HELLO auth clause is rejected', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, {
			hostname: 'redis.test',
			protocol: 3,
			password: 'nope'
		});
		await readCommand(server);
		await server.writeLine('-WRONGPASS invalid username-password pair or user is disabled.');
		await expect(pending).rejects.toThrow(AuthError);
	});

	it('leaves serverInfo undefined when HELLO answers something other than a map', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, { hostname: 'redis.test', protocol: 3 });
		await readCommand(server);
		await server.write(bytesOf('*2\r\n$6\r\nserver\r\n$5\r\nredis\r\n'));
		expect((await pending).serverInfo).toBeUndefined();
	});

	it('selects a database after authenticating', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, { hostname: 'redis.test', db: 3 });
		expect(await readCommand(server)).toEqual(['SELECT', '3']);
		await server.writeLine('+OK');
		await expect(pending).resolves.toBeDefined();
	});

	it('raises ProtocolError when SELECT is rejected', async () => {
		const { socket, server } = mockConnection();
		const pending = _connectOverSocket(socket, { hostname: 'redis.test', db: 99 });
		await readCommand(server);
		await server.writeLine('-ERR DB index is out of range');
		await expect(pending).rejects.toThrow(ProtocolError);
	});
});

describe('redis connect', () => {
	it('dials the default port in plaintext and hands the socket to the handshake', async () => {
		const { socket, server } = mockConnection();
		vi.mocked(coreConnect).mockResolvedValue(socket);
		const { connect } = await import('../../src/redis');
		const pending = connect({ hostname: 'redis.test', password: 'testpass' });
		expect(await readCommand(server)).toEqual(['AUTH', 'testpass']);
		await server.writeLine('+OK');
		await expect(pending).resolves.toBeDefined();
		expect(coreConnect).toHaveBeenCalledWith(
			expect.objectContaining({ hostname: 'redis.test', port: 6379, tls: 'off' })
		);
	});

	it('maps tls implicit onto the core on mode and honours an explicit port', async () => {
		const { socket } = mockConnection();
		vi.mocked(coreConnect).mockResolvedValue(socket);
		const { connect } = await import('../../src/redis');
		await connect({ hostname: 'redis.test', port: 6380, tls: 'implicit' });
		expect(coreConnect).toHaveBeenCalledWith(expect.objectContaining({ port: 6380, tls: 'on' }));
	});

	it('closes the socket when the handshake fails', async () => {
		const { socket, server } = mockConnection();
		const closed = vi.spyOn(socket, 'close');
		vi.mocked(coreConnect).mockResolvedValue(socket);
		const { connect } = await import('../../src/redis');
		const pending = connect({ hostname: 'redis.test', password: 'nope' });
		await readCommand(server);
		await server.writeLine('-WRONGPASS nope');
		await expect(pending).rejects.toThrow(AuthError);
		expect(closed).toHaveBeenCalled();
	});
});

describe('redis commands', () => {
	it('sends a command and returns its reply', async () => {
		const ctx = await connected();
		const reply = await exchange(ctx, () => ctx.session.send('PING'), ['PING'], '+PONG\r\n');
		expect((reply as { text(): string }).text()).toBe('PONG');
	});

	it('throws ProtocolError on an error reply', async () => {
		const ctx = await connected();
		const pending = ctx.session.send('LPUSH', 'k', 'v');
		await readCommand(ctx.server);
		await ctx.server.writeLine(
			'-WRONGTYPE Operation against a key holding the wrong kind of value'
		);
		await expect(pending).rejects.toThrow(ProtocolError);
	});

	it('throws AuthError on a NOAUTH or NOPERM reply', async () => {
		const ctx = await connected();
		const first = ctx.session.send('GET', 'k');
		await readCommand(ctx.server);
		await ctx.server.writeLine('-NOAUTH Authentication required.');
		await expect(first).rejects.toThrow(AuthError);

		const second = ctx.session.send('GET', 'k');
		await readCommand(ctx.server);
		await ctx.server.writeLine('-NOPERM this user has no permissions to run the get command');
		await expect(second).rejects.toThrow(AuthError);
	});

	it('keeps concurrent commands correlated with their replies', async () => {
		const ctx = await connected();
		const a = ctx.session.send('GET', 'a');
		const b = ctx.session.send('GET', 'b');
		expect(await readCommand(ctx.server)).toEqual(['GET', 'a']);
		expect(await readCommand(ctx.server)).toEqual(['GET', 'b']);
		await ctx.server.write(bytesOf('$2\r\nAA\r\n$2\r\nBB\r\n'));
		expect((await a).text()).toBe('AA');
		expect((await b).text()).toBe('BB');
	});

	it('pipelines commands into one frame and returns replies in order', async () => {
		const ctx = await connected();
		const pending = ctx.session.pipeline([
			['SET', 'k', 'v'],
			['INCR', 'n'],
			['GET', 'missing']
		]);
		expect(await readCommand(ctx.server)).toEqual(['SET', 'k', 'v']);
		expect(await readCommand(ctx.server)).toEqual(['INCR', 'n']);
		expect(await readCommand(ctx.server)).toEqual(['GET', 'missing']);
		await ctx.server.write(bytesOf('+OK\r\n:1\r\n$-1\r\n'));
		const replies = await pending;
		expect(replies.map((r) => r.value)).toEqual(['OK', 1, null]);
	});

	it('reports a failed pipeline command on its reply rather than throwing the batch away', async () => {
		const ctx = await connected();
		const pending = ctx.session.pipeline([
			['INCR', 'n'],
			['LPUSH', 'n', 'x']
		]);
		await readCommand(ctx.server);
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf(':1\r\n-WRONGTYPE nope\r\n'));
		const [ok, bad] = await pending;
		expect(ok!.number()).toBe(1);
		expect(bad!.error).toBe('WRONGTYPE nope');
		// reading a failed reply as data throws, so it cannot pass for a result
		expect(() => bad!.text()).toThrow(ProtocolError);
	});

	it('returns an empty result for an empty pipeline or transaction without writing', async () => {
		const ctx = await connected();
		await expect(ctx.session.pipeline([])).resolves.toEqual([]);
		await expect(ctx.session.multi([])).resolves.toEqual([]);
	});

	it('wraps a transaction in MULTI / EXEC and unwraps the EXEC array', async () => {
		const ctx = await connected();
		const pending = ctx.session.multi([
			['INCR', 'n'],
			['GET', 'n']
		]);
		expect(await readCommand(ctx.server)).toEqual(['MULTI']);
		expect(await readCommand(ctx.server)).toEqual(['INCR', 'n']);
		expect(await readCommand(ctx.server)).toEqual(['GET', 'n']);
		expect(await readCommand(ctx.server)).toEqual(['EXEC']);
		await ctx.server.write(bytesOf('+OK\r\n+QUEUED\r\n+QUEUED\r\n*2\r\n:1\r\n$1\r\n1\r\n'));
		const replies = await pending;
		expect(replies.map((r) => r.value)).toEqual([1, '1']);
	});

	it('keeps a per-command failure inside the EXEC array', async () => {
		const ctx = await connected();
		const pending = ctx.session.multi([
			['INCR', 'n'],
			['LPUSH', 'n', 'x']
		]);
		for (let i = 0; i < 4; i++) await readCommand(ctx.server);
		await ctx.server.write(bytesOf('+OK\r\n+QUEUED\r\n+QUEUED\r\n*2\r\n:1\r\n-WRONGTYPE nope\r\n'));
		const replies = await pending;
		expect(replies[0]!.number()).toBe(1);
		expect(replies[1]!.error).toBe('WRONGTYPE nope');
	});

	it('throws when EXEC itself is rejected', async () => {
		const ctx = await connected();
		const pending = ctx.session.multi([['NOSUCH']]);
		for (let i = 0; i < 3; i++) await readCommand(ctx.server);
		await ctx.server.write(
			bytesOf("+OK\r\n-ERR unknown command 'NOSUCH'\r\n-EXECABORT Transaction discarded.\r\n")
		);
		await expect(pending).rejects.toThrow(/EXECABORT/);
	});

	it('throws when the transaction is discarded', async () => {
		const ctx = await connected();
		const pending = ctx.session.multi([['INCR', 'n']]);
		for (let i = 0; i < 3; i++) await readCommand(ctx.server);
		await ctx.server.write(bytesOf('+OK\r\n+QUEUED\r\n*-1\r\n'));
		await expect(pending).rejects.toThrow(/transaction was discarded/);
	});

	it('rejects commands once the session is closed', async () => {
		const ctx = await connected();
		await ctx.session.close();
		await expect(ctx.session.send('PING')).rejects.toThrow(ConnectionError);
		await expect(ctx.session.pipeline([['PING']])).rejects.toThrow(ConnectionError);
		await expect(ctx.session.multi([['PING']])).rejects.toThrow(ConnectionError);
		await expect(ctx.session.subscribe('a')).rejects.toThrow(ConnectionError);
		// closing twice is a no-op
		await expect(ctx.session.close()).resolves.toBeUndefined();
	});

	it('rejects in-flight commands when the peer disconnects', async () => {
		const ctx = await connected();
		const pending = ctx.session.send('GET', 'k');
		await readCommand(ctx.server);
		await ctx.server.close();
		await expect(pending).rejects.toThrow(ConnectionError);
		// and surfaces the same failure to later callers
		await expect(ctx.session.send('GET', 'k')).rejects.toThrow(ConnectionError);
	});

	it('surfaces a malformed frame as a ProtocolError on the waiting command', async () => {
		const ctx = await connected();
		const pending = ctx.session.send('GET', 'k');
		await readCommand(ctx.server);
		await ctx.server.writeLine('^bogus');
		await expect(pending).rejects.toThrow(ProtocolError);
	});

	it('disposes the session with await using', async () => {
		const { socket, server } = mockConnection();
		const closed = vi.spyOn(socket, 'close');
		{
			await using session = await _connectOverSocket(socket, { hostname: 'redis.test' });
			const pending = session.send('PING');
			await readCommand(server);
			await server.writeLine('+PONG');
			await pending;
		}
		expect(closed).toHaveBeenCalled();
	});
});

describe('redis strings and keys', () => {
	it('gets a value as bytes and as text, and null for a missing key', async () => {
		const ctx = await connected();
		const bytes = (await exchange(
			ctx,
			() => ctx.session.get('k'),
			['GET', 'k'],
			'$3\r\nabc\r\n'
		)) as Uint8Array;
		expect(Array.from(bytes)).toEqual([0x61, 0x62, 0x63]);
		expect(await exchange(ctx, () => ctx.session.getText('k'), ['GET', 'k'], '$3\r\nabc\r\n')).toBe(
			'abc'
		);
		expect(await exchange(ctx, () => ctx.session.get('k'), ['GET', 'k'], '$-1\r\n')).toBeNull();
		expect(await exchange(ctx, () => ctx.session.getText('k'), ['GET', 'k'], '$-1\r\n')).toBeNull();
	});

	it('sets a key and reports whether the write landed', async () => {
		const ctx = await connected();
		expect(await exchange(ctx, () => ctx.session.set('k', 'v'), ['SET', 'k', 'v'], '+OK\r\n')).toBe(
			true
		);
		expect(
			await exchange(
				ctx,
				() => ctx.session.set('k', 'v', { nx: true }),
				['SET', 'k', 'v', 'NX'],
				'$-1\r\n'
			)
		).toBe(false);
	});

	it('renders every SET option in the order redis expects', async () => {
		const ctx = await connected();
		await exchange(
			ctx,
			() =>
				ctx.session.set('k', 'v', {
					ex: 1,
					px: 2,
					exat: 3,
					pxat: 4,
					keepTtl: true,
					nx: true,
					xx: true
				}),
			['SET', 'k', 'v', 'EX', '1', 'PX', '2', 'EXAT', '3', 'PXAT', '4', 'KEEPTTL', 'NX', 'XX'],
			'+OK\r\n'
		);
	});

	it('accepts raw bytes as a value', async () => {
		const ctx = await connected();
		const pending = ctx.session.set('bin', new Uint8Array([0, 255]));
		const args = await readCommand(ctx.server);
		expect(args.slice(0, 2)).toEqual(['SET', 'bin']);
		await ctx.server.writeLine('+OK');
		await pending;
	});

	it('counts deletions and existence', async () => {
		const ctx = await connected();
		expect(await exchange(ctx, () => ctx.session.del('a', 'b'), ['DEL', 'a', 'b'], ':2\r\n')).toBe(
			2
		);
		expect(
			await exchange(ctx, () => ctx.session.exists('a', 'b'), ['EXISTS', 'a', 'b'], ':1\r\n')
		).toBe(1);
	});

	it('reads and writes several keys at once', async () => {
		const ctx = await connected();
		expect(
			await exchange(
				ctx,
				() => ctx.session.mget(['a', 'b']),
				['MGET', 'a', 'b'],
				'*2\r\n$1\r\nA\r\n$-1\r\n'
			)
		).toEqual(['A', null]);
		await exchange(
			ctx,
			() => ctx.session.mset({ a: '1', b: 2 }),
			['MSET', 'a', '1', 'b', '2'],
			'+OK\r\n'
		);
	});

	it('increments and decrements', async () => {
		const ctx = await connected();
		expect(await exchange(ctx, () => ctx.session.incr('n'), ['INCR', 'n'], ':1\r\n')).toBe(1);
		expect(
			await exchange(ctx, () => ctx.session.incrBy('n', 5), ['INCRBY', 'n', '5'], ':6\r\n')
		).toBe(6);
		expect(await exchange(ctx, () => ctx.session.decr('n'), ['DECR', 'n'], ':5\r\n')).toBe(5);
	});

	it('sets and reads a time to live', async () => {
		const ctx = await connected();
		expect(
			await exchange(ctx, () => ctx.session.expire('k', 60), ['EXPIRE', 'k', '60'], ':1\r\n')
		).toBe(true);
		expect(
			await exchange(ctx, () => ctx.session.expire('k', 60), ['EXPIRE', 'k', '60'], ':0\r\n')
		).toBe(false);
		expect(await exchange(ctx, () => ctx.session.ttl('k'), ['TTL', 'k'], ':59\r\n')).toBe(59);
		expect(await exchange(ctx, () => ctx.session.ttl('k'), ['TTL', 'k'], ':-2\r\n')).toBe(-2);
	});

	it('lists keys by pattern', async () => {
		const ctx = await connected();
		expect(
			await exchange(
				ctx,
				() => ctx.session.keys('a*'),
				['KEYS', 'a*'],
				'*2\r\n$2\r\na1\r\n$2\r\na2\r\n'
			)
		).toEqual(['a1', 'a2']);
	});

	it('scans one page with every filter applied', async () => {
		const ctx = await connected();
		expect(
			await exchange(
				ctx,
				() => ctx.session.scan({ cursor: '17', match: 'a*', count: 50, type: 'string' }),
				['SCAN', '17', 'MATCH', 'a*', 'COUNT', '50', 'TYPE', 'string'],
				'*2\r\n$1\r\n0\r\n*1\r\n$2\r\na1\r\n'
			)
		).toEqual({ cursor: '0', keys: ['a1'] });
	});

	it('walks every page through scanIterator until the cursor returns to zero', async () => {
		const ctx = await connected();
		const found: string[] = [];
		const walk = (async () => {
			for await (const key of ctx.session.scanIterator({ match: 'k*' })) found.push(key);
		})();
		expect(await readCommand(ctx.server)).toEqual(['SCAN', '0', 'MATCH', 'k*']);
		await ctx.server.write(bytesOf('*2\r\n$2\r\n12\r\n*1\r\n$2\r\nk1\r\n'));
		expect(await readCommand(ctx.server)).toEqual(['SCAN', '12', 'MATCH', 'k*']);
		await ctx.server.write(bytesOf('*2\r\n$1\r\n0\r\n*2\r\n$2\r\nk2\r\n$2\r\nk3\r\n'));
		await walk;
		expect(found).toEqual(['k1', 'k2', 'k3']);
	});
});

describe('redis hashes, lists, sets, and sorted sets', () => {
	it('reads a hash field as bytes and as text', async () => {
		const ctx = await connected();
		const bytes = (await exchange(
			ctx,
			() => ctx.session.hget('h', 'f'),
			['HGET', 'h', 'f'],
			'$1\r\nv\r\n'
		)) as Uint8Array;
		expect(Array.from(bytes)).toEqual([0x76]);
		expect(
			await exchange(ctx, () => ctx.session.hgetText('h', 'f'), ['HGET', 'h', 'f'], '$1\r\nv\r\n')
		).toBe('v');
		expect(
			await exchange(ctx, () => ctx.session.hget('h', 'f'), ['HGET', 'h', 'f'], '$-1\r\n')
		).toBeNull();
		expect(
			await exchange(ctx, () => ctx.session.hgetText('h', 'f'), ['HGET', 'h', 'f'], '$-1\r\n')
		).toBeNull();
	});

	it('writes and deletes hash fields', async () => {
		const ctx = await connected();
		expect(
			await exchange(
				ctx,
				() => ctx.session.hset('h', { f1: 'v1', f2: 2 }),
				['HSET', 'h', 'f1', 'v1', 'f2', '2'],
				':2\r\n'
			)
		).toBe(2);
		expect(
			await exchange(ctx, () => ctx.session.hdel('h', 'f1'), ['HDEL', 'h', 'f1'], ':1\r\n')
		).toBe(1);
	});

	it('reads a whole hash from either the RESP2 array or the RESP3 map', async () => {
		const two = await connected();
		expect(
			await exchange(
				two,
				() => two.session.hgetall('h'),
				['HGETALL', 'h'],
				'*4\r\n$2\r\nf1\r\n$2\r\nv1\r\n$2\r\nf2\r\n$2\r\nv2\r\n'
			)
		).toEqual({ f1: 'v1', f2: 'v2' });

		const three = await connected({ protocol: 3 });
		expect(
			await exchange(
				three,
				() => three.session.hgetall('h'),
				['HGETALL', 'h'],
				'%2\r\n$2\r\nf1\r\n$2\r\nv1\r\n$2\r\nf2\r\n$2\r\nv2\r\n'
			)
		).toEqual({ f1: 'v1', f2: 'v2' });
	});

	it('drives the list commands', async () => {
		const ctx = await connected();
		expect(
			await exchange(
				ctx,
				() => ctx.session.lpush('l', 'a', 'b'),
				['LPUSH', 'l', 'a', 'b'],
				':2\r\n'
			)
		).toBe(2);
		expect(
			await exchange(ctx, () => ctx.session.rpush('l', 'c'), ['RPUSH', 'l', 'c'], ':3\r\n')
		).toBe(3);
		expect(await exchange(ctx, () => ctx.session.lpop('l'), ['LPOP', 'l'], '$1\r\nb\r\n')).toBe(
			'b'
		);
		expect(await exchange(ctx, () => ctx.session.rpop('l'), ['RPOP', 'l'], '$1\r\nc\r\n')).toBe(
			'c'
		);
		expect(await exchange(ctx, () => ctx.session.lpop('l'), ['LPOP', 'l'], '$-1\r\n')).toBeNull();
		expect(await exchange(ctx, () => ctx.session.rpop('l'), ['RPOP', 'l'], '$-1\r\n')).toBeNull();
		expect(
			await exchange(
				ctx,
				() => ctx.session.lrange('l', 0, -1),
				['LRANGE', 'l', '0', '-1'],
				'*1\r\n$1\r\na\r\n'
			)
		).toEqual(['a']);
		expect(await exchange(ctx, () => ctx.session.llen('l'), ['LLEN', 'l'], ':1\r\n')).toBe(1);
	});

	it('drives the set commands, reading a RESP3 set reply as members', async () => {
		const ctx = await connected({ protocol: 3 });
		expect(
			await exchange(ctx, () => ctx.session.sadd('s', 'x', 'y'), ['SADD', 's', 'x', 'y'], ':2\r\n')
		).toBe(2);
		expect(
			await exchange(ctx, () => ctx.session.srem('s', 'y'), ['SREM', 's', 'y'], ':1\r\n')
		).toBe(1);
		expect(
			await exchange(ctx, () => ctx.session.smembers('s'), ['SMEMBERS', 's'], '~1\r\n$1\r\nx\r\n')
		).toEqual(['x']);
		expect(
			await exchange(ctx, () => ctx.session.sismember('s', 'x'), ['SISMEMBER', 's', 'x'], '#t\r\n')
		).toBe(true);
		expect(
			await exchange(ctx, () => ctx.session.sismember('s', 'z'), ['SISMEMBER', 's', 'z'], '#f\r\n')
		).toBe(false);
	});

	it('adds scored members with the score before the member', async () => {
		const ctx = await connected();
		expect(
			await exchange(
				ctx,
				() => ctx.session.zadd('z', { a: 1, b: 2.5 }),
				['ZADD', 'z', '1', 'a', '2.5', 'b'],
				':2\r\n'
			)
		).toBe(2);
		expect(
			await exchange(ctx, () => ctx.session.zrem('z', 'a'), ['ZREM', 'z', 'a'], ':1\r\n')
		).toBe(1);
	});

	it('ranges a sorted set, forwards and reversed', async () => {
		const ctx = await connected();
		expect(
			await exchange(
				ctx,
				() => ctx.session.zrange('z', 0, -1),
				['ZRANGE', 'z', '0', '-1'],
				'*2\r\n$1\r\na\r\n$1\r\nb\r\n'
			)
		).toEqual(['a', 'b']);
		expect(
			await exchange(
				ctx,
				() => ctx.session.zrange('z', 0, -1, { rev: true }),
				['ZRANGE', 'z', '0', '-1', 'REV'],
				'*2\r\n$1\r\nb\r\n$1\r\na\r\n'
			)
		).toEqual(['b', 'a']);
	});

	it('normalizes WITHSCORES from the RESP2 flat list and the RESP3 pairs', async () => {
		const two = await connected();
		expect(
			await exchange(
				two,
				() => two.session.zrangeWithScores('z', 0, -1),
				['ZRANGE', 'z', '0', '-1', 'WITHSCORES'],
				'*4\r\n$1\r\na\r\n$1\r\n1\r\n$1\r\nb\r\n$3\r\n2.5\r\n'
			)
		).toEqual([
			{ member: 'a', score: 1 },
			{ member: 'b', score: 2.5 }
		]);

		const three = await connected({ protocol: 3 });
		expect(
			await exchange(
				three,
				() => three.session.zrangeWithScores('z', 0, -1, { rev: true }),
				['ZRANGE', 'z', '0', '-1', 'REV', 'WITHSCORES'],
				'*2\r\n*2\r\n$1\r\nb\r\n,2.5\r\n*2\r\n$1\r\na\r\n,1\r\n'
			)
		).toEqual([
			{ member: 'b', score: 2.5 },
			{ member: 'a', score: 1 }
		]);
	});

	it('returns nothing for an empty WITHSCORES range', async () => {
		const ctx = await connected();
		expect(
			await exchange(
				ctx,
				() => ctx.session.zrangeWithScores('z', 0, -1),
				['ZRANGE', 'z', '0', '-1', 'WITHSCORES'],
				'*0\r\n'
			)
		).toEqual([]);
	});
});

describe('redis scripting and connection commands', () => {
	it('passes the key count, keys, then args to EVAL', async () => {
		const ctx = await connected();
		await exchange(
			ctx,
			() => ctx.session.eval('return redis.call("GET", KEYS[1])', { keys: ['k'], args: [1, 'x'] }),
			['EVAL', 'return redis.call("GET", KEYS[1])', '2'.replace('2', '1'), 'k', '1', 'x'],
			'$1\r\nv\r\n'
		);
	});

	it('sends a bare EVAL with no keys or args', async () => {
		const ctx = await connected();
		await exchange(ctx, () => ctx.session.eval('return 1'), ['EVAL', 'return 1', '0'], ':1\r\n');
	});

	it('runs a cached script by its sha', async () => {
		const ctx = await connected();
		await exchange(
			ctx,
			() => ctx.session.evalSha('abc123', { keys: ['k'] }),
			['EVALSHA', 'abc123', '1', 'k'],
			':1\r\n'
		);
	});

	it('pings, with and without a payload', async () => {
		const ctx = await connected();
		expect(await exchange(ctx, () => ctx.session.ping(), ['PING'], '+PONG\r\n')).toBe('PONG');
		expect(await exchange(ctx, () => ctx.session.ping('hi'), ['PING', 'hi'], '$2\r\nhi\r\n')).toBe(
			'hi'
		);
	});

	it('selects a database on a live session', async () => {
		const ctx = await connected();
		await exchange(ctx, () => ctx.session.select(2), ['SELECT', '2'], '+OK\r\n');
	});

	it('parses the INFO report into fields, dropping section headers', async () => {
		const ctx = await connected();
		const report =
			'# Server\r\nredis_version:8.8.2\r\nuptime_in_seconds:41\r\n\r\n# Clients\r\nconnected_clients:1\r\n';
		expect(
			await exchange(ctx, () => ctx.session.info(), ['INFO'], `$${report.length}\r\n${report}\r\n`)
		).toEqual({ redis_version: '8.8.2', uptime_in_seconds: '41', connected_clients: '1' });
	});

	it('limits INFO to one section when asked', async () => {
		const ctx = await connected();
		const report = '# Memory\r\nused_memory:1024\r\n';
		expect(
			await exchange(
				ctx,
				() => ctx.session.info('memory'),
				['INFO', 'memory'],
				`$${report.length}\r\n${report}\r\n`
			)
		).toEqual({ used_memory: '1024' });
	});
});

describe('redis pub/sub', () => {
	it('publishes a payload and a JSON value', async () => {
		const ctx = await connected();
		expect(
			await exchange(ctx, () => ctx.session.publish('c', 'hi'), ['PUBLISH', 'c', 'hi'], ':2\r\n')
		).toBe(2);
		expect(
			await exchange(
				ctx,
				() => ctx.session.publishJson('c', { ok: true }),
				['PUBLISH', 'c', '{"ok":true}'],
				':1\r\n'
			)
		).toBe(1);
	});

	it('subscribes over RESP2, waiting for one array confirmation per channel', async () => {
		const ctx = await connected();
		const pending = ctx.session.subscribe('a', 'b');
		expect(await readCommand(ctx.server)).toEqual(['SUBSCRIBE', 'a', 'b']);
		await ctx.server.write(
			bytesOf(
				'*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n*3\r\n$9\r\nsubscribe\r\n$1\r\nb\r\n:2\r\n'
			)
		);
		const sub = await pending;
		expect(sub.channels).toEqual(['a', 'b']);
		expect(sub.pattern).toBe(false);
		expect(ctx.session.subscriptionCount).toBe(2);

		await ctx.server.write(bytesOf('*3\r\n$7\r\nmessage\r\n$1\r\na\r\n$5\r\nhello\r\n'));
		const { value } = await sub[Symbol.asyncIterator]().next();
		expect(value!.channel).toBe('a');
		expect(value!.pattern).toBeUndefined();
		expect(value!.text()).toBe('hello');
	});

	it('subscribes over RESP3, where the confirmations arrive as pushes', async () => {
		const ctx = await connected({ protocol: 3 });
		const pending = ctx.session.subscribe('a');
		expect(await readCommand(ctx.server)).toEqual(['SUBSCRIBE', 'a']);
		await ctx.server.write(bytesOf('>3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n'));
		const sub = await pending;
		expect(ctx.session.subscriptionCount).toBe(1);

		// RESP3 lets an ordinary command run while subscribed; its reply must not be confused
		// with the delivery that follows
		const get = ctx.session.getText('k');
		expect(await readCommand(ctx.server)).toEqual(['GET', 'k']);
		await ctx.server.write(bytesOf('$1\r\nv\r\n>3\r\n$7\r\nmessage\r\n$1\r\na\r\n$2\r\nhi\r\n'));
		expect(await get).toBe('v');
		const { value } = await sub[Symbol.asyncIterator]().next();
		expect(value!.text()).toBe('hi');
	});

	it('routes a pattern delivery to the pattern that matched', async () => {
		const ctx = await connected();
		const pending = ctx.session.psubscribe('news.*');
		expect(await readCommand(ctx.server)).toEqual(['PSUBSCRIBE', 'news.*']);
		await ctx.server.write(bytesOf('*3\r\n$10\r\npsubscribe\r\n$6\r\nnews.*\r\n:1\r\n'));
		const sub = await pending;
		expect(sub.pattern).toBe(true);

		await ctx.server.write(
			bytesOf('*4\r\n$8\r\npmessage\r\n$6\r\nnews.*\r\n$9\r\nnews.jazz\r\n$7\r\n{"a":1}\r\n')
		);
		const { value } = await sub[Symbol.asyncIterator]().next();
		expect(value!.pattern).toBe('news.*');
		expect(value!.channel).toBe('news.jazz');
		expect(value!.json()).toEqual({ a: 1 });
	});

	it('raises ProtocolError when a delivery is not valid json', async () => {
		const ctx = await connected();
		const pending = ctx.session.subscribe('a');
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf('*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n'));
		const sub = await pending;
		await ctx.server.write(bytesOf('*3\r\n$7\r\nmessage\r\n$1\r\na\r\n$3\r\nnot\r\n'));
		const { value } = await sub[Symbol.asyncIterator]().next();
		expect(() => value!.json()).toThrow(ProtocolError);
	});

	it('fans one delivery out to every subscription holding the channel', async () => {
		const ctx = await connected();
		const first = ctx.session.subscribe('a');
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf('*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n'));
		const subA = await first;
		const second = ctx.session.subscribe('a');
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf('*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n'));
		const subB = await second;

		await ctx.server.write(bytesOf('*3\r\n$7\r\nmessage\r\n$1\r\na\r\n$2\r\nhi\r\n'));
		expect((await subA[Symbol.asyncIterator]().next()).value!.text()).toBe('hi');
		expect((await subB[Symbol.asyncIterator]().next()).value!.text()).toBe('hi');

		// the channel is only released once the last holder lets go
		await subA.unsubscribe();
		const releasing = subB.unsubscribe();
		expect(await readCommand(ctx.server)).toEqual(['UNSUBSCRIBE', 'a']);
		await ctx.server.write(bytesOf('*3\r\n$11\r\nunsubscribe\r\n$1\r\na\r\n:0\r\n'));
		await releasing;
		expect(ctx.session.subscriptionCount).toBe(0);
	});

	it('ends the iterator when the subscription is disposed', async () => {
		const ctx = await connected();
		const pending = ctx.session.subscribe('a');
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf('*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n'));
		const sub = await pending;
		const iter = sub[Symbol.asyncIterator]();
		const done = iter.next();
		const disposing = sub[Symbol.asyncDispose]();
		expect(await readCommand(ctx.server)).toEqual(['UNSUBSCRIBE', 'a']);
		await ctx.server.write(bytesOf('*3\r\n$11\r\nunsubscribe\r\n$1\r\na\r\n:0\r\n'));
		await disposing;
		expect((await done).done).toBe(true);
	});

	it('unsubscribes patterns with PUNSUBSCRIBE', async () => {
		const ctx = await connected();
		const pending = ctx.session.psubscribe('news.*');
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf('*3\r\n$10\r\npsubscribe\r\n$6\r\nnews.*\r\n:1\r\n'));
		const sub = await pending;
		const releasing = sub.unsubscribe();
		expect(await readCommand(ctx.server)).toEqual(['PUNSUBSCRIBE', 'news.*']);
		await ctx.server.write(bytesOf('*3\r\n$12\r\npunsubscribe\r\n$6\r\nnews.*\r\n:0\r\n'));
		await releasing;
	});

	it('drops the registration when the SUBSCRIBE itself is refused', async () => {
		const ctx = await connected();
		const pending = ctx.session.subscribe('a');
		await readCommand(ctx.server);
		await ctx.server.writeLine('-ERR subscribe refused');
		await expect(pending).rejects.toThrow(ProtocolError);
		expect(ctx.session.subscriptionCount).toBe(0);
		// nothing is left registered, so a later delivery has nowhere to go and is dropped
		await ctx.server.write(bytesOf('*3\r\n$7\r\nmessage\r\n$1\r\na\r\n$2\r\nhi\r\n'));
		await exchange(ctx, () => ctx.session.send('PING'), ['PING'], '+PONG\r\n');
	});

	it('rejects a subscribe with no channels', async () => {
		const ctx = await connected();
		await expect(ctx.session.subscribe()).rejects.toThrow(/at least one channel/);
		await expect(ctx.session.psubscribe()).rejects.toThrow(/at least one channel/);
	});

	it('ends every subscription when the connection drops', async () => {
		const ctx = await connected();
		const pending = ctx.session.subscribe('a');
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf('*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n'));
		const sub = await pending;
		const done = sub[Symbol.asyncIterator]().next();
		await ctx.server.close();
		expect((await done).done).toBe(true);
		// unsubscribing after the drop is a no-op rather than a write to a dead socket
		await expect(sub.unsubscribe()).resolves.toBeUndefined();
	});

	it('refuses data commands while a RESP2 connection is subscribed, but allows PING', async () => {
		const ctx = await connected();
		const pending = ctx.session.subscribe('a');
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf('*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n'));
		await pending;

		await expect(ctx.session.getText('k')).rejects.toThrow(/not allowed while a RESP2 connection/);
		await expect(ctx.session.pipeline([['GET', 'k']])).rejects.toThrow(/protocol: 3/);
		await expect(ctx.session.multi([['GET', 'k']])).rejects.toThrow(/protocol: 3/);

		// PING is on the permitted list; its subscriber-mode array reply normalizes back to PONG,
		// and an explicit payload still comes back echoed
		expect(
			await exchange(ctx, () => ctx.session.ping(), ['PING'], '*2\r\n$4\r\npong\r\n$0\r\n\r\n')
		).toBe('PONG');
		expect(
			await exchange(
				ctx,
				() => ctx.session.ping('hi'),
				['PING', 'hi'],
				'*2\r\n$4\r\npong\r\n$2\r\nhi\r\n'
			)
		).toBe('hi');
	});

	it('treats an array of pubsub-looking data as data outside subscriber mode', async () => {
		const ctx = await connected();
		expect(
			await exchange(
				ctx,
				() => ctx.session.lrange('l', 0, -1),
				['LRANGE', 'l', '0', '-1'],
				'*3\r\n$7\r\nmessage\r\n$1\r\na\r\n$2\r\nhi\r\n'
			)
		).toEqual(['message', 'a', 'hi']);
	});

	it('ignores an out-of-band push it does not recognize', async () => {
		const ctx = await connected({ protocol: 3 });
		const pending = ctx.session.send('GET', 'k');
		await readCommand(ctx.server);
		// a client-side-caching invalidation must not be handed to the waiting command
		await ctx.server.write(bytesOf('>2\r\n$10\r\ninvalidate\r\n*1\r\n$1\r\nk\r\n$1\r\nv\r\n'));
		expect((await pending).text()).toBe('v');
	});
});

describe('redis edge paths', () => {
	it('surfaces a failed socket write as a ConnectionError on the waiting command', async () => {
		const { socket } = mockConnection();
		// swap in a writer that always fails, before the session captures it
		(socket as { writer: unknown }).writer = {
			write: () => Promise.reject(new Error('socket gone')),
			writeLine: () => Promise.reject(new Error('socket gone')),
			close: () => Promise.resolve()
		};
		const session = await _connectOverSocket(socket, { hostname: 'redis.test' });
		await expect(session.send('PING')).rejects.toThrow(ConnectionError);
		// the failed waiter is removed, so a later command is not resolved by a stale reply
		await expect(session.send('PING')).rejects.toThrow(/failed to write/);
	});

	it('accepts a subscribe confirmation for a raw SUBSCRIBE it never counted', async () => {
		const ctx = await connected({ protocol: 3 });
		// sent through the escape hatch, so no confirmation was expected; the push type still
		// identifies it unambiguously
		const pending = ctx.session.send('SUBSCRIBE', 'x');
		expect(await readCommand(ctx.server)).toEqual(['SUBSCRIBE', 'x']);
		await ctx.server.write(bytesOf('>3\r\n$9\r\nsubscribe\r\n$1\r\nx\r\n:1\r\n'));
		expect((await pending).strings()).toEqual(['subscribe', 'x', '1']);
		expect(ctx.session.subscriptionCount).toBe(1);
	});

	it('reads a pubsub frame whose elements are simple strings rather than bulk', async () => {
		// the RESP3 spec writes its push example with simple strings; redis sends bulk, but the
		// protocol permits either
		const ctx = await connected({ protocol: 3 });
		const pending = ctx.session.subscribe('somechannel');
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf('>3\r\n+subscribe\r\n+somechannel\r\n:1\r\n'));
		const sub = await pending;
		await ctx.server.write(bytesOf('>3\r\n+message\r\n+somechannel\r\n+this is the message\r\n'));
		const { value } = await sub[Symbol.asyncIterator]().next();
		expect(value!.channel).toBe('somechannel');
		expect(value!.text()).toBe('this is the message');
		expect(Array.from(value!.payload)).toEqual(
			Array.from(new TextEncoder().encode('this is the message'))
		);
	});

	it('drops a delivery aimed at a subscription that already stopped listening', async () => {
		const ctx = await connected();
		const first = ctx.session.subscribe('a');
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf('*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n'));
		const subA = await first;
		const second = ctx.session.subscribe('a');
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf('*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n'));
		const subB = await second;

		// releasing A leaves the channel live for B, so the next delivery reaches an ended queue
		await subA.unsubscribe();
		await ctx.server.write(bytesOf('*3\r\n$7\r\nmessage\r\n$1\r\na\r\n$2\r\nhi\r\n'));
		expect((await subB[Symbol.asyncIterator]().next()).value!.text()).toBe('hi');
		expect((await subA[Symbol.asyncIterator]().next()).done).toBe(true);
	});

	it('is idempotent when a subscription is released twice', async () => {
		const ctx = await connected();
		const pending = ctx.session.subscribe('a');
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf('*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n'));
		const sub = await pending;
		const releasing = sub.unsubscribe();
		expect(await readCommand(ctx.server)).toEqual(['UNSUBSCRIBE', 'a']);
		await ctx.server.write(bytesOf('*3\r\n$11\r\nunsubscribe\r\n$1\r\na\r\n:0\r\n'));
		await releasing;
		// the second release has nothing left to detach and writes nothing
		await expect(sub.unsubscribe()).resolves.toBeUndefined();
		await exchange(ctx, () => ctx.session.send('PING'), ['PING'], '+PONG\r\n');
	});

	it('refuses a nameless command while subscribed on RESP2', async () => {
		const ctx = await connected();
		const pending = ctx.session.subscribe('a');
		await readCommand(ctx.server);
		await ctx.server.write(bytesOf('*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n'));
		await pending;
		await expect(ctx.session.pipeline([[]])).rejects.toThrow(/is not allowed while a RESP2/);
	});

	it('defaults the scan cursor and the eval options when they are omitted', async () => {
		const ctx = await connected();
		expect(
			await exchange(ctx, () => ctx.session.scan(), ['SCAN', '0'], '*2\r\n$1\r\n0\r\n*0\r\n')
		).toEqual({ cursor: '0', keys: [] });

		const found: string[] = [];
		const walk = (async () => {
			for await (const key of ctx.session.scanIterator()) found.push(key);
		})();
		expect(await readCommand(ctx.server)).toEqual(['SCAN', '0']);
		await ctx.server.write(bytesOf('*2\r\n$1\r\n0\r\n*1\r\n$1\r\nk\r\n'));
		await walk;
		expect(found).toEqual(['k']);

		await exchange(ctx, () => ctx.session.evalSha('sha1'), ['EVALSHA', 'sha1', '0'], ':1\r\n');
	});
});

describe('redis one-shots', () => {
	it('command connects, runs one command, and closes', async () => {
		const { socket, server } = mockConnection();
		const closed = vi.spyOn(socket, 'close');
		vi.mocked(coreConnect).mockResolvedValue(socket);
		const pending = command({ hostname: 'redis.test', args: ['GET', 'k'] });
		expect(await readCommand(server)).toEqual(['GET', 'k']);
		await server.write(bytesOf('$5\r\nhello\r\n'));
		expect((await pending).text()).toBe('hello');
		expect(closed).toHaveBeenCalled();
	});

	it('publish connects, publishes, and reports the receiver count', async () => {
		const { socket, server } = mockConnection();
		vi.mocked(coreConnect).mockResolvedValue(socket);
		const pending = publish({ hostname: 'redis.test', channel: 'c', message: 'hi' });
		expect(await readCommand(server)).toEqual(['PUBLISH', 'c', 'hi']);
		await server.write(bytesOf(':3\r\n'));
		expect(await pending).toBe(3);
	});
});

describe('redis reply accessors', () => {
	const reply = (raw: RespValue) => makeReply(raw);
	const bulk = (s: string) => reply({ kind: 'bulk', value: new TextEncoder().encode(s) });

	it('reads text from every scalar kind', () => {
		expect(reply({ kind: 'string', value: 'OK' }).text()).toBe('OK');
		expect(bulk('hi').text()).toBe('hi');
		expect(reply({ kind: 'number', value: 7 }).text()).toBe('7');
		expect(reply({ kind: 'bignum', value: 10n }).text()).toBe('10');
		expect(reply({ kind: 'boolean', value: true }).text()).toBe('1');
		expect(reply({ kind: 'boolean', value: false }).text()).toBe('0');
		expect(reply({ kind: 'null' }).text()).toBe('');
		expect(
			reply({ kind: 'verbatim', format: 'txt', value: new TextEncoder().encode('v') }).text()
		).toBe('v');
	});

	it('renders the double specials the way RESP writes them', () => {
		expect(reply({ kind: 'double', value: 1.5 }).text()).toBe('1.5');
		expect(reply({ kind: 'double', value: Infinity }).text()).toBe('inf');
		expect(reply({ kind: 'double', value: -Infinity }).text()).toBe('-inf');
		expect(reply({ kind: 'double', value: NaN }).text()).toBe('nan');
	});

	it('reads bytes from bulk, verbatim, scalars, and null', () => {
		expect(Array.from(bulk('A').bytes())).toEqual([0x41]);
		expect(
			Array.from(reply({ kind: 'verbatim', format: 'txt', value: new Uint8Array([1]) }).bytes())
		).toEqual([1]);
		expect(Array.from(reply({ kind: 'number', value: 7 }).bytes())).toEqual([0x37]);
		expect(reply({ kind: 'null' }).bytes()).toHaveLength(0);
		expect(Array.from(reply({ kind: 'double', value: 1 }).bytes())).toEqual([0x31]);
		expect(Array.from(reply({ kind: 'bignum', value: 8n }).bytes())).toEqual([0x38]);
		expect(Array.from(reply({ kind: 'boolean', value: true }).bytes())).toEqual([0x31]);
	});

	it('reads numbers from integers, doubles, bignums, booleans, and numeric strings', () => {
		expect(reply({ kind: 'number', value: 7 }).number()).toBe(7);
		expect(reply({ kind: 'double', value: 1.5 }).number()).toBe(1.5);
		expect(reply({ kind: 'bignum', value: 9n }).number()).toBe(9);
		expect(reply({ kind: 'boolean', value: true }).number()).toBe(1);
		expect(reply({ kind: 'boolean', value: false }).number()).toBe(0);
		expect(bulk('2.5').number()).toBe(2.5);
		expect(reply({ kind: 'string', value: '4' }).number()).toBe(4);
	});

	it('reads booleans from every kind redis uses for a flag', () => {
		expect(reply({ kind: 'boolean', value: false }).boolean()).toBe(false);
		expect(reply({ kind: 'number', value: 0 }).boolean()).toBe(false);
		expect(reply({ kind: 'number', value: 1 }).boolean()).toBe(true);
		expect(reply({ kind: 'double', value: 0 }).boolean()).toBe(false);
		expect(reply({ kind: 'null' }).boolean()).toBe(false);
		expect(reply({ kind: 'string', value: 'OK' }).boolean()).toBe(true);
		expect(bulk('').boolean()).toBe(false);
		expect(reply({ kind: 'array', value: [] }).boolean()).toBe(true);
	});

	it('projects every kind onto plain javascript', () => {
		expect(reply({ kind: 'bignum', value: 12345678901234567890n }).value).toBe(
			12345678901234567890n
		);
		expect(reply({ kind: 'boolean', value: true }).value).toBe(true);
		expect(reply({ kind: 'double', value: 1.5 }).value).toBe(1.5);
		expect(reply({ kind: 'null' }).value).toBeNull();
		expect(reply({ kind: 'set', value: [{ kind: 'number', value: 1 }] }).value).toEqual([1]);
		expect(
			reply({ kind: 'verbatim', format: 'txt', value: new TextEncoder().encode('v') }).value
		).toBe('v');
	});

	it('parses json and reports a bad payload as a ProtocolError', () => {
		expect(bulk('{"a":1}').json()).toEqual({ a: 1 });
		expect(() => bulk('nope').json()).toThrow(ProtocolError);
	});

	it('reads aggregates as items, strings, and field-value objects', () => {
		const arr = reply({
			kind: 'array',
			value: [{ kind: 'bulk', value: new TextEncoder().encode('f') }, { kind: 'null' }]
		});
		expect(arr.items()).toHaveLength(2);
		expect(arr.strings()).toEqual(['f', '']);
		expect(arr.map()).toEqual({ f: '' });
		const set = reply({ kind: 'set', value: [{ kind: 'number', value: 1 }] });
		expect(set.strings()).toEqual(['1']);
		const push = reply({ kind: 'push', value: [{ kind: 'number', value: 2 }] });
		expect(push.strings()).toEqual(['2']);
	});

	it('flattens a map for strings and stringifies a structured key', () => {
		const map = reply({
			kind: 'map',
			value: [
				[{ kind: 'number', value: 1 }, { kind: 'null' }],
				[
					{ kind: 'array', value: [{ kind: 'number', value: 2 }] },
					{ kind: 'string', value: 'v' }
				]
			]
		});
		expect(map.map()).toEqual({ '1': '', '[2]': 'v' });
		expect(map.value).toEqual({ '1': null, '[2]': 'v' });
		// map() must stringify a structured key to build a Record; strings() stays strict and
		// points the caller at items() instead of quietly emitting a JSON blob
		expect(() => map.strings()).toThrow(/as text/);
	});

	it('rejects reading a value out of the wrong shape', () => {
		const arr = reply({ kind: 'array', value: [{ kind: 'number', value: 1 }] });
		expect(() => arr.text()).toThrow(/as text/);
		expect(() => arr.bytes()).toThrow(/as bytes/);
		expect(() => arr.number()).toThrow(/as a number/);
		expect(() => arr.map()).toThrow(/field-value pairs/);
		expect(() => bulk('abc').number()).toThrow(/not numeric/);
		expect(() => bulk('').number()).toThrow(/not numeric/);
		expect(() => reply({ kind: 'null' }).number()).toThrow(/as a number/);
		expect(() => bulk('x').items()).toThrow(/as a list/);
		expect(() => bulk('x').strings()).toThrow(/as a list/);
	});

	it('refuses to read an error reply as anything but its message', () => {
		const err = reply({ kind: 'error', value: 'WRONGTYPE nope' });
		expect(err.error).toBe('WRONGTYPE nope');
		expect(err.value).toBe('WRONGTYPE nope');
		expect(err.raw.kind).toBe('error');
		expect(err.isNull).toBe(false);
		for (const read of [
			() => err.text(),
			() => err.bytes(),
			() => err.number(),
			() => err.boolean(),
			() => err.json(),
			() => err.items(),
			() => err.strings(),
			() => err.map()
		]) {
			expect(read).toThrow(ProtocolError);
		}
	});
});
