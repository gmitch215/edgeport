// byte-exact RESP vectors: the examples in the protocol spec plus frames captured off a live
// redis 8.8 (DEBUG PROTOCOL for the RESP3 types, real HELLO/pubsub/EXEC exchanges)
import { describe, expect, it } from 'vitest';
import { StreamFramedReader } from '../../src/core/framing';
import {
	encodeCommand,
	encodeCommands,
	makeReply,
	readReply,
	respToNative,
	type RespValue
} from '../../src/redis/resp';

// latin1 so a vector written as a JS string maps one char to one byte (RESP payloads are binary)
function bytesOf(wire: string): Uint8Array {
	const out = new Uint8Array(wire.length);
	for (let i = 0; i < wire.length; i++) out[i] = wire.charCodeAt(i) & 0xff;
	return out;
}

function wireOf(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => String.fromCharCode(b)).join('');
}

function readerOf(wire: string): StreamFramedReader {
	const data = bytesOf(wire);
	return new StreamFramedReader(
		new ReadableStream<Uint8Array>({
			start(c) {
				c.enqueue(data);
				c.close();
			}
		})
	);
}

// decodes exactly one reply from a vector
function decode(wire: string): Promise<RespValue> {
	return readReply(readerOf(wire));
}

describe('resp command encoding', () => {
	it('encodes the spec LLEN example byte for byte', () => {
		expect(wireOf(encodeCommand(['LLEN', 'mylist']))).toBe('*2\r\n$4\r\nLLEN\r\n$6\r\nmylist\r\n');
	});

	it('stringifies numeric arguments so they match their string form exactly', () => {
		expect(wireOf(encodeCommand(['SET', 'k', 1]))).toBe(wireOf(encodeCommand(['SET', 'k', '1'])));
		expect(wireOf(encodeCommand(['EXPIRE', 'k', -30]))).toBe(
			'*3\r\n$6\r\nEXPIRE\r\n$1\r\nk\r\n$3\r\n-30\r\n'
		);
	});

	it('measures multi-byte arguments in bytes, not characters', () => {
		// 'é' is two UTF-8 bytes, so the bulk length is 2 while the string length is 1
		expect(wireOf(encodeCommand(['SET', 'k', 'é']))).toBe(
			'*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$2\r\n\xc3\xa9\r\n'
		);
	});

	it('passes byte arguments through untouched, including NUL and CRLF', () => {
		const raw = new Uint8Array([0x00, 0xff, 0x0d, 0x0a, 0x80]);
		expect(wireOf(encodeCommand(['SET', 'bin', raw]))).toBe(
			'*3\r\n$3\r\nSET\r\n$3\r\nbin\r\n$5\r\n\x00\xff\r\n\x80\r\n'
		);
	});

	it('encodes an empty argument as a zero-length bulk string', () => {
		expect(wireOf(encodeCommand(['SET', 'k', '']))).toBe(
			'*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$0\r\n\r\n'
		);
	});

	it('concatenates a pipeline into one frame', () => {
		expect(wireOf(encodeCommands([['PING'], ['GET', 'k']]))).toBe(
			'*1\r\n$4\r\nPING\r\n*2\r\n$3\r\nGET\r\n$1\r\nk\r\n'
		);
	});

	it('rejects an empty command', () => {
		expect(() => encodeCommand([])).toThrow(/at least a name/);
		expect(() => encodeCommands([])).toThrow(/no commands/);
	});
});

describe('resp2 reply decoding', () => {
	it('decodes the spec simple string, error, and integer examples', async () => {
		expect(await decode('+OK\r\n')).toEqual({ kind: 'string', value: 'OK' });
		expect(await decode("-ERR unknown command 'asdf'\r\n")).toEqual({
			kind: 'error',
			value: "ERR unknown command 'asdf'"
		});
		expect(await decode(':48293\r\n')).toEqual({ kind: 'number', value: 48293 });
		expect(await decode(':-1\r\n')).toEqual({ kind: 'number', value: -1 });
		expect(await decode(':+7\r\n')).toEqual({ kind: 'number', value: 7 });
	});

	it('decodes bulk strings including the empty one', async () => {
		const hello = await decode('$5\r\nhello\r\n');
		expect(hello.kind).toBe('bulk');
		expect(wireOf((hello as { value: Uint8Array }).value)).toBe('hello');
		expect(await decode('$0\r\n\r\n')).toEqual({ kind: 'bulk', value: new Uint8Array(0) });
	});

	it('keeps a bulk string binary-safe when it contains CRLF and NUL', async () => {
		const value = await decode('$5\r\n\x00\xff\r\n\x80\r\n');
		expect(Array.from((value as { value: Uint8Array }).value)).toEqual([
			0x00, 0xff, 0x0d, 0x0a, 0x80
		]);
	});

	it('collapses the RESP2 null bulk string and null array onto one null kind', async () => {
		expect(await decode('$-1\r\n')).toEqual({ kind: 'null' });
		expect(await decode('*-1\r\n')).toEqual({ kind: 'null' });
	});

	it('decodes the spec array examples', async () => {
		expect(await decode('*0\r\n')).toEqual({ kind: 'array', value: [] });
		expect(respToNative(await decode('*2\r\n$5\r\nhello\r\n$5\r\nworld\r\n'))).toEqual([
			'hello',
			'world'
		]);
		expect(respToNative(await decode('*3\r\n:1\r\n:2\r\n:3\r\n'))).toEqual([1, 2, 3]);
		expect(respToNative(await decode('*5\r\n:1\r\n:2\r\n:3\r\n:4\r\n$5\r\nhello\r\n'))).toEqual([
			1,
			2,
			3,
			4,
			'hello'
		]);
	});

	it('decodes the spec nested-array example', async () => {
		const nested = await decode('*2\r\n*3\r\n:1\r\n:2\r\n:3\r\n*2\r\n+Hello\r\n-World\r\n');
		expect(respToNative(nested)).toEqual([
			[1, 2, 3],
			['Hello', 'World']
		]);
		const [, second] = (nested as { value: RespValue[] }).value;
		expect((second as { value: RespValue[] }).value[1]!.kind).toBe('error');
	});

	it('decodes the spec null-element-in-array example', async () => {
		expect(respToNative(await decode('*3\r\n$5\r\nhello\r\n$-1\r\n$5\r\nworld\r\n'))).toEqual([
			'hello',
			null,
			'world'
		]);
	});
});

describe('resp3 reply decoding', () => {
	it('decodes null, booleans, and doubles as captured from redis 8.8', async () => {
		expect(await decode('_\r\n')).toEqual({ kind: 'null' });
		expect(await decode('#t\r\n')).toEqual({ kind: 'boolean', value: true });
		expect(await decode('#f\r\n')).toEqual({ kind: 'boolean', value: false });
		expect(await decode(',3.141\r\n')).toEqual({ kind: 'double', value: 3.141 });
		expect(await decode(',1.23\r\n')).toEqual({ kind: 'double', value: 1.23 });
		expect(await decode(',10\r\n')).toEqual({ kind: 'double', value: 10 });
		expect(await decode(',3.0e3\r\n')).toEqual({ kind: 'double', value: 3000 });
	});

	it('decodes the double infinities and NaN', async () => {
		expect(await decode(',inf\r\n')).toEqual({ kind: 'double', value: Infinity });
		expect(await decode(',-inf\r\n')).toEqual({ kind: 'double', value: -Infinity });
		expect((await decode(',nan\r\n')) as { value: number }).toEqual({
			kind: 'double',
			value: NaN
		});
	});

	it('decodes a big number past the 64-bit range as a bigint', async () => {
		expect(await decode('(3492890328409238509324850943850943825024385\r\n')).toEqual({
			kind: 'bignum',
			value: 3492890328409238509324850943850943825024385n
		});
		// the exact value DEBUG PROTOCOL bignum returns
		expect(await decode('(1234567999999999999999999999999999999\r\n')).toEqual({
			kind: 'bignum',
			value: 1234567999999999999999999999999999999n
		});
	});

	it('decodes a bulk error onto the same kind as a simple error', async () => {
		expect(await decode('!21\r\nSYNTAX invalid syntax\r\n')).toEqual({
			kind: 'error',
			value: 'SYNTAX invalid syntax'
		});
	});

	it('splits a verbatim string into its 3-byte encoding and its data', async () => {
		// captured verbatim: the length counts the 'txt:' prefix and the data holds a raw LF
		const value = await decode('=29\r\ntxt:This is a verbatim\nstring\r\n');
		expect(value.kind).toBe('verbatim');
		expect((value as { format: string }).format).toBe('txt');
		expect(wireOf((value as { value: Uint8Array }).value)).toBe('This is a verbatim\nstring');
	});

	it('decodes a map with non-string keys, as DEBUG PROTOCOL map returns', async () => {
		const value = await decode('%3\r\n:0\r\n#f\r\n:1\r\n#t\r\n:2\r\n#f\r\n');
		expect(value.kind).toBe('map');
		expect(respToNative(value)).toEqual({ '0': false, '1': true, '2': false });
	});

	it('decodes the spec map example', async () => {
		expect(respToNative(await decode('%2\r\n+first\r\n:1\r\n+second\r\n:2\r\n'))).toEqual({
			first: 1,
			second: 2
		});
	});

	it('decodes a set as its own kind', async () => {
		const value = await decode('~3\r\n:0\r\n:1\r\n:2\r\n');
		expect(value.kind).toBe('set');
		expect(respToNative(value)).toEqual([0, 1, 2]);
	});

	it('decodes a push as its own kind', async () => {
		const value = await decode('>3\r\n$7\r\nmessage\r\n$4\r\nchan\r\n$8\r\nhi there\r\n');
		expect(value.kind).toBe('push');
		expect(respToNative(value)).toEqual(['message', 'chan', 'hi there']);
	});

	it('folds an attribute into the value that follows it', async () => {
		// exactly what DEBUG PROTOCOL attrib sends
		const value = await decode(
			'|1\r\n$14\r\nkey-popularity\r\n*2\r\n$7\r\nkey:123\r\n:90\r\n$39\r\nSome real reply following the attribute\r\n'
		);
		expect(value.kind).toBe('bulk');
		expect(makeReply(value).text()).toBe('Some real reply following the attribute');
		expect(value.attributes).toHaveLength(1);
		expect(respToNative(value.attributes![0]![0]!)).toBe('key-popularity');
		expect(respToNative(value.attributes![0]![1]!)).toEqual(['key:123', 90]);
	});

	it('folds the spec attribute example onto the array element it annotates', async () => {
		const value = await decode('*3\r\n:1\r\n:2\r\n|1\r\n+ttl\r\n:3600\r\n:3\r\n');
		expect(respToNative(value)).toEqual([1, 2, 3]);
		const third = (value as { value: RespValue[] }).value[2]!;
		expect(respToNative(third.attributes![0]![0]!)).toBe('ttl');
		expect(respToNative(third.attributes![0]![1]!)).toBe(3600);
	});
});

describe('real captured exchanges', () => {
	it('decodes the HELLO 3 handshake map', async () => {
		const hello = await decode(
			'%7\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n8.8.2\r\n$5\r\nproto\r\n:3\r\n' +
				'$2\r\nid\r\n:12\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n$4\r\nrole\r\n$6\r\nmaster\r\n' +
				'$7\r\nmodules\r\n*0\r\n'
		);
		expect(respToNative(hello)).toEqual({
			server: 'redis',
			version: '8.8.2',
			proto: 3,
			id: 12,
			mode: 'standalone',
			role: 'master',
			modules: []
		});
	});

	it('decodes the RESP2 subscriber-mode frames in stream order', async () => {
		// SUBSCRIBE a b, then PING, then UNSUBSCRIBE a - exactly as redis 8.8 replied
		const reader = readerOf(
			'*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n' +
				'*3\r\n$9\r\nsubscribe\r\n$1\r\nb\r\n:2\r\n' +
				'*2\r\n$4\r\npong\r\n$0\r\n\r\n' +
				'*3\r\n$11\r\nunsubscribe\r\n$1\r\na\r\n:1\r\n'
		);
		expect(respToNative(await readReply(reader))).toEqual(['subscribe', 'a', 1]);
		expect(respToNative(await readReply(reader))).toEqual(['subscribe', 'b', 2]);
		expect(respToNative(await readReply(reader))).toEqual(['pong', '']);
		expect(respToNative(await readReply(reader))).toEqual(['unsubscribe', 'a', 1]);
	});

	it('decodes the RESP3 push confirmations and delivery in stream order', async () => {
		// SUBSCRIBE a b / PING / GET nope / PSUBSCRIBE news.* / a delivery
		const reader = readerOf(
			'>3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n' +
				'>3\r\n$9\r\nsubscribe\r\n$1\r\nb\r\n:2\r\n' +
				'+PONG\r\n' +
				'_\r\n' +
				'>3\r\n$10\r\npsubscribe\r\n$6\r\nnews.*\r\n:3\r\n' +
				'>3\r\n$7\r\nmessage\r\n$4\r\nchan\r\n$8\r\nhi there\r\n'
		);
		const kinds: string[] = [];
		for (let i = 0; i < 6; i++) kinds.push((await readReply(reader)).kind);
		expect(kinds).toEqual(['push', 'push', 'string', 'null', 'push', 'push']);
	});

	it('decodes a MULTI/EXEC batch, keeping a per-command error inside the array', async () => {
		const reader = readerOf('+OK\r\n+QUEUED\r\n+QUEUED\r\n+QUEUED\r\n');
		for (let i = 0; i < 4; i++) await readReply(reader);
		const exec = await decode(
			'*3\r\n:1\r\n$-1\r\n-WRONGTYPE Operation against a key holding the wrong kind of value\r\n'
		);
		const items = makeReply(exec).items();
		expect(items[0]!.number()).toBe(1);
		expect(items[1]!.isNull).toBe(true);
		expect(items[2]!.error).toMatch(/^WRONGTYPE/);
	});

	it('reads a pipelined burst of replies from a single frame', async () => {
		const reader = readerOf('+OK\r\n:2\r\n$3\r\nabc\r\n*1\r\n:9\r\n$-1\r\n');
		const values: unknown[] = [];
		for (let i = 0; i < 5; i++) values.push(respToNative(await readReply(reader)));
		expect(values).toEqual(['OK', 2, 'abc', [9], null]);
	});

	it('normalizes the RESP2 flat hash and the RESP3 hash map onto the same object', async () => {
		const resp2 = makeReply(await decode('*4\r\n$2\r\nf1\r\n$2\r\nv1\r\n$2\r\nf2\r\n$2\r\nv2\r\n'));
		const resp3 = makeReply(await decode('%2\r\n$2\r\nf1\r\n$2\r\nv1\r\n$2\r\nf2\r\n$2\r\nv2\r\n'));
		expect(resp2.map()).toEqual({ f1: 'v1', f2: 'v2' });
		expect(resp3.map()).toEqual(resp2.map());
	});

	it('reads the RESP2 and RESP3 WITHSCORES shapes as the same member/score pairs', async () => {
		const resp2 = makeReply(await decode('*4\r\n$1\r\na\r\n$1\r\n1\r\n$1\r\nb\r\n$3\r\n2.5\r\n'));
		const resp3 = makeReply(await decode('*2\r\n*2\r\n$1\r\na\r\n,1\r\n*2\r\n$1\r\nb\r\n,2.5\r\n'));
		expect(resp2.strings()).toEqual(['a', '1', 'b', '2.5']);
		expect(resp3.items().map((p) => p.strings())).toEqual([
			['a', '1'],
			['b', '2.5']
		]);
	});
});

describe('malformed frames', () => {
	it('rejects an unknown type byte', async () => {
		await expect(decode('^nope\r\n')).rejects.toThrow(/unknown resp type byte/);
	});

	it('rejects an empty frame', async () => {
		await expect(decode('\r\n')).rejects.toThrow(/empty resp frame/);
	});

	it('rejects a non-numeric length or integer', async () => {
		await expect(decode(':abc\r\n')).rejects.toThrow(/malformed resp integer/);
		await expect(decode('$x\r\nhi\r\n')).rejects.toThrow(/malformed resp integer/);
		await expect(decode(',1.2.3\r\n')).rejects.toThrow(/malformed resp double/);
		await expect(decode('(12.5\r\n')).rejects.toThrow(/malformed resp big number/);
	});

	it('rejects a malformed null or boolean', async () => {
		await expect(decode('_x\r\n')).rejects.toThrow(/malformed resp null/);
		await expect(decode('#y\r\n')).rejects.toThrow(/malformed resp boolean/);
	});

	it('rejects negative lengths on the types that have no null form', async () => {
		await expect(decode('!-1\r\n')).rejects.toThrow(/bulk error with negative length/);
		await expect(decode('~-1\r\n')).rejects.toThrow(/set with negative length/);
		await expect(decode('>-1\r\n')).rejects.toThrow(/push with negative length/);
		await expect(decode('%-1\r\n')).rejects.toThrow(/map with negative length/);
		await expect(decode('|-1\r\n')).rejects.toThrow(/attribute with negative length/);
	});

	it('rejects a verbatim string that is too short or missing its separator', async () => {
		await expect(decode('=2\r\ntx\r\n')).rejects.toThrow(/too short for its encoding prefix/);
		await expect(decode('=8\r\ntxt-data\r\n')).rejects.toThrow(/missing the :/);
	});

	it('rejects a reply nested past the depth limit', async () => {
		const deep = '*1\r\n'.repeat(200) + ':1\r\n';
		await expect(decode(deep)).rejects.toThrow(/nested deeper than 128 levels/);
	});

	it('accepts nesting right up to the depth limit', async () => {
		const ok = '*1\r\n'.repeat(64) + ':1\r\n';
		expect((await decode(ok)).kind).toBe('array');
	});

	it('rejects a frame that ends before its payload is complete', async () => {
		await expect(decode('$10\r\nshort\r\n')).rejects.toThrow(/connection closed/);
	});
});
