import { describe, expect, it } from 'vitest';
import { AuthError, ConnectionError, ProtocolError, TimeoutError } from '../../src/core/errors';
import {
	decodeJson,
	encodeJson,
	formatEmailAddress,
	fromBase64,
	fromHex,
	fromUtf8,
	parseEmailAddress,
	randomHex,
	randomId,
	retry,
	toBase64,
	toHex,
	toUtf8,
	withTimeout
} from '../../src/util';

const enc = new TextEncoder();
const dec = new TextDecoder();

describe('util hex', () => {
	it('encodes bytes to lowercase hex', () => {
		expect(toHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe('deadbeef');
		expect(toHex(new Uint8Array([0, 1, 15, 16, 255]))).toBe('00010f10ff');
	});

	it('round-trips and ignores whitespace on decode', () => {
		expect(Array.from(fromHex('de ad be ef'))).toEqual([0xde, 0xad, 0xbe, 0xef]);
		const bytes = new Uint8Array([1, 2, 3, 250, 128]);
		expect(Array.from(fromHex(toHex(bytes)))).toEqual(Array.from(bytes));
	});

	it('rejects odd-length and non-hex input', () => {
		expect(() => fromHex('abc')).toThrow(ProtocolError);
		expect(() => fromHex('zz')).toThrow(ProtocolError);
	});
});

describe('util base64', () => {
	it('encodes standard base64 with padding by default', () => {
		expect(toBase64(enc.encode('hi>?'))).toBe('aGk+Pw==');
	});

	it('encodes url-safe base64 unpadded by default', () => {
		expect(toBase64(enc.encode('hi>?'), { urlSafe: true })).toBe('aGk-Pw');
	});

	it('honors explicit pad option', () => {
		expect(toBase64(enc.encode('hi>?'), { urlSafe: true, pad: true })).toBe('aGk-Pw==');
		expect(toBase64(enc.encode('hi>?'), { pad: false })).toBe('aGk+Pw');
	});

	it('decodes standard and url-safe, restoring padding', () => {
		expect(dec.decode(fromBase64('aGk+Pw=='))).toBe('hi>?');
		expect(dec.decode(fromBase64('aGk-Pw'))).toBe('hi>?');
	});

	it('strips a data-uri prefix and whitespace before decoding', () => {
		expect(dec.decode(fromBase64('data:text/plain;base64,aGk+Pw=='))).toBe('hi>?');
		expect(dec.decode(fromBase64('aGk+\nPw=='))).toBe('hi>?');
	});

	it('round-trips arbitrary bytes both ways', () => {
		const bytes = new Uint8Array([0, 62, 63, 127, 128, 255, 1, 2]);
		expect(Array.from(fromBase64(toBase64(bytes)))).toEqual(Array.from(bytes));
		expect(Array.from(fromBase64(toBase64(bytes, { urlSafe: true })))).toEqual(Array.from(bytes));
	});

	it('rejects an impossible base64 length', () => {
		expect(() => fromBase64('aGk+Pw=A=')).toThrow(ProtocolError);
	});
});

describe('util random', () => {
	it('randomHex returns the requested byte length as hex', () => {
		expect(randomHex(8)).toMatch(/^[0-9a-f]{16}$/);
		expect(randomHex(4)).toMatch(/^[0-9a-f]{8}$/);
		expect(randomHex()).toMatch(/^[0-9a-f]{16}$/);
	});

	it('randomId prefixes a random hex suffix', () => {
		const id = randomId('edgeport');
		expect(id).toMatch(/^edgeport-[0-9a-f]{16}$/);
	});

	it('produces distinct values', () => {
		expect(randomHex()).not.toBe(randomHex());
	});
});

describe('util retry', () => {
	it('returns the first successful result without retrying', async () => {
		let calls = 0;
		const out = await retry(async () => {
			calls++;
			return 'ok';
		});
		expect(out).toBe('ok');
		expect(calls).toBe(1);
	});

	it('retries a transient ConnectionError then succeeds', async () => {
		let calls = 0;
		const out = await retry(
			async () => {
				calls++;
				if (calls < 3) throw new ConnectionError('boom');
				return calls;
			},
			{ attempts: 5, baseMs: 0 }
		);
		expect(out).toBe(3);
		expect(calls).toBe(3);
	});

	it('does not retry an AuthError', async () => {
		let calls = 0;
		await expect(
			retry(
				async () => {
					calls++;
					throw new AuthError('nope');
				},
				{ attempts: 5, baseMs: 0 }
			)
		).rejects.toBeInstanceOf(AuthError);
		expect(calls).toBe(1);
	});

	it('rethrows the last error once attempts are exhausted', async () => {
		let calls = 0;
		await expect(
			retry(
				async () => {
					calls++;
					throw new TimeoutError('slow');
				},
				{ attempts: 3, baseMs: 0 }
			)
		).rejects.toBeInstanceOf(TimeoutError);
		expect(calls).toBe(3);
	});

	it('honors a custom retryable predicate', async () => {
		let calls = 0;
		const out = await retry(
			async () => {
				calls++;
				if (calls < 2) throw new ProtocolError('retry me');
				return 'done';
			},
			{ attempts: 3, baseMs: 0, retryable: (e) => e instanceof ProtocolError }
		);
		expect(out).toBe('done');
		expect(calls).toBe(2);
	});
});

describe('util parseEmailAddress', () => {
	it('parses a bare address into local + domain', () => {
		expect(parseEmailAddress('ops@example.com')).toEqual({
			address: 'ops@example.com',
			local: 'ops',
			domain: 'example.com'
		});
	});

	it('parses a display-name form and strips the angle brackets', () => {
		expect(parseEmailAddress('Ada Lovelace <ada@example.com>')).toEqual({
			name: 'Ada Lovelace',
			address: 'ada@example.com',
			local: 'ada',
			domain: 'example.com'
		});
	});

	it('unquotes a quoted display name that contains a comma', () => {
		expect(parseEmailAddress('"Doe, John" <john@x.com>')).toEqual({
			name: 'Doe, John',
			address: 'john@x.com',
			local: 'john',
			domain: 'x.com'
		});
	});

	it('trims surrounding whitespace on the name and the bracketed address', () => {
		expect(parseEmailAddress('  Foo   <  a@b.com  >  ')).toEqual({
			name: 'Foo',
			address: 'a@b.com',
			local: 'a',
			domain: 'b.com'
		});
	});

	it('handles an angle-bracket-only address with no display name', () => {
		expect(parseEmailAddress('<a@b.com>')).toEqual({
			address: 'a@b.com',
			local: 'a',
			domain: 'b.com'
		});
	});

	it('omits the domain when the address has no @', () => {
		expect(parseEmailAddress('postmaster')).toEqual({ address: 'postmaster', local: 'postmaster' });
	});

	it('splits the domain on the last @', () => {
		const p = parseEmailAddress('"weird@local" <weird@local@example.com>');
		expect(p.address).toBe('weird@local@example.com');
		expect(p.local).toBe('weird@local');
		expect(p.domain).toBe('example.com');
	});

	it('yields an empty address for the null-path <>', () => {
		expect(parseEmailAddress('<>')).toEqual({ address: '', local: '' });
	});

	it('matches the old smtp bareAddress behavior (address field only)', () => {
		// the smtp envelope depends on parseEmailAddress(x).address == the old bareAddress(x)
		const bare = (a: string) => parseEmailAddress(a).address;
		expect(bare('user@example.com')).toBe('user@example.com');
		expect(bare('Support <me@example.com>')).toBe('me@example.com');
		expect(bare('  spaced@h  ')).toBe('spaced@h');
		expect(bare('<>')).toBe('');
	});
});

describe('util formatEmailAddress', () => {
	it('returns a bare address unchanged', () => {
		expect(formatEmailAddress({ address: 'ada@example.com' })).toBe('ada@example.com');
	});

	it('wraps a plain display name in angle brackets', () => {
		expect(formatEmailAddress({ name: 'Ada', address: 'ada@example.com' })).toBe(
			'Ada <ada@example.com>'
		);
	});

	it('quotes a display name that needs it', () => {
		expect(formatEmailAddress({ name: 'Doe, John', address: 'j@x.com' })).toBe(
			'"Doe, John" <j@x.com>'
		);
	});

	it('round-trips through parseEmailAddress', () => {
		const formatted = formatEmailAddress({ name: 'Grace Hopper', address: 'grace@navy.mil' });
		const parsed = parseEmailAddress(formatted);
		expect(parsed.name).toBe('Grace Hopper');
		expect(parsed.address).toBe('grace@navy.mil');
	});
});

describe('util withTimeout', () => {
	it('resolves with the promise result when it settles first', async () => {
		await expect(withTimeout(Promise.resolve('ok'), 1000, 'op')).resolves.toBe('ok');
	});

	it('rejects with TimeoutError when the deadline elapses', async () => {
		const never = new Promise<never>(() => {});
		await expect(withTimeout(never, 5, 'read')).rejects.toBeInstanceOf(TimeoutError);
	});

	it('includes the label and duration in the timeout message', async () => {
		const never = new Promise<never>(() => {});
		await expect(withTimeout(never, 5, 'read')).rejects.toThrow(/read timed out after 5ms/);
	});

	it('defaults the label to "operation"', async () => {
		const never = new Promise<never>(() => {});
		await expect(withTimeout(never, 5)).rejects.toThrow(/operation timed out after 5ms/);
	});

	it('propagates a rejection from the wrapped promise', async () => {
		const boom = Promise.reject(new ProtocolError('boom'));
		await expect(withTimeout(boom, 1000, 'op')).rejects.toBeInstanceOf(ProtocolError);
	});

	it('returns the same promise reference (no timer) when ms is undefined', () => {
		const p = Promise.resolve(42);
		expect(withTimeout(p, undefined)).toBe(p);
	});

	it('returns the same promise reference when ms is Infinity', () => {
		const p = Promise.resolve(7);
		expect(withTimeout(p, Infinity)).toBe(p);
	});
});

describe('utf8 + json helpers', () => {
	it('fromUtf8/toUtf8 round-trip, including a multibyte code point', () => {
		expect(Array.from(fromUtf8('hi'))).toEqual([0x68, 0x69]);
		const bytes = fromUtf8('\u00e9'); // 1 code point, 2 UTF-8 bytes
		expect(bytes.length).toBe(2);
		expect(toUtf8(bytes)).toBe('\u00e9');
	});

	it('encodeJson produces UTF-8 JSON bytes that decodeJson reads back', () => {
		const bytes = encodeJson({ ok: true, n: 2 });
		expect(toUtf8(bytes)).toBe('{"ok":true,"n":2}');
		expect(decodeJson<{ ok: boolean; n: number }>(bytes)).toEqual({ ok: true, n: 2 });
	});

	it('encodeJson honors the space argument', () => {
		expect(toUtf8(encodeJson({ a: 1 }, 2))).toBe('{\n  "a": 1\n}');
	});

	it('decodeJson accepts a string as well as bytes', () => {
		expect(decodeJson<number[]>('[1,2,3]')).toEqual([1, 2, 3]);
	});

	it('decodeJson throws ProtocolError on invalid JSON', () => {
		expect(() => decodeJson('{bad')).toThrow(ProtocolError);
	});
});
