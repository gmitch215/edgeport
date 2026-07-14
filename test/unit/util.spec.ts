import { describe, expect, it } from 'vitest';
import { AuthError, ConnectionError, ProtocolError, TimeoutError } from '../../src/core/errors';
import { fromBase64, fromHex, randomHex, randomId, retry, toBase64, toHex } from '../../src/util';

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
