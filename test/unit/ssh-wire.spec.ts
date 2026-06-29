import { describe, expect, it } from 'vitest';
import { SshReader, SshWriter, toMpintBody } from '../../src/wire';

const hex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(' ');
const fromHex = (s: string) => new Uint8Array(s.split(/\s+/).map((h) => parseInt(h, 16)));

describe('mpint encoding (RFC 4251 section 5 examples)', () => {
	it('encodes 0 as an empty body', () => {
		expect(hex(new SshWriter().mpint(fromHex('00')).bytes())).toBe('00 00 00 00');
	});

	it('encodes 0x09a378f9b2e332a7 verbatim (high bit clear)', () => {
		const v = fromHex('09 a3 78 f9 b2 e3 32 a7');
		expect(hex(new SshWriter().mpint(v).bytes())).toBe('00 00 00 08 09 a3 78 f9 b2 e3 32 a7');
	});

	it('prepends 0x00 to 0x80 (high bit set)', () => {
		expect(hex(new SshWriter().mpint(fromHex('80')).bytes())).toBe('00 00 00 02 00 80');
	});

	it('strips leading zeros then sign-pads 0xdeadbeef', () => {
		expect(hex(toMpintBody(fromHex('00 00 de ad be ef')))).toBe('00 de ad be ef');
	});
});

describe('SshWriter / SshReader round-trips', () => {
	it('round-trips byte, boolean, uint32, uint64', () => {
		const buf = new SshWriter()
			.byte(0x1f)
			.boolean(true)
			.uint32(0xdeadbeef)
			.uint64(0x0102030405060708n)
			.bytes();
		const r = new SshReader(buf);
		expect(r.byte()).toBe(0x1f);
		expect(r.boolean()).toBe(true);
		expect(r.uint32()).toBe(0xdeadbeef);
		expect(r.uint64()).toBe(0x0102030405060708n);
		expect(r.remaining).toBe(0);
	});

	it('round-trips strings and name-lists', () => {
		const buf = new SshWriter()
			.string('ssh-userauth')
			.nameList(['curve25519-sha256', 'ecdh-sha2-nistp256'])
			.nameList([])
			.bytes();
		const r = new SshReader(buf);
		expect(r.stringUtf8()).toBe('ssh-userauth');
		expect(r.nameList()).toEqual(['curve25519-sha256', 'ecdh-sha2-nistp256']);
		expect(r.nameList()).toEqual([]);
	});

	it('round-trips an mpint as a bigint', () => {
		const buf = new SshWriter().mpint(fromHex('80')).bytes();
		expect(new SshReader(buf).mpintBigInt()).toBe(0x80n);
	});

	it('throws ProtocolError when reading past the end', () => {
		const r = new SshReader(fromHex('00 00 00 04 01 02'));
		expect(() => r.string()).toThrow();
	});
});
