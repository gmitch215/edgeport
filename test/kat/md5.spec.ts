import { describe, expect, it } from 'vitest';
import { md5 } from '../../src/sip/digest';
import { toHex } from '../../src/util';

const enc = new TextEncoder();
const hex = (s: string) => toHex(md5(enc.encode(s)));

describe('md5 KAT (RFC 1321 appendix A.5)', () => {
	it('matches the RFC 1321 test suite', () => {
		expect(hex('')).toBe('d41d8cd98f00b204e9800998ecf8427e');
		expect(hex('a')).toBe('0cc175b9c0f1b6a831c399e269772661');
		expect(hex('abc')).toBe('900150983cd24fb0d6963f7d28e17f72');
		expect(hex('message digest')).toBe('f96b697d7cb7938d525a2f31aaf161d0');
		expect(hex('abcdefghijklmnopqrstuvwxyz')).toBe('c3fcd3d76192e4007dfb496cca67e13b');
		expect(hex('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')).toBe(
			'd174ab98d277d9f5a5611c2c9f419d9f'
		);
		expect(
			hex('12345678901234567890123456789012345678901234567890123456789012345678901234567890')
		).toBe('57edf4a22be3c955ac49da2e2107b67a');
	});

	it('handles the padding boundaries around one block (55/56/64 bytes)', () => {
		// 55 fits with the length in one block; 56 forces a second; verify all round-trip
		expect(hex('a'.repeat(55))).toBe('ef1772b6dff9a122358552954ad0df65');
		expect(hex('a'.repeat(56))).toBe('3b0c8ac703f828b04c6c197006d17218');
		expect(hex('a'.repeat(64))).toBe('014842d480b571495a4a0363793f7367');
	});

	it('hashes a large multi-block input (RFC 1321 million-a vector)', () => {
		expect(hex('a'.repeat(1_000_000))).toBe('7707d6ae4e027c70eea2a935c2296f21');
	});
});
