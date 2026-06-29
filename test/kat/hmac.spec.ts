import { expect, it } from 'vitest';
import { hmac } from '../../src/crypto/primitives';
import { toHex } from '../util';

const key = new TextEncoder().encode('Jefe');
const data = new TextEncoder().encode('what do ya want for nothing?');

it('matches RFC 4231 HMAC-SHA-256', async () => {
	expect(toHex(await hmac('SHA-256', key, data))).toBe(
		'5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
	);
});

it('matches RFC 4231 HMAC-SHA-512', async () => {
	expect(toHex(await hmac('SHA-512', key, data))).toBe(
		'164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737'
	);
});
