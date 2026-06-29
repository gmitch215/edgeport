import { poly1305 } from '@noble/ciphers/_poly1305.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { expect, it } from 'vitest';
import { fromHex, toHex } from '../util';

it('poly1305 matches RFC 8439 2.5.2', () => {
	const key = fromHex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
	const msg = new TextEncoder().encode('Cryptographic Forum Research Group');
	expect(toHex(poly1305(msg, key))).toBe('a8061dc1305136c6c22b8baf0c0127a9');
});

it('chacha20-poly1305 AEAD matches RFC 8439 2.8.2', () => {
	const key = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
	const nonce = fromHex('070000004041424344454647');
	const aad = fromHex('50515253c0c1c2c3c4c5c6c7');
	const pt = new TextEncoder().encode(
		"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	);
	const out = chacha20poly1305(key, nonce, aad).encrypt(pt);
	expect(toHex(out.slice(-16))).toBe('1ae10b594f09e26a7e902ecbd0600691');
});
