import { expect, it } from 'vitest';
import { deriveShared } from '../../src/kex/curve25519';
import { b64url, fromHex, toHex } from '../util';

const alicePriv = fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
const alicePub = fromHex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
const bobPub = fromHex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
const sharedK = fromHex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');

it('derives the RFC 7748 6.1 shared secret', async () => {
	const priv = await crypto.subtle.importKey(
		'jwk',
		{
			kty: 'OKP',
			crv: 'X25519',
			d: b64url(alicePriv),
			x: b64url(alicePub),
			key_ops: ['deriveBits'],
			ext: true
		},
		{ name: 'X25519' },
		false,
		['deriveBits']
	);
	const shared = await deriveShared(priv, bobPub);
	expect(toHex(shared)).toBe(toHex(sharedK));
});
