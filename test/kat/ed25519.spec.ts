import { expect, it } from 'vitest';
import { b64url, fromHex, toHex } from '../util';

const seed = fromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
const pub = fromHex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
const message = new Uint8Array(0);
const expectedSig = fromHex(
	'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
);

it('produces the RFC 8032 TEST 1 signature and verifies it', async () => {
	const priv = await crypto.subtle.importKey(
		'jwk',
		{ kty: 'OKP', crv: 'Ed25519', d: b64url(seed), x: b64url(pub), key_ops: ['sign'], ext: true },
		{ name: 'Ed25519' },
		false,
		['sign']
	);
	const sig = new Uint8Array(
		await crypto.subtle.sign({ name: 'Ed25519' }, priv, message as BufferSource)
	);
	expect(toHex(sig)).toBe(toHex(expectedSig));

	const pubKey = await crypto.subtle.importKey(
		'raw',
		pub as BufferSource,
		{ name: 'Ed25519' },
		false,
		['verify']
	);
	const ok = await crypto.subtle.verify(
		{ name: 'Ed25519' },
		pubKey,
		expectedSig as BufferSource,
		message as BufferSource
	);
	expect(ok).toBe(true);
});
