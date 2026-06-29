// security: user-key signing and host-key verification must agree for every key type,
// and verification must reject tampered data / wrong keys
import { describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/errors';
import { loadUserKey, verifyHostSignature } from '../../src/crypto';

const data = new TextEncoder().encode('exchange-hash-stand-in');

async function genPrivate(kind: 'ed25519' | 'ecdsa' | 'rsa'): Promise<CryptoKey> {
	if (kind === 'ed25519') {
		return (
			(await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
				'sign',
				'verify'
			])) as CryptoKeyPair
		).privateKey;
	}
	if (kind === 'ecdsa') {
		return (
			(await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
				'sign',
				'verify'
			])) as CryptoKeyPair
		).privateKey;
	}
	return (
		(await crypto.subtle.generateKey(
			{
				name: 'RSASSA-PKCS1-v1_5',
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: 'SHA-512'
			},
			true,
			['sign', 'verify']
		)) as CryptoKeyPair
	).privateKey;
}

describe('user-key sign <-> host-key verify round-trip', () => {
	for (const kind of ['ed25519', 'ecdsa', 'rsa'] as const) {
		it(`${kind}: a fresh signature verifies, a tampered message does not`, async () => {
			const key = await loadUserKey(await genPrivate(kind));
			const sig = await key.sign(data);
			expect(await verifyHostSignature(key.algorithm, key.publicBlob, sig, data)).toBe(true);

			const tampered = data.slice();
			tampered[0]! ^= 0xff;
			expect(await verifyHostSignature(key.algorithm, key.publicBlob, sig, tampered)).toBe(false);
		});
	}
});

describe('loadUserKey', () => {
	it('parses a PKCS8 PEM (ed25519) and signs verifiably', async () => {
		const pem = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPPGnP1OPdTdAUzAf5iM/AsZ//kp00OKoDxsi/zPEmiL
-----END PRIVATE KEY-----`;
		const key = await loadUserKey({ pem });
		expect(key.algorithm).toBe('ssh-ed25519');
		const sig = await key.sign(data);
		expect(await verifyHostSignature('ssh-ed25519', key.publicBlob, sig, data)).toBe(true);
	});

	it('rejects an unparseable key with AuthError', async () => {
		await expect(
			loadUserKey({ pem: '-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5\n-----END PRIVATE KEY-----' })
		).rejects.toBeInstanceOf(AuthError);
	});
});
