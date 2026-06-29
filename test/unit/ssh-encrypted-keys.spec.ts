// security: encrypted private keys (PBES2 PKCS#8 + OpenSSH bcrypt) must decrypt with the
// right passphrase and produce verifiable signatures; wrong/missing passphrases must fail
import { describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/errors';
import { loadUserKey, verifyHostSignature } from '../../src/crypto';
import osshEc from '../fixtures/ecdsa_openssh?raw';
import osshEd from '../fixtures/ed25519_openssh?raw';
import osshEdEnc from '../fixtures/ed25519_openssh_enc?raw';
import pkcs8Enc from '../fixtures/ed25519_pkcs8_enc.pem?raw';
import osshRsa from '../fixtures/rsa_openssh?raw';

const data = new TextEncoder().encode('exchange-hash-stand-in');

async function signsAndVerifies(pem: string, passphrase?: string): Promise<boolean> {
	const key = await loadUserKey({ pem, passphrase });
	const sig = await key.sign(data);
	return verifyHostSignature(key.algorithm, key.publicBlob, sig, data);
}

describe('encrypted PKCS#8 (PBES2)', () => {
	it('decrypts with the passphrase and signs verifiably', async () => {
		expect(await signsAndVerifies(pkcs8Enc, 'secret')).toBe(true);
	});

	it('rejects a wrong passphrase with AuthError', async () => {
		await expect(loadUserKey({ pem: pkcs8Enc, passphrase: 'nope' })).rejects.toBeInstanceOf(
			AuthError
		);
	});

	it('requires a passphrase', async () => {
		await expect(loadUserKey({ pem: pkcs8Enc })).rejects.toBeInstanceOf(AuthError);
	});
});

describe('OpenSSH private-key format', () => {
	it('loads an unencrypted ed25519 key', async () => {
		expect(await signsAndVerifies(osshEd)).toBe(true);
	});

	it('loads an unencrypted ecdsa-p256 key', async () => {
		expect(await signsAndVerifies(osshEc)).toBe(true);
	});

	it('loads an unencrypted rsa key', async () => {
		expect(await signsAndVerifies(osshRsa)).toBe(true);
	});

	it('decrypts a bcrypt-encrypted ed25519 key with the passphrase', async () => {
		expect(await signsAndVerifies(osshEdEnc, 'secret')).toBe(true);
	});

	it('rejects a wrong passphrase with AuthError', async () => {
		await expect(loadUserKey({ pem: osshEdEnc, passphrase: 'nope' })).rejects.toBeInstanceOf(
			AuthError
		);
	});

	it('requires a passphrase for an encrypted key', async () => {
		await expect(loadUserKey({ pem: osshEdEnc })).rejects.toBeInstanceOf(AuthError);
	});
});
