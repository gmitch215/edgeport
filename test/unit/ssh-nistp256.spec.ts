// the ecdh-sha2-nistp256 fallback kex: both sides must derive the same secret
import { expect, it } from 'vitest';
import { nistp256 } from '../../src/kex';
import { toHex } from '../util';

it('derives a matching shared secret on both ends', async () => {
	const a = await nistp256.generateKeyPair();
	const b = await nistp256.generateKeyPair();
	const ab = await nistp256.deriveShared(a.privateKey, b.publicKey);
	const ba = await nistp256.deriveShared(b.privateKey, a.publicKey);
	expect(ab).toHaveLength(32);
	expect(toHex(ab)).toBe(toHex(ba));
});

it('rejects an invalid peer point', async () => {
	const a = await nistp256.generateKeyPair();
	await expect(nistp256.deriveShared(a.privateKey, new Uint8Array(65))).rejects.toBeTruthy();
});
