import { describe, expect, it } from 'vitest';
import { fromBase64, toHex } from '../../src/util';
import { hi, scramClient } from '../../src/xmpp/sasl';

// RFC 5802 section 5 worked example (SCRAM-SHA-1)
//   username = "user", password = "pencil"
//   client nonce  = fyko+d2lbbFgONRv9qkxdawL
//   server nonce  = 3rfcNHYJY1ZVvWVs7j (appended)
//   salt (base64) = QSXCR+Q6sek8bf92, i = 4096
const CLIENT_NONCE = 'fyko+d2lbbFgONRv9qkxdawL';
const COMBINED_NONCE = 'fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j';
const SERVER_FIRST = `r=${COMBINED_NONCE},s=QSXCR+Q6sek8bf92,i=4096`;
const SERVER_FINAL = 'v=rmF9pqV8S7suAoZWja4dJRkFsKQ=';

// the exact client-final message the RFC prints (including the ClientProof p=)
const EXPECTED_CLIENT_FINAL =
	'c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=';
const EXPECTED_PROOF = 'v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=';
// SaltedPassword = Hi("pencil", salt, 4096), the canonical SHA-1 vector
const EXPECTED_SALTED = '1d96ee3a529b5a5f9e47c01f229a2cb8a6e15f7d';

describe('SCRAM-SHA-1 KAT (RFC 5802 worked example)', () => {
	it('produces the RFC client-first-bare', () => {
		const c = scramClient('SCRAM-SHA-1', 'user', 'pencil', { nonce: CLIENT_NONCE });
		expect(c.clientFirst).toBe('n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL');
		expect(c.clientFirstBare).toBe('n=user,r=fyko+d2lbbFgONRv9qkxdawL');
	});

	it('derives the salted password via Hi() byte-exact', async () => {
		const salt = fromBase64('QSXCR+Q6sek8bf92');
		const salted = await hi(new TextEncoder().encode('pencil'), salt, 4096, 'SHA-1');
		expect(toHex(salted)).toBe(EXPECTED_SALTED);
	});

	it('computes the client-final message and ClientProof byte-exact', async () => {
		const c = scramClient('SCRAM-SHA-1', 'user', 'pencil', { nonce: CLIENT_NONCE });
		const clientFinal = await c.handleServerFirst(SERVER_FIRST);
		expect(clientFinal).toBe(EXPECTED_CLIENT_FINAL);
		const proof = clientFinal.slice(clientFinal.indexOf(',p=') + 3);
		expect(proof).toBe(EXPECTED_PROOF);
	});

	it('verifies the RFC ServerSignature (server-final)', async () => {
		const c = scramClient('SCRAM-SHA-1', 'user', 'pencil', { nonce: CLIENT_NONCE });
		await c.handleServerFirst(SERVER_FIRST);
		await expect(c.verifyServerFinal(SERVER_FINAL)).resolves.toBeUndefined();
	});

	it('rejects a tampered ServerSignature', async () => {
		const c = scramClient('SCRAM-SHA-1', 'user', 'pencil', { nonce: CLIENT_NONCE });
		await c.handleServerFirst(SERVER_FIRST);
		await expect(c.verifyServerFinal('v=AAAApqV8S7suAoZWja4dJRkFsKQ=')).rejects.toBeTruthy();
	});
});
