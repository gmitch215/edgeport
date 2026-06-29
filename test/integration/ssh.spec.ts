import { describe, expect, it } from 'vitest';
import { connect, exec } from '../../src/ssh/index';
// encrypted PKCS#8 form of the same ed25519 key authorized in docker/compose.yml
import encryptedKey from '../fixtures/ed25519_pkcs8_enc.pem?raw';

const base = { hostname: '127.0.0.1', port: 2222, username: 'tester', password: 'testpass' };
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

// matches docker/compose.yml openssh PUBLIC_KEY; private half loads via publickey auth
const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPPGnP1OPdTdAUzAf5iM/AsZ//kp00OKoDxsi/zPEmiL
-----END PRIVATE KEY-----`;

it('runs a command via password auth and captures stdout + exit code', async () => {
	const r = await exec({ ...base, command: 'echo hello-edgeport' });
	expect(r.code).toBe(0);
	expect(dec(r.stdout)).toContain('hello-edgeport');
});

it('captures stderr and a non-zero exit code', async () => {
	const r = await exec({ ...base, command: 'echo oops 1>&2; exit 3' });
	expect(r.code).toBe(3);
	expect(dec(r.stderr)).toContain('oops');
});

// the assembly-verification gate: force each cipher path against the real server
describe('cipher interop (forced via algorithms override)', () => {
	for (const cipher of ['aes256-gcm@openssh.com', 'aes256-ctr', 'chacha20-poly1305@openssh.com']) {
		it(`handshakes and execs over ${cipher}`, async () => {
			const r = await exec({
				...base,
				algorithms: { cipher: [cipher] },
				command: 'echo ' + cipher
			});
			expect(r.code).toBe(0);
			expect(dec(r.stdout)).toContain(cipher);
		});
	}
});

it('reuses a session for multiple commands', async () => {
	await using ssh = await connect(base);
	expect(dec((await ssh.exec('echo one')).stdout)).toContain('one');
	expect(dec((await ssh.exec('echo two')).stdout)).toContain('two');
});

it('authenticates with an ed25519 private key (publickey)', async () => {
	const r = await exec({
		hostname: '127.0.0.1',
		port: 2222,
		username: 'tester',
		privateKey: { pem: PRIVATE_KEY_PEM },
		command: 'echo pk-ok'
	});
	expect(r.code).toBe(0);
	expect(dec(r.stdout)).toContain('pk-ok');
});

it('authenticates with a passphrase-protected (encrypted) key', async () => {
	const r = await exec({
		hostname: '127.0.0.1',
		port: 2222,
		username: 'tester',
		privateKey: { pem: encryptedKey, passphrase: 'secret' },
		command: 'echo enc-pk-ok'
	});
	expect(r.code).toBe(0);
	expect(dec(r.stdout)).toContain('enc-pk-ok');
});

it('interops with dropbear (a second SSH implementation)', async () => {
	const r = await exec({
		hostname: '127.0.0.1',
		port: 2223,
		username: 'tester',
		password: 'testpass',
		command: 'echo dropbear-ok'
	});
	expect(r.code).toBe(0);
	expect(dec(r.stdout)).toContain('dropbear-ok');
});
