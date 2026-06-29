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

// dropbear allows local (direct-tcpip) forwarding by default; linuxserver/openssh disables it
const fwd = { hostname: '127.0.0.1', port: 2223, username: 'tester', password: 'testpass' };

it('tunnels to an internal service via direct-tcpip (forwardOut)', async () => {
	await using ssh = await connect(fwd);
	// reach the bastion's own sshd through the tunnel and read its banner
	await using tun = await ssh.forwardOut('127.0.0.1', 2223);
	const reader = tun.stdout.getReader();
	const { value } = await reader.read();
	expect(dec(value!)).toContain('SSH-2.0');
});

it('rejects forwarding to an unreachable port with ConnectionError', async () => {
	await using ssh = await connect(fwd);
	await expect(ssh.forwardOut('127.0.0.1', 1)).rejects.toMatchObject({ name: 'ConnectionError' });
});

// in-session key re-exchange (RFC 4253 section 9), manual and auto-triggered
describe('key re-exchange (rekey)', () => {
	it('manual rekey: the session keeps working after session.rekey()', async () => {
		await using ssh = await connect(base);
		expect(dec((await ssh.exec('echo before')).stdout)).toContain('before');
		await ssh.rekey(); // client-initiated; resolves when new keys are installed
		expect(dec((await ssh.exec('echo after')).stdout)).toContain('after');
		await ssh.rekey(); // a second rekey on the same session must also work
		expect((await ssh.exec('true')).code).toBe(0);
	});

	it('auto-rekey: a large transfer past a low byte threshold stays intact', async () => {
		await using ssh = await connect({ ...base, rekeyThresholdBytes: 4096 });
		// ~100 KB of output forces several auto-rekeys mid-stream; output must be complete + ordered
		const r = await ssh.exec('seq 1 20000');
		expect(r.code).toBe(0);
		const lines = dec(r.stdout).trim().split('\n');
		expect(lines.length).toBe(20000);
		expect(lines[0]).toBe('1');
		expect(lines[lines.length - 1]).toBe('20000');
	});
});
