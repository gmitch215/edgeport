import { describe, expect, it } from 'vitest';
import { connect as sftpConnect } from '../../src/sftp/index';
import { connect, exec, sudo, sudoExec } from '../../src/ssh/index';
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

describe('session reuse and connectivity hardening', () => {
	it('survives exec -> sftp write -> exec on one reused session (the reported repro)', async () => {
		await using ssh = await connect(base);
		const dir = '/tmp/edgeport-reuse';
		expect((await ssh.exec(`mkdir -p ${dir}`)).code).toBe(0);
		{
			// sftp over the SAME ssh session; disposing it client-closes the subsystem channel
			await using sftp = await sftpConnect({ session: ssh });
			await sftp.writeFile(`${dir}/x.txt`, new TextEncoder().encode('reuse-ok\n'));
		}
		// with the bug, the duplicate close disconnected us before this third channel finished
		const r = await ssh.exec(`cat ${dir}/x.txt`);
		expect(r.code).toBe(0);
		expect(dec(r.stdout)).toContain('reuse-ok');
		await ssh.exec(`rm -rf ${dir}`);
	});

	it('stays usable after repeatedly opening and client-closing channels', async () => {
		await using ssh = await connect(base);
		for (let i = 0; i < 5; i++) {
			const shell = await ssh.shell();
			await shell.close(); // client initiates the close - the bug's trigger
			expect((await ssh.exec(`echo round-${i}`)).code).toBe(0);
		}
		expect(dec((await ssh.exec('echo still-alive')).stdout)).toContain('still-alive');
	});

	it('opens and client-closes a subsystem, then keeps reusing the session', async () => {
		await using ssh = await connect(base);
		const sftp = await sftpConnect({ session: ssh });
		await sftp.list('/tmp');
		await sftp.close(); // client-initiated subsystem channel close
		expect((await ssh.exec('echo after-sftp')).code).toBe(0);
		// a second sftp subsystem on the same session must also work
		await using sftp2 = await sftpConnect({ session: ssh });
		await sftp2.writeFile('/tmp/edgeport-reuse2.txt', new TextEncoder().encode('two\n'));
		expect(dec((await ssh.exec('cat /tmp/edgeport-reuse2.txt')).stdout)).toContain('two');
		await ssh.exec('rm -f /tmp/edgeport-reuse2.txt');
	});

	it('runs concurrent channels on one session', async () => {
		await using ssh = await connect(base);
		const [a, b, c] = await Promise.all([
			ssh.exec('echo aaa'),
			ssh.exec('echo bbb'),
			ssh.exec('echo ccc')
		]);
		expect(dec(a.stdout)).toContain('aaa');
		expect(dec(b.stdout)).toContain('bbb');
		expect(dec(c.stdout)).toContain('ccc');
	});

	it('execStream round-trips stdin through cat', async () => {
		await using ssh = await connect(base);
		await using ch = await ssh.execStream('cat');
		await ch.write(new TextEncoder().encode('hello-edgeport\n'));
		await ch.eof();
		const reader = ch.stdout.getReader();
		let out = '';
		for (;;) {
			const { value, done } = await reader.read();
			if (done) break;
			if (value) out += dec(value);
		}
		await ch.exit;
		expect(out.trim()).toBe('hello-edgeport');
	});
});

// password sudo (tester has password-required sudo via docker/openssh-init)
describe('sudo', () => {
	it('sudoExec runs as root via credential reuse (uid 0)', async () => {
		const { stdout, code } = await sudoExec({ ...base, command: 'id -u' });
		expect(code).toBe(0);
		expect(dec(stdout).trim()).toBe('0');
	});

	it('sudo over an already-open session runs as root', async () => {
		await using ssh = await connect(base);
		const { stdout, code } = await sudo(ssh, 'whoami', { password: 'testpass' });
		expect(code).toBe(0);
		expect(dec(stdout).trim()).toBe('root');
	});
});

// POSIX command helpers against the real server (the container is alpine/busybox)
describe('command helpers', () => {
	it('round-trips mkdirp/writeTextFile/readTextFile/exists/stat/rm', async () => {
		await using ssh = await connect(base);
		const dir = `/tmp/edgeport-it-${Date.now()}`;
		const file = `${dir}/note.txt`;
		const body = 'hello from edgeport\nsecond line\n';

		await ssh.mkdirp(dir, { mode: 0o755 });
		expect(await ssh.exists(dir)).toBe(true);

		await ssh.writeTextFile(file, body);
		expect(await ssh.exists(file)).toBe(true);
		expect(await ssh.readTextFile(file)).toBe(body);

		const st = await ssh.stat(file);
		expect(st.size).toBe(new TextEncoder().encode(body).length);
		expect(st.isDirectory).toBe(false);
		expect(st.isSymlink).toBe(false);
		expect(st.mtime).toBeGreaterThan(0);
		expect((await ssh.stat(dir)).isDirectory).toBe(true);

		await ssh.writeTextFile(file, 'third line\n', { append: true });
		expect(await ssh.readTextFile(file)).toBe(body + 'third line\n');

		await ssh.rm(dir, { recursive: true, force: true });
		expect(await ssh.exists(dir)).toBe(false);
	});

	it('df and which return parsed, portable results', async () => {
		await using ssh = await connect(base);
		const rows = await ssh.df('/');
		expect(rows.length).toBeGreaterThan(0);
		expect(rows[0]!.mountedOn.length).toBeGreaterThan(0);
		expect(Number.isNaN(rows[0]!.sizeKb)).toBe(false);
		const sh = await ssh.which('sh');
		expect(sh).toContain('/sh');
		expect(await ssh.which('definitely-not-a-real-binary-xyz')).toBeNull();
	});
});
