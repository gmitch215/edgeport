// recipe: secure SSH + SFTP deploy/ops flow against the dockerized openssh box
import { describe, expect, it } from 'vitest';
import { AuthError } from '../../../src/core/errors';
import { connect as sftpConnect } from '../../../src/sftp/index';
import { connect as sshConnect } from '../../../src/ssh/index';
import { artifact, uniqueId } from './_helpers';

const base = { hostname: '127.0.0.1', port: 2222, username: 'tester', password: 'testpass' };
const dec = (b: Uint8Array) => new TextDecoder().decode(b);
const enc = (s: string) => new TextEncoder().encode(s);

// drains a readable stream until `predicate(text)` holds or the deadline elapses
async function readUntil(
	stream: ReadableStream<Uint8Array>,
	predicate: (acc: string) => boolean,
	timeoutMs = 8000
): Promise<string> {
	const reader = stream.getReader();
	const deadline = performance.now() + timeoutMs;
	let acc = '';
	try {
		while (performance.now() < deadline) {
			const { value, done } = await reader.read();
			if (done) break;
			if (value) acc += dec(value);
			if (predicate(acc)) return acc;
		}
		return acc;
	} finally {
		reader.releaseLock();
	}
}

// parses `df -P /` output: header line then a data row whose 2nd-4th columns are 1k-blocks
function parseDfAvailable(out: string): number {
	const lines = out.trim().split('\n');
	expect(lines.length).toBeGreaterThanOrEqual(2);
	const cols = (lines[lines.length - 1] ?? '').trim().split(/\s+/);
	// Filesystem 1024-blocks Used Available Capacity Mounted-on
	const avail = Number(cols[3]);
	return avail;
}

describe('secure deploy/ops flow (ssh + sftp)', () => {
	it('runs end to end: disk check, upload over a reused session, resume, perms, shell tail', async () => {
		await using ssh = await sshConnect(base);

		// 1. disk space readable via exec
		const df = await ssh.exec('df -P /');
		expect(df.code).toBe(0);
		const avail = parseDfAvailable(dec(df.stdout));
		expect(Number.isFinite(avail)).toBe(true);
		expect(avail).toBeGreaterThan(0);

		// 2. upload a build artifact over an SFTP session reusing the SSH connection
		await using sftp = await sftpConnect({ session: ssh });
		const build = artifact(100_000);
		const remote = `/config/${uniqueId('build')}.bin`;
		await sftp.writeFile(remote, build);
		const st = await sftp.stat(remote);
		expect(st.size).toBe(build.length);

		// 3. resume-after-interruption: write first half, stat partial, write remainder at offset
		const resumePath = `/config/${uniqueId('resume')}.bin`;
		const half = Math.floor(build.length / 2);
		await sftp.writeFile(resumePath, build.subarray(0, half));
		const partial = await sftp.stat(resumePath);
		expect(partial.size).toBe(half);
		await sftp.writeFile(resumePath, build.subarray(partial.size!), { offset: partial.size! });
		const finished = await sftp.stat(resumePath);
		expect(finished.size).toBe(build.length);
		const readBack = await sftp.readFile(resumePath);
		expect(readBack.length).toBe(build.length);
		expect(readBack).toEqual(build); // byte-exact

		// 4. set permissions + simulate a service restart, asserting clean exit codes
		const chmod = await ssh.exec(`chmod 600 ${remote}`);
		expect(chmod.code).toBe(0);
		const restart = await ssh.exec('echo restarting && true');
		expect(restart.code).toBe(0);
		expect(dec(restart.stdout)).toContain('restarting');

		// 5. tail logs over an interactive shell channel
		const marker = `log-line-${uniqueId('tail')}`;
		const shell = await ssh.shell();
		await shell.write(enc(`echo ${marker}\n`));
		const seen = await readUntil(shell.stdout, (acc) => acc.includes(marker));
		expect(seen).toContain(marker);
		// close the shell cleanly: signal EOF, then close the channel
		await shell.eof().catch(() => {});
		await shell.close();

		// cleanup the uploaded artifacts (best effort)
		await sftp.remove(remote).catch(() => {});
		await sftp.remove(resumePath).catch(() => {});

		// 6. clean disconnect happens via `await using` scope exit (asserted by absence of throw)
	});

	it('captures a non-zero exit code instead of throwing', async () => {
		await using ssh = await sshConnect(base);
		const r = await ssh.exec('echo to-stderr 1>&2; exit 7');
		expect(r.code).toBe(7);
		expect(dec(r.stderr)).toContain('to-stderr');
	});

	it('rejects a wrong password with AuthError', async () => {
		await expect(sshConnect({ ...base, password: 'wrong-password' })).rejects.toBeInstanceOf(
			AuthError
		);
	});

	it('reuses one SSH session for both sftp transfer and exec ops', async () => {
		await using ssh = await sshConnect(base);
		await using sftp = await sftpConnect({ session: ssh });
		const path = `/config/${uniqueId('reuse')}.txt`;
		const payload = enc('edgeport-reuse');
		await sftp.writeFile(path, payload);
		// exec sees the file the sftp side just wrote (same connection, same box)
		const cat = await ssh.exec(`cat ${path}`);
		expect(cat.code).toBe(0);
		expect(dec(cat.stdout)).toContain('edgeport-reuse');
		await sftp.remove(path).catch(() => {});
	});
});
