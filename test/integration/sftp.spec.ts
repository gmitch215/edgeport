import { expect, it } from 'vitest';
import { connect } from '../../src/sftp/index';
import { connect as sshConnect } from '../../src/ssh/index';

const base = { hostname: '127.0.0.1', port: 2222, username: 'tester', password: 'testpass' };

it('writes, stats, reads, lists, renames and removes a file', async () => {
	await using sftp = await connect(base);
	const dir = '/config';
	const path = `${dir}/edgeport-sftp-${Math.floor(Date.now()).toString(36)}.txt`;
	const body = new TextEncoder().encode('edgeport sftp round-trip\n');

	await sftp.writeFile(path, body);

	const attrs = await sftp.stat(path);
	expect(attrs.size).toBe(body.length);
	expect(attrs.isDirectory).toBe(false);

	const read = await sftp.readFile(path);
	expect(new TextDecoder().decode(read)).toBe('edgeport sftp round-trip\n');

	const listing = await sftp.list(dir);
	expect(listing.some((e) => path.endsWith(e.filename))).toBe(true);

	const renamed = path + '.bak';
	await sftp.rename(path, renamed);
	await sftp.remove(renamed);
});

it('reuses an existing ssh session for sftp', async () => {
	await using ssh = await sshConnect(base);
	await using sftp = await connect({ session: ssh });
	const resolved = await sftp.realpath('.');
	expect(resolved.length).toBeGreaterThan(0);
});

it('streams a larger file through createReadStream', async () => {
	await using sftp = await connect(base);
	const path = `/config/edgeport-stream-${Math.floor(Date.now()).toString(36)}.bin`;
	const big = new Uint8Array(100_000).map((_, i) => i & 0xff);
	await sftp.writeFile(path, big);

	const reader = sftp.createReadStream(path).getReader();
	let total = 0;
	for (;;) {
		const { value, done } = await reader.read();
		if (done) break;
		if (value) total += value.length;
	}
	expect(total).toBe(big.length);
	await sftp.remove(path);
});
