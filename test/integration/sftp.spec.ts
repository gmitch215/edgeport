import { describe, expect, it } from 'vitest';
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

describe('sftp convenience helpers', () => {
	const tag = Math.floor(Date.now()).toString(36);

	it('exists reflects presence and absence', async () => {
		await using sftp = await connect(base);
		const path = `/config/edgeport-exists-${tag}.txt`;
		expect(await sftp.exists(path)).toBe(false);
		await sftp.writeText(path, 'present\n');
		expect(await sftp.exists(path)).toBe(true);
		await sftp.remove(path);
		expect(await sftp.exists(path)).toBe(false);
	});

	it('ensureDir creates nested directories and is idempotent', async () => {
		await using sftp = await connect(base);
		const root = `/config/edgeport-tree-${tag}`;
		const nested = `${root}/a/b/c`;
		await sftp.ensureDir(nested);
		expect((await sftp.stat(nested)).isDirectory).toBe(true);
		await sftp.ensureDir(nested); // second call must not throw
		await sftp.removeAll(root);
		expect(await sftp.exists(root)).toBe(false);
	});

	it('round-trips text and JSON', async () => {
		await using sftp = await connect(base);
		const textPath = `/config/edgeport-text-${tag}.txt`;
		await sftp.writeText(textPath, 'hello edgeport\n');
		expect(await sftp.readText(textPath)).toBe('hello edgeport\n');

		const jsonPath = `/config/edgeport-json-${tag}.json`;
		const value = { name: 'edge', nested: { n: 1 }, list: [1, 2, 3] };
		await sftp.writeJson(jsonPath, value, { space: 2 });
		expect(await sftp.readJson<typeof value>(jsonPath)).toEqual(value);

		await sftp.removeMany([textPath, jsonPath]);
		expect(await sftp.exists(textPath)).toBe(false);
		expect(await sftp.exists(jsonPath)).toBe(false);
	});

	it('chmod changes the permission bits', async () => {
		await using sftp = await connect(base);
		const path = `/config/edgeport-chmod-${tag}.sh`;
		await sftp.writeText(path, '#!/bin/sh\necho hi\n');
		await sftp.chmod(path, 0o755);
		expect((await sftp.stat(path)).permissions! & 0o777).toBe(0o755);
		await sftp.remove(path);
	});

	it('removeAll recursively clears a populated tree, removeMany tolerates missing', async () => {
		await using sftp = await connect(base);
		const root = `/config/edgeport-rm-${tag}`;
		await sftp.ensureDir(`${root}/sub`);
		await sftp.writeText(`${root}/a.txt`, 'a');
		await sftp.writeText(`${root}/sub/b.txt`, 'b');

		await sftp.removeAll(root);
		expect(await sftp.exists(root)).toBe(false);

		// idempotent removeMany over now-missing files
		await sftp.removeMany([`${root}/a.txt`, `${root}/sub/b.txt`], { ignoreMissing: true });
	});
});
