import { expect, it } from 'vitest';
import { connect } from '../../src/ftp/index';

const base = { hostname: '127.0.0.1', port: 21, username: 'tester', password: 'testpass' };

it('uploads, lists, downloads and deletes a file (passive mode)', async () => {
	await using ftp = await connect(base);
	const path = `edgeport-${Math.floor(Date.now()).toString(36)}.txt`;
	const body = new TextEncoder().encode('edgeport ftp round-trip\n');

	await ftp.put(path, body);

	const names = await ftp.nameList();
	expect(names).toContain(path);

	const listing = await ftp.list();
	expect(listing.some((e) => e.name === path)).toBe(true);

	const got = await ftp.get(path);
	expect(new TextDecoder().decode(got)).toBe('edgeport ftp round-trip\n');

	await ftp.delete(path);
});

it('rejects bad credentials with an error', async () => {
	await expect(connect({ ...base, password: 'wrong' })).rejects.toBeTruthy();
});
