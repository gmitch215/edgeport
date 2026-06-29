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

it('transfers a CRLF text file in ascii mode (TYPE A)', async () => {
	await using ftp = await connect(base);
	const path = `edgeport-ascii-${Math.floor(Date.now()).toString(36)}.txt`;
	// CRLF source text; on a Linux server (native LF) TYPE A is a no-op vs TYPE I, so the
	// point of this test is that TYPE A is issued, accepted, and the round-trip still works
	const body = new TextEncoder().encode('line one\r\nline two\r\nline three\r\n');

	await ftp.put(path, body, { type: 'ascii' });
	const got = await ftp.get(path, { type: 'ascii' });
	expect(Array.from(got)).toEqual(Array.from(body));

	// a following binary transfer still works after the session switched to ascii and back
	const bin = await ftp.get(path);
	expect(Array.from(bin)).toEqual(Array.from(body));

	await ftp.delete(path);
});

it('resumes a download from a byte offset (REST + RETR)', async () => {
	await using ftp = await connect(base);
	const path = `edgeport-rest-get-${Math.floor(Date.now()).toString(36)}.bin`;
	const blob = new Uint8Array(256);
	for (let i = 0; i < blob.length; i++) blob[i] = i;

	await ftp.put(path, blob);

	const offset = 100;
	const tail = await ftp.get(path, { offset });
	expect(Array.from(tail)).toEqual(Array.from(blob.subarray(offset)));

	await ftp.delete(path);
});

it('resumes an upload via offset (REST + STOR)', async () => {
	await using ftp = await connect(base);
	const path = `edgeport-rest-put-${Math.floor(Date.now()).toString(36)}.bin`;
	const full = new Uint8Array(200);
	for (let i = 0; i < full.length; i++) full[i] = (i * 7) & 0xff;
	const half = full.length / 2;

	// upload the first half, then overwrite from the midpoint onward with REST
	await ftp.put(path, full.subarray(0, half));
	await ftp.put(path, full.subarray(half), { offset: half });

	const got = await ftp.get(path);
	expect(Array.from(got)).toEqual(Array.from(full));

	await ftp.delete(path);
});

it('resumes an upload via append (APPE)', async () => {
	await using ftp = await connect(base);
	const path = `edgeport-appe-${Math.floor(Date.now()).toString(36)}.bin`;
	const full = new Uint8Array(180);
	for (let i = 0; i < full.length; i++) full[i] = (i * 3 + 1) & 0xff;
	const half = full.length / 2;

	await ftp.put(path, full.subarray(0, half));
	await ftp.put(path, full.subarray(half), { append: true });

	const got = await ftp.get(path);
	expect(Array.from(got)).toEqual(Array.from(full));

	await ftp.delete(path);
});
