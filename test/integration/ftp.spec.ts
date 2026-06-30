import { describe, expect, it } from 'vitest';
import { ProtocolError } from '../../src/core/errors';
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

describe('convenience helpers', () => {
	const tag = () => Math.floor(Date.now()).toString(36) + Math.random().toString(36).slice(2, 6);

	it('exists reports presence then absence around a put/delete', async () => {
		await using ftp = await connect(base);
		const path = `edgeport-exists-${tag()}.txt`;

		expect(await ftp.exists(path)).toBe(false);
		await ftp.put(path, new TextEncoder().encode('hi\n'));
		expect(await ftp.exists(path)).toBe(true);
		await ftp.delete(path);
		expect(await ftp.exists(path)).toBe(false);
	});

	it('mtime returns a recent Date for a freshly stored file', async () => {
		await using ftp = await connect(base);
		const path = `edgeport-mtime-${tag()}.txt`;
		const before = Date.now();
		await ftp.put(path, new TextEncoder().encode('stamp\n'));

		const when = await ftp.mtime(path);
		expect(when).toBeInstanceOf(Date);
		expect(Number.isNaN(when.getTime())).toBe(false);
		// the file was just created; allow generous skew for server clock differences
		expect(Math.abs(when.getTime() - before)).toBeLessThan(5 * 60 * 1000);

		await ftp.delete(path);
	});

	it('ensureDir creates nested directories idempotently', async () => {
		await using ftp = await connect(base);
		const root = `edgeport-ed-${tag()}`;
		const nested = `${root}/a/b/c`;

		await ftp.ensureDir(nested);
		// a second call must be a no-op (every MKD returns 550 already-exists, swallowed)
		await ftp.ensureDir(nested);

		// prove the leaf is a usable directory by writing into it
		const file = `${nested}/probe.txt`;
		await ftp.put(file, new TextEncoder().encode('ok\n'));
		expect(await ftp.exists(file)).toBe(true);

		await ftp.removeAll(root);
		expect(await ftp.exists(file)).toBe(false);
	});

	it('getText/putText round-trip UTF-8 text', async () => {
		await using ftp = await connect(base);
		const path = `edgeport-text-${tag()}.txt`;
		const text = 'line one\nline two\nutf-8 ok\n';

		await ftp.putText(path, text);
		expect(await ftp.getText(path)).toBe(text);

		await ftp.delete(path);
	});

	it('getJson/putJson round-trip a value (with indentation)', async () => {
		await using ftp = await connect(base);
		const path = `edgeport-json-${tag()}.json`;
		const value = { name: 'edge', tags: ['a', 'b'], nested: { n: 1 } };

		await ftp.putJson(path, value, { space: 2 });
		const text = await ftp.getText(path);
		expect(text).toBe(JSON.stringify(value, null, 2));
		expect(await ftp.getJson<typeof value>(path)).toEqual(value);

		await ftp.delete(path);
	});

	it('removeAll deletes a populated tree depth-first', async () => {
		await using ftp = await connect(base);
		const root = `edgeport-rm-${tag()}`;

		await ftp.ensureDir(`${root}/sub`);
		await ftp.putText(`${root}/top.txt`, 'top\n');
		await ftp.putText(`${root}/sub/leaf.txt`, 'leaf\n');

		expect(await ftp.exists(`${root}/sub/leaf.txt`)).toBe(true);
		await ftp.removeAll(root);
		expect(await ftp.exists(`${root}/top.txt`)).toBe(false);
	});

	it('removeAll refuses the server root', async () => {
		await using ftp = await connect(base);
		await expect(ftp.removeAll('/')).rejects.toBeInstanceOf(ProtocolError);
	});
});
