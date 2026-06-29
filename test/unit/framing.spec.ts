import { describe, expect, it } from 'vitest';
import { ConnectionError, TimeoutError } from '../../src/core/errors';
import { StreamFramedReader, StreamFramedWriter } from '../../src/core/framing';

const enc = (s: string) => new TextEncoder().encode(s);

// builds a ReadableStream that emits the given chunks then closes
function streamOf(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
	let i = 0;
	return new ReadableStream<Uint8Array>({
		pull(controller) {
			if (i < chunks.length) controller.enqueue(chunks[i++]);
			else controller.close();
		}
	});
}

// a stream the test drives by hand
function controllable() {
	let controller!: ReadableStreamDefaultController<Uint8Array>;
	const stream = new ReadableStream<Uint8Array>({
		start(c) {
			controller = c;
		}
	});
	return {
		stream,
		push: (u: Uint8Array) => controller.enqueue(u),
		close: () => controller.close()
	};
}

describe('StreamFramedReader.readN', () => {
	it('reads exact bytes across many tiny chunks', async () => {
		const r = new StreamFramedReader(
			streamOf([...enc('hello world')].map((b) => new Uint8Array([b])))
		);
		expect(new TextDecoder().decode(await r.readN(5))).toBe('hello');
		expect(new TextDecoder().decode(await r.readN(6))).toBe(' world');
	});

	it('reads across multi-byte chunk boundaries', async () => {
		const r = new StreamFramedReader(streamOf([enc('ab'), enc('cde'), enc('f')]));
		expect(new TextDecoder().decode(await r.readN(4))).toBe('abcd');
		expect(new TextDecoder().decode(await r.readN(2))).toBe('ef');
	});

	it('throws ConnectionError on EOF before enough bytes', async () => {
		const r = new StreamFramedReader(streamOf([enc('abc')]));
		await expect(r.readN(10)).rejects.toBeInstanceOf(ConnectionError);
	});

	it('times out without dropping bytes that arrive late', async () => {
		const { stream, push } = controllable();
		const r = new StreamFramedReader(stream);
		await expect(r.readN(4, 30)).rejects.toBeInstanceOf(TimeoutError);
		push(new Uint8Array([1, 2, 3, 4, 5]));
		expect([...(await r.readN(4, 1000))]).toEqual([1, 2, 3, 4]);
		expect([...(await r.readN(1))]).toEqual([5]);
	});
});

describe('StreamFramedReader.readUntil / readLine', () => {
	it('finds a delimiter that spans a chunk boundary', async () => {
		const r = new StreamFramedReader(streamOf([enc('foo\r'), enc('\nbar')]));
		expect(new TextDecoder().decode(await r.readUntil(enc('\r\n')))).toBe('foo\r\n');
		expect(new TextDecoder().decode(await r.readN(3))).toBe('bar');
	});

	it('reads CRLF lines and strips the terminator', async () => {
		const r = new StreamFramedReader(streamOf([enc('220 ready\r\nEHLO\r\n')]));
		expect(await r.readLine()).toBe('220 ready');
		expect(await r.readLine()).toBe('EHLO');
	});

	it('reads bare-LF lines too', async () => {
		const r = new StreamFramedReader(streamOf([enc('one\ntwo\n')]));
		expect(await r.readLine()).toBe('one');
		expect(await r.readLine()).toBe('two');
	});

	it('enforces the max scan window', async () => {
		const r = new StreamFramedReader(streamOf([enc('x'.repeat(50))]));
		await expect(r.readUntil(enc('\n'), 10)).rejects.toBeInstanceOf(ConnectionError);
	});
});

describe('StreamFramedReader.peek', () => {
	it('returns bytes without consuming them', async () => {
		const r = new StreamFramedReader(streamOf([enc('abcdef')]));
		expect(new TextDecoder().decode(await r.peek(3))).toBe('abc');
		expect(new TextDecoder().decode(await r.readN(3))).toBe('abc');
		expect(new TextDecoder().decode(await r.readN(3))).toBe('def');
	});
});

describe('StreamFramedWriter', () => {
	it('writes raw chunks and CRLF-terminated lines', async () => {
		const chunks: Uint8Array[] = [];
		const ws = new WritableStream<Uint8Array>({
			write(c) {
				chunks.push(c);
			}
		});
		const w = new StreamFramedWriter(ws);
		await w.write(enc('RAW'));
		await w.writeLine('EHLO host');
		expect(new TextDecoder().decode(chunks[0])).toBe('RAW');
		expect(new TextDecoder().decode(chunks[1])).toBe('EHLO host\r\n');
	});
});
