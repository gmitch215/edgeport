/**
 * @fileoverview Buffered, framed read/write over the runtime's WHATWG byte streams.
 *
 * `cloudflare:sockets` exposes a raw {@link ReadableStream}/{@link WritableStream} pair
 * whose chunk boundaries have nothing to do with protocol message boundaries. Every
 * protocol codec instead needs to ask for "exactly N bytes" or "everything up to CRLF".
 * {@link FramedReader} holds an internal carry buffer that bridges that gap, and
 * {@link FramedWriter} adds line-oriented convenience over the writer.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { ConnectionError, TimeoutError } from './errors';

const CR = 0x0d;
const LF = 0x0a;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Rejects with {@link TimeoutError} if `promise` does not settle within `ms`. */
function withTimeout<T>(promise: Promise<T>, ms: number | undefined, what: string): Promise<T> {
	if (ms === undefined || ms === Infinity) return promise;
	let timer: ReturnType<typeof setTimeout>;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(() => reject(new TimeoutError(`${what} timed out after ${ms}ms`)), ms);
	});
	return Promise.race([promise, timeout]).finally(() => clearTimeout(timer)) as Promise<T>;
}

/**
 * Reads exact byte counts and delimited frames from a byte stream, hiding TCP chunking.
 *
 * Reads are buffered: a single underlying chunk may satisfy several `readN` calls, and a
 * single `readN` may consume several chunks. Only one underlying read is ever in flight,
 * so a `readN` that rejects with {@link TimeoutError} leaves any late-arriving bytes in
 * the buffer for the next call rather than dropping them.
 *
 * @since 1.0.0
 */
export interface FramedReader {
	/**
	 * Reads and consumes exactly `n` bytes.
	 *
	 * @param n - Number of bytes to read.
	 * @param timeoutMs - Optional deadline; rejects with {@link TimeoutError} if exceeded.
	 * @returns The `n` bytes read.
	 * @throws {ConnectionError} If the stream ends before `n` bytes are available.
	 * @throws {TimeoutError} If `timeoutMs` elapses first.
	 */
	readN(n: number, timeoutMs?: number): Promise<Uint8Array>;
	/**
	 * Reads and consumes bytes up to and including the first occurrence of `delim`.
	 *
	 * @param delim - The delimiter to scan for.
	 * @param max - Optional cap on bytes scanned before failing (guards against a peer
	 *   that never sends the delimiter).
	 * @param timeoutMs - Optional deadline.
	 * @returns Everything up to and including `delim`.
	 * @throws {ConnectionError} If the stream ends first, or `max` is exceeded.
	 * @throws {TimeoutError} If `timeoutMs` elapses first.
	 */
	readUntil(delim: Uint8Array, max?: number, timeoutMs?: number): Promise<Uint8Array>;
	/**
	 * Reads one line terminated by LF, returning it decoded as UTF-8 with the trailing
	 * CRLF or LF stripped. Suitable for the text line protocols (SMTP, IMAP, POP3).
	 *
	 * @param timeoutMs - Optional deadline.
	 * @returns The line without its terminator.
	 */
	readLine(timeoutMs?: number): Promise<string>;
	/**
	 * Returns the next `n` bytes without consuming them.
	 *
	 * @param n - Number of bytes to inspect.
	 * @param timeoutMs - Optional deadline.
	 * @returns A copy of the next `n` bytes.
	 */
	peek(n: number, timeoutMs?: number): Promise<Uint8Array>;
	/** Releases the underlying reader and cancels the stream. */
	cancel(): Promise<void>;
}

/** Line-oriented writer over a byte {@link WritableStream}. */
export interface FramedWriter {
	/** Writes a chunk of bytes. */
	write(chunk: Uint8Array): Promise<void>;
	/** Writes `s` as UTF-8 followed by CRLF. */
	writeLine(s: string): Promise<void>;
	/** Closes the writable side. */
	close(): Promise<void>;
}

/** {@link FramedReader} backed by a {@link ReadableStream} of bytes. */
export class StreamFramedReader implements FramedReader {
	readonly #reader: ReadableStreamDefaultReader<Uint8Array>;
	// carry buffer; #off marks how much of #buf has already been consumed
	#buf: Uint8Array = new Uint8Array(0);
	#off = 0;
	#ended = false;
	// single in-flight underlying read, shared so a timed-out caller never double-reads
	#pending: Promise<boolean> | null = null;

	constructor(stream: ReadableStream<Uint8Array>) {
		this.#reader = stream.getReader();
	}

	get #available(): number {
		return this.#buf.length - this.#off;
	}

	#append(chunk: Uint8Array): void {
		const keep = this.#available;
		const next = new Uint8Array(keep + chunk.length);
		next.set(this.#buf.subarray(this.#off), 0);
		next.set(chunk, keep);
		this.#buf = next;
		this.#off = 0;
	}

	#take(n: number): Uint8Array {
		const out = this.#buf.slice(this.#off, this.#off + n);
		this.#off += n;
		return out;
	}

	// pulls exactly one chunk into the buffer; returns false once the stream is exhausted
	#pull(): Promise<boolean> {
		if (this.#ended) return Promise.resolve(false);
		if (!this.#pending) {
			this.#pending = this.#reader
				.read()
				.then(({ value, done }) => {
					if (done) {
						this.#ended = true;
						return false;
					}
					if (value && value.length) this.#append(value);
					return true;
				})
				.finally(() => {
					this.#pending = null;
				});
		}
		return this.#pending;
	}

	async #ensure(min: number): Promise<void> {
		while (this.#available < min) {
			if (!(await this.#pull())) {
				throw new ConnectionError('connection closed before enough bytes were read');
			}
		}
	}

	async readN(n: number, timeoutMs?: number): Promise<Uint8Array> {
		if (n < 0) throw new RangeError('readN: n must be >= 0');
		// time out only the (non-consuming) buffering phase, then take synchronously so a
		// timed-out read can never consume bytes that arrive after it gave up
		await withTimeout(this.#ensure(n), timeoutMs, 'readN');
		return this.#take(n);
	}

	async readUntil(delim: Uint8Array, max?: number, timeoutMs?: number): Promise<Uint8Array> {
		if (delim.length === 0) throw new RangeError('readUntil: delim must be non-empty');
		const cut = await withTimeout(this.#scanUntil(delim, max), timeoutMs, 'readUntil');
		return this.#take(cut);
	}

	async readLine(timeoutMs?: number): Promise<string> {
		const line = await this.readUntil(new Uint8Array([LF]), undefined, timeoutMs);
		let end = line.length - 1; // drop LF
		if (end > 0 && line[end - 1] === CR) end -= 1; // drop CR if present
		return decoder.decode(line.subarray(0, end));
	}

	async peek(n: number, timeoutMs?: number): Promise<Uint8Array> {
		await withTimeout(this.#ensure(n), timeoutMs, 'peek');
		return this.#buf.slice(this.#off, this.#off + n);
	}

	// buffers until delim is present; returns the byte count up to and including it (does
	// not consume, so a timed-out scan leaves bytes for the next call)
	async #scanUntil(delim: Uint8Array, max?: number): Promise<number> {
		let scanned = 0;
		for (;;) {
			const idx = this.#indexOf(delim, Math.max(0, scanned - (delim.length - 1)));
			if (idx >= 0) return idx + delim.length;
			scanned = this.#available;
			if (max !== undefined && scanned > max) {
				throw new ConnectionError(`readUntil: exceeded ${max} bytes without delimiter`);
			}
			if (!(await this.#pull())) {
				throw new ConnectionError('connection closed before delimiter was found');
			}
		}
	}

	// searches the unconsumed buffer for delim starting at relative offset `from`
	#indexOf(delim: Uint8Array, from: number): number {
		const base = this.#off;
		const len = this.#available;
		const last = len - delim.length;
		for (let i = from; i <= last; i++) {
			let match = true;
			for (let j = 0; j < delim.length; j++) {
				if (this.#buf[base + i + j] !== delim[j]) {
					match = false;
					break;
				}
			}
			if (match) return i;
		}
		return -1;
	}

	async cancel(): Promise<void> {
		try {
			await this.#reader.cancel();
		} finally {
			this.#reader.releaseLock();
		}
	}

	// drops the stream lock without cancelling (used when the socket is upgraded by startTls)
	release(): void {
		try {
			this.#reader.releaseLock();
		} catch {
			// a read may be in flight; the underlying socket is being discarded anyway
		}
	}
}

/** {@link FramedWriter} backed by a {@link WritableStream} of bytes. */
export class StreamFramedWriter implements FramedWriter {
	readonly #writer: WritableStreamDefaultWriter<Uint8Array>;

	constructor(stream: WritableStream<Uint8Array>) {
		this.#writer = stream.getWriter();
	}

	write(chunk: Uint8Array): Promise<void> {
		return this.#writer.write(chunk);
	}

	writeLine(s: string): Promise<void> {
		return this.#writer.write(encoder.encode(s + '\r\n'));
	}

	async close(): Promise<void> {
		try {
			await this.#writer.close();
		} catch {
			// peer may have already closed; releasing the lock is enough
		} finally {
			this.release();
		}
	}

	// drops the stream lock without closing (used when the socket is upgraded by startTls)
	release(): void {
		try {
			this.#writer.releaseLock();
		} catch {
			// a write may be in flight; the underlying socket is being discarded anyway
		}
	}
}
