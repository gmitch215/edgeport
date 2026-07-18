/**
 * @fileoverview MSRP (Message Session Relay Protocol, RFC 4975) codec and session.
 *
 * MSRP carries the message content of a SIP session-mode chat (the body an INVITE/SDP set up).
 * A frame is `MSRP <tid> <method-or-status>`, headers (To-Path / From-Path / Message-ID /
 * Byte-Range / Content-Type), an optional body, then an end-line of seven hyphens, the
 * transaction id, and a continuation flag (`$` complete, `+` more chunks, `#` abort). A Worker
 * cannot accept inbound TCP, so the session is always the ACTIVE side: it dials the peer's
 * MSRP path (from the SDP answer) and both sends and receives on that one connection.
 *
 * @author Gregory Mitchell
 * @since 1.0.3
 */
import {
	ConnectionError,
	ProtocolError,
	connect as coreConnect,
	type CoreSocket,
	type FramedReader,
	type FramedWriter
} from '../core';
import { randomHex } from '../util';

const PROTO = 'msrp';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const DEFAULT_MSRP_PORT = 2855;
const DEFAULT_CHUNK = 2048;
const END_DASHES = '-------';

/** A decoded MSRP request (`SEND` or `REPORT`). */
export interface MsrpRequest {
	/** Discriminant. */
	kind: 'request';
	/** The transaction id from the first line. */
	transactionId: string;
	/** The method. */
	method: string;
	/** Header name/value pairs (case preserved as sent). */
	headers: Record<string, string>;
	/** The body octets (empty when none). */
	body: Uint8Array;
	/** The continuation flag: `$` complete, `+` more chunks, `#` aborted. */
	continuation: string;
}

/** A decoded MSRP response (transaction result). */
export interface MsrpResponse {
	/** Discriminant. */
	kind: 'response';
	/** The transaction id echoed from the request. */
	transactionId: string;
	/** The status code (200 = ok). */
	code: number;
	/** The reason phrase. */
	reason: string;
	/** Header name/value pairs. */
	headers: Record<string, string>;
	/** The continuation flag. */
	continuation: string;
}

/** A decoded MSRP frame. */
export type MsrpFrame = MsrpRequest | MsrpResponse;

/** Case-insensitive header lookup on a decoded frame. */
function header(frame: MsrpFrame, name: string): string | undefined {
	const lower = name.toLowerCase();
	for (const [k, v] of Object.entries(frame.headers)) if (k.toLowerCase() === lower) return v;
	return undefined;
}

/**
 * Encodes an MSRP frame (request or response) to bytes.
 *
 * @param frame - The frame to encode.
 * @returns The complete MSRP frame bytes, including the end-line.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { encodeMsrp } from 'edgeport/sip';
 *
 * const bytes = encodeMsrp({
 * 	kind: 'request',
 * 	transactionId: 'abc',
 * 	method: 'SEND',
 * 	headers: { 'To-Path': to, 'From-Path': from, 'Content-Type': 'text/plain' },
 * 	body: new TextEncoder().encode('hi'),
 * 	continuation: '$'
 * });
 * ```
 */
export function encodeMsrp(frame: MsrpFrame): Uint8Array {
	const firstLine =
		frame.kind === 'request'
			? `MSRP ${frame.transactionId} ${frame.method}`
			: `MSRP ${frame.transactionId} ${frame.code} ${frame.reason}`;
	let head = firstLine + '\r\n';
	for (const [name, value] of Object.entries(frame.headers)) head += `${name}: ${value}\r\n`;
	const body = frame.kind === 'request' ? frame.body : new Uint8Array(0);
	// a body is separated from the headers by a blank line and followed by CRLF before the end-line
	const bodyPrefix = body.length > 0 ? '\r\n' : '';
	const endLine = `${bodyPrefix ? '\r\n' : ''}${END_DASHES}${frame.transactionId}${frame.continuation}\r\n`;
	const headBytes = encoder.encode(head + bodyPrefix);
	const endBytes = encoder.encode(endLine);
	const out = new Uint8Array(headBytes.length + body.length + endBytes.length);
	out.set(headBytes, 0);
	out.set(body, headBytes.length);
	out.set(endBytes, headBytes.length + body.length);
	return out;
}

/**
 * Decodes a complete MSRP frame from a buffer.
 *
 * @param bytes - A buffer holding exactly one MSRP frame (first line through end-line).
 * @returns The decoded request or response.
 * @throws {ProtocolError} If the first line or framing is malformed.
 * @since 1.0.3
 */
export function decodeMsrp(bytes: Uint8Array): MsrpFrame {
	const text = decoder.decode(bytes);
	const firstEnd = text.indexOf('\r\n');
	if (firstEnd < 0)
		throw new ProtocolError('malformed MSRP frame (no first line)', { protocol: PROTO });
	const first = text.slice(0, firstEnd);
	const m = first.match(/^MSRP\s+(\S+)\s+(.+)$/);
	if (!m)
		throw new ProtocolError(`malformed MSRP first line: ${JSON.stringify(first)}`, {
			protocol: PROTO
		});
	const transactionId = m[1]!;
	const rest = m[2]!;

	// locate the end-line: -------<tid><flag>
	const endMarker = `${END_DASHES}${transactionId}`;
	const endIdx = text.lastIndexOf(endMarker);
	if (endIdx < 0) throw new ProtocolError('MSRP frame missing end-line', { protocol: PROTO });
	const continuation = text[endIdx + endMarker.length] ?? '$';

	// headers run from after the first line to the blank line (or the end-line)
	const afterFirst = firstEnd + 2;
	const headerText = text.slice(afterFirst, endIdx);
	const blank = headerText.indexOf('\r\n\r\n');
	const headersRaw = blank >= 0 ? headerText.slice(0, blank) : headerText.replace(/\r\n$/, '');
	const headers: Record<string, string> = {};
	for (const line of headersRaw.split('\r\n')) {
		if (!line) continue;
		const colon = line.indexOf(':');
		if (colon >= 0) headers[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
	}
	// body (if any) is the bytes between the header blank line and the CRLF before the end-line
	let body = new Uint8Array(0);
	if (blank >= 0) {
		const bodyStartChar = afterFirst + blank + 4;
		// recompute byte offsets by measuring the char-prefix in bytes (bodies may be binary-ish)
		const bodyText = text.slice(bodyStartChar, endIdx).replace(/\r\n$/, '');
		body = encoder.encode(bodyText);
	}

	const status = rest.match(/^(\d{3})\s*(.*)$/);
	if (status) {
		return {
			kind: 'response',
			transactionId,
			code: Number(status[1]),
			reason: status[2] ?? '',
			headers,
			continuation
		};
	}
	return { kind: 'request', transactionId, method: rest.trim(), headers, body, continuation };
}

// reads one complete MSRP frame off a framed reader (dynamic end-line keyed on the tid)
async function readMsrpFrame(reader: FramedReader, timeoutMs?: number): Promise<MsrpFrame | null> {
	let firstLine: Uint8Array;
	try {
		firstLine = await reader.readUntil(new Uint8Array([0x0d, 0x0a]), 8192, timeoutMs);
	} catch (err) {
		if (err instanceof ConnectionError) return null;
		throw err;
	}
	const first = decoder.decode(firstLine).replace(/\r\n$/, '');
	const m = first.match(/^MSRP\s+(\S+)\s+/);
	if (!m)
		throw new ProtocolError(`malformed MSRP first line: ${JSON.stringify(first)}`, {
			protocol: PROTO
		});
	const tid = m[1]!;
	// read up to and including the end-line "-------<tid>"
	const endMarker = encoder.encode(`\r\n${END_DASHES}${tid}`);
	const rest = await reader.readUntil(endMarker, undefined, timeoutMs);
	// consume the continuation flag byte + trailing CRLF after the end marker
	const tail = await reader.readUntil(new Uint8Array([0x0d, 0x0a]), 8, timeoutMs);
	const full = new Uint8Array(firstLine.length + rest.length + tail.length);
	full.set(firstLine, 0);
	full.set(rest, firstLine.length);
	full.set(tail, firstLine.length + rest.length);
	return decodeMsrp(full);
}

/** Parses an `msrp://host:port/session;tcp` (or `msrps://`) URI into its dial parts. */
function parseMsrpUri(uri: string): { host: string; port: number; tls: boolean } {
	const m = uri.match(/^(msrps?):\/\/([^:/;]+)(?::(\d+))?/i);
	if (!m)
		throw new ProtocolError(`malformed MSRP uri: ${JSON.stringify(uri)}`, { protocol: PROTO });
	return {
		host: m[2]!,
		port: m[3] ? Number(m[3]) : DEFAULT_MSRP_PORT,
		tls: m[1]!.toLowerCase() === 'msrps'
	};
}

/** An inbound MSRP message delivered to {@link MsrpSession.messages}. */
export interface MsrpMessage {
	/** The raw body octets. */
	body: Uint8Array;
	/** The `Content-Type` header, if present. */
	contentType?: string;
	/** The `Message-ID`, if present. */
	messageId?: string;
	/** Decodes the body as UTF-8 text. */
	text(): string;
}

/** Options for {@link connectMsrp}. */
export interface MsrpConnectOptions {
	/** The peer/relay MSRP path to dial and send to (the SDP answer's `a=path`). */
	remotePath: string;
	/** Our local MSRP path (the SDP offer's `a=path`). */
	localPath: string;
	/** Max body octets per SEND chunk; defaults to 2048. */
	chunkSize?: number;
	/** Per-response read deadline in milliseconds. */
	timeoutMs?: number;
}

/**
 * A live MSRP session over one active TCP/TLS connection.
 *
 * @since 1.0.3
 */
export interface MsrpSession extends AsyncDisposable {
	/**
	 * Sends a message, chunking bodies larger than the configured chunk size, and resolving once
	 * every chunk is acknowledged.
	 *
	 * @param body - The message body (a string is UTF-8 encoded).
	 * @param opts - Optional content type and message id.
	 * @returns Resolves once all chunks are acknowledged.
	 */
	send(
		body: Uint8Array | string,
		opts?: { contentType?: string; messageId?: string }
	): Promise<void>;
	/** Async iterable of inbound {@link MsrpMessage}s (each auto-acknowledged with 200). */
	messages(): AsyncIterable<MsrpMessage>;
	/** Closes the MSRP connection. */
	close(): Promise<void>;
}

interface Deferred<T> {
	promise: Promise<T>;
	resolve: (v: T) => void;
	reject: (e: Error) => void;
}
function deferred<T>(): Deferred<T> {
	let resolve!: (v: T) => void;
	let reject!: (e: Error) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

class MsrpQueue {
	#items: MsrpMessage[] = [];
	#waiters: ((r: IteratorResult<MsrpMessage>) => void)[] = [];
	#done = false;
	push(m: MsrpMessage): void {
		if (this.#done) return;
		const w = this.#waiters.shift();
		if (w) w({ value: m, done: false });
		else this.#items.push(m);
	}
	end(): void {
		if (this.#done) return;
		this.#done = true;
		for (const w of this.#waiters) w({ value: undefined, done: true });
		this.#waiters = [];
	}
	next(): Promise<IteratorResult<MsrpMessage>> {
		const m = this.#items.shift();
		if (m) return Promise.resolve({ value: m, done: false });
		if (this.#done) return Promise.resolve({ value: undefined, done: true });
		return new Promise((r) => this.#waiters.push(r));
	}
}

class MsrpSessionImpl implements MsrpSession {
	readonly #socket: CoreSocket;
	readonly #reader: FramedReader;
	readonly #writer: FramedWriter;
	readonly #localPath: string;
	readonly #remotePath: string;
	readonly #chunkSize: number;
	readonly #timeoutMs?: number;
	readonly #pending = new Map<string, Deferred<MsrpResponse>>();
	readonly #queue = new MsrpQueue();
	#closed = false;
	#pumpError: Error | null = null;

	constructor(socket: CoreSocket, opts: MsrpConnectOptions) {
		this.#socket = socket;
		this.#reader = socket.reader;
		this.#writer = socket.writer;
		this.#localPath = opts.localPath;
		this.#remotePath = opts.remotePath;
		this.#chunkSize = opts.chunkSize ?? DEFAULT_CHUNK;
		this.#timeoutMs = opts.timeoutMs;
	}

	start(): void {
		void this.#pump();
	}

	async #pump(): Promise<void> {
		try {
			for (;;) {
				const frame = await readMsrpFrame(this.#reader);
				if (frame === null) break;
				if (frame.kind === 'response') {
					const w = this.#pending.get(frame.transactionId);
					if (w) {
						this.#pending.delete(frame.transactionId);
						w.resolve(frame);
					}
				} else if (frame.method === 'SEND') {
					// acknowledge, then deliver the chunk body
					await this.#ackSend(frame);
					const body = frame.body;
					const ct = header(frame, 'Content-Type');
					this.#queue.push({
						body,
						contentType: ct,
						messageId: header(frame, 'Message-ID'),
						text: () => decoder.decode(body)
					});
				}
				// REPORT and others are consumed silently
			}
		} catch (err) {
			if (!this.#closed) this.#pumpError = err as Error;
		} finally {
			const reason =
				this.#pumpError ?? new ConnectionError('msrp connection closed', { protocol: PROTO });
			for (const w of this.#pending.values()) w.reject(reason);
			this.#pending.clear();
			this.#queue.end();
		}
	}

	// sends a 200 OK for an inbound SEND (unless the sender suppressed success reports)
	async #ackSend(req: MsrpRequest): Promise<void> {
		if (
			(header(req, 'Success-Report') ?? 'no').toLowerCase() === 'no' &&
			req.continuation !== '$'
		) {
			// still ack the transaction; MSRP responses are per-transaction
		}
		const from = header(req, 'From-Path') ?? this.#remotePath;
		const resp: MsrpResponse = {
			kind: 'response',
			transactionId: req.transactionId,
			code: 200,
			reason: 'OK',
			headers: { 'To-Path': from, 'From-Path': this.#localPath },
			continuation: '$'
		};
		await this.#writer.write(encodeMsrp(resp));
	}

	async send(
		body: Uint8Array | string,
		opts?: { contentType?: string; messageId?: string }
	): Promise<void> {
		if (this.#closed) throw new ConnectionError('msrp session is closed', { protocol: PROTO });
		if (this.#pumpError) throw this.#pumpError;
		const bytes = typeof body === 'string' ? encoder.encode(body) : body;
		const messageId = opts?.messageId ?? randomHex(8);
		const total = bytes.length;
		let offset = 0;
		do {
			const end = Math.min(offset + this.#chunkSize, total);
			const chunk = bytes.subarray(offset, end);
			const last = end >= total;
			const tid = randomHex(8);
			const req: MsrpRequest = {
				kind: 'request',
				transactionId: tid,
				method: 'SEND',
				headers: {
					'To-Path': this.#remotePath,
					'From-Path': this.#localPath,
					'Message-ID': messageId,
					'Byte-Range': `${offset + 1}-${end}/${total}`,
					'Content-Type': opts?.contentType ?? 'text/plain'
				},
				body: chunk,
				continuation: last ? '$' : '+'
			};
			const d = deferred<MsrpResponse>();
			this.#pending.set(tid, d);
			await this.#writer.write(encodeMsrp(req));
			const resp = await this.#withTimeout(d.promise);
			if (resp.code >= 300) {
				throw new ProtocolError(`msrp SEND rejected: ${resp.code} ${resp.reason}`, {
					protocol: PROTO
				});
			}
			offset = end;
		} while (offset < total);
	}

	#withTimeout<T>(p: Promise<T>): Promise<T> {
		const ms = this.#timeoutMs;
		if (ms === undefined) return p;
		let timer: ReturnType<typeof setTimeout>;
		const t = new Promise<never>((_, reject) => {
			timer = setTimeout(
				() => reject(new ConnectionError('msrp response timed out', { protocol: PROTO })),
				ms
			);
		});
		return Promise.race([p, t]).finally(() => clearTimeout(timer)) as Promise<T>;
	}

	messages(): AsyncIterable<MsrpMessage> {
		const queue = this.#queue;
		return {
			[Symbol.asyncIterator](): AsyncIterator<MsrpMessage> {
				return { next: () => queue.next() };
			}
		};
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		this.#queue.end();
		await this.#socket.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

/**
 * Opens an active MSRP session by dialing the peer's MSRP path.
 *
 * The peer path (from the SDP answer's `a=path`) supplies the host/port/TLS to connect to; the
 * session sends `SEND` requests with `To-Path`/`From-Path` set, chunks large bodies, and
 * delivers inbound messages via {@link MsrpSession.messages}.
 *
 * @param opts - The remote/local MSRP paths and options.
 * @returns The live MSRP session.
 * @throws {ConnectionError} If the MSRP connection cannot be opened.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { connectMsrp } from 'edgeport/sip';
 *
 * await using msrp = await connectMsrp({ remotePath: peerPath, localPath: myPath });
 * await msrp.send('hello over MSRP');
 * ```
 */
export async function connectMsrp(opts: MsrpConnectOptions): Promise<MsrpSession> {
	const { host, port, tls } = parseMsrpUri(opts.remotePath);
	const socket = await coreConnect({
		hostname: host,
		port,
		tls: tls ? 'on' : 'off',
		connectTimeoutMs: opts.timeoutMs
	});
	return _msrpSessionFromSocket(socket, opts);
}

/**
 * Wraps an already-connected core socket in an MSRP session and starts its read pump.
 *
 * Public {@link connectMsrp} dials the peer's MSRP path then calls this; unit tests call it
 * directly with a mock socket to drive the session (send/chunking/ack/receive) without a network.
 *
 * @param socket - A connected core socket (already TLS when the path is `msrps://`).
 * @param opts - The session options.
 * @returns The live MSRP session.
 * @internal
 */
export function _msrpSessionFromSocket(socket: CoreSocket, opts: MsrpConnectOptions): MsrpSession {
	const session = new MsrpSessionImpl(socket, opts);
	session.start();
	return session;
}
