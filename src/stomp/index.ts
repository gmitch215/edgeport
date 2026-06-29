/**
 * @fileoverview A STOMP 1.2 client (connect / send / subscribe) for the Cloudflare Workers runtime.
 *
 * STOMP is a simple text framing over TCP: a command line, LF-terminated `key:value` header lines,
 * a blank line, the body, and a terminating NUL byte. This module runs the `CONNECT` -> `CONNECTED`
 * handshake (optional `login`/`passcode` auth, vhost, heart-beat negotiation), optionally upgrades
 * to TLS, then drives a background read pump that routes `MESSAGE` frames to subscriptions, resolves
 * `RECEIPT` waiters, and turns `ERROR` frames into rejections. It builds on the shared core transport
 * and never touches the runtime socket API directly.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import {
	AuthError,
	ConnectionError,
	connect as coreConnect,
	ProtocolError,
	TimeoutError,
	type CoreSocket,
	type FramedReader,
	type FramedWriter
} from '../core';

const DEFAULT_STOMP_PORT = 61613;
const DEFAULT_TIMEOUT_MS = 10000;
const PROTO = 'stomp';
const ACCEPT_VERSION = '1.2';

const encoder = new TextEncoder();
const NUL = 0x00;
const NUL_DELIM = new Uint8Array([NUL]);

/**
 * A single decoded STOMP frame: a command, its headers, and a raw body.
 *
 * The body is left as bytes so binary payloads (including embedded NULs framed by `content-length`)
 * survive intact. Header keys and values are already unescaped from their on-the-wire form.
 *
 * @since 1.0.0
 */
export interface StompFrame {
	/** The frame command (e.g. `'CONNECT'`, `'MESSAGE'`, `'ERROR'`). */
	command: string;
	/** The decoded headers, first occurrence winning per the STOMP repeat-header rule. */
	headers: Record<string, string>;
	/** The raw body bytes (empty when the frame has no body). */
	body: Uint8Array;
}

/**
 * Escapes a STOMP 1.2 header key or value for the wire.
 *
 * Encodes the four reserved characters so a header line stays unambiguous: backslash, carriage
 * return, line feed, and colon. Bodies are never escaped; only header octets pass through here.
 *
 * @param s - The raw header key or value.
 * @returns The escaped string safe to place in a `key:value` line.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { escapeHeader } from 'edgeport/stomp';
 *
 * escapeHeader('a:b\nc'); // 'a\\cb\\nc'
 * ```
 */
export function escapeHeader(s: string): string {
	let out = '';
	for (const ch of s) {
		if (ch === '\\') out += '\\\\';
		else if (ch === '\r') out += '\\r';
		else if (ch === '\n') out += '\\n';
		else if (ch === ':') out += '\\c';
		else out += ch;
	}
	return out;
}

/**
 * Unescapes a STOMP 1.2 header key or value read from the wire.
 *
 * Reverses {@link escapeHeader}, turning the four escape sequences back into their literal
 * characters. An unknown escape sequence is malformed and rejected.
 *
 * @param s - The escaped header key or value.
 * @returns The decoded literal string.
 * @throws {ProtocolError} If an unrecognized escape sequence is present.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { unescapeHeader } from 'edgeport/stomp';
 *
 * unescapeHeader('a\\cb\\nc'); // 'a:b\nc'
 * ```
 */
export function unescapeHeader(s: string): string {
	let out = '';
	for (let i = 0; i < s.length; i++) {
		const ch = s[i]!;
		if (ch !== '\\') {
			out += ch;
			continue;
		}
		const next = s[++i];
		if (next === '\\') out += '\\';
		else if (next === 'r') out += '\r';
		else if (next === 'n') out += '\n';
		else if (next === 'c') out += ':';
		else
			throw new ProtocolError(`invalid stomp header escape: \\${next ?? ''}`, { protocol: PROTO });
	}
	return out;
}

/**
 * Encodes a STOMP frame into its on-the-wire bytes.
 *
 * Emits the command line, escaped header lines, a blank line, the body, and the terminating NUL.
 * When a body is present and no `content-length` header was supplied, one is added so binary bodies
 * with embedded NULs round-trip; pass an empty body to omit it entirely.
 *
 * @param command - The frame command.
 * @param headers - The (unescaped) headers to send.
 * @param body - The raw body bytes; defaults to empty.
 * @returns The full frame as bytes, ready to write.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { encodeFrame } from 'edgeport/stomp';
 *
 * const bytes = encodeFrame('SEND', { destination: '/queue/a' }, new TextEncoder().encode('hi'));
 * ```
 */
export function encodeFrame(
	command: string,
	headers: Record<string, string>,
	body: Uint8Array = new Uint8Array(0)
): Uint8Array {
	const merged: Record<string, string> = { ...headers };
	// content-length lets the peer frame bodies that contain NUL bytes
	if (body.length > 0 && merged['content-length'] === undefined) {
		merged['content-length'] = String(body.length);
	}
	let head = command + '\n';
	for (const [key, value] of Object.entries(merged)) {
		head += `${escapeHeader(key)}:${escapeHeader(value)}\n`;
	}
	head += '\n';
	const headBytes = encoder.encode(head);
	const frame = new Uint8Array(headBytes.length + body.length + 1);
	frame.set(headBytes, 0);
	frame.set(body, headBytes.length);
	frame[frame.length - 1] = NUL; // trailing terminator
	return frame;
}

/**
 * Reads and decodes one STOMP frame from a framed reader.
 *
 * Reads the command line and headers, then the body: when a `content-length` header is present it
 * reads exactly that many bytes and consumes the trailing NUL, otherwise it reads up to the first
 * NUL. Leading blank lines (heart-beat newlines) before a command are skipped.
 *
 * @param reader - The framed reader to pull from.
 * @param timeoutMs - Optional read deadline applied to each underlying read.
 * @returns The decoded frame.
 * @throws {ProtocolError} If the frame is malformed.
 * @throws {ConnectionError} If the stream ends mid-frame.
 * @throws {TimeoutError} If a read exceeds `timeoutMs`.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { decodeFrame } from 'edgeport/stomp';
 * // const frame = await decodeFrame(socket.reader);
 * ```
 */
export async function decodeFrame(reader: FramedReader, timeoutMs?: number): Promise<StompFrame> {
	// skip heart-beat / leading newlines until a real command line
	let command = await reader.readLine(timeoutMs);
	while (command === '') command = await reader.readLine(timeoutMs);

	const headers: Record<string, string> = {};
	for (;;) {
		const line = await reader.readLine(timeoutMs);
		if (line === '') break; // blank line ends the header block
		const idx = line.indexOf(':');
		if (idx === -1) {
			throw new ProtocolError(`malformed stomp header line: ${line}`, { protocol: PROTO });
		}
		const key = unescapeHeader(line.slice(0, idx));
		const value = unescapeHeader(line.slice(idx + 1));
		// repeated header keys: first value wins
		if (headers[key] === undefined) headers[key] = value;
	}

	let body: Uint8Array;
	const lenHeader = headers['content-length'];
	if (lenHeader !== undefined) {
		const n = Number(lenHeader);
		if (!Number.isInteger(n) || n < 0) {
			throw new ProtocolError(`invalid stomp content-length: ${lenHeader}`, { protocol: PROTO });
		}
		body = await reader.readN(n, timeoutMs);
		const term = await reader.readN(1, timeoutMs);
		if (term[0] !== NUL) {
			throw new ProtocolError('stomp frame not terminated by NUL', { protocol: PROTO });
		}
	} else {
		// read everything up to and including the NUL, then drop it
		const withNul = await reader.readUntil(NUL_DELIM, undefined, timeoutMs);
		body = withNul.subarray(0, withNul.length - 1);
	}
	return { command, headers, body };
}

/**
 * Options for {@link connect}.
 *
 * @since 1.0.0
 */
export interface StompConnectOptions {
	/** Remote STOMP host (also used for TLS certificate validation). */
	hostname: string;
	/** Remote port; defaults to 61613. */
	port?: number;
	/**
	 * Transport security:
	 * - `'off'` (default): plaintext.
	 * - `'implicit'`: TLS from the first byte.
	 * - `'starttls'`: dial plaintext, then upgrade to TLS before the `CONNECT` frame.
	 */
	tls?: 'off' | 'implicit' | 'starttls';
	/** Login name sent in the `login` header when provided. */
	login?: string;
	/** Passcode sent in the `passcode` header when provided. */
	passcode?: string;
	/** Virtual host sent in the `host` header; defaults to `hostname`. */
	host?: string;
	/** Heart-beat as `[cx, cy]` milliseconds; defaults to `[0, 0]` (disabled). */
	heartBeat?: [number, number];
	/** Read deadline in milliseconds for the connect handshake. */
	timeoutMs?: number;
}

/**
 * A message delivered to a {@link StompSubscription}.
 *
 * For `client` / `client-individual` ack modes the broker supplies an `ack` header, and this object
 * exposes {@link StompMessage.ack} / {@link StompMessage.nack} to settle it; in `auto` mode those are
 * absent.
 *
 * @since 1.0.0
 */
export interface StompMessage {
	/** The destination the message was published to. */
	destination: string;
	/** The raw message body bytes. */
	body: Uint8Array;
	/** The decoded MESSAGE headers. */
	headers: Record<string, string>;
	/** The broker's `message-id` for this message. */
	messageId: string;
	/** Acknowledges the message (`client` / `client-individual` modes only). */
	ack?(): Promise<void>;
	/** Negatively acknowledges the message (`client` / `client-individual` modes only). */
	nack?(): Promise<void>;
}

/**
 * An active subscription that yields {@link StompMessage}s as they arrive.
 *
 * Iterate it with `for await`; the loop ends when {@link unsubscribe} is called or the connection
 * closes. It is an `AsyncDisposable`, so `await using` unsubscribes automatically.
 *
 * @since 1.0.0
 */
export interface StompSubscription extends AsyncIterable<StompMessage>, AsyncDisposable {
	/** The destination this subscription matches. */
	readonly destination: string;
	/** The broker-facing subscription id. */
	readonly id: string;
	/**
	 * Stops the subscription (`UNSUBSCRIBE`) and ends the iterator.
	 *
	 * @returns Resolves once the `UNSUBSCRIBE` is written.
	 */
	unsubscribe(): Promise<void>;
}

/**
 * A STOMP transaction (RFC frames `BEGIN`/`COMMIT`/`ABORT`). Sends made through it are
 * staged by the broker and only delivered to subscribers on {@link StompTransaction.commit};
 * {@link StompTransaction.abort} discards them.
 *
 * @since 1.0.0
 */
export interface StompTransaction {
	/** The transaction id carried in the `transaction` header. */
	readonly id: string;
	/** Sends a message within the transaction (delivered only after `commit`). */
	send(
		destination: string,
		body: Uint8Array | string,
		opts?: { headers?: Record<string, string>; contentType?: string }
	): Promise<void>;
	/** Commits the transaction, releasing all staged sends. */
	commit(): Promise<void>;
	/** Aborts the transaction, discarding all staged sends. */
	abort(): Promise<void>;
}

/**
 * A live STOMP session over a single socket.
 *
 * Obtain one from {@link connect}. A background pump reads the socket and routes frames, so sending,
 * subscribing, and receiving can all be in flight at once. It is an `AsyncDisposable`, so
 * `await using` closes it cleanly (sending `DISCONNECT` with a receipt first).
 *
 * @since 1.0.0
 */
export interface StompSession extends AsyncDisposable {
	/**
	 * Sends a message to a destination.
	 *
	 * @param destination - The destination to send to (e.g. `/queue/a`).
	 * @param body - The payload; strings are UTF-8 encoded.
	 * @param opts - Optional extra headers and a `content-type`.
	 * @returns Resolves once the `SEND` frame is written.
	 * @throws {ConnectionError} If the session is closed.
	 */
	send(
		destination: string,
		body: Uint8Array | string,
		opts?: { headers?: Record<string, string>; contentType?: string }
	): Promise<void>;
	/**
	 * Subscribes to a destination.
	 *
	 * @param destination - The destination to subscribe to.
	 * @param opts - Optional ack mode (defaults to `'auto'`) and extra headers.
	 * @returns A subscription whose async iterator yields matching messages.
	 * @throws {ConnectionError} If the session is closed.
	 */
	subscribe(
		destination: string,
		opts?: { ack?: 'auto' | 'client' | 'client-individual'; headers?: Record<string, string> }
	): StompSubscription;
	/**
	 * Unsubscribes by subscription id.
	 *
	 * @param id - The subscription id to cancel.
	 * @returns Resolves once the `UNSUBSCRIBE` is written.
	 */
	unsubscribe(id: string): Promise<void>;
	/**
	 * Begins a transaction. Sends made through the returned {@link StompTransaction} are staged
	 * by the broker until `commit()`; `abort()` discards them.
	 *
	 * @returns The open transaction.
	 * @throws {ConnectionError} If the session is closed.
	 */
	begin(): Promise<StompTransaction>;
	/**
	 * Sends `DISCONNECT` with a receipt, waits for it, and closes the socket.
	 *
	 * @returns Resolves once the socket is closed.
	 */
	close(): Promise<void>;
}

// a single-consumer push/pull queue backing one subscription's async iterator
class MessageQueue {
	#queue: StompMessage[] = [];
	#waiters: ((r: IteratorResult<StompMessage>) => void)[] = [];
	#done = false;

	push(msg: StompMessage): void {
		if (this.#done) return;
		const waiter = this.#waiters.shift();
		if (waiter) waiter({ value: msg, done: false });
		else this.#queue.push(msg);
	}

	end(): void {
		if (this.#done) return;
		this.#done = true;
		for (const waiter of this.#waiters) waiter({ value: undefined, done: true });
		this.#waiters = [];
	}

	next(): Promise<IteratorResult<StompMessage>> {
		const msg = this.#queue.shift();
		if (msg) return Promise.resolve({ value: msg, done: false });
		if (this.#done) return Promise.resolve({ value: undefined, done: true });
		return new Promise((resolve) => this.#waiters.push(resolve));
	}
}

class Subscription implements StompSubscription {
	readonly destination: string;
	readonly id: string;
	readonly #queue = new MessageQueue();
	readonly #onUnsub: (id: string) => Promise<void>;

	constructor(id: string, destination: string, onUnsub: (id: string) => Promise<void>) {
		this.id = id;
		this.destination = destination;
		this.#onUnsub = onUnsub;
	}

	deliver(msg: StompMessage): void {
		this.#queue.push(msg);
	}

	// pump-side close: ends the iterator without writing UNSUBSCRIBE (socket is gone)
	stop(): void {
		this.#queue.end();
	}

	async unsubscribe(): Promise<void> {
		this.#queue.end();
		await this.#onUnsub(this.id);
	}

	[Symbol.asyncIterator](): AsyncIterator<StompMessage> {
		return { next: () => this.#queue.next() };
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.unsubscribe();
	}
}

class StompSessionImpl implements StompSession {
	#socket: CoreSocket;
	#writer: FramedWriter;
	readonly #subs = new Map<string, Subscription>();
	#subCounter = 0;
	#receiptCounter = 0;
	#txCounter = 0;
	#closed = false;
	// in-flight RECEIPT waiters keyed by receipt id; the pump resolves or rejects them
	readonly #receipts = new Map<string, { resolve: () => void; reject: (e: Error) => void }>();
	#pumpError: Error | null = null;

	constructor(socket: CoreSocket) {
		this.#socket = socket;
		this.#writer = socket.writer;
	}

	// starts the background read loop; routes frames until the socket ends or errors
	startPump(): void {
		void this.#pump(this.#socket.reader);
	}

	async #pump(reader: FramedReader): Promise<void> {
		try {
			for (;;) {
				const frame = await decodeFrame(reader);
				this.#dispatch(frame);
			}
		} catch (err) {
			if (!this.#closed) this.#pumpError = err as Error;
		} finally {
			const reason =
				this.#pumpError ?? new ConnectionError('stomp connection closed', { protocol: PROTO });
			for (const w of this.#receipts.values()) w.reject(reason);
			this.#receipts.clear();
			this.#endAll();
		}
	}

	#dispatch(frame: StompFrame): void {
		switch (frame.command) {
			case 'MESSAGE':
				this.#handleMessage(frame);
				return;
			case 'RECEIPT': {
				const id = frame.headers['receipt-id'];
				const waiter = id !== undefined ? this.#receipts.get(id) : undefined;
				if (id !== undefined && waiter) {
					this.#receipts.delete(id);
					waiter.resolve();
				}
				return;
			}
			case 'ERROR': {
				// surface a server ERROR to every waiter and stop the pump
				this.#pumpError = errorFrameToError(frame);
				throw this.#pumpError;
			}
			default:
				throw new ProtocolError(`unexpected stomp frame: ${frame.command}`, { protocol: PROTO });
		}
	}

	#handleMessage(frame: StompFrame): void {
		const subId = frame.headers['subscription'];
		const sub = subId !== undefined ? this.#subs.get(subId) : undefined;
		if (!sub) return; // message for a subscription we no longer track
		const ackId = frame.headers['ack'];
		const msg: StompMessage = {
			destination: frame.headers['destination'] ?? sub.destination,
			body: frame.body,
			headers: frame.headers,
			messageId: frame.headers['message-id'] ?? ''
		};
		if (ackId !== undefined) {
			msg.ack = () => this.#sendAck('ACK', ackId);
			msg.nack = () => this.#sendAck('NACK', ackId);
		}
		sub.deliver(msg);
	}

	async #sendAck(command: 'ACK' | 'NACK', ackId: string): Promise<void> {
		this.#assertOpen();
		await this.#writer.write(encodeFrame(command, { id: ackId }));
	}

	#endAll(): void {
		for (const sub of this.#subs.values()) sub.stop();
		this.#subs.clear();
	}

	#assertOpen(): void {
		if (this.#closed) throw new ConnectionError('stomp session is closed', { protocol: PROTO });
		if (this.#pumpError) throw this.#pumpError;
	}

	async send(
		destination: string,
		body: Uint8Array | string,
		opts?: { headers?: Record<string, string>; contentType?: string }
	): Promise<void> {
		this.#assertOpen();
		const payload = typeof body === 'string' ? encoder.encode(body) : body;
		const headers: Record<string, string> = { destination, ...opts?.headers };
		if (opts?.contentType !== undefined) headers['content-type'] = opts.contentType;
		await this.#writer.write(encodeFrame('SEND', headers, payload));
	}

	subscribe(
		destination: string,
		opts?: { ack?: 'auto' | 'client' | 'client-individual'; headers?: Record<string, string> }
	): StompSubscription {
		this.#assertOpen();
		const id = String(++this.#subCounter);
		const sub = new Subscription(id, destination, (sid) => this.#sendUnsubscribe(sid));
		this.#subs.set(id, sub);
		const headers: Record<string, string> = {
			id,
			destination,
			ack: opts?.ack ?? 'auto',
			...opts?.headers
		};
		// fire-and-forget the SUBSCRIBE write; ordering is preserved by the single writer
		void this.#writer.write(encodeFrame('SUBSCRIBE', headers));
		return sub;
	}

	async unsubscribe(id: string): Promise<void> {
		const sub = this.#subs.get(id);
		if (sub) sub.stop();
		await this.#sendUnsubscribe(id);
	}

	async begin(): Promise<StompTransaction> {
		this.#assertOpen();
		const id = `tx-${++this.#txCounter}`;
		await this.#writer.write(encodeFrame('BEGIN', { transaction: id }));
		const session = this;
		return {
			id,
			async send(destination, body, opts) {
				// the transaction header stages the SEND until COMMIT
				await session.send(destination, body, {
					contentType: opts?.contentType,
					headers: { transaction: id, ...opts?.headers }
				});
			},
			async commit() {
				session.#assertOpen();
				await session.#writer.write(encodeFrame('COMMIT', { transaction: id }));
			},
			async abort() {
				session.#assertOpen();
				await session.#writer.write(encodeFrame('ABORT', { transaction: id }));
			}
		};
	}

	async #sendUnsubscribe(id: string): Promise<void> {
		if (!this.#subs.delete(id)) return;
		if (this.#closed || this.#pumpError) return;
		await this.#writer.write(encodeFrame('UNSUBSCRIBE', { id }));
	}

	// writes a frame and waits for the matching RECEIPT the pump will route
	#writeWithReceipt(command: string, headers: Record<string, string>): Promise<void> {
		const receipt = `r-${++this.#receiptCounter}`;
		const wait = new Promise<void>((resolve, reject) => {
			this.#receipts.set(receipt, { resolve, reject });
		});
		void this.#writer.write(encodeFrame(command, { ...headers, receipt }));
		return wait;
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		// send DISCONNECT with a receipt so the broker flushes, but never fail close on it
		if (!this.#pumpError) {
			try {
				await this.#writeWithReceipt('DISCONNECT', {});
			} catch {
				// broker may have closed first; closing the socket below is enough
			}
		}
		this.#closed = true;
		this.#endAll();
		await this.#socket.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

// classifies a server ERROR frame: auth-related wording -> AuthError, else ProtocolError
function errorFrameToError(frame: StompFrame): AuthError | ProtocolError {
	const message = frame.headers['message'] ?? new TextDecoder().decode(frame.body);
	const lower = `${message} ${new TextDecoder().decode(frame.body)}`.toLowerCase();
	const authy =
		lower.includes('authenticat') ||
		lower.includes('authoriz') ||
		lower.includes('login') ||
		lower.includes('passcode') ||
		lower.includes('credential') ||
		lower.includes('access is denied') ||
		lower.includes('not allowed to');
	const text = `stomp ERROR: ${message}`;
	return authy
		? new AuthError(text, { protocol: PROTO })
		: new ProtocolError(text, { protocol: PROTO });
}

/**
 * Connects to a STOMP broker, performs the handshake, and returns a live session.
 *
 * Dials the core transport (implicit TLS when `tls: 'implicit'`, otherwise plaintext optionally
 * upgraded via `starttls`), sends `CONNECT` with `accept-version`, `host`, `heart-beat`, and any
 * `login`/`passcode`, and waits for `CONNECTED`. An `ERROR` frame during connect surfaces as
 * {@link AuthError} when it looks auth-related, otherwise {@link ProtocolError}. A background pump
 * then routes messages and receipts.
 *
 * @param opts - Connection and credential options.
 * @returns The live session.
 * @throws {AuthError} If the broker rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the broker speaks the protocol incorrectly.
 * @throws {TimeoutError} If the handshake exceeds the deadline.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { connect } from 'edgeport/stomp';
 *
 * await using stomp = await connect({
 * 	hostname: 'broker.example.com',
 * 	login: 'user',
 * 	passcode: 'secret'
 * });
 * await stomp.send('/queue/jobs', 'hello');
 * await using sub = stomp.subscribe('/queue/jobs');
 * for await (const msg of sub) {
 * 	console.log(new TextDecoder().decode(msg.body));
 * 	break;
 * }
 * ```
 */
export async function connect(opts: StompConnectOptions): Promise<StompSession> {
	const port = opts.port ?? DEFAULT_STOMP_PORT;
	const implicit = opts.tls === 'implicit';
	const socket = await coreConnect({
		hostname: opts.hostname,
		port,
		tls: implicit ? 'on' : 'starttls',
		connectTimeoutMs: opts.timeoutMs
	});
	try {
		let active = socket;
		// upgrade before CONNECT when starttls is requested; re-acquire reader/writer
		if (opts.tls === 'starttls') {
			active = socket.startTls({ expectedServerHostname: opts.hostname });
		}
		return await _connectOverSocket(active, opts);
	} catch (err) {
		await socket.close().catch(() => {});
		throw err;
	}
}

/**
 * Runs the STOMP handshake and read pump over an already-connected {@link CoreSocket}.
 *
 * Sends `CONNECT` (with `accept-version`, `host`, `heart-beat`, and optional `login`/`passcode`) and
 * waits for `CONNECTED`, classifying an `ERROR` reply as {@link AuthError} or {@link ProtocolError}.
 * Public {@link connect} dials the transport (and does any `starttls` upgrade) then calls this;
 * tests call it directly with a mock socket.
 *
 * @param socket - A connected core socket (already TLS when applicable).
 * @param opts - Connection and credential options.
 * @returns The live session.
 * @throws {AuthError} If the broker rejects the credentials.
 * @throws {ProtocolError} If the broker speaks the protocol incorrectly.
 * @throws {TimeoutError} If the handshake exceeds the deadline.
 * @internal
 */
export async function _connectOverSocket(
	socket: CoreSocket,
	opts: StompConnectOptions
): Promise<StompSession> {
	const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const hb = opts.heartBeat ?? [0, 0];
	const headers: Record<string, string> = {
		'accept-version': ACCEPT_VERSION,
		host: opts.host ?? opts.hostname,
		'heart-beat': `${hb[0]},${hb[1]}`
	};
	if (opts.login !== undefined) headers['login'] = opts.login;
	if (opts.passcode !== undefined) headers['passcode'] = opts.passcode;

	await socket.writer.write(encodeFrame('CONNECT', headers));

	// the handshake reply is read inline; the pump only starts once CONNECTED arrives
	const reply = await decodeFrame(socket.reader, timeoutMs);
	if (reply.command === 'ERROR') {
		throw errorFrameToError(reply);
	}
	if (reply.command !== 'CONNECTED') {
		throw new ProtocolError(`expected CONNECTED, got ${reply.command}`, { protocol: PROTO });
	}

	const session = new StompSessionImpl(socket);
	session.startPump();
	return session;
}
