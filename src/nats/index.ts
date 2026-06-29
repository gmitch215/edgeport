/**
 * @fileoverview A NATS core client (publish / subscribe / request-reply) for the Cloudflare
 * Workers runtime.
 *
 * NATS speaks a simple text control protocol over TCP: CRLF-terminated verbs (`INFO`, `CONNECT`,
 * `PUB`, `SUB`, `MSG`, `PING`, `PONG`, `+OK`, `-ERR`) with raw message payloads framed by an
 * explicit byte count. This module runs the `INFO` -> `CONNECT` handshake (token, user/pass, or
 * nkey auth), optionally upgrades to TLS, then drives a background read pump that routes incoming
 * `MSG` frames to subscriptions and answers server `PING`s. It builds on the shared core
 * transport and never touches the runtime socket API directly.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import {
	AuthError,
	ConnectionError,
	ProtocolError,
	TimeoutError,
	connect as coreConnect,
	type CoreSocket,
	type FramedReader,
	type FramedWriter
} from '../core';
import { parseCreds, signNonce } from './nkey';

export * from './nkey';

const DEFAULT_NATS_PORT = 4222;
const DEFAULT_REQUEST_TIMEOUT_MS = 2000;
const PROTO = 'nats';

const encoder = new TextEncoder();
const CRLF = encoder.encode('\r\n');

/** The subset of the server `INFO` JSON this client reads. */
interface ServerInfo {
	/** Whether the server requires the client to upgrade to TLS before `CONNECT`. */
	tls_required?: boolean;
	/** A nonce the client must sign when authenticating with an nkey. */
	nonce?: string;
	/** The largest payload the server accepts, in bytes. */
	max_payload?: number;
}

/**
 * Options for {@link connect}.
 *
 * @since 1.0.0
 */
export interface NatsConnectOptions {
	/** Remote NATS host. */
	hostname: string;
	/** Remote port; defaults to 4222. */
	port?: number;
	/**
	 * Transport security:
	 * - `'off'`: plaintext.
	 * - `'implicit'`: TLS from the first byte.
	 * - `'starttls'`: plaintext, upgraded to TLS right after the server `INFO`.
	 *
	 * Defaults to `'starttls'` when the server advertises `tls_required`, otherwise `'off'`.
	 */
	tls?: 'off' | 'implicit' | 'starttls';
	/** Bearer token auth (`auth_token`). */
	token?: string;
	/** Username for user/password auth. */
	username?: string;
	/** Password for user/password auth. */
	password?: string;
	/** Base32 seed string (`S...`) for nkey auth; signs the server nonce. */
	nkeySeed?: string;
	/** Full contents of a NATS `.creds` file (user JWT + nkey seed) for JWT auth. */
	creds?: string;
	/** User JWT for JWT auth (pair with {@link nkeySeed}); ignored if {@link creds} is set. */
	jwt?: string;
	/** Client name advertised in `CONNECT`; defaults to `edgeport`. */
	name?: string;
	/** Read deadline in milliseconds for the connect handshake. */
	timeoutMs?: number;
}

/**
 * A message delivered to a {@link NatsSubscription} or returned by a request.
 *
 * @since 1.0.0
 */
export interface NatsMessage {
	/** The subject the message was published to. */
	subject: string;
	/** The subscription id that received it. */
	sid: string;
	/** The reply subject, when the publisher set one (request-reply). */
	reply?: string;
	/** The raw payload bytes. */
	data: Uint8Array;
}

/**
 * An active subscription that yields {@link NatsMessage}s as they arrive.
 *
 * Iterate it with `for await`; the loop ends when {@link unsubscribe} is called or the connection
 * closes. It is an `AsyncDisposable`, so `await using` unsubscribes automatically.
 *
 * @since 1.0.0
 */
export interface NatsSubscription extends AsyncIterable<NatsMessage>, AsyncDisposable {
	/** The subject this subscription matches. */
	readonly subject: string;
	/**
	 * Stops the subscription (`UNSUB`) and ends the iterator.
	 *
	 * @returns Resolves once the `UNSUB` is written.
	 */
	unsubscribe(): Promise<void>;
}

/**
 * A live NATS connection over a single socket.
 *
 * Obtain one from {@link connect}. A background pump reads the socket and routes messages, so
 * publishing, subscribing, and requesting can all be in flight at once. It is an
 * `AsyncDisposable`, so `await using` closes it cleanly.
 *
 * @since 1.0.0
 */
export interface NatsConnection extends AsyncDisposable {
	/**
	 * Publishes a message to a subject.
	 *
	 * @param subject - The subject to publish to.
	 * @param data - The payload (string is UTF-8 encoded); empty if omitted.
	 * @param opts - Optional reply subject for request-reply.
	 * @returns Resolves once the `PUB` frame is written.
	 * @throws {ConnectionError} If the connection is closed.
	 */
	publish(subject: string, data?: Uint8Array | string, opts?: { reply?: string }): Promise<void>;
	/**
	 * Subscribes to a subject, optionally as part of a queue group.
	 *
	 * @param subject - The subject (may contain `*` / `>` wildcards).
	 * @param opts - Optional queue group name for load-balanced delivery.
	 * @returns A subscription whose async iterator yields matching messages.
	 */
	subscribe(subject: string, opts?: { queue?: string }): NatsSubscription;
	/**
	 * Sends a request and waits for the first reply on a private inbox.
	 *
	 * @param subject - The subject to send the request to.
	 * @param data - The request payload (string is UTF-8 encoded).
	 * @param opts - Optional per-request timeout (defaults to 2000ms).
	 * @returns The first reply message.
	 * @throws {TimeoutError} If no reply arrives before the deadline.
	 * @throws {ConnectionError} If the connection is closed.
	 */
	request(
		subject: string,
		data?: Uint8Array | string,
		opts?: { timeoutMs?: number }
	): Promise<NatsMessage>;
	/**
	 * Closes the connection and ends every subscription.
	 *
	 * @returns Resolves once the socket is closed.
	 */
	close(): Promise<void>;
}

// a single-consumer push/pull queue backing one subscription's async iterator
class MessageQueue {
	#queue: NatsMessage[] = [];
	#waiters: ((r: IteratorResult<NatsMessage>) => void)[] = [];
	#done = false;

	push(msg: NatsMessage): void {
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

	next(): Promise<IteratorResult<NatsMessage>> {
		const msg = this.#queue.shift();
		if (msg) return Promise.resolve({ value: msg, done: false });
		if (this.#done) return Promise.resolve({ value: undefined, done: true });
		return new Promise((resolve) => this.#waiters.push(resolve));
	}
}

class Subscription implements NatsSubscription {
	readonly subject: string;
	readonly #queue = new MessageQueue();
	readonly #onUnsub: (sid: string) => Promise<void>;
	readonly sid: string;

	constructor(sid: string, subject: string, onUnsub: (sid: string) => Promise<void>) {
		this.sid = sid;
		this.subject = subject;
		this.#onUnsub = onUnsub;
	}

	deliver(msg: NatsMessage): void {
		this.#queue.push(msg);
	}

	// pump-side close: ends the iterator without writing UNSUB (socket is gone)
	stop(): void {
		this.#queue.end();
	}

	async unsubscribe(): Promise<void> {
		this.#queue.end();
		await this.#onUnsub(this.sid);
	}

	[Symbol.asyncIterator](): AsyncIterator<NatsMessage> {
		return { next: () => this.#queue.next() };
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.unsubscribe();
	}
}

class NatsConnectionImpl implements NatsConnection {
	#socket: CoreSocket;
	#reader: FramedReader;
	#writer: FramedWriter;
	readonly #info: ServerInfo;
	readonly #subs = new Map<string, Subscription>();
	#sidCounter = 0;
	#closed = false;
	// in-flight PING waiters; the pump resolves one per PONG, or rejects all on error
	#pongWaiters: { resolve: () => void; reject: (e: Error) => void }[] = [];
	#pumpError: Error | null = null;

	constructor(socket: CoreSocket, info: ServerInfo) {
		this.#socket = socket;
		this.#reader = socket.reader;
		this.#writer = socket.writer;
		this.#info = info;
	}

	// rebinds reader/writer after a startTls upgrade swaps the socket
	rebind(socket: CoreSocket): void {
		this.#socket = socket;
		this.#reader = socket.reader;
		this.#writer = socket.writer;
	}

	// waits for the next PONG (used to round-trip the handshake and surface auth -ERR)
	waitPong(): Promise<void> {
		if (this.#pumpError) return Promise.reject(this.#pumpError);
		return new Promise((resolve, reject) => this.#pongWaiters.push({ resolve, reject }));
	}

	// starts the background read loop; resolves when the socket ends or errors
	startPump(): void {
		void this.#pump();
	}

	async #pump(): Promise<void> {
		try {
			for (;;) {
				const line = await this.#reader.readLine();
				await this.#dispatch(line);
			}
		} catch (err) {
			// ConnectionError on a clean close is expected once we are closing
			if (!this.#closed) this.#pumpError = err as Error;
		} finally {
			// reject any handshake/ping still waiting; the PONG will never arrive
			const pending = this.#pongWaiters;
			this.#pongWaiters = [];
			const reason =
				this.#pumpError ?? new ConnectionError('nats connection closed', { protocol: PROTO });
			for (const w of pending) w.reject(reason);
			this.#endAll();
		}
	}

	async #dispatch(line: string): Promise<void> {
		const sp = line.indexOf(' ');
		const verb = (sp === -1 ? line : line.slice(0, sp)).toUpperCase();
		const rest = sp === -1 ? '' : line.slice(sp + 1);
		switch (verb) {
			case 'MSG':
				await this.#handleMsg(rest);
				return;
			case 'PING':
				await this.#writer.write(encoder.encode('PONG\r\n'));
				return;
			case 'PONG': {
				const waiter = this.#pongWaiters.shift();
				if (waiter) waiter.resolve();
				return;
			}
			case '+OK':
			case 'INFO':
				return; // nothing to do
			case '-ERR': {
				const msg = rest.replace(/^'|'$/g, '');
				const lower = msg.toLowerCase();
				const err =
					lower.includes('authorization') || lower.includes('authentication')
						? new AuthError(`nats -ERR: ${msg}`, { protocol: PROTO })
						: new ProtocolError(`nats -ERR: ${msg}`, { protocol: PROTO });
				// throw so the pump exits; its finally rejects every pending PONG with this
				this.#pumpError = err;
				throw err;
			}
			default:
				throw new ProtocolError(`unexpected nats verb: ${verb}`, { protocol: PROTO });
		}
	}

	// MSG <subject> <sid> [reply-to] <#bytes>\r\n<payload>\r\n
	async #handleMsg(rest: string): Promise<void> {
		const parts = rest.split(/\s+/);
		if (parts.length < 3 || parts.length > 4) {
			throw new ProtocolError(`malformed MSG header: ${rest}`, { protocol: PROTO });
		}
		const subject = parts[0]!;
		const sid = parts[1]!;
		const reply = parts.length === 4 ? parts[2] : undefined;
		const nBytes = Number(parts[parts.length - 1]);
		if (!Number.isInteger(nBytes) || nBytes < 0) {
			throw new ProtocolError(`malformed MSG byte count: ${rest}`, { protocol: PROTO });
		}
		const data = await this.#reader.readN(nBytes);
		await this.#reader.readN(2); // trailing CRLF
		const sub = this.#subs.get(sid);
		if (sub) sub.deliver({ subject, sid, reply, data });
	}

	#endAll(): void {
		for (const sub of this.#subs.values()) sub.stop();
		this.#subs.clear();
	}

	#assertOpen(): void {
		if (this.#closed) throw new ConnectionError('nats connection is closed', { protocol: PROTO });
		if (this.#pumpError) throw this.#pumpError;
	}

	async publish(
		subject: string,
		data?: Uint8Array | string,
		opts?: { reply?: string }
	): Promise<void> {
		this.#assertOpen();
		const payload = typeof data === 'string' ? encoder.encode(data) : (data ?? new Uint8Array(0));
		const head =
			opts?.reply !== undefined
				? `PUB ${subject} ${opts.reply} ${payload.length}\r\n`
				: `PUB ${subject} ${payload.length}\r\n`;
		const frame = new Uint8Array(head.length + payload.length + 2);
		frame.set(encoder.encode(head), 0);
		frame.set(payload, head.length);
		frame.set(CRLF, head.length + payload.length);
		await this.#writer.write(frame);
	}

	subscribe(subject: string, opts?: { queue?: string }): NatsSubscription {
		this.#assertOpen();
		const sid = String(++this.#sidCounter);
		const sub = new Subscription(sid, subject, (s) => this.#sendUnsub(s));
		this.#subs.set(sid, sub);
		const line =
			opts?.queue !== undefined
				? `SUB ${subject} ${opts.queue} ${sid}\r\n`
				: `SUB ${subject} ${sid}\r\n`;
		// fire-and-forget the SUB write; ordering is preserved by the single writer
		void this.#writer.write(encoder.encode(line));
		return sub;
	}

	async #sendUnsub(sid: string): Promise<void> {
		this.#subs.delete(sid);
		if (this.#closed) return;
		await this.#writer.write(encoder.encode(`UNSUB ${sid}\r\n`));
	}

	async request(
		subject: string,
		data?: Uint8Array | string,
		opts?: { timeoutMs?: number }
	): Promise<NatsMessage> {
		this.#assertOpen();
		const timeoutMs = opts?.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
		const inbox = `_INBOX.${randomToken()}`;
		const sub = this.subscribe(inbox) as Subscription;
		try {
			await this.publish(subject, data, { reply: inbox });
			const iter = sub[Symbol.asyncIterator]();
			let timer: ReturnType<typeof setTimeout>;
			const timeout = new Promise<never>((_, reject) => {
				timer = setTimeout(
					() =>
						reject(new TimeoutError(`nats request to ${subject} timed out`, { protocol: PROTO })),
					timeoutMs
				);
			});
			try {
				const result = await Promise.race([iter.next(), timeout]);
				if (result.done) {
					throw new ConnectionError('nats connection closed before reply', { protocol: PROTO });
				}
				return result.value;
			} finally {
				clearTimeout(timer!);
			}
		} finally {
			await sub.unsubscribe().catch(() => {});
		}
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		this.#endAll();
		await this.#socket.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

// 16 random hex chars for a unique reply inbox; crypto, never Math.random
function randomToken(): string {
	const bytes = new Uint8Array(8);
	crypto.getRandomValues(bytes);
	return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// reads INFO, parses its JSON, and decides whether TLS is required
async function readInfo(reader: FramedReader, timeoutMs: number | undefined): Promise<ServerInfo> {
	const line = await reader.readLine(timeoutMs);
	if (!line.toUpperCase().startsWith('INFO ')) {
		throw new ProtocolError(`expected INFO greeting, got: ${line}`, { protocol: PROTO });
	}
	try {
		return JSON.parse(line.slice(5)) as ServerInfo;
	} catch (cause) {
		throw new ProtocolError('could not parse nats INFO json', { protocol: PROTO, cause });
	}
}

// builds the CONNECT json with the right auth fields for the chosen scheme
async function buildConnect(
	opts: NatsConnectOptions,
	info: ServerInfo,
	tlsRequired: boolean
): Promise<string> {
	const connect: Record<string, unknown> = {
		verbose: false,
		pedantic: false,
		tls_required: tlsRequired,
		name: opts.name ?? 'edgeport',
		lang: 'edgeport',
		version: '1.0.0',
		protocol: 1,
		headers: false
	};
	// JWT auth (creds file, or explicit jwt+seed) presents the JWT and signs the nonce
	const jwtAuth = opts.creds
		? parseCreds(opts.creds)
		: opts.jwt && opts.nkeySeed
			? { jwt: opts.jwt, seed: opts.nkeySeed }
			: null;
	if (jwtAuth) {
		if (!info.nonce) throw new AuthError('jwt auth requires a server nonce', { protocol: PROTO });
		const { sig } = await signNonce(jwtAuth.seed, encoder.encode(info.nonce));
		connect.jwt = jwtAuth.jwt;
		connect.sig = sig;
	} else if (opts.token !== undefined) {
		connect.auth_token = opts.token;
	} else if (opts.username !== undefined || opts.password !== undefined) {
		connect.user = opts.username ?? '';
		connect.pass = opts.password ?? '';
	} else if (opts.nkeySeed !== undefined) {
		if (!info.nonce) {
			throw new AuthError('nkey auth requires a server nonce', { protocol: PROTO });
		}
		const { nkey, sig } = await signNonce(opts.nkeySeed, encoder.encode(info.nonce));
		connect.nkey = nkey;
		connect.sig = sig;
	}
	return JSON.stringify(connect);
}

/**
 * Connects to a NATS server, authenticates, and returns a live connection.
 *
 * Dials the core transport (implicit TLS when `tls: 'implicit'`, otherwise plaintext that may be
 * upgraded), reads the server `INFO`, performs a `STARTTLS`-style upgrade when requested or
 * required, sends `CONNECT` + `PING`, and waits for `PONG` so an auth failure surfaces here as
 * {@link AuthError}. A background pump then routes incoming messages to subscriptions.
 *
 * @param opts - Connection and credential options.
 * @returns The live connection.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @throws {TimeoutError} If the handshake exceeds the deadline.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { connect } from 'edgeport/nats';
 *
 * await using nc = await connect({ hostname: 'nats.example.com', token: 'secret' });
 * await using sub = nc.subscribe('updates.>');
 * await nc.publish('updates.temp', '21.5');
 * for await (const msg of sub) {
 * 	console.log(msg.subject, new TextDecoder().decode(msg.data));
 * 	break;
 * }
 * ```
 */
export async function connect(opts: NatsConnectOptions): Promise<NatsConnection> {
	const port = opts.port ?? DEFAULT_NATS_PORT;
	const implicit = opts.tls === 'implicit';
	const socket = await coreConnect({
		hostname: opts.hostname,
		port,
		tls: implicit ? 'on' : 'starttls',
		connectTimeoutMs: opts.timeoutMs
	});
	try {
		return await _connectOverSocket(socket, opts);
	} catch (err) {
		await socket.close().catch(() => {});
		throw err;
	}
}

/**
 * Runs the NATS handshake and read pump over an already-connected {@link CoreSocket}.
 *
 * Reads `INFO`, upgrades to TLS when `tls: 'starttls'` is requested or the server requires it,
 * sends `CONNECT` + `PING`, and waits for the `PONG`. Public {@link connect} dials the transport
 * then calls this; tests call it directly with a mock socket.
 *
 * @param socket - A connected core socket (already TLS when `tls: 'implicit'`).
 * @param opts - Connection and credential options.
 * @returns The live connection.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @throws {TimeoutError} If the handshake exceeds the deadline.
 * @internal
 */
export async function _connectOverSocket(
	socket: CoreSocket,
	opts: NatsConnectOptions
): Promise<NatsConnection> {
	const info = await readInfo(socket.reader, opts.timeoutMs);

	// upgrade to TLS when asked or when the server demands it (handshake happens before CONNECT)
	const upgrade = opts.tls === 'starttls' || (opts.tls === undefined && info.tls_required === true);
	if (upgrade && opts.tls !== 'implicit') {
		socket = socket.startTls({ expectedServerHostname: opts.hostname });
	}
	const tlsRequired = upgrade || opts.tls === 'implicit' || info.tls_required === true;

	const conn = new NatsConnectionImpl(socket, info);
	if (upgrade && opts.tls !== 'implicit') conn.rebind(socket);

	const connectJson = await buildConnect(opts, info, tlsRequired);
	await socket.writer.write(encoder.encode(`CONNECT ${connectJson}\r\n`));
	await socket.writer.write(encoder.encode('PING\r\n'));

	// start the pump, then wait for the PONG it will route; a -ERR rejects the wait
	conn.startPump();
	await conn.waitPong();

	return conn;
}
