/**
 * @fileoverview A WebSocket client for the Cloudflare Workers runtime.
 *
 * Unlike the other edgeport protocols, the WebSocket client does NOT touch
 * `cloudflare:sockets`; it rides the platform WebSocket API instead. The outbound client
 * handshake is performed with a `fetch` upgrade, and the runtime owns the wss TLS,
 * RFC 6455 framing, and client masking. Messages are consumed with `for await`.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { ConnectionError, ProtocolError } from '../core';

/** Options for {@link connect}. */
export interface WsConnectOptions {
	/** Subprotocols to offer; sent as the `Sec-WebSocket-Protocol` header. */
	protocols?: string[];
	/** Extra request headers merged into the upgrade `fetch`. */
	headers?: Record<string, string>;
}

/**
 * A single inbound WebSocket message.
 *
 * Text frames arrive as `{ type: 'text' }` with a string payload; binary frames arrive as
 * `{ type: 'binary' }` with a {@link Uint8Array} payload. Branch on `type` before reading
 * `data`.
 *
 * @since 1.0.0
 */
export type WsMessage =
	| {
			type: 'text';
			data: string;
			/**
			 * Parses the text payload as JSON.
			 *
			 * @typeParam T - The expected shape of the decoded value.
			 * @returns The parsed value.
			 * @throws {ProtocolError} If the text is not valid JSON.
			 * @since 1.0.2
			 */
			json<T = unknown>(): T;
	  }
	| { type: 'binary'; data: Uint8Array };

/**
 * A live WebSocket connection.
 *
 * Async-iterate it to receive messages in arrival order; the iteration ends when the peer
 * closes the socket. It is an `AsyncDisposable`, so `await using` closes it on scope exit.
 *
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { connect } from 'edgeport/ws';
 *
 * await using ws = await connect('wss://echo.example.com');
 * ws.send('hello');
 * for await (const msg of ws) {
 * 	if (msg.type === 'text') console.log('text:', msg.data);
 * 	else console.log('binary bytes:', msg.data.length);
 * 	break;
 * }
 * ```
 */
export interface WsConnection extends AsyncDisposable, AsyncIterable<WsMessage> {
	/**
	 * Sends a message to the peer.
	 *
	 * @param data - A string for a text frame, or bytes for a binary frame.
	 */
	send(data: string | Uint8Array): void;
	/**
	 * Serializes a value to JSON and sends it as a text frame.
	 *
	 * The value is `JSON.stringify`-ed and sent with {@link send}.
	 *
	 * @param value - The value to serialize and send.
	 * @since 1.0.2
	 */
	sendJson(value: unknown): void;
	/**
	 * Closes the connection.
	 *
	 * @param code - Optional RFC 6455 close code (e.g. `1000`).
	 * @param reason - Optional human-readable close reason.
	 */
	close(code?: number, reason?: string): void;
	/** Resolves with the close code and reason once the peer's close frame arrives. */
	readonly closed: Promise<{ code: number; reason: string }>;
}

/**
 * The minimal slice of the platform WebSocket API this module depends on.
 *
 * Declared narrowly so unit tests can supply a fake without a real socket. `accept` is
 * optional because only Cloudflare's `resp.webSocket` requires it.
 *
 * @internal
 */
export interface MinimalWebSocket {
	/** Accepts a Cloudflare server-side socket so events begin to flow. */
	accept?(): void;
	/** Sends a frame to the peer. */
	send(data: string | ArrayBuffer | Uint8Array): void;
	/** Begins the closing handshake. */
	close(code?: number, reason?: string): void;
	/** Registers a listener for `'message'`, `'close'`, or `'error'`. */
	addEventListener(type: string, listener: (event: any) => void): void;
}

// parses a text frame as JSON; a parse failure is a ProtocolError, never a raw SyntaxError
function decodeTextJson<T>(text: string): T {
	try {
		return JSON.parse(text) as T;
	} catch (cause) {
		throw new ProtocolError('websocket text message is not valid json', { protocol: 'ws', cause });
	}
}

// normalizes a 'message' event payload into a WsMessage
function toWsMessage(data: unknown): WsMessage {
	if (typeof data === 'string') {
		return { type: 'text', data, json: <T = unknown>(): T => decodeTextJson<T>(data) };
	}
	if (data instanceof Uint8Array) return { type: 'binary', data };
	if (data instanceof ArrayBuffer) return { type: 'binary', data: new Uint8Array(data) };
	if (ArrayBuffer.isView(data)) {
		const view = data as ArrayBufferView;
		return {
			type: 'binary',
			data: new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
		};
	}
	throw new ProtocolError('received a websocket message of an unsupported type', {
		protocol: 'ws'
	});
}

// a reader parked in next(), carrying both halves of its promise
interface Waiter {
	resolve(result: IteratorResult<WsMessage>): void;
	reject(err: unknown): void;
}

class WsConnectionImpl implements WsConnection {
	readonly #ws: MinimalWebSocket;

	// push/pull queue: buffered messages waiting for a reader, and readers waiting for a message
	readonly #buffer: WsMessage[] = [];
	readonly #waiters: Waiter[] = [];

	#done = false;
	// set when 'error' fires before any reader is parked; surfaced to the next next() call
	#error: ProtocolError | undefined;

	readonly closed: Promise<{ code: number; reason: string }>;
	#resolveClosed!: (value: { code: number; reason: string }) => void;

	constructor(ws: MinimalWebSocket) {
		this.#ws = ws;
		this.closed = new Promise((resolve) => {
			this.#resolveClosed = resolve;
		});

		ws.addEventListener('message', (event: { data: unknown }) => {
			if (this.#done) return;
			this.#push(toWsMessage(event.data));
		});

		ws.addEventListener('close', (event: { code?: number; reason?: string }) => {
			this.#finish();
			this.#resolveClosed({ code: event.code ?? 1005, reason: event.reason ?? '' });
		});

		ws.addEventListener('error', (event: { message?: string; error?: unknown }) => {
			if (this.#done) return;
			const err = new ProtocolError(event?.message ?? 'websocket error', {
				protocol: 'ws',
				cause: event?.error
			});
			const waiter = this.#waiters.shift();
			// reject a parked reader now, else stash it for the next next()
			if (waiter) waiter.reject(err);
			else this.#error = err;
		});
	}

	#push(msg: WsMessage): void {
		const waiter = this.#waiters.shift();
		if (waiter) waiter.resolve({ done: false, value: msg });
		else this.#buffer.push(msg);
	}

	// marks the stream done and flushes every parked reader with done:true
	#finish(): void {
		if (this.#done) return;
		this.#done = true;
		let waiter: Waiter | undefined;
		while ((waiter = this.#waiters.shift())) {
			waiter.resolve({ done: true, value: undefined });
		}
	}

	send(data: string | Uint8Array): void {
		this.#ws.send(data);
	}

	sendJson(value: unknown): void {
		this.#ws.send(JSON.stringify(value));
	}

	close(code?: number, reason?: string): void {
		this.#ws.close(code, reason);
	}

	[Symbol.asyncIterator](): AsyncIterator<WsMessage> {
		const next = (): Promise<IteratorResult<WsMessage>> => {
			const buffered = this.#buffer.shift();
			if (buffered) return Promise.resolve({ done: false, value: buffered });

			if (this.#error) {
				const err = this.#error;
				this.#error = undefined;
				return Promise.reject(err);
			}
			if (this.#done) return Promise.resolve({ done: true, value: undefined });

			return new Promise<IteratorResult<WsMessage>>((resolve, reject) => {
				// park both halves so 'message'/'close' resolve and 'error' rejects this reader
				this.#waiters.push({ resolve, reject });
			});
		};

		return {
			next,
			return: (): Promise<IteratorResult<WsMessage>> => {
				this.close();
				this.#finish();
				return Promise.resolve({ done: true, value: undefined });
			}
		};
	}

	async [Symbol.asyncDispose](): Promise<void> {
		this.close();
	}
}

/**
 * Wraps an already-open WebSocket-like object in a {@link WsConnection}.
 *
 * The public {@link connect} performs the `fetch` upgrade and then defers to this. It is
 * exposed so unit tests can inject a fake socket without any real network, and so callers
 * who already hold a `WebSocket` (for example a Durable Object's accepted client) can reuse
 * the same iteration semantics. The socket is `accept()`-ed if it exposes that method.
 *
 * @param ws - A WebSocket-like object implementing {@link MinimalWebSocket}.
 * @returns A {@link WsConnection} over the given socket.
 * @since 1.0.0
 * @internal
 *
 * @example
 * ```typescript
 * import { _wrap } from 'edgeport/ws';
 *
 * const conn = _wrap(someAcceptedWebSocket);
 * for await (const msg of conn) {
 * 	if (msg.type === 'text') console.log(msg.data);
 * }
 * ```
 */
export function _wrap(ws: MinimalWebSocket): WsConnection {
	ws.accept?.();
	return new WsConnectionImpl(ws);
}

// the slice of a fetch Response we read; the runtime exposes resp.webSocket on a 101
interface UpgradeResponse {
	webSocket?: MinimalWebSocket | null;
}

/**
 * Opens a WebSocket connection from a Cloudflare Worker.
 *
 * Performs the outbound client handshake with a `fetch` upgrade (the runtime handles the
 * wss TLS, RFC 6455 framing, and client masking), accepts the returned socket, then yields
 * a {@link WsConnection} you async-iterate for inbound messages. Offered subprotocols are
 * sent as a comma-joined `Sec-WebSocket-Protocol` header; any `opts.headers` are merged in.
 *
 * @param url - The `ws://` or `wss://` endpoint to dial.
 * @param opts - Optional subprotocols and extra request headers.
 * @returns The connected {@link WsConnection}.
 * @throws {ConnectionError} If the server does not complete the upgrade or `fetch` fails.
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { connect } from 'edgeport/ws';
 *
 * const ws = await connect('wss://echo.example.com', { protocols: ['chat'] });
 * ws.send('ping');
 * for await (const msg of ws) {
 * 	if (msg.type === 'text') console.log('reply:', msg.data);
 * 	break;
 * }
 * ws.close(1000, 'done');
 * const { code } = await ws.closed;
 * console.log('closed with', code);
 * ```
 */
export async function connect(url: string, opts: WsConnectOptions = {}): Promise<WsConnection> {
	const headers: Record<string, string> = { Upgrade: 'websocket', ...opts.headers };
	if (opts.protocols && opts.protocols.length > 0) {
		headers['Sec-WebSocket-Protocol'] = opts.protocols.join(', ');
	}

	// the runtime's fetch upgrade speaks http(s); map the ws(s) scheme onto it
	const fetchUrl = url.replace(/^ws:/i, 'http:').replace(/^wss:/i, 'https:');

	let resp: UpgradeResponse;
	try {
		resp = (await fetch(fetchUrl, { headers })) as unknown as UpgradeResponse;
	} catch (cause) {
		throw new ConnectionError(`failed to open websocket to ${url}`, { protocol: 'ws', cause });
	}

	const ws = resp.webSocket;
	if (!ws) {
		throw new ConnectionError('server did not accept the websocket upgrade', { protocol: 'ws' });
	}

	return _wrap(ws);
}
