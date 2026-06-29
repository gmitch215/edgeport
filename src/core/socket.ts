/**
 * @fileoverview The private core transport: the only module in edgeport that imports
 * `cloudflare:sockets`.
 *
 * Every protocol is built on {@link connect}, {@link CoreSocket}, and the framing layer,
 * and none of them touch the runtime socket API directly. Keeping this the single
 * chokepoint is the central maintainability invariant of the library: the surface that
 * depends on the Workers runtime is one small file.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { connect as cfConnect } from 'cloudflare:sockets';
import { ConnectionError, TimeoutError } from './errors';
import {
	StreamFramedReader,
	StreamFramedWriter,
	type FramedReader,
	type FramedWriter
} from './framing';

const DEFAULT_CONNECT_TIMEOUT_MS = 15_000;

/** Options for {@link connect}. */
export interface ConnectOptions {
	/** Remote host to dial. */
	hostname: string;
	/** Remote TCP port. */
	port: number;
	/**
	 * Transport security mode:
	 * - `'off'` (default): plaintext.
	 * - `'on'`: TLS from the first byte (implicit TLS, e.g. SMTPS/IMAPS/POP3S).
	 * - `'starttls'`: plaintext that can later be upgraded via {@link CoreSocket.startTls}.
	 */
	tls?: 'off' | 'on' | 'starttls';
	/** Keep the writable side open after the peer half-closes. */
	allowHalfOpen?: boolean;
	/** Connect deadline in milliseconds (default 15000); rejects with {@link TimeoutError}. */
	connectTimeoutMs?: number;
}

/** Options for {@link CoreSocket.startTls}. */
export interface TlsUpgradeOptions {
	/** Hostname to validate the server certificate against. */
	expectedServerHostname?: string;
}

/**
 * A connected transport with buffered framed I/O.
 *
 * Obtain one from {@link connect}. It is an `AsyncDisposable`, so it can be scoped with
 * `await using`.
 *
 * @since 1.0.0
 */
export interface CoreSocket extends AsyncDisposable {
	/** Buffered reader over the socket's readable side. */
	readonly reader: FramedReader;
	/** Line-capable writer over the socket's writable side. */
	readonly writer: FramedWriter;
	/**
	 * Upgrades a `'starttls'` connection to TLS.
	 *
	 * Returns a brand-new {@link CoreSocket}; the original is dead afterwards and its
	 * reader/writer must not be used. Re-acquire them from the returned socket. Only valid
	 * when this socket was opened with `tls: 'starttls'`.
	 *
	 * @param opts - TLS options such as the expected server hostname.
	 * @returns The upgraded socket.
	 */
	startTls(opts?: TlsUpgradeOptions): CoreSocket;
	/** Resolves when the socket is fully closed. */
	readonly closed: Promise<void>;
	/** Closes the socket. */
	close(): Promise<void>;
}

// the structural shape of a cloudflare:sockets Socket we rely on (typed loosely because
// the runtime types expose readable/writable as `unknown`)
interface RuntimeSocket {
	readable: ReadableStream<Uint8Array>;
	writable: WritableStream<Uint8Array>;
	opened: Promise<unknown>;
	closed: Promise<void>;
	close(): Promise<void>;
	startTls(options: TlsUpgradeOptions): RuntimeSocket;
}

class CoreSocketImpl implements CoreSocket {
	readonly reader: StreamFramedReader;
	readonly writer: StreamFramedWriter;
	readonly #socket: RuntimeSocket;
	readonly #starttls: boolean;

	constructor(socket: RuntimeSocket, starttls: boolean) {
		this.#socket = socket;
		this.#starttls = starttls;
		this.reader = new StreamFramedReader(socket.readable);
		this.writer = new StreamFramedWriter(socket.writable);
	}

	get closed(): Promise<void> {
		return this.#socket.closed;
	}

	startTls(opts: TlsUpgradeOptions = {}): CoreSocket {
		if (!this.#starttls) {
			throw new ConnectionError("startTls requires the socket to be opened with tls: 'starttls'");
		}
		// the old socket is closed by startTls; drop our stream locks before upgrading
		this.reader.release();
		this.writer.release();
		const upgraded = this.#socket.startTls(opts);
		// the upgraded socket is already TLS; it cannot be upgraded again
		return new CoreSocketImpl(upgraded, false);
	}

	async close(): Promise<void> {
		try {
			await this.#socket.close();
		} catch {
			// already closed by the peer or a prior call
		}
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

/**
 * Opens a TCP connection (optionally TLS) and returns a buffered {@link CoreSocket}.
 *
 * Resolves once the underlying socket reports it is open, or rejects with
 * {@link TimeoutError} if the connect deadline elapses and {@link ConnectionError} for any
 * other failure.
 *
 * @param opts - Connection options.
 * @returns The connected socket.
 * @throws {TimeoutError} If the connect deadline elapses.
 * @throws {ConnectionError} If the connection cannot be established.
 * @since 1.0.0
 */
export async function connect(opts: ConnectOptions): Promise<CoreSocket> {
	const secureTransport = opts.tls ?? 'off';
	let socket: RuntimeSocket;
	try {
		socket = cfConnect(
			{ hostname: opts.hostname, port: opts.port },
			{ secureTransport, allowHalfOpen: opts.allowHalfOpen ?? false }
		) as unknown as RuntimeSocket;
	} catch (cause) {
		throw new ConnectionError(`failed to connect to ${opts.hostname}:${opts.port}`, { cause });
	}

	const timeoutMs = opts.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		const deadline = new Promise<never>((_, reject) => {
			timer = setTimeout(
				() => reject(new TimeoutError(`connect to ${opts.hostname}:${opts.port} timed out`)),
				timeoutMs
			);
		});
		await Promise.race([socket.opened, deadline]);
	} catch (err) {
		await socket.close().catch(() => {});
		if (err instanceof TimeoutError) throw err;
		throw new ConnectionError(`failed to open ${opts.hostname}:${opts.port}`, { cause: err });
	} finally {
		clearTimeout(timer);
	}

	return new CoreSocketImpl(socket, secureTransport === 'starttls');
}
