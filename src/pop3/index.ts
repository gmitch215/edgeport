/**
 * @fileoverview A read-oriented POP3 client (RFC 1939, STLS per RFC 2595) for the Cloudflare
 * Workers runtime.
 *
 * This module speaks the `+OK` / `-ERR` line dialogue of POP3 over the shared core transport.
 * It covers the read path a Worker needs: authenticate, count and list messages, retrieve raw
 * message bytes, and mark messages deleted. It supports implicit TLS (port 995) and the STLS
 * upgrade (port 110), and undoes the dot-stuffing servers apply to multiline payloads.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import {
	AuthError,
	ProtocolError,
	connect as coreConnect,
	type CoreSocket,
	type FramedReader,
	type FramedWriter
} from '../core';

const DEFAULT_POP3_PORT = 995;
const PROTO = 'pop3';
const encoder = new TextEncoder();

/** Options for {@link connect} and {@link retrieveAll}. */
export interface Pop3ConnectOptions {
	/** Remote POP3 host. */
	hostname: string;
	/** Remote port; defaults to 995 (implicit TLS). */
	port?: number;
	/**
	 * Transport security:
	 * - `'implicit'` (default): TLS from the first byte (POP3S, port 995).
	 * - `'starttls'`: plaintext, upgraded with the `STLS` command (port 110).
	 * - `'off'`: plaintext with no upgrade (trusted internal / dev servers).
	 */
	tls?: 'implicit' | 'starttls' | 'off';
	/** Login credentials sent via the `USER`/`PASS` commands. */
	auth: { username: string; password: string };
	/** Per-operation read deadline in milliseconds. */
	timeoutMs?: number;
}

/**
 * An authenticated POP3 session over a single connection.
 *
 * Obtain one from {@link connect}. It is an `AsyncDisposable`, so it can be scoped with
 * `await using` to guarantee a clean `QUIT` and socket close. Methods issue one command at a
 * time and must not be called concurrently on the same session.
 *
 * @since 1.0.0
 */
export interface Pop3Session extends AsyncDisposable {
	/**
	 * Reports the message count and total mailbox size via `STAT`.
	 *
	 * @returns The number of messages and their combined octet size.
	 * @throws {ProtocolError} If the server rejects the command.
	 */
	stat(): Promise<{ count: number; size: number }>;
	/**
	 * Lists each message's id and size via the multiline `LIST`.
	 *
	 * @returns One entry per message.
	 * @throws {ProtocolError} If the server rejects the command.
	 */
	list(): Promise<{ id: number; size: number }[]>;
	/**
	 * Retrieves a message's raw bytes via `RETR`, undoing dot-stuffing.
	 *
	 * @param id - The message number to retrieve.
	 * @returns The raw RFC 822 message bytes.
	 * @throws {ProtocolError} If the server rejects the command.
	 */
	retrieve(id: number): Promise<Uint8Array>;
	/**
	 * Retrieves a message and returns it as UTF-8 text, so callers do not build a `TextDecoder`.
	 * Equivalent to decoding {@link retrieve} but without materializing the intermediate bytes.
	 *
	 * @param id - The message number to retrieve.
	 * @returns The message as text.
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.4
	 */
	retrieveText(id: number): Promise<string>;
	/**
	 * Marks a message for deletion via `DELE` (applied on `QUIT`).
	 *
	 * @param id - The message number to delete.
	 * @throws {ProtocolError} If the server rejects the command.
	 */
	delete(id: number): Promise<void>;
	/**
	 * Sends `QUIT` and closes the connection.
	 *
	 * @returns Resolves once the socket is closed.
	 */
	close(): Promise<void>;
}

/**
 * Connects to a POP3 server and authenticates, returning a ready session.
 *
 * Opens the transport (implicit TLS or STLS), runs `USER`/`PASS`, and hands back a
 * {@link Pop3Session}. A rejected `PASS` surfaces as {@link AuthError}; any other command-level
 * failure surfaces as {@link ProtocolError}.
 *
 * @param opts - Connection and credential options.
 * @returns The authenticated session.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { connect } from 'edgeport/pop3';
 *
 * await using session = await connect({
 * 	hostname: 'pop.example.com',
 * 	auth: { username: 'me', password: 'secret' }
 * });
 * const { count } = await session.stat();
 * if (count > 0) {
 * 	const first = await session.retrieve(1);
 * }
 * ```
 */
export async function connect(opts: Pop3ConnectOptions): Promise<Pop3Session> {
	const port = opts.port ?? DEFAULT_POP3_PORT;
	const coreTls = opts.tls === 'starttls' ? 'starttls' : opts.tls === 'off' ? 'off' : 'on';
	const socket = await coreConnect({
		hostname: opts.hostname,
		port,
		tls: coreTls,
		connectTimeoutMs: opts.timeoutMs
	});
	try {
		return await _pop3SessionFromSocket(socket, opts);
	} catch (err) {
		await socket.close().catch(() => {});
		throw err;
	}
}

/**
 * Connects, retrieves every message in the mailbox, then quits.
 *
 * A one-shot convenience over {@link connect}: it reads the `STAT` count, retrieves each
 * message in order, and closes the connection before returning. Messages are left on the
 * server (no `DELE`).
 *
 * @param opts - Connection and credential options.
 * @returns The raw bytes of every message, in mailbox order.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { retrieveAll } from 'edgeport/pop3';
 *
 * const messages = await retrieveAll({
 * 	hostname: 'pop.example.com',
 * 	auth: { username: 'me', password: 'secret' }
 * });
 * ```
 */
export async function retrieveAll(opts: Pop3ConnectOptions): Promise<Uint8Array[]> {
	await using session = await connect(opts);
	const { count } = await session.stat();
	const out: Uint8Array[] = [];
	for (let id = 1; id <= count; id++) {
		out.push(await session.retrieve(id));
	}
	return out;
}

/**
 * Builds a {@link Pop3Session} over an already-connected {@link CoreSocket}.
 *
 * Reads the server greeting, performs the STLS upgrade if requested, and runs `USER`/`PASS`.
 * Public {@link connect} dials the core transport and then calls this; tests call it directly
 * with a mock socket.
 *
 * @param socket - A connected core socket.
 * @param opts - Connection and credential options.
 * @returns The authenticated session.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @internal
 */
export async function _pop3SessionFromSocket(
	socket: CoreSocket,
	opts: Pop3ConnectOptions
): Promise<Pop3Session> {
	const client = new Pop3Client(socket, opts.timeoutMs);

	// greeting (+OK ...)
	await client.readStatus();

	if (opts.tls === 'starttls') {
		await client.command('STLS');
		socket = socket.startTls({ expectedServerHostname: opts.hostname });
		client.rebind(socket.reader, socket.writer);
	}

	try {
		await client.command(`USER ${opts.auth.username}`);
		await client.command(`PASS ${opts.auth.password}`);
	} catch (err) {
		if (err instanceof ProtocolError) {
			throw new AuthError('pop3 authentication rejected', { protocol: PROTO, cause: err });
		}
		throw err;
	}

	return new Pop3SessionImpl(client, socket);
}

// drives the +OK/-ERR command loop and multiline (dot-terminated) reads
class Pop3Client {
	#reader: FramedReader;
	#writer: FramedWriter;
	readonly #timeoutMs: number | undefined;

	constructor(socket: CoreSocket, timeoutMs: number | undefined) {
		this.#reader = socket.reader;
		this.#writer = socket.writer;
		this.#timeoutMs = timeoutMs;
	}

	rebind(reader: FramedReader, writer: FramedWriter): void {
		this.#reader = reader;
		this.#writer = writer;
	}

	// reads a single status line; throws ProtocolError on -ERR so callers can map it
	async readStatus(): Promise<string> {
		const line = await this.#reader.readLine(this.#timeoutMs);
		if (line.startsWith('+OK')) return line.slice(3).trim();
		if (line.startsWith('-ERR')) {
			throw new ProtocolError(`pop3 -ERR: ${line.slice(4).trim()}`, { protocol: PROTO });
		}
		throw new ProtocolError(`unexpected pop3 response: ${line}`, { protocol: PROTO });
	}

	// sends a command and reads its single status line
	async command(line: string): Promise<string> {
		await this.#writer.writeLine(line);
		return this.readStatus();
	}

	// reads a multiline payload terminated by a line containing only '.', undoing dot-stuffing
	async readMultiline(): Promise<string> {
		const lines: string[] = [];
		for (;;) {
			const line = await this.#reader.readLine(this.#timeoutMs);
			if (line === '.') break;
			// dot-stuffing: a leading '.' on a data line is doubled by the server
			lines.push(line.startsWith('.') ? line.slice(1) : line);
		}
		return lines.join('\r\n');
	}
}

/** {@link Pop3Session} backed by a {@link Pop3Client}. */
class Pop3SessionImpl implements Pop3Session {
	readonly #client: Pop3Client;
	readonly #socket: CoreSocket;

	constructor(client: Pop3Client, socket: CoreSocket) {
		this.#client = client;
		this.#socket = socket;
	}

	async stat(): Promise<{ count: number; size: number }> {
		const status = await this.#client.command('STAT');
		const parts = status.trim().split(/\s+/);
		const count = Number(parts[0] ?? 0);
		const size = Number(parts[1] ?? 0);
		return { count, size };
	}

	async list(): Promise<{ id: number; size: number }[]> {
		await this.#client.command('LIST');
		const body = await this.#client.readMultiline();
		const out: { id: number; size: number }[] = [];
		for (const line of body.split('\r\n')) {
			if (line === '') continue;
			const parts = line.trim().split(/\s+/);
			if (parts.length < 2) continue;
			out.push({ id: Number(parts[0]), size: Number(parts[1]) });
		}
		return out;
	}

	async retrieve(id: number): Promise<Uint8Array> {
		return encoder.encode(await this.#retrieveRaw(id));
	}

	async retrieveText(id: number): Promise<string> {
		return this.#retrieveRaw(id);
	}

	// RETR the message and return the server's text as-is (retrieve encodes it; retrieveText does not)
	async #retrieveRaw(id: number): Promise<string> {
		await this.#client.command(`RETR ${id}`);
		return this.#client.readMultiline();
	}

	async delete(id: number): Promise<void> {
		await this.#client.command(`DELE ${id}`);
	}

	async close(): Promise<void> {
		try {
			await this.#client.command('QUIT');
		} catch {
			// best-effort quit; the socket close below is what matters
		}
		await this.#socket.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}
