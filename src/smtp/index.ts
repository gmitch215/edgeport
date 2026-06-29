/**
 * @fileoverview SMTP submission client (RFC 5321 + STARTTLS RFC 3207 + AUTH RFC 4954).
 *
 * A small, dependency-free SMTP sender for the Cloudflare Workers runtime. It speaks the
 * submission flow end to end: greeting, `EHLO` capability negotiation, optional STARTTLS
 * upgrade or implicit TLS, `AUTH PLAIN`/`AUTH LOGIN`, and the `MAIL FROM` / `RCPT TO` /
 * `DATA` envelope with dot-stuffing. Messages are assembled by the MIME builder in
 * `./mime`, so the API stays close to a nodemailer-style `send`.
 *
 * The transport is the shared core ({@link import('../core').connect}); this module never
 * touches `cloudflare:sockets` directly. {@link connect} returns a reusable
 * {@link SmtpSession}; {@link send} is the one-shot convenience that opens, sends, and
 * quits.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import {
	AuthError,
	connect as coreConnect,
	ProtocolError,
	type CoreSocket,
	type FramedReader,
	type FramedWriter
} from '../core';
import { buildMime } from './mime';

const PROTOCOL = 'smtp';
const DEFAULT_SUBMISSION_PORT = 587;
const IMPLICIT_TLS_PORT = 465;
const DOT_CRLF_DOT = new Uint8Array([0x0d, 0x0a, 0x2e, 0x0d, 0x0a]); // CRLF . CRLF terminator

const encoder = new TextEncoder();

/**
 * Options for opening an SMTP submission session.
 *
 * @since 1.0.0
 */
export interface SmtpConnectOptions {
	/** Mail server hostname (also used for TLS certificate validation). */
	hostname: string;
	/** TCP port; defaults to 587 for `starttls` and 465 for `implicit`. */
	port?: number;
	/**
	 * Transport security:
	 * - `'starttls'` (default): connect in plaintext, upgrade via STARTTLS.
	 * - `'implicit'`: TLS from the first byte (SMTPS, port 465).
	 * - `'off'`: plaintext with no upgrade (for trusted internal relays / dev servers).
	 */
	tls?: 'starttls' | 'implicit' | 'off';
	/** Credentials; when omitted, no `AUTH` is attempted. */
	auth?: {
		/** Login user (often the full email address). */
		username: string;
		/** Login password or app token. */
		password: string;
		/** Mechanism to use; defaults to `'PLAIN'`. */
		mechanism?: 'PLAIN' | 'LOGIN';
	};
	/** Per-step read deadline in milliseconds. */
	timeoutMs?: number;
}

/**
 * A message to send.
 *
 * Provide `text`, `html`, both (multipart/alternative), or a fully pre-rendered `raw`
 * payload. Recipient lists from `to`, `cc`, and `bcc` are all added to the SMTP envelope;
 * `bcc` is intentionally never written into the message headers.
 *
 * @since 1.0.0
 */
export interface Mail {
	/** Envelope and header From address. */
	from: string;
	/** Primary recipient(s). */
	to: string | string[];
	/** Carbon-copy recipients (added to headers and envelope). */
	cc?: string[];
	/** Blind carbon-copy recipients (added to envelope only, never to headers). */
	bcc?: string[];
	/** Subject line. */
	subject: string;
	/** Plain-text body. */
	text?: string;
	/** HTML body. */
	html?: string;
	/** Extra headers appended verbatim (keep values ASCII). */
	headers?: Record<string, string>;
	/**
	 * File attachments. When present the message is built as `multipart/mixed` with the
	 * text/html body as the first part and each file base64-encoded after it.
	 */
	attachments?: Array<{ filename: string; content: Uint8Array; contentType?: string }>;
	/** A complete, pre-rendered RFC 5322 message; bypasses the MIME builder when set. */
	raw?: Uint8Array;
}

/**
 * The result of a successful {@link SmtpSession.send}.
 *
 * @since 1.0.0
 */
export interface SendResult {
	/** Recipients the server accepted (those that returned 250/251 to `RCPT TO`). */
	accepted: string[];
	/** The final server reply text to the message body (the response to `CRLF.CRLF`). */
	response: string;
}

/**
 * A live, authenticated SMTP session that can send one or more messages.
 *
 * Obtain one with {@link connect}. It is an `AsyncDisposable`, so it can be scoped with
 * `await using` and will `QUIT` on disposal.
 *
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { connect } from 'edgeport/smtp';
 *
 * await using session = await connect({
 * 	hostname: 'smtp.example.com',
 * 	auth: { username: 'me@example.com', password: process.env.SMTP_PASS! }
 * });
 * await session.send({ from: 'me@example.com', to: 'you@example.com', subject: 'Hi', text: 'Yo' });
 * ```
 */
export interface SmtpSession extends AsyncDisposable {
	/**
	 * Sends one message over the open session.
	 *
	 * @param mail - The message to send.
	 * @returns The accepted recipients and the server's final reply.
	 * @throws {ProtocolError} If the server rejects any envelope or data command.
	 */
	send(mail: Mail): Promise<SendResult>;
	/** Sends `QUIT` and closes the underlying socket. */
	close(): Promise<void>;
}

/** A parsed multiline SMTP reply. */
interface SmtpReply {
	/** Three-digit status code (e.g. 250). */
	code: number;
	/** Full reply text, lines joined by `\n`. */
	text: string;
}

/**
 * Reads one complete SMTP reply, following multiline continuations.
 *
 * A reply line is `\d{3}[ -]text`; while the 4th character is `-` more lines follow, and
 * the line with a space after the code is the last.
 */
async function readReply(reader: FramedReader, timeoutMs?: number): Promise<SmtpReply> {
	const lines: string[] = [];
	let code = -1;
	for (;;) {
		const line = await reader.readLine(timeoutMs);
		// shortest valid reply line is "NNN" (3 digits)
		if (line.length < 3 || !/^\d{3}/.test(line)) {
			throw new ProtocolError(`malformed SMTP reply: ${JSON.stringify(line)}`, {
				protocol: PROTOCOL
			});
		}
		code = Number(line.slice(0, 3));
		lines.push(line.length > 4 ? line.slice(4) : '');
		// a hyphen in the 4th column means another line follows; a space (or none) ends it
		if (line[3] !== '-') break;
	}
	return { code, text: lines.join('\n') };
}

/** Writes a command line and reads its reply. */
async function command(
	writer: FramedWriter,
	reader: FramedReader,
	line: string,
	timeoutMs?: number
): Promise<SmtpReply> {
	await writer.writeLine(line);
	return readReply(reader, timeoutMs);
}

/** Throws {@link ProtocolError} unless the reply code is in `expected`. */
function expect(reply: SmtpReply, expected: number[], what: string): void {
	if (!expected.includes(reply.code)) {
		throw new ProtocolError(`SMTP ${what} failed: ${reply.code} ${reply.text}`, {
			protocol: PROTOCOL
		});
	}
}

/** base64-encodes a UTF-8 string (Workers-safe, no Buffer). */
function b64(s: string): string {
	let bin = '';
	for (const byte of encoder.encode(s)) bin += String.fromCharCode(byte);
	return btoa(bin);
}

/** Parses the capability tokens (first word of each line after the code) from an EHLO reply. */
function parseCapabilities(reply: SmtpReply): Set<string> {
	const caps = new Set<string>();
	for (const line of reply.text.split('\n')) {
		const token = line.trim().split(/\s+/)[0];
		if (token) caps.add(token.toUpperCase());
	}
	return caps;
}

/** Sends EHLO and returns the advertised capabilities. */
async function ehlo(
	writer: FramedWriter,
	reader: FramedReader,
	clientName: string,
	timeoutMs?: number
): Promise<Set<string>> {
	const reply = await command(writer, reader, `EHLO ${clientName}`, timeoutMs);
	expect(reply, [250], 'EHLO');
	return parseCapabilities(reply);
}

/** Runs AUTH PLAIN or AUTH LOGIN against the server; throws {@link AuthError} on rejection. */
async function authenticate(
	writer: FramedWriter,
	reader: FramedReader,
	auth: NonNullable<SmtpConnectOptions['auth']>,
	timeoutMs?: number
): Promise<void> {
	const mechanism = auth.mechanism ?? 'PLAIN';
	if (mechanism === 'PLAIN') {
		// authzid is empty: \0authcid\0passwd
		const token = b64(`\0${auth.username}\0${auth.password}`);
		const reply = await command(writer, reader, `AUTH PLAIN ${token}`, timeoutMs);
		assertAuth(reply);
		return;
	}

	// LOGIN: server prompts (334) for username then password, each base64
	const start = await command(writer, reader, 'AUTH LOGIN', timeoutMs);
	if (start.code !== 334) assertAuth(start);
	const userReply = await command(writer, reader, b64(auth.username), timeoutMs);
	if (userReply.code !== 334) assertAuth(userReply);
	const passReply = await command(writer, reader, b64(auth.password), timeoutMs);
	assertAuth(passReply);
}

/** Accepts 235 (auth ok); maps 535/530 to {@link AuthError} and anything else to a protocol error. */
function assertAuth(reply: SmtpReply): void {
	if (reply.code === 235) return;
	if (reply.code === 535 || reply.code === 530) {
		throw new AuthError(`SMTP authentication rejected: ${reply.code} ${reply.text}`, {
			protocol: PROTOCOL
		});
	}
	throw new ProtocolError(`unexpected AUTH reply: ${reply.code} ${reply.text}`, {
		protocol: PROTOCOL
	});
}

/** Strips angle-bracket wrapping from an address so we can re-wrap it cleanly in the envelope. */
function bareAddress(addr: string): string {
	const m = addr.match(/<([^>]*)>/);
	return (m?.[1] ?? addr).trim();
}

/**
 * Dot-stuffs a message body per RFC 5321 section 4.5.2 and appends the `CRLF.CRLF`
 * terminator.
 *
 * Any line beginning with `.` gets an extra leading `.` so it is not read as the end of
 * data. Lone LF line endings are normalized to CRLF first.
 */
function frameData(body: Uint8Array): Uint8Array {
	// normalize to text to do line work, then re-encode; bodies are UTF-8/ASCII
	const text = new TextDecoder().decode(body);
	const normalized = text.replace(/\r\n|\r|\n/g, '\r\n');
	const stuffed = normalized.replace(/^\./gm, '..');
	const payload = encoder.encode(stuffed);

	// payload + (CRLF if it doesn't already end with one) + ".\r\n"
	const endsCrlf =
		payload.length >= 2 &&
		payload[payload.length - 2] === 0x0d &&
		payload[payload.length - 1] === 0x0a;
	const out = new Uint8Array(
		payload.length + (endsCrlf ? DOT_CRLF_DOT.length - 2 : DOT_CRLF_DOT.length)
	);
	out.set(payload, 0);
	if (endsCrlf) {
		// already CRLF-terminated; just add ".\r\n"
		out.set(new Uint8Array([0x2e, 0x0d, 0x0a]), payload.length);
	} else {
		out.set(DOT_CRLF_DOT, payload.length);
	}
	return out;
}

/** Builds the {@link SmtpSession} backed by an already-connected, post-handshake socket. */
function makeSession(
	socket: CoreSocket,
	getIo: () => { reader: FramedReader; writer: FramedWriter },
	timeoutMs?: number
): SmtpSession {
	let closed = false;

	const send = async (mail: Mail): Promise<SendResult> => {
		const { reader, writer } = getIo();

		const mailFrom = await command(
			writer,
			reader,
			`MAIL FROM:<${bareAddress(mail.from)}>`,
			timeoutMs
		);
		expect(mailFrom, [250], 'MAIL FROM');

		const recipients = [
			...(Array.isArray(mail.to) ? mail.to : [mail.to]),
			...(mail.cc ?? []),
			...(mail.bcc ?? [])
		];
		const accepted: string[] = [];
		for (const rcpt of recipients) {
			const reply = await command(writer, reader, `RCPT TO:<${bareAddress(rcpt)}>`, timeoutMs);
			// 250 = ok, 251 = will forward; both count as accepted. a per-recipient rejection
			// (4xx/5xx) is not fatal to the message - the recipient is simply left out of the
			// accepted list, matching how submission servers handle a mixed RCPT batch
			if (reply.code === 250 || reply.code === 251) {
				accepted.push(rcpt);
			}
		}
		if (accepted.length === 0) {
			throw new ProtocolError('SMTP RCPT TO: no recipients were accepted', {
				protocol: PROTOCOL
			});
		}

		const data = await command(writer, reader, 'DATA', timeoutMs);
		expect(data, [354], 'DATA');

		await writer.write(frameData(buildMime(mail)));
		const final = await readReply(reader, timeoutMs);
		expect(final, [250], 'message');

		return { accepted, response: final.text };
	};

	const close = async (): Promise<void> => {
		if (closed) return;
		closed = true;
		const { reader, writer } = getIo();
		try {
			await command(writer, reader, 'QUIT', timeoutMs);
		} catch {
			// server may have dropped already; closing the socket is what matters
		}
		await socket.close();
	};

	return {
		send,
		close,
		[Symbol.asyncDispose]: close
	};
}

/**
 * Runs the SMTP handshake (greeting, EHLO, optional STARTTLS, optional AUTH) on a given
 * core socket and returns a ready session.
 *
 * Public {@link connect} dials the transport then calls this; unit tests call it directly
 * with a mock socket to drive the protocol without a real network.
 *
 * @param socket - A connected core socket. For `starttls` it must have been opened with
 *   `tls: 'starttls'` so {@link CoreSocket.startTls} works.
 * @param opts - The session options.
 * @returns A ready {@link SmtpSession}.
 * @throws {ProtocolError} On any unexpected reply code.
 * @throws {AuthError} If authentication is rejected.
 * @internal
 * @since 1.0.0
 */
export async function _sessionFromSocket(
	socket: CoreSocket,
	opts: SmtpConnectOptions
): Promise<SmtpSession> {
	const tls = opts.tls ?? 'starttls';
	const clientName = 'edgeport';
	const timeoutMs = opts.timeoutMs;

	// io is re-acquired after a TLS upgrade swaps the socket out from under us
	let active = socket;
	const getIo = () => ({ reader: active.reader, writer: active.writer });

	// 1. greeting
	const greeting = await readReply(active.reader, timeoutMs);
	expect(greeting, [220], 'greeting');

	// 2. first EHLO
	await ehlo(active.writer, active.reader, clientName, timeoutMs);

	// 3. STARTTLS upgrade (implicit TLS needs nothing here; it is already encrypted)
	if (tls === 'starttls') {
		const reply = await command(active.writer, active.reader, 'STARTTLS', timeoutMs);
		expect(reply, [220], 'STARTTLS');
		active = active.startTls({ expectedServerHostname: opts.hostname });
		// protocol resets after the upgrade; EHLO again over the encrypted channel
		await ehlo(active.writer, active.reader, clientName, timeoutMs);
	}

	// 4. AUTH
	if (opts.auth) {
		await authenticate(active.writer, active.reader, opts.auth, timeoutMs);
	}

	return makeSession(active, getIo, timeoutMs);
}

/**
 * Opens an authenticated SMTP submission session.
 *
 * Connects to the server (plaintext + STARTTLS by default, or implicit TLS when
 * `tls: 'implicit'`), negotiates `EHLO`, optionally authenticates, and returns a reusable
 * {@link SmtpSession}. Remember to {@link SmtpSession.close} (or use `await using`) to
 * send `QUIT` and release the socket.
 *
 * @param opts - Connection and auth options.
 * @returns A ready session.
 * @throws {ConnectionError} If the socket cannot be opened.
 * @throws {ProtocolError} If the server speaks SMTP incorrectly.
 * @throws {AuthError} If authentication fails.
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { connect } from 'edgeport/smtp';
 *
 * const session = await connect({
 * 	hostname: 'smtp.example.com',
 * 	port: 587,
 * 	auth: { username: 'me@example.com', password: 'app-password' }
 * });
 * try {
 * 	const { accepted } = await session.send({
 * 		from: 'me@example.com',
 * 		to: ['a@example.com', 'b@example.com'],
 * 		subject: 'Report',
 * 		html: '<p>done</p>'
 * 	});
 * 	console.log('accepted', accepted);
 * } finally {
 * 	await session.close();
 * }
 * ```
 */
export async function connect(opts: SmtpConnectOptions): Promise<SmtpSession> {
	const tls = opts.tls ?? 'starttls';
	const port = opts.port ?? (tls === 'implicit' ? IMPLICIT_TLS_PORT : DEFAULT_SUBMISSION_PORT);
	const coreTls = tls === 'implicit' ? 'on' : tls === 'off' ? 'off' : 'starttls';
	const socket = await coreConnect({
		hostname: opts.hostname,
		port,
		tls: coreTls,
		connectTimeoutMs: opts.timeoutMs
	});
	return _sessionFromSocket(socket, opts);
}

/**
 * Sends a single message in one call: connect, authenticate, send, quit.
 *
 * A convenience wrapper over {@link connect} + {@link SmtpSession.send} for the common
 * fire-once case. The session is always closed, even if sending throws. The shape mirrors
 * nodemailer's `transporter.sendMail` so it drops into existing code with minimal change.
 *
 * @param opts - Connection options merged with the message fields.
 * @returns The accepted recipients and the server's final reply.
 * @throws {ConnectionError} If the socket cannot be opened.
 * @throws {ProtocolError} If the server rejects the envelope or data.
 * @throws {AuthError} If authentication fails.
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { send } from 'edgeport/smtp';
 *
 * await send({
 * 	hostname: 'smtp.example.com',
 * 	auth: { username: 'me@example.com', password: 'app-password' },
 * 	from: 'me@example.com',
 * 	to: 'you@example.com',
 * 	subject: 'Hello',
 * 	text: 'Sent straight from a Worker.'
 * });
 * ```
 */
export async function send(opts: SmtpConnectOptions & Mail): Promise<SendResult> {
	const session = await connect(opts);
	try {
		return await session.send(opts);
	} finally {
		await session.close();
	}
}
