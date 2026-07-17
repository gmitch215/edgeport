/**
 * @fileoverview A read-oriented IMAP client (RFC 3501) for the Cloudflare Workers runtime.
 *
 * This module speaks the tagged command/response dialogue of IMAP4rev1 over the shared core
 * transport. It is deliberately scoped to the read path most Workers need: log in, list and
 * select mailboxes, search, and fetch envelopes and bodies. It handles both implicit TLS
 * (port 993) and the STARTTLS upgrade (port 143), and parses the literal `{N}` byte-count
 * syntax servers use to deliver message bodies.
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

const DEFAULT_IMAP_PORT = 993;
const PROTO = 'imap';
const decoder = new TextDecoder();

/** Options for {@link connect} and {@link fetchRecent}. */
export interface ImapConnectOptions {
	/** Remote IMAP host. */
	hostname: string;
	/** Remote port; defaults to 993 (implicit TLS). */
	port?: number;
	/**
	 * Transport security:
	 * - `'implicit'` (default): TLS from the first byte (IMAPS, port 993).
	 * - `'starttls'`: plaintext, upgraded with the `STARTTLS` command (port 143).
	 */
	tls?: 'implicit' | 'starttls' | 'off';
	/** Login credentials sent via the `LOGIN` command. */
	auth: { username: string; password: string };
	/** Per-operation read deadline in milliseconds. */
	timeoutMs?: number;
}

/** A single message returned by {@link ImapSession.fetch}. */
export interface ImapMessage {
	/** Unique identifier within the selected mailbox. */
	uid: number;
	/** IMAP flags set on the message (e.g. `\Seen`, `\Flagged`). */
	flags: string[];
	/** Parsed RFC 822 headers, lowercased keys, when the body was fetched. */
	headers?: Record<string, string>;
	/** Server-side internal date string, when present. */
	internalDate?: string;
	/** Octet size reported by `RFC822.SIZE`, when requested. */
	size?: number;
	/** Raw message bytes, when the body was fetched. */
	body?: Uint8Array;
	/**
	 * Decodes the raw {@link body} as UTF-8 text, or returns `''` when no body was fetched, so
	 * callers do not build a `TextDecoder`. The raw bytes remain on {@link body}.
	 *
	 * @returns The decoded message body.
	 * @since 1.0.4
	 */
	text(): string;
}

/** A search query, translated to IMAP `SEARCH` criteria. */
export interface ImapSearch {
	/** Match every message (the `ALL` key). */
	all?: boolean;
	/** Match unseen messages only. */
	unseen?: boolean;
	/** Match messages whose internal date is on or after this date. */
	since?: Date;
	/** Match messages whose `From` header contains this substring. */
	from?: string;
	/** Match messages whose `Subject` header contains this substring. */
	subject?: string;
}

/** Selects which parts of each message {@link ImapSession.fetch} requests. */
export interface ImapFetchFields {
	/** Request `ENVELOPE` (parsed here into headers from the fetched body). */
	envelope?: boolean;
	/** Request `FLAGS`. */
	flags?: boolean;
	/** Request the full body via `BODY.PEEK[]`. */
	body?: boolean;
	/** Request `RFC822.SIZE`. */
	size?: boolean;
}

/**
 * An authenticated IMAP session over a single connection.
 *
 * Obtain one from {@link connect}. It is an `AsyncDisposable`, so it can be scoped with
 * `await using` to guarantee the connection is logged out and closed. Methods issue one
 * tagged command at a time and must not be called concurrently on the same session.
 *
 * @since 1.0.0
 */
export interface ImapSession extends AsyncDisposable {
	/**
	 * Lists the available mailbox names via the `LIST` command.
	 *
	 * @returns The mailbox names the server reports.
	 * @throws {ProtocolError} If the server rejects the command.
	 */
	listMailboxes(): Promise<string[]>;
	/**
	 * Selects a mailbox for subsequent searches and fetches via `SELECT`.
	 *
	 * @param mailbox - The mailbox name (e.g. `INBOX`).
	 * @returns The message count and UID validity reported by the server.
	 * @throws {ProtocolError} If the mailbox cannot be selected.
	 */
	select(mailbox: string): Promise<{ exists: number; uidValidity: number }>;
	/**
	 * Searches the selected mailbox via `UID SEARCH`.
	 *
	 * @param query - The criteria to match.
	 * @returns The matching message UIDs.
	 * @throws {ProtocolError} If the server rejects the search.
	 */
	search(query: ImapSearch): Promise<number[]>;
	/**
	 * Fetches the requested fields for a set of UIDs via `UID FETCH`.
	 *
	 * @param uids - The message UIDs to fetch.
	 * @param fields - Which parts of each message to request.
	 * @returns One {@link ImapMessage} per UID the server returns.
	 * @throws {ProtocolError} If the server rejects the fetch.
	 */
	fetch(uids: number[], fields: ImapFetchFields): Promise<ImapMessage[]>;
	/**
	 * Logs out and closes the connection.
	 *
	 * @returns Resolves once the socket is closed.
	 */
	close(): Promise<void>;
}

/**
 * Connects to an IMAP server and logs in, returning a ready session.
 *
 * Opens the transport (implicit TLS or STARTTLS), runs `LOGIN`, and hands back an
 * {@link ImapSession}. A failed login surfaces as {@link AuthError}; any other protocol-level
 * rejection surfaces as {@link ProtocolError}.
 *
 * @param opts - Connection and credential options.
 * @returns The authenticated session.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { connect } from 'edgeport/imap';
 *
 * await using session = await connect({
 * 	hostname: 'imap.example.com',
 * 	auth: { username: 'me', password: 'secret' }
 * });
 * await session.select('INBOX');
 * const uids = await session.search({ unseen: true });
 * const messages = await session.fetch(uids, { flags: true, body: true });
 * ```
 */
export async function connect(opts: ImapConnectOptions): Promise<ImapSession> {
	const port = opts.port ?? DEFAULT_IMAP_PORT;
	const coreTls = opts.tls === 'starttls' ? 'starttls' : opts.tls === 'off' ? 'off' : 'on';
	let socket = await coreConnect({
		hostname: opts.hostname,
		port,
		tls: coreTls,
		connectTimeoutMs: opts.timeoutMs
	});
	try {
		return await _imapSessionFromSocket(socket, opts);
	} catch (err) {
		await socket.close().catch(() => {});
		throw err;
	}
}

/**
 * Connects, selects a mailbox, and fetches the most recent messages, then logs out.
 *
 * A one-shot convenience over {@link connect}: it selects the mailbox (defaulting to
 * `INBOX`), takes the highest-numbered `count` messages, fetches their flags and bodies, and
 * closes the connection before returning.
 *
 * @param opts - Connection options plus the mailbox and message count.
 * @returns Up to `count` recent messages, oldest first.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { fetchRecent } from 'edgeport/imap';
 *
 * const recent = await fetchRecent({
 * 	hostname: 'imap.example.com',
 * 	auth: { username: 'me', password: 'secret' },
 * 	count: 10
 * });
 * ```
 */
export async function fetchRecent(
	opts: ImapConnectOptions & { mailbox?: string; count: number }
): Promise<ImapMessage[]> {
	await using session = await connect(opts);
	await session.select(opts.mailbox ?? 'INBOX');
	const uids = await session.search({ all: true });
	const recent = uids.slice(Math.max(0, uids.length - opts.count));
	return session.fetch(recent, { flags: true, body: true, size: true });
}

/**
 * Builds an {@link ImapSession} over an already-connected {@link CoreSocket}.
 *
 * Reads the server greeting, performs the STARTTLS upgrade if requested, and runs `LOGIN`.
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
export async function _imapSessionFromSocket(
	socket: CoreSocket,
	opts: ImapConnectOptions
): Promise<ImapSession> {
	const timeoutMs = opts.timeoutMs;
	const client = new ImapClient(socket, timeoutMs);

	// untagged server greeting (* OK ...)
	await client.readGreeting();

	if (opts.tls === 'starttls') {
		await client.command('STARTTLS');
		socket = socket.startTls({ expectedServerHostname: opts.hostname });
		client.rebind(socket.reader, socket.writer);
	}

	const user = quote(opts.auth.username);
	const pass = quote(opts.auth.password);
	try {
		await client.command(`LOGIN ${user} ${pass}`);
	} catch (err) {
		if (err instanceof ProtocolError) {
			throw new AuthError('imap login rejected', { protocol: PROTO, cause: err });
		}
		throw err;
	}

	return new ImapSessionImpl(client, socket);
}

/** Result of one tagged command: the untagged lines plus the tagged status line. */
interface CommandResult {
	untagged: string[];
	status: 'OK' | 'NO' | 'BAD';
	text: string;
}

// drives the tagged command/response loop and the literal {N} reads
class ImapClient {
	#reader: FramedReader;
	#writer: FramedWriter;
	readonly #timeoutMs: number | undefined;
	#tag = 0;

	constructor(socket: CoreSocket, timeoutMs: number | undefined) {
		this.#reader = socket.reader;
		this.#writer = socket.writer;
		this.#timeoutMs = timeoutMs;
	}

	rebind(reader: FramedReader, writer: FramedWriter): void {
		this.#reader = reader;
		this.#writer = writer;
	}

	async readGreeting(): Promise<void> {
		const line = await this.#reader.readLine(this.#timeoutMs);
		if (!line.startsWith('* ')) {
			throw new ProtocolError(`unexpected imap greeting: ${line}`, { protocol: PROTO });
		}
	}

	#nextTag(): string {
		this.#tag += 1;
		return 'a' + String(this.#tag).padStart(3, '0');
	}

	// sends one tagged command and collects untagged lines until the tagged status arrives;
	// throws ProtocolError on NO/BAD so callers map it (e.g. login -> AuthError)
	async command(line: string): Promise<CommandResult> {
		const tag = this.#nextTag();
		await this.#writer.writeLine(`${tag} ${line}`);
		const result = await this.readResponse(tag);
		if (result.status !== 'OK') {
			throw new ProtocolError(`imap ${result.status}: ${result.text}`, { protocol: PROTO });
		}
		return result;
	}

	// reads response lines for `tag`, resolving any literal {N} payloads inline
	async readResponse(tag: string): Promise<CommandResult> {
		const untagged: string[] = [];
		for (;;) {
			let line = await this.#readLogicalLine();
			const taggedPrefix = tag + ' ';
			if (line.startsWith(taggedPrefix)) {
				const rest = line.slice(taggedPrefix.length);
				const sp = rest.indexOf(' ');
				const word = sp === -1 ? rest : rest.slice(0, sp);
				const text = sp === -1 ? '' : rest.slice(sp + 1);
				if (word !== 'OK' && word !== 'NO' && word !== 'BAD') {
					throw new ProtocolError(`unexpected tagged status: ${line}`, { protocol: PROTO });
				}
				return { untagged, status: word, text };
			}
			if (line.startsWith('* ')) {
				untagged.push(line);
				continue;
			}
			if (line.startsWith('+ ')) {
				// continuation request; nothing to send for the commands we issue
				continue;
			}
			// tolerate stray lines rather than choking on minor server quirks
			untagged.push(line);
		}
	}

	// reads one logical line, splicing in any IMAP literals {N} so the returned string holds
	// the literal bytes (decoded) where the {N} marker stood
	async #readLogicalLine(): Promise<string> {
		let line = await this.#reader.readLine(this.#timeoutMs);
		for (;;) {
			const lit = matchTrailingLiteral(line);
			if (lit === null) return line;
			const bytes = await this.#reader.readN(lit, this.#timeoutMs);
			const next = await this.#reader.readLine(this.#timeoutMs);
			line = line + decoder.decode(bytes) + next;
		}
	}
}

/** {@link ImapSession} backed by an {@link ImapClient}. */
class ImapSessionImpl implements ImapSession {
	readonly #client: ImapClient;
	readonly #socket: CoreSocket;

	constructor(client: ImapClient, socket: CoreSocket) {
		this.#client = client;
		this.#socket = socket;
	}

	async listMailboxes(): Promise<string[]> {
		const res = await this.#client.command('LIST "" "*"');
		const names: string[] = [];
		for (const line of res.untagged) {
			const name = parseListName(line);
			if (name !== null) names.push(name);
		}
		return names;
	}

	async select(mailbox: string): Promise<{ exists: number; uidValidity: number }> {
		const res = await this.#client.command(`SELECT ${quote(mailbox)}`);
		let exists = 0;
		let uidValidity = 0;
		for (const line of res.untagged) {
			const ex = /^\* (\d+) EXISTS\b/.exec(line);
			if (ex && ex[1]) exists = Number(ex[1]);
			const uv = /\[UIDVALIDITY (\d+)\]/.exec(line);
			if (uv && uv[1]) uidValidity = Number(uv[1]);
		}
		return { exists, uidValidity };
	}

	async search(query: ImapSearch): Promise<number[]> {
		const res = await this.#client.command(`UID SEARCH ${buildSearch(query)}`);
		const uids: number[] = [];
		for (const line of res.untagged) {
			const m = /^\* SEARCH\b(.*)$/.exec(line);
			if (!m) continue;
			for (const tok of (m[1] ?? '').trim().split(/\s+/)) {
				if (tok && /^\d+$/.test(tok)) uids.push(Number(tok));
			}
		}
		return uids;
	}

	async fetch(uids: number[], fields: ImapFetchFields): Promise<ImapMessage[]> {
		if (uids.length === 0) return [];
		const items = buildFetchItems(fields);
		const res = await this.#client.command(`UID FETCH ${uids.join(',')} (${items})`);
		const out: ImapMessage[] = [];
		for (const line of res.untagged) {
			const msg = parseFetch(line);
			if (msg) out.push(msg);
		}
		return out;
	}

	async close(): Promise<void> {
		try {
			await this.#client.command('LOGOUT');
		} catch {
			// best-effort logout; the socket close below is what matters
		}
		await this.#socket.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

// returns the literal byte count if `line` ends with a {N} marker, else null
function matchTrailingLiteral(line: string): number | null {
	const m = /\{(\d+)\}$/.exec(line);
	if (!m || !m[1]) return null;
	return Number(m[1]);
}

// wraps a value in an IMAP quoted string, escaping backslashes and quotes
function quote(s: string): string {
	return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

// "* LIST (\HasNoChildren) "/" INBOX" -> "INBOX"
function parseListName(line: string): string | null {
	if (!/^\* LIST\b/.test(line)) return null;
	// name is the last token; quoted or atom
	const quoted = /"((?:[^"\\]|\\.)*)"\s*$/.exec(line);
	if (quoted && quoted[1] !== undefined) {
		return quoted[1].replace(/\\(.)/g, '$1');
	}
	const parts = line.trim().split(/\s+/);
	const last = parts[parts.length - 1];
	return last ?? null;
}

// translates an ImapSearch into IMAP SEARCH criteria
function buildSearch(query: ImapSearch): string {
	const keys: string[] = [];
	if (query.unseen) keys.push('UNSEEN');
	if (query.since) keys.push(`SINCE ${imapDate(query.since)}`);
	if (query.from) keys.push(`FROM ${quote(query.from)}`);
	if (query.subject) keys.push(`SUBJECT ${quote(query.subject)}`);
	if (keys.length === 0 || query.all) keys.unshift('ALL');
	return keys.join(' ');
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// formats a Date as IMAP's "dd-Mon-yyyy" (UTC)
function imapDate(d: Date): string {
	const day = String(d.getUTCDate()).padStart(2, '0');
	const mon = MONTHS[d.getUTCMonth()] ?? 'Jan';
	return `${day}-${mon}-${d.getUTCFullYear()}`;
}

// builds the fetch item list; always asks for UID so messages can be keyed
function buildFetchItems(fields: ImapFetchFields): string {
	const items = ['UID'];
	if (fields.flags) items.push('FLAGS');
	if (fields.size) items.push('RFC822.SIZE');
	// envelope is satisfied by parsing headers out of the fetched body
	if (fields.body || fields.envelope) items.push('BODY.PEEK[]');
	return items.join(' ');
}

// parses one "* N FETCH (...)" untagged line (with any literal already spliced in)
function parseFetch(line: string): ImapMessage | null {
	if (!/^\* \d+ FETCH /.test(line)) return null;
	const msg: ImapMessage = {
		uid: 0,
		flags: [],
		text: () => (msg.body ? decoder.decode(msg.body) : '')
	};

	const uid = /\bUID (\d+)/.exec(line);
	if (uid && uid[1]) msg.uid = Number(uid[1]);

	const size = /\bRFC822\.SIZE (\d+)/.exec(line);
	if (size && size[1]) msg.size = Number(size[1]);

	const date = /\bINTERNALDATE "([^"]*)"/.exec(line);
	if (date && date[1] !== undefined) msg.internalDate = date[1];

	const flags = /\bFLAGS \(([^)]*)\)/.exec(line);
	if (flags) {
		const inner = (flags[1] ?? '').trim();
		msg.flags = inner.length ? inner.split(/\s+/) : [];
	}

	// the body literal was spliced in by the reader as BODY[] {N}<bytes>; recover it
	const body = /\bBODY\[\]\s*(?:\{\d+\})?(.*)$/s.exec(line);
	if (body && body[1] !== undefined) {
		// trim a single trailing ')' that closes the FETCH parenthesis group
		let raw = body[1];
		if (raw.endsWith(')')) raw = raw.slice(0, -1);
		const bytes = new TextEncoder().encode(raw);
		msg.body = bytes;
		msg.headers = parseHeaders(raw);
	}

	return msg;
}

// parses RFC 822 header block (up to the first blank line) into lowercased keys
function parseHeaders(raw: string): Record<string, string> {
	const headers: Record<string, string> = {};
	const normalized = raw.replace(/\r\n/g, '\n');
	const blank = normalized.indexOf('\n\n');
	const head = blank === -1 ? normalized : normalized.slice(0, blank);
	let lastKey: string | null = null;
	for (const rawLine of head.split('\n')) {
		if (rawLine === '') continue;
		if ((rawLine.startsWith(' ') || rawLine.startsWith('\t')) && lastKey) {
			// folded continuation of the previous header
			headers[lastKey] += ' ' + rawLine.trim();
			continue;
		}
		const colon = rawLine.indexOf(':');
		if (colon === -1) continue;
		const key = rawLine.slice(0, colon).trim().toLowerCase();
		const value = rawLine.slice(colon + 1).trim();
		headers[key] = value;
		lastKey = key;
	}
	return headers;
}
