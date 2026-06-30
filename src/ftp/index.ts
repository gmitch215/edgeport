/**
 * @fileoverview A plaintext FTP client (RFC 959, EPSV per RFC 2428) for the Cloudflare
 * Workers runtime.
 *
 * This module speaks the numeric-reply control dialogue of FTP over the shared core transport
 * and moves payloads over a separate passive data connection. It is PASSIVE MODE ONLY: the
 * Workers runtime cannot accept inbound connections, so active mode (`PORT`) is impossible.
 * There is no FTPS/TLS here either; that was dropped from v1 due to a Workers runtime
 * limitation. It covers the common file operations a Worker needs: list, retrieve, store,
 * delete, make/remove directories, rename, change/print working directory, and size.
 *
 * The data channel always opens first (prefer `EPSV`, fall back to `PASV`), then the transfer
 * command is sent; control returns a `1xx` preliminary reply, bytes flow on the data channel,
 * and control closes with a `2xx` completion reply.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import {
	AuthError,
	ConnectionError,
	ProtocolError,
	connect as coreConnect,
	type CoreSocket,
	type FramedReader,
	type FramedWriter
} from '../core';

const DEFAULT_FTP_PORT = 21;
const DEFAULT_USERNAME = 'anonymous';
const PROTO = 'ftp';

/** Options for {@link connect}, {@link getFile}, and {@link putFile}. */
export interface FtpConnectOptions {
	/** Remote FTP host. */
	hostname: string;
	/** Remote control port; defaults to 21. */
	port?: number;
	/** Login user; defaults to `'anonymous'`. */
	username?: string;
	/** Login password; defaults to the empty string. */
	password?: string;
	/** Per-operation read deadline in milliseconds. */
	timeoutMs?: number;
}

/**
 * FTP transfer representation type.
 *
 * - `'binary'` issues `TYPE I` (image): bytes pass through unchanged. This is the default.
 * - `'ascii'` issues `TYPE A`: the server performs end-of-line conversion between its native
 *   line ending and the protocol `CRLF`. Use it for text files when the local and remote
 *   platforms differ. On Linux servers (native LF) `TYPE A` and `TYPE I` are often byte-identical
 *   since LF needs no conversion, but the command is still negotiated.
 *
 * @since 1.1.0
 */
export type FtpTransferType = 'binary' | 'ascii';

/** Per-transfer options for {@link FtpSession.get} and {@link FtpSession.getStream}. */
export interface FtpGetOptions {
	/** Transfer representation type; defaults to `'binary'`. */
	type?: FtpTransferType;
	/**
	 * Byte offset to resume the download from, issued as `REST <offset>` before `RETR`. The
	 * returned bytes are the tail of the file starting at this offset. Resume offsets are only
	 * meaningful for binary transfers.
	 */
	offset?: number;
}

/** Per-transfer options for {@link FtpSession.put}. */
export interface FtpPutOptions {
	/** Transfer representation type; defaults to `'binary'`. */
	type?: FtpTransferType;
	/**
	 * Append to the destination via `APPE` instead of `STOR`. When set, `offset` is ignored.
	 * Use this to resume an interrupted upload by sending only the remaining bytes.
	 */
	append?: boolean;
	/**
	 * Byte offset to resume the upload from, issued as `REST <offset>` before `STOR`, overwriting
	 * the destination from that offset onward. Ignored when `append` is set.
	 */
	offset?: number;
}

/** A single directory entry returned by {@link FtpSession.list}. */
export interface FtpEntry {
	/** The entry's file or directory name. */
	name: string;
	/** The size in bytes when known (parsed from a Unix `ls -l` listing). */
	size?: number;
	/** Whether the entry is a directory. */
	isDirectory: boolean;
	/** The unparsed listing line, always preserved. */
	raw: string;
}

/**
 * An authenticated FTP session over a single control connection.
 *
 * Obtain one from {@link connect}. It is an `AsyncDisposable`, so it can be scoped with
 * `await using` to guarantee a clean `QUIT` and socket close. Methods issue one command at a
 * time and must not be called concurrently on the same session, since each data transfer opens
 * its own passive connection while the control channel is in use.
 *
 * @since 1.0.0
 */
export interface FtpSession extends AsyncDisposable {
	/**
	 * Lists a directory via `LIST`, parsing Unix `ls -l` lines into {@link FtpEntry} records.
	 *
	 * @param path - Directory to list; omit for the current working directory.
	 * @returns One entry per line, with the raw line always preserved.
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * for (const entry of await session.list('/pub')) {
	 * 	console.log(entry.isDirectory ? 'dir' : 'file', entry.name);
	 * }
	 * ```
	 */
	list(path?: string): Promise<FtpEntry[]>;
	/**
	 * Lists bare names via `NLST`.
	 *
	 * @param path - Directory to list; omit for the current working directory.
	 * @returns One name per line.
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const names = await session.nameList('/pub');
	 * ```
	 */
	nameList(path?: string): Promise<string[]>;
	/**
	 * Retrieves a file's bytes via `RETR`.
	 *
	 * Defaults to binary (`TYPE I`). Pass `{ type: 'ascii' }` for a text-mode transfer (`TYPE A`,
	 * server line-ending conversion) or `{ offset }` to resume an interrupted download from a byte
	 * offset (`REST <offset>` before `RETR`), in which case the returned bytes are the tail of the
	 * file from that offset.
	 *
	 * @param path - Path of the file to fetch.
	 * @param opts - Optional transfer type and resume offset.
	 * @returns The file's raw bytes (the tail from `opts.offset` when set).
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const bytes = await session.get('/pub/readme.txt');
	 * const text = await session.get('/pub/readme.txt', { type: 'ascii' });
	 * const tail = await session.get('/pub/big.bin', { offset: 1024 });
	 * ```
	 */
	get(path: string, opts?: FtpGetOptions): Promise<Uint8Array>;
	/**
	 * Retrieves a file as a stream via `RETR`, for payloads too large to buffer.
	 *
	 * The returned stream owns the data connection; read it to completion (or cancel it) so the
	 * underlying socket closes. Accepts the same `type` and `offset` options as {@link FtpSession.get}.
	 *
	 * @param path - Path of the file to fetch.
	 * @param opts - Optional transfer type and resume offset.
	 * @returns A readable stream of the file's bytes.
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const stream = await session.getStream('/var/log/big.log');
	 * await stream.pipeTo(someWritable);
	 * ```
	 */
	getStream(path: string, opts?: FtpGetOptions): Promise<ReadableStream<Uint8Array>>;
	/**
	 * Stores bytes to a file via `STOR` (or `APPE`).
	 *
	 * Defaults to binary (`TYPE I`). Pass `{ type: 'ascii' }` for a text-mode transfer, or resume
	 * an interrupted upload with `{ append: true }` (use `APPE`, sending only the remaining bytes)
	 * or `{ offset }` (issue `REST <offset>` before `STOR`, overwriting from that offset).
	 *
	 * @param path - Destination path.
	 * @param data - The bytes to write.
	 * @param opts - Optional transfer type and resume mode (`append` or `offset`).
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * await session.put('/incoming/report.csv', new TextEncoder().encode('a,b,c\n'));
	 * // resume an upload that died after the first 1024 bytes
	 * await session.put('/incoming/big.bin', rest, { append: true });
	 * ```
	 */
	put(path: string, data: Uint8Array, opts?: FtpPutOptions): Promise<void>;
	/**
	 * Deletes a file via `DELE`.
	 *
	 * @param path - Path of the file to delete.
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * await session.delete('/incoming/old.csv');
	 * ```
	 */
	delete(path: string): Promise<void>;
	/**
	 * Creates a directory via `MKD`.
	 *
	 * @param path - Path of the directory to create.
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * await session.mkdir('/incoming/2026');
	 * ```
	 */
	mkdir(path: string): Promise<void>;
	/**
	 * Removes a directory via `RMD`.
	 *
	 * @param path - Path of the directory to remove.
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * await session.rmdir('/incoming/2025');
	 * ```
	 */
	rmdir(path: string): Promise<void>;
	/**
	 * Renames or moves a path via `RNFR`/`RNTO`.
	 *
	 * @param from - Existing path.
	 * @param to - New path.
	 * @throws {ProtocolError} If the server rejects either command.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * await session.rename('/tmp/a.txt', '/tmp/b.txt');
	 * ```
	 */
	rename(from: string, to: string): Promise<void>;
	/**
	 * Changes the working directory via `CWD`.
	 *
	 * @param path - Directory to change into.
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * await session.cwd('/pub');
	 * ```
	 */
	cwd(path: string): Promise<void>;
	/**
	 * Returns the current working directory via `PWD`.
	 *
	 * @returns The absolute working directory reported by the server.
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const dir = await session.pwd();
	 * ```
	 */
	pwd(): Promise<string>;
	/**
	 * Returns a file's size in bytes via `SIZE`.
	 *
	 * @param path - Path of the file to measure.
	 * @returns The size in bytes.
	 * @throws {ProtocolError} If the server rejects the command or returns a non-numeric size.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const n = await session.size('/pub/readme.txt');
	 * ```
	 */
	size(path: string): Promise<number>;
	/**
	 * Reports whether a path exists by probing it with `SIZE`.
	 *
	 * Issues `SIZE <path>` and treats a `213` reply as existence and a `550` (or any other
	 * command failure surfaced as {@link ProtocolError}) as absence. Because `SIZE` is a
	 * file-oriented probe, some servers reject it for directories even when they exist; for a
	 * directory, prefer {@link FtpSession.cwd} or {@link FtpSession.list}. The `path` is
	 * resolved by the server relative to the current working directory unless it is absolute.
	 *
	 * @param path - Path to probe (absolute, or relative to the working directory).
	 * @returns `true` if the server reports a size for the path, `false` if it is missing.
	 * @throws {ConnectionError} If the control connection fails.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * if (await session.exists('/pub/readme.txt')) {
	 * 	const bytes = await session.get('/pub/readme.txt');
	 * }
	 * ```
	 */
	exists(path: string): Promise<boolean>;
	/**
	 * Creates a directory and all missing parents, like `mkdir -p`.
	 *
	 * FTP `MKD` is single-level, so this splits `path` on `/` and issues `MKD` for each
	 * cumulative segment, ignoring the `550` "already exists" failure on segments that are
	 * already present. A leading `/` is preserved so absolute paths create from the root; a
	 * relative path creates under the current working directory. This is a client-side walk:
	 * it makes one round trip per segment and is not atomic.
	 *
	 * @param path - Directory path to create, with `/` separating segments.
	 * @throws {ConnectionError} If the control connection fails.
	 * @throws {ProtocolError} If a segment fails for a reason other than already existing.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * await session.ensureDir('/incoming/2026/reports');
	 * ```
	 */
	ensureDir(path: string): Promise<void>;
	/**
	 * Retrieves a file and decodes its bytes as UTF-8 text.
	 *
	 * A convenience over {@link FtpSession.get} that runs the same `RETR` transfer and decodes
	 * the result with {@link TextDecoder}. Accepts the same transfer options as `get`.
	 *
	 * @param path - Path of the file to fetch.
	 * @param opts - Optional transfer type and resume offset (see {@link FtpGetOptions}).
	 * @returns The file contents decoded as UTF-8.
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * const text = await session.getText('/pub/readme.txt');
	 * ```
	 */
	getText(path: string, opts?: FtpGetOptions): Promise<string>;
	/**
	 * Encodes a string as UTF-8 and stores it via `STOR`.
	 *
	 * A convenience over {@link FtpSession.put} that encodes `content` with {@link TextEncoder}
	 * and uploads it. Accepts the same transfer options as `put`.
	 *
	 * @param path - Destination path.
	 * @param content - The text to write; encoded as UTF-8.
	 * @param opts - Optional transfer type and resume mode (see {@link FtpPutOptions}).
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * await session.putText('/incoming/note.txt', 'hello world\n');
	 * ```
	 */
	putText(path: string, content: string, opts?: FtpPutOptions): Promise<void>;
	/**
	 * Retrieves a file and parses it as JSON.
	 *
	 * A convenience over {@link FtpSession.get} that decodes the bytes as UTF-8 and runs
	 * `JSON.parse`. The type parameter `T` annotates the parsed shape; it is not validated at
	 * runtime.
	 *
	 * @typeParam T - The expected shape of the parsed JSON.
	 * @param path - Path of the JSON file to fetch.
	 * @returns The parsed value, typed as `T`.
	 * @throws {ProtocolError} If the server rejects the command.
	 * @throws {SyntaxError} If the body is not valid JSON.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * interface Config { name: string }
	 * const cfg = await session.getJson<Config>('/etc/app/config.json');
	 * ```
	 */
	getJson<T = unknown>(path: string): Promise<T>;
	/**
	 * Serializes a value as JSON and stores it via `STOR`.
	 *
	 * A convenience over {@link FtpSession.put} that runs `JSON.stringify`, encodes the result
	 * as UTF-8, and uploads it.
	 *
	 * @param path - Destination path.
	 * @param value - The value to serialize; must be JSON-serializable.
	 * @param opts - Optional formatting; `space` is forwarded to `JSON.stringify` for indentation.
	 * @throws {ProtocolError} If the server rejects the command.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * await session.putJson('/etc/app/config.json', { name: 'edge' }, { space: 2 });
	 * ```
	 */
	putJson(path: string, value: unknown, opts?: { space?: number }): Promise<void>;
	/**
	 * Recursively deletes a directory tree (files then directories, depth-first).
	 *
	 * Walks `path` with `LIST`, deleting files with `DELE` and recursing into subdirectories,
	 * then removes each emptied directory with `RMD`. This is a client-side walk: it makes many
	 * round trips (`O(N)` for `N` entries) and is not atomic, so a failure partway through
	 * leaves the tree partly deleted. Rejects when `path` is empty or `/` as a guard against
	 * wiping the server root. The `path` is resolved by the server relative to the current
	 * working directory unless it is absolute.
	 *
	 * @param path - Directory tree to remove; must not be empty or `/`.
	 * @throws {ProtocolError} If `path` is empty or `/`, or the server rejects a command.
	 * @throws {ConnectionError} If the control connection fails.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * await session.removeAll('/incoming/2025');
	 * ```
	 */
	removeAll(path: string): Promise<void>;
	/**
	 * Returns a file's last-modified time via `MDTM`.
	 *
	 * Issues `MDTM <path>` and parses the `213 YYYYMMDDHHMMSS` reply as a UTC timestamp. Per
	 * RFC 3659 the `MDTM` time is always UTC. A fractional-seconds suffix (`.sss`), when the
	 * server sends one, is parsed too. The `path` is resolved by the server relative to the
	 * current working directory unless it is absolute.
	 *
	 * @param path - Path of the file to stat.
	 * @returns The modification time as a {@link Date}.
	 * @throws {ProtocolError} If the server rejects the command or returns a malformed timestamp.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * const when = await session.mtime('/pub/readme.txt');
	 * ```
	 */
	mtime(path: string): Promise<Date>;
	/**
	 * Sends `QUIT` and closes the control connection.
	 *
	 * @returns Resolves once the socket is closed.
	 * @since 1.0.0
	 */
	close(): Promise<void>;
}

/** A parsed FTP control reply. */
interface FtpReply {
	/** The 3-digit reply code. */
	code: number;
	/** The reply text (joined across multiline replies with LF). */
	text: string;
}

/**
 * Parses one logical FTP control reply from its raw lines.
 *
 * A reply is either a single `NNN text` line or a multiline block that opens with `NNN-...`
 * and continues until a line beginning `NNN ` (code followed by a space). The leading 3-digit
 * code is taken from the first line; its first digit classifies the reply (1=preliminary,
 * 2=complete, 3=more input, 4/5=error).
 *
 * @param lines - The reply lines, each already stripped of its CRLF.
 * @returns The parsed code and joined text.
 * @throws {ProtocolError} If `lines` is empty or the first line has no 3-digit code.
 * @since 1.0.0
 * @example
 * ```typescript
 * parseReply(['257 "/home/me" is current directory']); // { code: 257, text: '"/home/me" ...' }
 * parseReply(['211-Features:', ' SIZE', '211 End']);    // { code: 211, text: 'Features:\n SIZE\nEnd' }
 * ```
 */
export function parseReply(lines: string[]): FtpReply {
	if (lines.length === 0) {
		throw new ProtocolError('empty ftp reply', { protocol: PROTO });
	}
	const first = lines[0]!;
	const m = /^(\d{3})/.exec(first);
	if (!m) {
		throw new ProtocolError(`malformed ftp reply: ${first}`, { protocol: PROTO });
	}
	const code = Number(m[1]);
	// strip the leading "NNN" plus the separator ('-' or ' ') from each line's text
	const text = lines
		.map((line) => {
			const lm = /^(\d{3})[ -]?/.exec(line);
			return lm ? line.slice(lm[0].length) : line;
		})
		.join('\n');
	return { code, text };
}

/**
 * Parses the port out of an `EPSV` (RFC 2428) `229` reply.
 *
 * The reply carries `(|||PORT|)` where the address family and host fields are empty and the
 * port sits between the last two `|` delimiters; the host is reused from the control channel.
 *
 * @param line - The full reply text, e.g. `229 Entering Extended Passive Mode (|||49152|)`.
 * @returns The data port to dial.
 * @throws {ProtocolError} If no `(|||PORT|)` group is present.
 * @since 1.0.0
 * @example
 * ```typescript
 * parseEpsv('229 Entering Extended Passive Mode (|||49152|)'); // 49152
 * ```
 */
export function parseEpsv(line: string): number {
	// the delimiter is the first char inside the parens; it repeats 3 times before the port
	const m = /\((.)\1\1(\d+)\1?\)/.exec(line);
	if (!m) {
		throw new ProtocolError(`malformed EPSV reply: ${line}`, { protocol: PROTO });
	}
	return Number(m[2]);
}

/**
 * Parses the host and port out of a `PASV` (RFC 959) `227` reply.
 *
 * The reply carries `(h1,h2,h3,h4,p1,p2)`; the host is `h1.h2.h3.h4` and the port is
 * `p1*256 + p2`.
 *
 * @param line - The full reply text, e.g. `227 Entering Passive Mode (192,168,0,1,19,136)`.
 * @returns The host and port to dial.
 * @throws {ProtocolError} If no six-number group is present.
 * @since 1.0.0
 * @example
 * ```typescript
 * parsePasv('227 Entering Passive Mode (192,168,0,1,19,136)'); // { host: '192.168.0.1', port: 5000 }
 * ```
 */
export function parsePasv(line: string): { host: string; port: number } {
	const m = /(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})/.exec(line);
	if (!m) {
		throw new ProtocolError(`malformed PASV reply: ${line}`, { protocol: PROTO });
	}
	const host = `${m[1]}.${m[2]}.${m[3]}.${m[4]}`;
	const port = Number(m[5]) * 256 + Number(m[6]);
	return { host, port };
}

/**
 * Parses one Unix `ls -l` listing line into an {@link FtpEntry}.
 *
 * Recognizes the conventional 9-field long format: a permission string (whose first character
 * is `d` for directories), link count, owner, group, size, three date fields, and the name
 * (which may itself contain spaces). Parsing is tolerant: a line it cannot read is returned
 * with its raw text and a best-effort name (the last whitespace-delimited token), no size, and
 * `isDirectory` taken from a leading `d` if present.
 *
 * @param line - A single listing line, stripped of its CRLF.
 * @returns The parsed entry; `size` is omitted when it cannot be determined.
 * @since 1.0.0
 * @example
 * ```typescript
 * parseListLine('-rw-r--r-- 1 me grp 1234 Jun 28 12:00 readme.txt');
 * // { name: 'readme.txt', size: 1234, isDirectory: false, raw: '...' }
 * parseListLine('drwxr-xr-x 2 me grp 4096 Jun 28 12:00 pub');
 * // { name: 'pub', size: 4096, isDirectory: true, raw: '...' }
 * ```
 */
export function parseListLine(line: string): FtpEntry {
	const isDirectory = line[0] === 'd';
	// perms, links, owner, group, size, month, day, time-or-year, then the name (rest of line)
	const m =
		/^[bcdlps-][rwxXsStT-]{9}[.+]?\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(.+)$/.exec(line);
	if (m) {
		let name = m[2]!;
		// symlinks render as "name -> target"; keep only the link's own name
		if (line[0] === 'l') {
			const arrow = name.indexOf(' -> ');
			if (arrow >= 0) name = name.slice(0, arrow);
		}
		return { name, size: Number(m[1]), isDirectory, raw: line };
	}
	// best-effort fallback: last token as the name, directory flag from a leading 'd'
	const tokens = line.trim().split(/\s+/);
	const name = tokens.length > 0 ? tokens[tokens.length - 1]! : line;
	return { name, isDirectory, raw: line };
}

/**
 * Parses an `MDTM` (RFC 3659) `213` reply timestamp into a UTC {@link Date}.
 *
 * The reply text is `YYYYMMDDHHMMSS` with an optional `.sss` fractional-seconds suffix, always
 * expressed in UTC. The fields are read positionally and assembled with `Date.UTC`.
 *
 * @param text - The `213` reply text, e.g. `20260628120000` or `20260628120000.250`.
 * @returns The modification time as a UTC `Date`.
 * @throws {ProtocolError} If the text is not a 14-digit timestamp.
 * @since 1.0.2
 * @example
 * ```typescript
 * parseMdtm('20260628120000'); // 2026-06-28T12:00:00.000Z
 * ```
 */
export function parseMdtm(text: string): Date {
	const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?/.exec(text.trim());
	if (!m) {
		throw new ProtocolError(`malformed MDTM reply: ${text}`, { protocol: PROTO });
	}
	// pad/truncate a fractional-seconds suffix to whole milliseconds
	const ms = m[7] ? Number((m[7] + '000').slice(0, 3)) : 0;
	const t = Date.UTC(
		Number(m[1]),
		Number(m[2]) - 1,
		Number(m[3]),
		Number(m[4]),
		Number(m[5]),
		Number(m[6]),
		ms
	);
	return new Date(t);
}

/**
 * Connects to an FTP server and logs in, returning a ready session.
 *
 * Opens a plaintext control connection (`tls: 'off'`), reads the `220` greeting, runs
 * `USER`/`PASS`, and switches to binary mode with `TYPE I`. A rejected login (`530`/`532`)
 * surfaces as {@link AuthError}; any other command failure surfaces as {@link ProtocolError}.
 *
 * @param opts - Connection and credential options.
 * @returns The authenticated session.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { connect } from 'edgeport/ftp';
 *
 * await using session = await connect({
 * 	hostname: 'ftp.example.com',
 * 	username: 'me',
 * 	password: 'secret'
 * });
 * const entries = await session.list('/pub');
 * ```
 */
export async function connect(opts: FtpConnectOptions): Promise<FtpSession> {
	const port = opts.port ?? DEFAULT_FTP_PORT;
	const socket = await coreConnect({
		hostname: opts.hostname,
		port,
		tls: 'off',
		// data transfers half-close the data channel, never the control channel
		connectTimeoutMs: opts.timeoutMs
	});
	try {
		return await _sessionOverSocket(socket, opts);
	} catch (err) {
		await socket.close().catch(() => {});
		throw err;
	}
}

/**
 * Connects, retrieves a single file, then quits.
 *
 * A one-shot convenience over {@link connect} that opens a session, runs {@link FtpSession.get},
 * and closes the connection before returning.
 *
 * @param opts - Connection, credential, `path`, and optional transfer (`type`/`offset`) options.
 * @returns The file's raw bytes (the tail from `opts.offset` when set).
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { getFile } from 'edgeport/ftp';
 *
 * const bytes = await getFile({ hostname: 'ftp.example.com', path: '/pub/readme.txt' });
 * const text = await getFile({ hostname: 'ftp.example.com', path: '/a.txt', type: 'ascii' });
 * ```
 */
export async function getFile(
	opts: FtpConnectOptions & { path: string } & FtpGetOptions
): Promise<Uint8Array> {
	await using session = await connect(opts);
	return session.get(opts.path, { type: opts.type, offset: opts.offset });
}

/**
 * Connects, stores a single file, then quits.
 *
 * A one-shot convenience over {@link connect} that opens a session, runs {@link FtpSession.put},
 * and closes the connection before returning.
 *
 * @param opts - Connection, credential, `path`, `data`, and optional transfer
 *   (`type`/`append`/`offset`) options.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { putFile } from 'edgeport/ftp';
 *
 * await putFile({
 * 	hostname: 'ftp.example.com',
 * 	username: 'me',
 * 	password: 'secret',
 * 	path: '/incoming/report.csv',
 * 	data: new TextEncoder().encode('a,b,c\n')
 * });
 * ```
 */
export async function putFile(
	opts: FtpConnectOptions & { path: string; data: Uint8Array } & FtpPutOptions
): Promise<void> {
	await using session = await connect(opts);
	await session.put(opts.path, opts.data, {
		type: opts.type,
		append: opts.append,
		offset: opts.offset
	});
}

/**
 * Builds an {@link FtpSession} over an already-connected control {@link CoreSocket}.
 *
 * Reads the `220` greeting, runs `USER`/`PASS`, and switches to binary mode with `TYPE I`.
 * Public {@link connect} dials the core transport and then calls this; tests call it directly
 * with a mock control socket. Data transfers still dial real passive connections.
 *
 * @param control - A connected core socket for the control channel.
 * @param opts - Connection and credential options.
 * @returns The authenticated session.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @internal
 */
export async function _sessionOverSocket(
	control: CoreSocket,
	opts: FtpConnectOptions
): Promise<FtpSession> {
	const client = new FtpControl(control.reader, control.writer, opts.timeoutMs, opts.hostname);

	// greeting (220)
	await client.expect(await client.read(), 220);

	const username = opts.username ?? DEFAULT_USERNAME;
	const password = opts.password ?? '';
	const userReply = await client.command(`USER ${username}`);
	// 230 = already logged in, 202 = login superfluous; otherwise USER must ask for a password
	if (userReply.code !== 230 && userReply.code !== 202) {
		client.expect(userReply, 331, 332);
		// expect maps 530/532 to AuthError and any other non-2xx to ProtocolError
		client.expect(await client.command(`PASS ${password}`), 230, 202);
	}

	// binary mode for all transfers
	client.expect(await client.command('TYPE I'), 200);

	return new FtpSessionImpl(client, control);
}

// drives the numeric-reply control loop and opens passive data connections
class FtpControl {
	readonly #reader: FramedReader;
	readonly #writer: FramedWriter;
	readonly #timeoutMs: number | undefined;
	readonly #host: string;
	// tracks the negotiated TYPE so we only re-issue the command when it actually changes
	#currentType: FtpTransferType = 'binary';

	constructor(
		reader: FramedReader,
		writer: FramedWriter,
		timeoutMs: number | undefined,
		host: string
	) {
		this.#reader = reader;
		this.#writer = writer;
		this.#timeoutMs = timeoutMs;
		this.#host = host;
	}

	// issues TYPE A / TYPE I only when the requested type differs from the negotiated one
	async ensureType(type: FtpTransferType): Promise<void> {
		if (this.#currentType === type) return;
		this.expect(await this.command(type === 'ascii' ? 'TYPE A' : 'TYPE I'), 200);
		this.#currentType = type;
	}

	// issues REST <offset> ahead of a transfer command (350 = restart marker accepted)
	async rest(offset: number): Promise<void> {
		this.expect(await this.command(`REST ${offset}`), 350);
	}

	// reads one logical reply, consuming all lines of a multiline block
	async read(): Promise<FtpReply> {
		const first = await this.#reader.readLine(this.#timeoutMs);
		const m = /^(\d{3})([ -]?)/.exec(first);
		if (!m) {
			throw new ProtocolError(`malformed ftp reply: ${first}`, { protocol: PROTO });
		}
		const lines = [first];
		// multiline: opener is "NNN-"; continue until a line begins "NNN " (same code + space)
		if (m[2] === '-') {
			const code = m[1]!;
			const terminator = `${code} `;
			for (;;) {
				const next = await this.#reader.readLine(this.#timeoutMs);
				lines.push(next);
				if (next.startsWith(terminator)) break;
			}
		}
		return parseReply(lines);
	}

	// sends a command line and reads its reply
	async command(line: string): Promise<FtpReply> {
		await this.#writer.writeLine(line);
		return this.read();
	}

	// asserts a reply's code is one of the expected ones, mapping failures to the right error
	expect(reply: FtpReply, ...codes: number[]): FtpReply {
		if (codes.includes(reply.code)) return reply;
		// 530 (not logged in) and 532 (need account for storing) are auth failures
		if (reply.code === 530 || reply.code === 532) {
			throw new AuthError(`ftp ${reply.code}: ${reply.text}`, { protocol: PROTO });
		}
		throw new ProtocolError(`ftp ${reply.code}: ${reply.text}`, { protocol: PROTO });
	}

	// opens a passive data connection: prefer EPSV, fall back to PASV on rejection
	async openPassive(): Promise<CoreSocket> {
		let host: string;
		let port: number;
		const epsv = await this.command('EPSV');
		if (epsv.code === 229) {
			host = this.#host;
			port = parseEpsv(epsv.text);
		} else {
			const pasv = this.expect(await this.command('PASV'), 227);
			const parsed = parsePasv(pasv.text);
			host = parsed.host;
			port = parsed.port;
		}
		return coreConnect({ hostname: host, port, tls: 'off', connectTimeoutMs: this.#timeoutMs });
	}
}

/** {@link FtpSession} backed by an {@link FtpControl}. */
class FtpSessionImpl implements FtpSession {
	readonly #control: FtpControl;
	readonly #socket: CoreSocket;

	constructor(control: FtpControl, socket: CoreSocket) {
		this.#control = control;
		this.#socket = socket;
	}

	// shared download path: open data channel, send command, read to EOF, await completion.
	// REST must be sent on the control channel after the data channel is open but before the
	// transfer command, so it is issued here rather than by the caller.
	async #download(command: string, offset?: number): Promise<Uint8Array> {
		const data = await this.#control.openPassive();
		try {
			if (offset) await this.#control.rest(offset);
			// 150/125 preliminary, then bytes flow on the data channel
			this.#control.expect(await this.#control.command(command), 150, 125);
			const bytes = await drainReader(data.reader);
			await data.close();
			// 226/250 completion
			this.#control.expect(await this.#control.read(), 226, 250);
			return bytes;
		} catch (err) {
			await data.close().catch(() => {});
			throw err;
		}
	}

	async list(path?: string): Promise<FtpEntry[]> {
		const bytes = await this.#download(path ? `LIST ${path}` : 'LIST');
		return splitLines(bytes).map(parseListLine);
	}

	async nameList(path?: string): Promise<string[]> {
		const bytes = await this.#download(path ? `NLST ${path}` : 'NLST');
		return splitLines(bytes);
	}

	async get(path: string, opts?: FtpGetOptions): Promise<Uint8Array> {
		await this.#control.ensureType(opts?.type ?? 'binary');
		return this.#download(`RETR ${path}`, opts?.offset);
	}

	async getStream(path: string, opts?: FtpGetOptions): Promise<ReadableStream<Uint8Array>> {
		await this.#control.ensureType(opts?.type ?? 'binary');
		const data = await this.#control.openPassive();
		try {
			if (opts?.offset) await this.#control.rest(opts.offset);
			this.#control.expect(await this.#control.command(`RETR ${path}`), 150, 125);
		} catch (err) {
			await data.close().catch(() => {});
			throw err;
		}
		const control = this.#control;
		// stream owns the data connection; the completion reply is read once the source drains
		return new ReadableStream<Uint8Array>({
			start: async (controller) => {
				try {
					for await (const chunk of readAllChunks(data.reader)) {
						controller.enqueue(chunk);
					}
					await data.close();
					control.expect(await control.read(), 226, 250);
					controller.close();
				} catch (err) {
					await data.close().catch(() => {});
					controller.error(err);
				}
			}
		});
	}

	async put(path: string, data: Uint8Array, opts?: FtpPutOptions): Promise<void> {
		await this.#control.ensureType(opts?.type ?? 'binary');
		const conn = await this.#control.openPassive();
		try {
			// APPE appends; otherwise STOR, optionally restarted at a byte offset via REST
			const append = opts?.append ?? false;
			const command = append ? `APPE ${path}` : `STOR ${path}`;
			if (!append && opts?.offset) await this.#control.rest(opts.offset);
			this.#control.expect(await this.#control.command(command), 150, 125);
			await conn.writer.write(data);
			// half-close the data channel to signal end of transfer
			await conn.writer.close();
			this.#control.expect(await this.#control.read(), 226, 250);
		} finally {
			await conn.close().catch(() => {});
		}
	}

	async delete(path: string): Promise<void> {
		this.#control.expect(await this.#control.command(`DELE ${path}`), 250);
	}

	async mkdir(path: string): Promise<void> {
		this.#control.expect(await this.#control.command(`MKD ${path}`), 257);
	}

	async rmdir(path: string): Promise<void> {
		this.#control.expect(await this.#control.command(`RMD ${path}`), 250);
	}

	async rename(from: string, to: string): Promise<void> {
		this.#control.expect(await this.#control.command(`RNFR ${from}`), 350);
		this.#control.expect(await this.#control.command(`RNTO ${to}`), 250);
	}

	async cwd(path: string): Promise<void> {
		this.#control.expect(await this.#control.command(`CWD ${path}`), 250);
	}

	async pwd(): Promise<string> {
		const reply = this.#control.expect(await this.#control.command('PWD'), 257);
		return parsePwd(reply.text);
	}

	async size(path: string): Promise<number> {
		const reply = this.#control.expect(await this.#control.command(`SIZE ${path}`), 213);
		const n = Number(reply.text.trim());
		if (!Number.isFinite(n)) {
			throw new ProtocolError(`malformed SIZE reply: ${reply.text}`, { protocol: PROTO });
		}
		return n;
	}

	async exists(path: string): Promise<boolean> {
		try {
			await this.size(path);
			return true;
		} catch (err) {
			// a missing path surfaces as ProtocolError (550); anything else (connection, auth) rethrows
			if (err instanceof ProtocolError) return false;
			throw err;
		}
	}

	async ensureDir(path: string): Promise<void> {
		// preserve a leading slash so absolute paths build from the root
		const absolute = path.startsWith('/');
		const segments = path.split('/').filter((s) => s.length > 0);
		let prefix = absolute ? '' : '.';
		for (const segment of segments) {
			prefix = prefix === '' ? `/${segment}` : `${prefix}/${segment}`;
			const reply = await this.#control.command(`MKD ${prefix}`);
			// 550 means the segment already exists (or cannot be made); single-level MKD, so ignore
			if (reply.code === 257 || reply.code === 550) continue;
			this.#control.expect(reply, 257);
		}
	}

	async getText(path: string, opts?: FtpGetOptions): Promise<string> {
		return new TextDecoder().decode(await this.get(path, opts));
	}

	async putText(path: string, content: string, opts?: FtpPutOptions): Promise<void> {
		await this.put(path, new TextEncoder().encode(content), opts);
	}

	async getJson<T = unknown>(path: string): Promise<T> {
		return JSON.parse(await this.getText(path)) as T;
	}

	async putJson(path: string, value: unknown, opts?: { space?: number }): Promise<void> {
		await this.putText(path, JSON.stringify(value, null, opts?.space));
	}

	async removeAll(path: string): Promise<void> {
		const trimmed = path.trim();
		// guard against wiping the server root or the working directory
		if (trimmed === '' || trimmed === '/') {
			throw new ProtocolError(`refusing to removeAll on ${JSON.stringify(path)}`, {
				protocol: PROTO
			});
		}
		// depth-first: clear children before removing the directory itself
		const entries = await this.list(trimmed);
		for (const entry of entries) {
			// skip the self/parent links some servers include in LIST output
			if (entry.name === '.' || entry.name === '..') continue;
			const child = trimmed.endsWith('/') ? `${trimmed}${entry.name}` : `${trimmed}/${entry.name}`;
			if (entry.isDirectory) {
				await this.removeAll(child);
			} else {
				await this.delete(child);
			}
		}
		await this.rmdir(trimmed);
	}

	async mtime(path: string): Promise<Date> {
		const reply = this.#control.expect(await this.#control.command(`MDTM ${path}`), 213);
		return parseMdtm(reply.text);
	}

	async close(): Promise<void> {
		try {
			await this.#control.command('QUIT');
		} catch {
			// best-effort quit; the socket close below is what matters
		}
		await this.#socket.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

// reads a FramedReader to EOF into one Uint8Array (used by RETR/LIST/NLST)
async function drainReader(reader: FramedReader): Promise<Uint8Array> {
	const chunks: Uint8Array[] = [];
	let total = 0;
	for await (const chunk of readAllChunks(reader)) {
		chunks.push(chunk);
		total += chunk.length;
	}
	const out = new Uint8Array(total);
	let off = 0;
	for (const chunk of chunks) {
		out.set(chunk, off);
		off += chunk.length;
	}
	return out;
}

// yields the bytes of a FramedReader until the peer half-closes the data connection.
// FramedReader has no partial-at-EOF read, so we probe the buffered region with peek (which
// leaves a clean carry on EOF) and consume exactly what is confirmed present with readN.
async function* readAllChunks(reader: FramedReader): AsyncGenerator<Uint8Array> {
	for (;;) {
		// peek(1) forces one underlying pull; ConnectionError here means a clean EOF
		try {
			await reader.peek(1);
		} catch (err) {
			if (err instanceof ConnectionError) return;
			throw err;
		}
		// grow the peek until the next size would block past EOF; peek returns exactly `probe`
		// bytes or throws ConnectionError at the tail, so `have` is the confirmed buffered count
		let have = 1;
		for (;;) {
			const probe = have * 2;
			try {
				await reader.peek(probe);
			} catch (err) {
				if (err instanceof ConnectionError) break;
				throw err;
			}
			have = probe;
		}
		yield await reader.readN(have);
	}
}

// extracts the quoted path from a 257 reply ("/home/me" is current directory), un-doubling ""
function parsePwd(text: string): string {
	const m = /"((?:[^"]|"")*)"/.exec(text);
	if (!m) return text.trim();
	return m[1]!.replace(/""/g, '"');
}

// splits decoded text bytes into non-empty CRLF/LF-delimited lines
function splitLines(bytes: Uint8Array): string[] {
	const text = new TextDecoder().decode(bytes);
	return text.split(/\r?\n/).filter((line) => line.length > 0);
}
