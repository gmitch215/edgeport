/**
 * @fileoverview Syslog client (RFC 5424 messages over TCP, RFC 6587 framing, RFC 5425 TLS).
 *
 * A dependency-free syslog sender for the Cloudflare Workers runtime. It formats RFC 5424
 * structured messages (PRI, version, timestamp, host/app/proc/msg ids, structured data, and
 * the free-form message) and writes them over a TCP transport framed per RFC 6587: either
 * octet-counting (a decimal byte length, a space, then the message) or non-transparent
 * LF-framing (the message followed by a single LF). Transport security is implicit TLS or a
 * STARTTLS-style upgrade per RFC 5425.
 *
 * Syslog over TCP is fire-and-forget: the server sends no replies, so this module never
 * reads from the socket. The transport is the shared core
 * ({@link import('../core').connect}); this module never touches `cloudflare:sockets`
 * directly. {@link connect} returns a reusable {@link SyslogSession}; {@link send} is the
 * one-shot convenience that opens, logs one line, and closes.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { connect as coreConnect, ProtocolError, type CoreSocket, type FramedWriter } from '../core';

const PROTOCOL = 'syslog';
const DEFAULT_PORT = 514;
const VERSION = 1;
const NIL = '-';

const encoder = new TextEncoder();

/**
 * RFC 5424 severity levels, lowest number is most severe.
 *
 * The numeric value is half of the PRI calculation: `PRI = facility * 8 + severity`. Pass
 * a member of this enum, its number, or its lowercase name to any logging call.
 *
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { Severity } from 'edgeport/syslog';
 *
 * console.log(Severity.error); // 3
 * ```
 */
export enum Severity {
	emerg = 0,
	alert = 1,
	crit = 2,
	error = 3,
	warning = 4,
	notice = 5,
	info = 6,
	debug = 7
}

/**
 * RFC 5424 facility codes.
 *
 * The numeric value is multiplied by 8 in the PRI calculation. Pass a member of this enum,
 * its number, or its lowercase name to any logging call.
 *
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { Facility } from 'edgeport/syslog';
 *
 * console.log(Facility.local0); // 16
 * ```
 */
export enum Facility {
	kern = 0,
	user = 1,
	mail = 2,
	daemon = 3,
	auth = 4,
	syslog = 5,
	lpr = 6,
	news = 7,
	uucp = 8,
	cron = 9,
	authpriv = 10,
	ftp = 11,
	ntp = 12,
	audit = 13,
	alert = 14,
	clock = 15,
	local0 = 16,
	local1 = 17,
	local2 = 18,
	local3 = 19,
	local4 = 20,
	local5 = 21,
	local6 = 22,
	local7 = 23
}

/** A severity given as the enum, its numeric value, or its lowercase name. */
export type SeverityInput = Severity | number | keyof typeof Severity;

/** A facility given as the enum, its numeric value, or its lowercase name. */
export type FacilityInput = Facility | number | keyof typeof Facility;

/**
 * One RFC 5424 structured-data element: an SD-ID plus its parameters.
 *
 * Renders as `[SD-ID NAME="VALUE" ...]`. Param values are escaped per RFC 5424 (the
 * characters `"`, `\`, and `]` are backslash-escaped). The SD-ID and param names are
 * written verbatim, so keep them to the RFC's restricted character set.
 *
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * const sd = { id: 'exampleSDID@32473', params: { iut: '3', eventID: '1011' } };
 * ```
 */
export interface StructuredDataElement {
	/** The SD-ID, e.g. `'exampleSDID@32473'`. */
	id: string;
	/** Parameter name/value pairs; values are escaped on render. */
	params: Record<string, string>;
}

/** Framing mode for the wire, per RFC 6587. */
export type Framing = 'octet-counting' | 'lf';

/**
 * Options for opening a syslog session.
 *
 * Per-message defaults set here (`appName`, `hostnameField`, `procId`) are applied to every
 * {@link SyslogSession.log} that does not override them.
 *
 * @since 1.0.0
 */
export interface SyslogConnectOptions {
	/** Collector hostname (also used for TLS certificate validation). */
	hostname: string;
	/** TCP port; defaults to 514. */
	port?: number;
	/**
	 * Transport security:
	 * - `'off'` (default): plaintext TCP.
	 * - `'implicit'`: TLS from the first byte (RFC 5425).
	 * - `'starttls'`: connect in plaintext, then upgrade immediately.
	 */
	tls?: 'off' | 'implicit' | 'starttls';
	/** Wire framing; defaults to `'octet-counting'`. */
	framing?: Framing;
	/** Default APP-NAME field for every message. */
	appName?: string;
	/** Default HOSTNAME field for every message. */
	hostnameField?: string;
	/** Default PROCID field for every message. */
	procId?: string;
	/** Connect deadline in milliseconds. */
	timeoutMs?: number;
}

/**
 * A single log record to format and send.
 *
 * Only `severity` and `message` are required. Absent fields render as the NIL value `-`,
 * except `facility` (defaults to `user`), `timestamp` (defaults to now), and the
 * `appName`/`hostname`/`procId` session defaults.
 *
 * @since 1.0.0
 */
export interface LogOptions {
	/** Severity as the enum, number, or lowercase name. */
	severity: SeverityInput;
	/** Facility as the enum, number, or lowercase name; defaults to `user`. */
	facility?: FacilityInput;
	/** The free-form message text (a leading BOM + UTF-8 is preserved as given). */
	message: string;
	/** Structured-data elements, or omit for the NIL value. */
	structuredData?: StructuredDataElement[];
	/** APP-NAME override for this message. */
	appName?: string;
	/** MSGID override for this message. */
	msgId?: string;
	/** PROCID override for this message. */
	procId?: string;
	/** TIMESTAMP as a `Date` or pre-formatted string; defaults to now. */
	timestamp?: Date | string;
	/** HOSTNAME override for this message. */
	hostname?: string;
}

/**
 * A live syslog session that can send one or more records.
 *
 * Obtain one with {@link connect}. It is an `AsyncDisposable`, so it can be scoped with
 * `await using` and closes the socket on disposal. Because syslog over TCP is one-way, no
 * method ever reads a reply.
 *
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { connect } from 'edgeport/syslog';
 *
 * await using session = await connect({ hostname: 'logs.example.com', appName: 'api' });
 * await session.log({ severity: 'info', message: 'service started' });
 * ```
 */
export interface SyslogSession extends AsyncDisposable {
	/**
	 * Formats a record as an RFC 5424 line, frames it, and writes it.
	 *
	 * @param opts - The record to send.
	 * @returns Resolves once the bytes are written to the transport.
	 * @throws {ProtocolError} If the message cannot be formatted.
	 * @throws {ConnectionError} If the write fails.
	 */
	log(opts: LogOptions): Promise<void>;
	/**
	 * Frames and sends an already-formatted line verbatim.
	 *
	 * @param rawLine - A complete syslog message; it is framed but not otherwise altered.
	 * @returns Resolves once the bytes are written.
	 */
	emit(rawLine: string): Promise<void>;
	/** Closes the underlying socket. */
	close(): Promise<void>;
}

/**
 * Resolves a {@link SeverityInput} to its numeric value.
 *
 * Accepts the enum, a raw number, or a lowercase name such as `'info'`. The range is
 * checked so an out-of-range number or unknown name fails fast.
 *
 * @param input - The severity to resolve.
 * @returns The numeric severity, 0 through 7.
 * @throws {ProtocolError} If the value is not a valid severity.
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { resolveSeverity } from 'edgeport/syslog';
 *
 * resolveSeverity('info'); // 6
 * resolveSeverity(3); // 3
 * ```
 */
export function resolveSeverity(input: SeverityInput): number {
	return resolveCode(input, Severity, 7, 'severity');
}

/**
 * Resolves a {@link FacilityInput} to its numeric value.
 *
 * Accepts the enum, a raw number, or a lowercase name such as `'local0'`. The range is
 * checked so an out-of-range number or unknown name fails fast.
 *
 * @param input - The facility to resolve.
 * @returns The numeric facility, 0 through 23.
 * @throws {ProtocolError} If the value is not a valid facility.
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { resolveFacility } from 'edgeport/syslog';
 *
 * resolveFacility('local0'); // 16
 * resolveFacility(1); // 1
 * ```
 */
export function resolveFacility(input: FacilityInput): number {
	return resolveCode(input, Facility, 23, 'facility');
}

/** Shared name/number resolver for the two enums, with a range check. */
function resolveCode(
	input: number | string,
	table: Record<string, string | number>,
	max: number,
	what: string
): number {
	if (typeof input === 'number') {
		if (!Number.isInteger(input) || input < 0 || input > max) {
			throw new ProtocolError(`invalid ${what}: ${input} (expected 0..${max})`, {
				protocol: PROTOCOL
			});
		}
		return input;
	}
	// reverse-mapped numeric enums expose name->number; string lookup must yield a number
	const mapped = table[input];
	if (typeof mapped !== 'number') {
		throw new ProtocolError(`unknown ${what} name: ${JSON.stringify(input)}`, {
			protocol: PROTOCOL
		});
	}
	return mapped;
}

/**
 * Computes the RFC 5424 PRI value from a facility and severity.
 *
 * `PRI = facility * 8 + severity`. Both inputs are resolved first, so names and numbers
 * give the same result.
 *
 * @param facility - The facility input.
 * @param severity - The severity input.
 * @returns The integer priority value.
 * @throws {ProtocolError} If either input is invalid.
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { computePri } from 'edgeport/syslog';
 *
 * computePri('local0', 'info'); // 16 * 8 + 6 = 134
 * ```
 */
export function computePri(facility: FacilityInput, severity: SeverityInput): number {
	return resolveFacility(facility) * 8 + resolveSeverity(severity);
}

/** Escapes a structured-data param value per RFC 5424 (backslash-escape " \ and ]). */
function escapeSdValue(value: string): string {
	return value.replace(/([\\\]"])/g, '\\$1');
}

/** Renders the STRUCTURED-DATA field: `-` when empty, else one or more SD-ELEMENTs. */
function renderStructuredData(elements?: StructuredDataElement[]): string {
	if (!elements || elements.length === 0) return NIL;
	let out = '';
	for (const el of elements) {
		out += `[${el.id}`;
		for (const [name, value] of Object.entries(el.params)) {
			out += ` ${name}="${escapeSdValue(value)}"`;
		}
		out += ']';
	}
	return out;
}

/** Formats a timestamp field: an ISO8601 string for a Date, the string as-is, or NIL. */
function renderTimestamp(timestamp?: Date | string): string {
	if (timestamp === undefined) return new Date().toISOString();
	if (timestamp instanceof Date) return timestamp.toISOString();
	return timestamp;
}

/** A field value or the NIL placeholder when blank. */
function field(value: string | undefined): string {
	return value === undefined || value === '' ? NIL : value;
}

/**
 * Builds the full RFC 5424 message line (no framing applied).
 *
 * Assembles `<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP
 * STRUCTURED-DATA SP MSG`. Absent header fields render as `-`; the message is appended
 * verbatim (any leading BOM is preserved).
 *
 * @param opts - The record and the session defaults already merged in.
 * @returns The formatted line, without any RFC 6587 framing.
 * @throws {ProtocolError} If the severity or facility is invalid.
 * @internal
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { _formatRfc5424 } from 'edgeport/syslog';
 *
 * _formatRfc5424({
 * 	severity: 'info',
 * 	facility: 'local0',
 * 	message: 'hello',
 * 	timestamp: '2025-01-01T00:00:00Z'
 * });
 * // "<134>1 2025-01-01T00:00:00Z - - - - - hello"
 * ```
 */
export function _formatRfc5424(opts: LogOptions): string {
	const pri = computePri(opts.facility ?? Facility.user, opts.severity);
	const timestamp = renderTimestamp(opts.timestamp);
	const hostname = field(opts.hostname);
	const appName = field(opts.appName);
	const procId = field(opts.procId);
	const msgId = field(opts.msgId);
	const sd = renderStructuredData(opts.structuredData);
	const header = `<${pri}>${VERSION} ${timestamp} ${hostname} ${appName} ${procId} ${msgId} ${sd}`;
	return `${header} ${opts.message}`;
}

/**
 * Frames a message line into wire bytes per RFC 6587.
 *
 * Octet-counting prepends the decimal byte length and a space; LF-framing appends a single
 * trailing LF. The length is computed on the UTF-8 byte length, not the character count, so
 * multibyte messages frame correctly.
 *
 * @param line - The formatted message line.
 * @param framing - The framing mode.
 * @returns The bytes to write to the transport.
 * @internal
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { _frame } from 'edgeport/syslog';
 *
 * new TextDecoder().decode(_frame('hi', 'octet-counting')); // "2 hi"
 * new TextDecoder().decode(_frame('hi', 'lf')); // "hi\n"
 * ```
 */
export function _frame(line: string, framing: Framing): Uint8Array {
	const body = encoder.encode(line);
	if (framing === 'lf') {
		const out = new Uint8Array(body.length + 1);
		out.set(body, 0);
		out[body.length] = 0x0a; // trailing LF
		return out;
	}
	// octet-counting: "<len> " + body, where len is the byte length of body
	const prefix = encoder.encode(`${body.length} `);
	const out = new Uint8Array(prefix.length + body.length);
	out.set(prefix, 0);
	out.set(body, prefix.length);
	return out;
}

/** Builds a {@link SyslogSession} backed by an already-connected, post-handshake socket. */
function makeSession(
	socket: CoreSocket,
	writer: FramedWriter,
	opts: SyslogConnectOptions
): SyslogSession {
	const framing: Framing = opts.framing ?? 'octet-counting';
	let closed = false;

	const emit = async (rawLine: string): Promise<void> => {
		await writer.write(_frame(rawLine, framing));
	};

	const log = async (logOpts: LogOptions): Promise<void> => {
		// session defaults fill in fields the call omits
		const line = _formatRfc5424({
			...logOpts,
			appName: logOpts.appName ?? opts.appName,
			procId: logOpts.procId ?? opts.procId,
			hostname: logOpts.hostname ?? opts.hostnameField
		});
		await emit(line);
	};

	const close = async (): Promise<void> => {
		if (closed) return;
		closed = true;
		await socket.close();
	};

	return {
		log,
		emit,
		close,
		[Symbol.asyncDispose]: close
	};
}

/**
 * Wraps an already-connected core socket in a {@link SyslogSession}.
 *
 * Public {@link connect} dials the transport (and upgrades TLS when asked) then calls this;
 * unit tests call it directly with a mock socket to drive the wire format without a real
 * network. No handshake is performed because syslog over TCP has none.
 *
 * @param socket - A connected core socket. For `'starttls'` it must have been opened with
 *   `tls: 'starttls'` so {@link CoreSocket.startTls} works.
 * @param opts - The session options.
 * @returns A ready {@link SyslogSession}.
 * @internal
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { _sessionFromSocket } from 'edgeport/syslog';
 *
 * const session = _sessionFromSocket(socket, { hostname: 'logs.example.com' });
 * await session.log({ severity: 'info', message: 'up' });
 * ```
 */
export function _sessionFromSocket(socket: CoreSocket, opts: SyslogConnectOptions): SyslogSession {
	let active = socket;
	if ((opts.tls ?? 'off') === 'starttls') {
		// rfc 5425: upgrade immediately; the socket swaps out so re-acquire the writer below
		active = active.startTls({ expectedServerHostname: opts.hostname });
	}
	return makeSession(active, active.writer, opts);
}

/**
 * Opens a syslog session over TCP.
 *
 * Connects to the collector (plaintext by default, implicit TLS, or a STARTTLS upgrade),
 * applies the framing and per-message defaults, and returns a reusable
 * {@link SyslogSession}. Remember to {@link SyslogSession.close} (or use `await using`) to
 * release the socket.
 *
 * @param opts - Connection and default-field options.
 * @returns A ready session.
 * @throws {ConnectionError} If the socket cannot be opened.
 * @throws {ProtocolError} If a default facility or severity is later found invalid.
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { connect, Severity } from 'edgeport/syslog';
 *
 * const session = await connect({ hostname: 'logs.example.com', appName: 'api' });
 * try {
 * 	await session.log({
 * 		severity: Severity.warning,
 * 		message: 'disk almost full',
 * 		structuredData: [{ id: 'meta@1', params: { pct: '92' } }]
 * 	});
 * } finally {
 * 	await session.close();
 * }
 * ```
 */
export async function connect(opts: SyslogConnectOptions): Promise<SyslogSession> {
	const tls = opts.tls ?? 'off';
	const port = opts.port ?? DEFAULT_PORT;
	const socket = await coreConnect({
		hostname: opts.hostname,
		port,
		tls: tls === 'implicit' ? 'on' : tls === 'starttls' ? 'starttls' : 'off',
		connectTimeoutMs: opts.timeoutMs
	});
	return _sessionFromSocket(socket, opts);
}

/**
 * Sends a single log record in one call: connect, log once, close.
 *
 * A convenience wrapper over {@link connect} + {@link SyslogSession.log} for the fire-once
 * case. The session is always closed, even if logging throws.
 *
 * @param opts - Connection options merged with the record fields.
 * @returns Resolves once the message is written and the socket is closed.
 * @throws {ConnectionError} If the socket cannot be opened.
 * @throws {ProtocolError} If the record cannot be formatted.
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { send } from 'edgeport/syslog';
 *
 * await send({
 * 	hostname: 'logs.example.com',
 * 	appName: 'cron',
 * 	severity: 'notice',
 * 	message: 'nightly job complete'
 * });
 * ```
 */
export async function send(opts: SyslogConnectOptions & LogOptions): Promise<void> {
	const session = await connect(opts);
	try {
		await session.log(opts);
	} finally {
		await session.close();
	}
}
