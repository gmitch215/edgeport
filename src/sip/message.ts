/**
 * @fileoverview SIP message model, parser, and serializer (RFC 3261 §7).
 *
 * A SIP message is a start line, a set of `Name: value` headers, a blank line, then an
 * optional body whose length is the `Content-Length` header. This module is pure (no I/O):
 * it turns bytes into a {@link SipMessage} and back, and provides the small helpers the rest
 * of the stack needs - URI parse/format, header parameter parsing, and RFC 3261 identifier
 * generation (branch, tag, Call-ID) built on the shared {@link import('../util').randomHex}.
 *
 * Header handling is a case-insensitive multimap that expands the RFC 3261 §20 compact forms
 * (`v`->Via, `f`->From, ...) on the way in and emits canonical names on the way out. Framing
 * (reading exactly one message off a socket) lives in `./transport`; this module only parses
 * a complete byte buffer.
 *
 * @author Gregory Mitchell
 * @since 1.0.3
 */
import { ProtocolError } from '../core';
import { randomHex } from '../util';

const PROTO = 'sip';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** The RFC 3261 branch parameter magic cookie; every compliant branch starts with it. */
export const BRANCH_MAGIC = 'z9hG4bK';

// compact header form -> canonical name (RFC 3261 §20, plus refer/event extensions)
const COMPACT: Record<string, string> = {
	i: 'Call-ID',
	m: 'Contact',
	e: 'Content-Encoding',
	l: 'Content-Length',
	c: 'Content-Type',
	f: 'From',
	s: 'Subject',
	k: 'Supported',
	t: 'To',
	v: 'Via',
	o: 'Event',
	r: 'Refer-To',
	b: 'Referred-By',
	u: 'Allow-Events'
};

// canonical casing for the headers we emit; anything else is passed through as given
const CANONICAL: Record<string, string> = {};
for (const name of [
	'Via',
	'From',
	'To',
	'Call-ID',
	'CSeq',
	'Max-Forwards',
	'Contact',
	'Content-Type',
	'Content-Length',
	'Expires',
	'Route',
	'Record-Route',
	'Path',
	'Supported',
	'Require',
	'Allow',
	'Allow-Events',
	'Event',
	'Subscription-State',
	'Accept',
	'User-Agent',
	'WWW-Authenticate',
	'Authorization',
	'Proxy-Authenticate',
	'Proxy-Authorization',
	'Refer-To',
	'Referred-By',
	'Content-Disposition',
	'Date',
	'Reason'
]) {
	CANONICAL[name.toLowerCase()] = name;
}

/** Canonicalizes a header name: expands a compact form, then applies known casing. */
function canonicalName(name: string): string {
	const lower = name.trim().toLowerCase();
	const expanded = lower.length === 1 && COMPACT[lower] ? COMPACT[lower] : name.trim();
	return CANONICAL[expanded.toLowerCase()] ?? expanded;
}

/**
 * An ordered, case-insensitive multimap of SIP headers.
 *
 * Names are canonicalized (compact forms expanded, known headers title-cased) so lookups are
 * name-insensitive while serialization stays tidy. A header may repeat (Via, Route, ...), so
 * {@link getAll} returns every value in insertion order and {@link get} returns the first.
 *
 * @since 1.0.3
 */
export class SipHeaders {
	// insertion-ordered entries; name is already canonical
	readonly #entries: Array<{ name: string; value: string }> = [];

	/**
	 * Appends a header (does not replace an existing one of the same name).
	 *
	 * @param name - Header name (compact forms accepted).
	 * @param value - Header value.
	 * @returns This instance, for chaining.
	 */
	add(name: string, value: string): this {
		this.#entries.push({ name: canonicalName(name), value: value.trim() });
		return this;
	}

	/**
	 * Sets a header, removing any existing values of the same name first.
	 *
	 * @param name - Header name (compact forms accepted).
	 * @param value - Header value.
	 * @returns This instance, for chaining.
	 */
	set(name: string, value: string): this {
		this.delete(name);
		return this.add(name, value);
	}

	/**
	 * Returns the first value of a header, or `undefined`.
	 *
	 * @param name - Header name (case-insensitive, compact accepted).
	 * @returns The first value, or `undefined` if absent.
	 */
	get(name: string): string | undefined {
		const c = canonicalName(name);
		return this.#entries.find((e) => e.name === c)?.value;
	}

	/**
	 * Returns every value of a header in order.
	 *
	 * @param name - Header name (case-insensitive, compact accepted).
	 * @returns All values (empty array if absent).
	 */
	getAll(name: string): string[] {
		const c = canonicalName(name);
		return this.#entries.filter((e) => e.name === c).map((e) => e.value);
	}

	/**
	 * Whether a header is present.
	 *
	 * @param name - Header name.
	 * @returns True if at least one value exists.
	 */
	has(name: string): boolean {
		const c = canonicalName(name);
		return this.#entries.some((e) => e.name === c);
	}

	/**
	 * Removes all values of a header.
	 *
	 * @param name - Header name.
	 * @returns This instance, for chaining.
	 */
	delete(name: string): this {
		const c = canonicalName(name);
		for (let i = this.#entries.length - 1; i >= 0; i--) {
			if (this.#entries[i]!.name === c) this.#entries.splice(i, 1);
		}
		return this;
	}

	/** Returns the ordered `[name, value]` entries (canonical names). */
	entries(): Array<[string, string]> {
		return this.#entries.map((e) => [e.name, e.value]);
	}

	/** A shallow copy. */
	clone(): SipHeaders {
		const h = new SipHeaders();
		for (const e of this.#entries) h.add(e.name, e.value);
		return h;
	}
}

/** A SIP request line: method + Request-URI. */
export interface SipRequest {
	/** Discriminant. */
	kind: 'request';
	/** The SIP method (e.g. `REGISTER`, `MESSAGE`, `INVITE`). */
	method: string;
	/** The Request-URI. */
	uri: string;
	/** The message headers. */
	headers: SipHeaders;
	/** The message body (empty when there is none). */
	body: Uint8Array;
}

/** A SIP status line: code + reason. */
export interface SipResponse {
	/** Discriminant. */
	kind: 'response';
	/** The three-digit status code. */
	status: number;
	/** The reason phrase. */
	reason: string;
	/** The message headers. */
	headers: SipHeaders;
	/** The message body (empty when there is none). */
	body: Uint8Array;
}

/** A parsed SIP message: either a {@link SipRequest} or a {@link SipResponse}. */
export type SipMessage = SipRequest | SipResponse;

/** Narrows a {@link SipMessage} to a request. */
export function isRequest(msg: SipMessage): msg is SipRequest {
	return msg.kind === 'request';
}

/** Narrows a {@link SipMessage} to a response. */
export function isResponse(msg: SipMessage): msg is SipResponse {
	return msg.kind === 'response';
}

/** A parsed SIP URI. */
export interface SipUri {
	/** Scheme: `sip` or `sips`. */
	scheme: 'sip' | 'sips';
	/** User part (before `@`), if present. */
	user?: string;
	/** Host (domain or IP). */
	host: string;
	/** Port, if present. */
	port?: number;
	/** URI parameters (`;name=value` or `;flag`), keyed by name (flags map to `''`). */
	params: Record<string, string>;
}

/**
 * Parses a SIP or SIPS URI, tolerating an enclosing `<...>` and a leading display name.
 *
 * @param input - A URI such as `sip:alice@example.com:5060;transport=tcp` or `"A" <sip:a@b>`.
 * @returns The parsed URI.
 * @throws {ProtocolError} If the scheme is not `sip`/`sips` or the host is missing.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { parseUri } from 'edgeport/sip';
 *
 * parseUri('<sip:bob@example.com;transport=tcp>').host; // 'example.com'
 * ```
 */
export function parseUri(input: string): SipUri {
	let s = input.trim();
	// strip a name-addr wrapper: [display-name] <uri>
	const angle = s.match(/<([^>]*)>/);
	if (angle) s = angle[1]!.trim();
	const schemeIdx = s.indexOf(':');
	const scheme = s.slice(0, schemeIdx).toLowerCase();
	if (scheme !== 'sip' && scheme !== 'sips') {
		throw new ProtocolError(`unsupported SIP uri scheme: ${JSON.stringify(scheme)}`, {
			protocol: PROTO
		});
	}
	let rest = s.slice(schemeIdx + 1);
	// uri params begin at the first ';'; uri headers (rare) at '?'
	const semi = rest.indexOf(';');
	const params: Record<string, string> = {};
	if (semi >= 0) {
		for (const p of rest.slice(semi + 1).split(';')) {
			if (!p) continue;
			const eq = p.indexOf('=');
			if (eq >= 0) params[p.slice(0, eq).toLowerCase()] = p.slice(eq + 1);
			else params[p.toLowerCase()] = '';
		}
		rest = rest.slice(0, semi);
	}
	let user: string | undefined;
	const at = rest.indexOf('@');
	if (at >= 0) {
		user = rest.slice(0, at);
		rest = rest.slice(at + 1);
	}
	let host = rest;
	let port: number | undefined;
	const colon = rest.lastIndexOf(':');
	if (colon >= 0 && !rest.includes(']')) {
		// host:port (skip IPv6 [::1] forms, which we leave in host)
		host = rest.slice(0, colon);
		port = Number(rest.slice(colon + 1));
	}
	if (!host) throw new ProtocolError('SIP uri is missing a host', { protocol: PROTO });
	return { scheme: scheme as 'sip' | 'sips', user, host, port, params };
}

/**
 * Formats a {@link SipUri} back into its string form.
 *
 * @param uri - The URI parts.
 * @returns The `scheme:user@host:port;params` string.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { formatUri } from 'edgeport/sip';
 *
 * formatUri({ scheme: 'sip', user: 'a', host: 'x', params: { transport: 'tcp' } });
 * // 'sip:a@x;transport=tcp'
 * ```
 */
export function formatUri(uri: SipUri): string {
	let s = `${uri.scheme}:`;
	if (uri.user) s += `${uri.user}@`;
	s += uri.host;
	if (uri.port !== undefined) s += `:${uri.port}`;
	for (const [name, value] of Object.entries(uri.params)) {
		s += value === '' ? `;${name}` : `;${name}=${value}`;
	}
	return s;
}

/**
 * Parses generic `;`-delimited header parameters (e.g. the tags on a Via or From).
 *
 * @param value - A header value whose parameters follow the first `;`.
 * @returns A record of parameter name (lowercased) to value (`''` for a flag).
 * @since 1.0.3
 * @example
 * ```typescript
 * import { parseParams } from 'edgeport/sip';
 *
 * parseParams('<sip:a@b>;tag=abc'); // { tag: 'abc' }
 * ```
 */
export function parseParams(value: string): Record<string, string> {
	const params: Record<string, string> = {};
	const parts = value.split(';');
	for (let i = 1; i < parts.length; i++) {
		const p = parts[i]!.trim();
		if (!p) continue;
		const eq = p.indexOf('=');
		if (eq >= 0) params[p.slice(0, eq).trim().toLowerCase()] = p.slice(eq + 1).trim();
		else params[p.toLowerCase()] = '';
	}
	return params;
}

/**
 * Reads a single header parameter's value (e.g. the `tag` off a From header).
 *
 * @param value - The header value.
 * @param name - The parameter name (case-insensitive).
 * @returns The parameter value, `''` for a valueless flag, or `undefined` if absent.
 * @since 1.0.3
 */
export function getParam(value: string, name: string): string | undefined {
	return parseParams(value)[name.toLowerCase()];
}

// index of the CRLFCRLF (or LFLF) that ends the header block
function headerEnd(bytes: Uint8Array): number {
	for (let i = 0; i + 1 < bytes.length; i++) {
		if (
			bytes[i] === 0x0d &&
			bytes[i + 1] === 0x0a &&
			bytes[i + 2] === 0x0d &&
			bytes[i + 3] === 0x0a
		) {
			return i + 4;
		}
		// tolerate bare LFLF
		if (bytes[i] === 0x0a && bytes[i + 1] === 0x0a) return i + 2;
	}
	return -1;
}

/**
 * Parses a complete SIP message from a byte buffer.
 *
 * The buffer must contain the whole message: start line, headers, the blank-line separator,
 * and exactly `Content-Length` body octets. Folded (continuation) header lines are unfolded.
 *
 * @param bytes - The complete message bytes.
 * @returns The parsed request or response.
 * @throws {ProtocolError} If the start line or header block is malformed.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { parseMessage, isResponse } from 'edgeport/sip';
 *
 * const msg = parseMessage(raw);
 * if (isResponse(msg)) console.log(msg.status);
 * ```
 */
export function parseMessage(bytes: Uint8Array): SipMessage {
	const end = headerEnd(bytes);
	const headerBytes = end < 0 ? bytes : bytes.subarray(0, end);
	const body = end < 0 ? new Uint8Array(0) : bytes.subarray(end);
	const text = decoder.decode(headerBytes);
	// unfold continuation lines (a line starting with SP/HTAB continues the previous)
	const unfolded = text.replace(/\r\n[ \t]+/g, ' ').replace(/\n[ \t]+/g, ' ');
	const lines = unfolded.split(/\r\n|\n/).filter((l, i) => !(i > 0 && l === ''));
	const startLine = lines.shift();
	if (!startLine) throw new ProtocolError('empty SIP message', { protocol: PROTO });

	const headers = new SipHeaders();
	for (const line of lines) {
		if (line === '') continue;
		const colon = line.indexOf(':');
		if (colon < 0)
			throw new ProtocolError(`malformed SIP header line: ${JSON.stringify(line)}`, {
				protocol: PROTO
			});
		headers.add(line.slice(0, colon), line.slice(colon + 1));
	}

	if (startLine.startsWith('SIP/2.0')) {
		// response: "SIP/2.0 SP status SP reason"
		const m = startLine.match(/^SIP\/2\.0\s+(\d{3})\s*(.*)$/);
		if (!m)
			throw new ProtocolError(`malformed SIP status line: ${JSON.stringify(startLine)}`, {
				protocol: PROTO
			});
		return { kind: 'response', status: Number(m[1]), reason: m[2] ?? '', headers, body };
	}
	// request: "METHOD SP Request-URI SP SIP/2.0"
	const m = startLine.match(/^(\S+)\s+(\S+)\s+SIP\/2\.0$/);
	if (!m)
		throw new ProtocolError(`malformed SIP request line: ${JSON.stringify(startLine)}`, {
			protocol: PROTO
		});
	return { kind: 'request', method: m[1]!, uri: m[2]!, headers, body };
}

/**
 * Serializes a {@link SipMessage} to bytes, forcing `Content-Length` to match the body.
 *
 * @param msg - The message to serialize.
 * @returns The complete message bytes with CRLF line endings.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { serializeMessage, SipHeaders } from 'edgeport/sip';
 *
 * const bytes = serializeMessage({
 * 	kind: 'request',
 * 	method: 'OPTIONS',
 * 	uri: 'sip:example.com',
 * 	headers: new SipHeaders().add('Max-Forwards', '70'),
 * 	body: new Uint8Array(0)
 * });
 * ```
 */
export function serializeMessage(msg: SipMessage): Uint8Array {
	const startLine =
		msg.kind === 'request'
			? `${msg.method} ${msg.uri} SIP/2.0`
			: `SIP/2.0 ${msg.status} ${msg.reason}`;
	const headers = msg.headers.clone();
	// Content-Length is authoritative on the wire; always set it from the body
	headers.set('Content-Length', String(msg.body.length));
	let head = startLine + '\r\n';
	for (const [name, value] of headers.entries()) head += `${name}: ${value}\r\n`;
	head += '\r\n';
	const headBytes = encoder.encode(head);
	const out = new Uint8Array(headBytes.length + msg.body.length);
	out.set(headBytes, 0);
	out.set(msg.body, headBytes.length);
	return out;
}

/**
 * Generates an RFC 3261-compliant Via branch parameter (the {@link BRANCH_MAGIC} cookie plus
 * random hex).
 *
 * @returns A unique branch token.
 * @since 1.0.3
 */
export function newBranch(): string {
	return BRANCH_MAGIC + randomHex(8);
}

/**
 * Generates a random From/To tag.
 *
 * @returns A unique tag token.
 * @since 1.0.3
 */
export function newTag(): string {
	return randomHex(6);
}

/**
 * Generates a Call-ID, optionally scoped to a host.
 *
 * @param host - Optional host to append as `random@host`.
 * @returns A unique Call-ID.
 * @since 1.0.3
 */
export function newCallId(host?: string): string {
	const id = randomHex(12);
	return host ? `${id}@${host}` : id;
}
