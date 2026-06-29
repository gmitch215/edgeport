/**
 * @fileoverview RFC 5322 / MIME message builder for the SMTP client.
 *
 * Turns a structured {@link Mail} into the raw byte payload that goes between SMTP `DATA`
 * and the terminating `CRLF.CRLF`. It assembles the standard headers (From, To, Cc,
 * Subject, Date, MIME-Version, Message-ID), picks the right content type for a text-only,
 * html-only, or both-bodies message, and emits CRLF line endings throughout. When the
 * caller supplies a pre-built `raw` payload it is returned verbatim and no headers are
 * added.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import type { Mail } from './index';

const encoder = new TextEncoder();

/** Normalizes a recipient field (string or array) into a flat list of addresses. */
function toList(value: string | string[] | undefined): string[] {
	if (value === undefined) return [];
	return Array.isArray(value) ? value : [value];
}

/**
 * Generates a syntactically valid Message-ID using the From address domain when present.
 *
 * Uniqueness comes from `crypto.randomUUID()` (always available on the Workers runtime),
 * so two messages built in the same millisecond still differ.
 */
function messageId(from: string): string {
	const at = from.lastIndexOf('@');
	// strip a possible trailing '>' from a "Name <addr>" form
	const domainRaw = at >= 0 ? from.slice(at + 1) : 'localhost';
	const domain = domainRaw.replace(/[>\s].*$/, '').trim() || 'localhost';
	return `<${crypto.randomUUID()}@${domain}>`;
}

/** A single MIME header line; values are emitted as-is (caller keeps them ASCII). */
function header(name: string, value: string): string {
	return `${name}: ${value}`;
}

/**
 * Builds the raw RFC 5322 message bytes for a {@link Mail}.
 *
 * If `mail.raw` is set it is returned unchanged. Otherwise standard headers are generated
 * and the body is encoded as `text/plain`, `text/html`, or a `multipart/alternative`
 * envelope when both `text` and `html` are present. The returned bytes use CRLF line
 * endings and do NOT include SMTP dot-stuffing or the trailing `CRLF.CRLF` terminator;
 * the protocol layer adds those.
 *
 * @param mail - The message to render.
 * @returns The encoded message ready to feed into SMTP `DATA`.
 * @since 1.0.0
 *
 * @example
 * ```typescript
 * import { buildMime } from 'edgeport/smtp/mime';
 *
 * const bytes = buildMime({
 * 	from: 'me@example.com',
 * 	to: 'you@example.com',
 * 	subject: 'Hi',
 * 	text: 'Hello there'
 * });
 * // bytes is a CRLF-delimited RFC 5322 message
 * ```
 */
export function buildMime(mail: Mail): Uint8Array {
	if (mail.raw) return mail.raw;

	const to = toList(mail.to);
	const cc = toList(mail.cc);

	const lines: string[] = [];
	lines.push(header('From', mail.from));
	if (to.length) lines.push(header('To', to.join(', ')));
	if (cc.length) lines.push(header('Cc', cc.join(', ')));
	lines.push(header('Subject', mail.subject));
	lines.push(header('Date', new Date().toUTCString()));
	lines.push(header('Message-ID', messageId(mail.from)));
	lines.push(header('MIME-Version', '1.0'));

	// caller-supplied extra headers override none of the above; they are simply appended
	if (mail.headers) {
		for (const [name, value] of Object.entries(mail.headers)) {
			lines.push(header(name, value));
		}
	}

	const text = mail.text;
	const html = mail.html;

	if (text !== undefined && html !== undefined) {
		// both bodies -> multipart/alternative so clients pick the richest they render
		const boundary = `=_edgeport_${crypto.randomUUID().replace(/-/g, '')}`;
		lines.push(header('Content-Type', `multipart/alternative; boundary="${boundary}"`));
		lines.push('');
		lines.push(`--${boundary}`);
		lines.push(header('Content-Type', 'text/plain; charset=utf-8'));
		lines.push('');
		lines.push(...text.split(/\r\n|\n/));
		lines.push(`--${boundary}`);
		lines.push(header('Content-Type', 'text/html; charset=utf-8'));
		lines.push('');
		lines.push(...html.split(/\r\n|\n/));
		lines.push(`--${boundary}--`);
	} else if (html !== undefined) {
		lines.push(header('Content-Type', 'text/html; charset=utf-8'));
		lines.push('');
		lines.push(...html.split(/\r\n|\n/));
	} else {
		// default to a (possibly empty) text/plain body
		lines.push(header('Content-Type', 'text/plain; charset=utf-8'));
		lines.push('');
		lines.push(...(text ?? '').split(/\r\n|\n/));
	}

	return encoder.encode(lines.join('\r\n'));
}
