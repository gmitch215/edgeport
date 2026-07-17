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
import { parseEmailAddress } from '../util';
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
	const domain =
		(parseEmailAddress(from).domain ?? '').replace(/[>\s].*$/, '').trim() || 'localhost';
	return `<${crypto.randomUUID()}@${domain}>`;
}

/** A single MIME header line; values are emitted as-is (caller keeps them ASCII). */
function header(name: string, value: string): string {
	return `${name}: ${value}`;
}

/** Encodes bytes as base64 wrapped at 76 columns (RFC 2045). */
function base64Lines(data: Uint8Array): string[] {
	let bin = '';
	for (const b of data) bin += String.fromCharCode(b);
	const b64 = btoa(bin);
	const out: string[] = [];
	for (let i = 0; i < b64.length; i += 76) out.push(b64.slice(i, i + 76));
	return out.length ? out : [''];
}

// renders the message body as a MIME entity (its content-type header line(s) + content),
// so it can be inlined or nested as the first part of a multipart/mixed envelope
function renderBody(
	text: string | undefined,
	html: string | undefined
): {
	headerLines: string[];
	contentLines: string[];
} {
	if (text !== undefined && html !== undefined) {
		const boundary = `=_alt_${crypto.randomUUID().replace(/-/g, '')}`;
		return {
			headerLines: [header('Content-Type', `multipart/alternative; boundary="${boundary}"`)],
			contentLines: [
				`--${boundary}`,
				header('Content-Type', 'text/plain; charset=utf-8'),
				'',
				...text.split(/\r\n|\n/),
				`--${boundary}`,
				header('Content-Type', 'text/html; charset=utf-8'),
				'',
				...html.split(/\r\n|\n/),
				`--${boundary}--`
			]
		};
	}
	if (html !== undefined) {
		return {
			headerLines: [header('Content-Type', 'text/html; charset=utf-8')],
			contentLines: html.split(/\r\n|\n/)
		};
	}
	return {
		headerLines: [header('Content-Type', 'text/plain; charset=utf-8')],
		contentLines: (text ?? '').split(/\r\n|\n/)
	};
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

	const body = renderBody(mail.text, mail.html);
	const attachments = mail.attachments ?? [];

	if (attachments.length === 0) {
		// no attachments -> the body entity is the message body
		lines.push(...body.headerLines, '', ...body.contentLines);
	} else {
		// attachments -> wrap the body + each file in a multipart/mixed envelope
		const boundary = `=_mixed_${crypto.randomUUID().replace(/-/g, '')}`;
		lines.push(header('Content-Type', `multipart/mixed; boundary="${boundary}"`));
		lines.push('', `--${boundary}`, ...body.headerLines, '', ...body.contentLines);
		for (const att of attachments) {
			lines.push(`--${boundary}`);
			lines.push(
				header(
					'Content-Type',
					`${att.contentType ?? 'application/octet-stream'}; name="${att.filename}"`
				)
			);
			lines.push(header('Content-Transfer-Encoding', 'base64'));
			lines.push(header('Content-Disposition', `attachment; filename="${att.filename}"`));
			lines.push('');
			lines.push(...base64Lines(att.content));
		}
		lines.push(`--${boundary}--`);
	}

	return encoder.encode(lines.join('\r\n'));
}
