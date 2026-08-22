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
import { ProtocolError } from '../core/errors';
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
	return `${clean(name, 'header name')}: ${clean(value, `header ${name}`)}`;
}

/**
 * Refuses a CR or LF in anything that becomes part of a header line.
 *
 * A header block is delimited by CRLF and terminated by a blank line, so a newline reaching
 * this function is not a formatting problem -- it is a second header, or the start of the
 * body. `subject: 'Hi\r\nBcc: attacker@example.com'` silently adds a recipient, and
 * `'\r\n\r\n'` replaces the message. Every caller-supplied field arrives here: the addresses,
 * the subject, `headers`, and an attachment filename.
 *
 * THROWN, not stripped. A subject quietly missing a line is a message the sender did not
 * write, and folding it correctly (RFC 5322 §2.2.3) would mean guessing which of the two
 * meanings was intended. A NUL is refused with them; it terminates the string for some
 * downstream parsers and can hide the rest of the line from a filter that reads C strings.
 */
function clean(value: string, what: string): string {
	const text = String(value ?? '');
	if (/[\r\n\0]/.test(text)) {
		throw new ProtocolError(
			`${what} contains a line break or NUL, which would inject a header or a body`
		);
	}
	return text;
}

/** A header parameter as a quoted-string, with `\` and `"` escaped so it cannot end early. */
function quoted(value: string): string {
	return `"${String(value ?? '').replace(/([\\"])/g, '\\$1')}"`;
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
			// quoted-string escaping (RFC 2045 via RFC 822): a `"` in a filename would otherwise
			// close the parameter early and let the rest of the name become further parameters
			const filename = quoted(att.filename);
			lines.push(
				header('Content-Type', `${att.contentType ?? 'application/octet-stream'}; name=${filename}`)
			);
			lines.push(header('Content-Transfer-Encoding', 'base64'));
			lines.push(header('Content-Disposition', `attachment; filename=${filename}`));
			lines.push('');
			lines.push(...base64Lines(att.content));
		}
		lines.push(`--${boundary}--`);
	}

	return encoder.encode(lines.join('\r\n'));
}
