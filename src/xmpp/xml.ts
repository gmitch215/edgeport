/**
 * @fileoverview A minimal, transport-free streaming XML layer for XMPP.
 *
 * XMPP is not "documents": a client and server exchange one never-closing
 * `<stream:stream>` root whose direct children (`<message>`, `<presence>`, `<iq>`,
 * `<stream:features>`, ...) arrive as an open-ended sequence of stanzas. A DOM parser
 * cannot help because the document never ends. This module provides exactly what the
 * protocol needs and nothing more: a tiny {@link XmlElement} tree model, a
 * {@link serialize serializer} and {@link el builder}, an escape-hatch
 * {@link parseFragment} for raw XML strings, and an incremental {@link XmlStreamReader}
 * that pulls one tag at a time off a {@link FramedReader} and emits each completed
 * top-level stanza as it closes.
 *
 * It is deliberately not a general XML processor - no DTDs, no namespaces beyond the
 * `xmlns` attribute already on the wire, no mixed-content coalescing rules. It handles
 * the constructs XMPP servers actually send: start/end/self-closing tags, the special
 * never-closing stream header, the XML declaration, comments, CDATA, and the five named
 * plus numeric entities.
 *
 * @author Gregory Mitchell
 * @since 1.0.4
 */
import { ConnectionError, ProtocolError, type FramedReader } from '../core';

const PROTO = 'xmpp';
// the stream root open/close tag; it never nests and is reported as its own event
const STREAM_TAG = 'stream:stream';
// readUntil delimiter: the '>' byte that ends every tag
const GT = new Uint8Array([0x3e]);

/** A parsed XML node: either an {@link XmlElement} or a run of character data. */
export type XmlNode = XmlElement | string;

/**
 * A parsed XML element: its (possibly prefixed) tag name, its attributes, and its ordered
 * children (nested elements and text runs).
 *
 * @since 1.0.4
 */
export interface XmlElement {
	/** The tag name exactly as on the wire, including any prefix (e.g. `stream:features`). */
	name: string;
	/** Attributes as a plain map; values are already entity-decoded. */
	attrs: Record<string, string>;
	/** Child nodes in document order (elements and text). */
	children: XmlNode[];
}

/**
 * A structural event produced by {@link XmlStreamReader.readEvent}.
 *
 * - `open`: the stream root (`<stream:stream ...>`) opened; it never closes normally, so it
 *   is reported on its own rather than as a completed element.
 * - `element`: a complete top-level stanza (a direct child of the stream root) closed.
 * - `close`: the stream root closed (`</stream:stream>`).
 *
 * @since 1.0.4
 */
export type StreamEvent =
	| { type: 'open'; element: XmlElement }
	| { type: 'element'; element: XmlElement }
	| { type: 'close' };

/** Returns the local part of a (possibly prefixed) name: `stream:features` -> `features`. */
export function localName(name: string): string {
	const i = name.indexOf(':');
	return i === -1 ? name : name.slice(i + 1);
}

/**
 * Builds an {@link XmlElement}. Nullish children are dropped and arrays are flattened, so
 * conditional children (`cond ? el(...) : null`) and spread lists compose cleanly.
 *
 * @param name - The tag name (include a prefix if needed, e.g. `stream:features`).
 * @param attrs - Attribute map; omit or pass `{}` for none.
 * @param children - Child elements or text; `null`/`undefined` are skipped, arrays flattened.
 * @returns The constructed element.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { el, serialize } from 'edgeport/xmpp';
 *
 * const iq = el('iq', { type: 'get', id: '1' }, el('query', { xmlns: 'jabber:iq:roster' }));
 * serialize(iq); // <iq type="get" id="1"><query xmlns="jabber:iq:roster"/></iq>
 * ```
 */
export function el(
	name: string,
	attrs: Record<string, string> = {},
	...children: (XmlNode | null | undefined | (XmlNode | null | undefined)[])[]
): XmlElement {
	const kids: XmlNode[] = [];
	for (const c of children) {
		if (c === null || c === undefined) continue;
		if (Array.isArray(c)) {
			for (const x of c) if (x !== null && x !== undefined) kids.push(x);
		} else {
			kids.push(c);
		}
	}
	return { name, attrs, children: kids };
}

/**
 * Serializes an {@link XmlNode} back to its on-the-wire form.
 *
 * Attribute values and text are entity-escaped; an element with no children is emitted
 * self-closing (`<x/>`).
 *
 * @param node - The element or text to serialize.
 * @returns The XML string.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { el, serialize } from 'edgeport/xmpp';
 *
 * serialize(el('body', {}, 'hi & bye')); // <body>hi &amp; bye</body>
 * ```
 */
export function serialize(node: XmlNode): string {
	if (typeof node === 'string') return escapeText(node);
	let out = '<' + node.name;
	for (const [k, v] of Object.entries(node.attrs)) out += ` ${k}="${escapeAttr(v)}"`;
	if (node.children.length === 0) return out + '/>';
	out += '>';
	for (const c of node.children) out += serialize(c);
	return out + `</${node.name}>`;
}

/**
 * Parses a single complete XML element from a string (the raw-XML escape hatch).
 *
 * Intended for building a stanza payload from hand-written markup. The input must contain
 * exactly one root element (leading declaration/comments are ignored).
 *
 * @param xml - A well-formed XML fragment with a single root element.
 * @returns The parsed root element.
 * @throws {ProtocolError} If the input has no element or is malformed.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { parseFragment } from 'edgeport/xmpp';
 *
 * const geo = parseFragment("<geoloc xmlns='http://jabber.org/protocol/geoloc'><lat>1</lat></geoloc>");
 * ```
 */
export function parseFragment(xml: string): XmlElement {
	const stack: XmlElement[] = [];
	let root: XmlElement | undefined;
	let i = 0;
	while (i < xml.length) {
		if (xml[i] !== '<') {
			let j = xml.indexOf('<', i);
			if (j === -1) j = xml.length;
			const t = xml.slice(i, j);
			if (stack.length > 0 && t.length > 0) stack[stack.length - 1]!.children.push(unescapeXml(t));
			i = j;
			continue;
		}
		if (xml.startsWith('<!--', i)) {
			const end = xml.indexOf('-->', i);
			i = end === -1 ? xml.length : end + 3;
			continue;
		}
		if (xml.startsWith('<![CDATA[', i)) {
			const end = xml.indexOf(']]>', i);
			const content = xml.slice(i + 9, end === -1 ? xml.length : end);
			if (stack.length > 0) stack[stack.length - 1]!.children.push(content);
			i = end === -1 ? xml.length : end + 3;
			continue;
		}
		if (xml.startsWith('<?', i)) {
			const end = xml.indexOf('?>', i);
			i = end === -1 ? xml.length : end + 2;
			continue;
		}
		const end = findTagEnd(xml, i);
		if (end === -1) throw new ProtocolError('xml fragment: unterminated tag', { protocol: PROTO });
		const tag = parseTag(xml.slice(i, end + 1));
		i = end + 1;
		if (tag.kind === 'close') {
			const done = stack.pop();
			if (done && stack.length === 0) root = done;
		} else {
			const e = makeElement(tag);
			if (stack.length > 0) stack[stack.length - 1]!.children.push(e);
			if (tag.kind === 'empty') {
				if (stack.length === 0) root = e;
			} else {
				stack.push(e);
			}
		}
	}
	if (!root) throw new ProtocolError('xml fragment: no root element', { protocol: PROTO });
	return root;
}

/**
 * Finds the first child element matching a local name (and optionally an `xmlns`).
 *
 * @param parent - The element to search.
 * @param name - The local name to match (prefix-insensitive).
 * @param namespace - If given, require the child's `xmlns` attribute to equal it.
 * @returns The first matching child element, or `undefined`.
 * @since 1.0.4
 */
export function findChild(
	parent: XmlElement,
	name: string,
	namespace?: string
): XmlElement | undefined {
	for (const c of parent.children) {
		if (typeof c === 'string') continue;
		if (localName(c.name) !== name) continue;
		if (namespace !== undefined && c.attrs['xmlns'] !== namespace) continue;
		return c;
	}
	return undefined;
}

/**
 * Finds all child elements matching a local name (and optionally an `xmlns`).
 *
 * @param parent - The element to search.
 * @param name - The local name to match (prefix-insensitive).
 * @param namespace - If given, require each child's `xmlns` attribute to equal it.
 * @returns The matching child elements in document order (possibly empty).
 * @since 1.0.4
 */
export function findChildren(parent: XmlElement, name: string, namespace?: string): XmlElement[] {
	const out: XmlElement[] = [];
	for (const c of parent.children) {
		if (typeof c === 'string') continue;
		if (localName(c.name) !== name) continue;
		if (namespace !== undefined && c.attrs['xmlns'] !== namespace) continue;
		out.push(c);
	}
	return out;
}

/**
 * Returns the concatenated character data directly inside an element.
 *
 * @param element - The element whose text to collect.
 * @returns The joined text of the element's direct string children (empty if none).
 * @since 1.0.4
 */
export function text(element: XmlElement): string {
	let out = '';
	for (const c of element.children) if (typeof c === 'string') out += c;
	return out;
}

/**
 * Returns the first element child, if any (the payload slot for pubsub items and the like).
 *
 * @param element - The element to inspect.
 * @returns The first child that is an element, or `undefined`.
 * @since 1.0.4
 */
export function firstElement(element: XmlElement): XmlElement | undefined {
	for (const c of element.children) if (typeof c !== 'string') return c;
	return undefined;
}

// ---- streaming reader ---------------------------------------------------------------------

interface ParsedTag {
	kind: 'open' | 'close' | 'empty';
	name: string;
	attrs: Record<string, string>;
}

type Token = { kind: 'text'; value: string } | { kind: 'skip' } | { kind: 'tag'; tag: ParsedTag };

/**
 * Incrementally parses an XMPP byte stream into structural {@link StreamEvent}s.
 *
 * Wraps a {@link FramedReader} and pulls one tag at a time (reading up to each `>`), tracking
 * element depth. The stream root is reported once as an `open` event and never pushed onto the
 * stack, so each direct child of the root is emitted as a complete `element` event the moment it
 * closes; the root's own close is a `close` event. Text between top-level stanzas (whitespace
 * keep-alives) is ignored. Comments, the XML declaration, and processing instructions are
 * skipped; CDATA sections contribute their literal contents as text.
 *
 * @since 1.0.4
 */
export class XmlStreamReader {
	readonly #reader: FramedReader;
	readonly #decoder = new TextDecoder();
	#buf = '';
	#stack: XmlElement[] = [];
	#ended = false;

	/** @param reader - The framed reader to pull bytes from. */
	constructor(reader: FramedReader) {
		this.#reader = reader;
	}

	/**
	 * Reads the next structural event, or `null` once the underlying stream ends.
	 *
	 * @param timeoutMs - Optional per-read deadline.
	 * @returns The next {@link StreamEvent}, or `null` at end of stream.
	 * @throws {ProtocolError} If a closing tag has no matching open.
	 * @throws {TimeoutError} If `timeoutMs` elapses before a full tag arrives.
	 */
	async readEvent(timeoutMs?: number): Promise<StreamEvent | null> {
		for (;;) {
			const tok = await this.#readToken(timeoutMs);
			if (tok === null) return null;
			if (tok.kind === 'skip') continue;
			if (tok.kind === 'text') {
				// only meaningful inside a stanza; inter-stanza whitespace is dropped
				if (this.#stack.length > 0) this.#stack[this.#stack.length - 1]!.children.push(tok.value);
				continue;
			}
			const tag = tok.tag;
			if (tag.kind === 'open') {
				if (tag.name === STREAM_TAG) return { type: 'open', element: makeElement(tag) };
				const e = makeElement(tag);
				if (this.#stack.length > 0) this.#stack[this.#stack.length - 1]!.children.push(e);
				this.#stack.push(e);
				continue;
			}
			if (tag.kind === 'empty') {
				const e = makeElement(tag);
				if (this.#stack.length === 0) return { type: 'element', element: e };
				this.#stack[this.#stack.length - 1]!.children.push(e);
				continue;
			}
			// close tag
			if (tag.name === STREAM_TAG) return { type: 'close' };
			const done = this.#stack.pop();
			if (!done) throw new ProtocolError('xml: unbalanced closing tag', { protocol: PROTO });
			if (this.#stack.length === 0) return { type: 'element', element: done };
		}
	}

	// pulls one token out of the buffer, filling from the reader until one is complete
	async #readToken(timeoutMs?: number): Promise<Token | null> {
		for (;;) {
			const t = this.#tryToken();
			if (t) return t;
			if (!(await this.#fill(timeoutMs))) return null;
		}
	}

	// one underlying read up to the next '>' (always an ASCII byte boundary, so per-chunk
	// utf-8 decode is safe); false once the stream is exhausted
	async #fill(timeoutMs?: number): Promise<boolean> {
		if (this.#ended) return false;
		try {
			const chunk = await this.#reader.readUntil(GT, undefined, timeoutMs);
			this.#buf += this.#decoder.decode(chunk);
			return true;
		} catch (err) {
			if (err instanceof ConnectionError) {
				this.#ended = true;
				return false;
			}
			throw err;
		}
	}

	// parses a single complete token from the front of #buf, or null if more bytes are needed
	#tryToken(): Token | null {
		const buf = this.#buf;
		if (buf.length === 0) return null;
		if (buf[0] !== '<') {
			const lt = buf.indexOf('<');
			if (lt === -1) return null; // text may continue; wait for the following markup
			this.#buf = buf.slice(lt);
			return { kind: 'text', value: unescapeXml(buf.slice(0, lt)) };
		}
		if (buf.startsWith('<!--')) {
			const end = buf.indexOf('-->');
			if (end === -1) return null;
			this.#buf = buf.slice(end + 3);
			return { kind: 'skip' };
		}
		if (buf.startsWith('<![CDATA[')) {
			const end = buf.indexOf(']]>');
			if (end === -1) return null;
			const content = buf.slice(9, end);
			this.#buf = buf.slice(end + 3);
			return { kind: 'text', value: content };
		}
		if (buf.startsWith('<?')) {
			const end = buf.indexOf('?>');
			if (end === -1) return null;
			this.#buf = buf.slice(end + 2);
			return { kind: 'skip' };
		}
		if (buf.startsWith('<!')) {
			const end = buf.indexOf('>');
			if (end === -1) return null;
			this.#buf = buf.slice(end + 1);
			return { kind: 'skip' };
		}
		const end = findTagEnd(buf, 0);
		if (end === -1) return null; // '>' seen inside a quoted attr; need more bytes
		const raw = buf.slice(0, end + 1);
		this.#buf = buf.slice(end + 1);
		return { kind: 'tag', tag: parseTag(raw) };
	}
}

// ---- shared tag parsing -------------------------------------------------------------------

// index of the '>' that ends a tag starting at `start`, ignoring '>' inside quoted values
function findTagEnd(s: string, start: number): number {
	let quote = 0; // 0 none, 1 single, 2 double
	for (let i = start + 1; i < s.length; i++) {
		const c = s[i];
		if (quote === 0) {
			if (c === '"') quote = 2;
			else if (c === "'") quote = 1;
			else if (c === '>') return i;
		} else if (quote === 1 && c === "'") quote = 0;
		else if (quote === 2 && c === '"') quote = 0;
	}
	return -1;
}

const ATTR_RE = /([^\s=/]+)\s*=\s*("([^"]*)"|'([^']*)')/g;

// parses a full tag (including the surrounding '<' '>') into name/attrs/kind
function parseTag(raw: string): ParsedTag {
	let inner = raw.slice(1, raw.length - 1).trim();
	let kind: ParsedTag['kind'] = 'open';
	if (inner[0] === '/') {
		kind = 'close';
		inner = inner.slice(1).trim();
	} else if (inner.endsWith('/')) {
		kind = 'empty';
		inner = inner.slice(0, -1).trim();
	}
	let i = 0;
	while (i < inner.length && !isSpace(inner[i]!)) i++;
	const name = inner.slice(0, i);
	const attrs: Record<string, string> = {};
	if (kind !== 'close') {
		const rest = inner.slice(i);
		ATTR_RE.lastIndex = 0;
		let m: RegExpExecArray | null;
		while ((m = ATTR_RE.exec(rest)) !== null) {
			const val = m[3] !== undefined ? m[3] : (m[4] ?? '');
			attrs[m[1]!] = unescapeXml(val);
		}
	}
	return { kind, name, attrs };
}

function makeElement(tag: ParsedTag): XmlElement {
	return { name: tag.name, attrs: tag.attrs, children: [] };
}

function isSpace(c: string): boolean {
	return c === ' ' || c === '\t' || c === '\r' || c === '\n';
}

// ---- entities -----------------------------------------------------------------------------

/**
 * Decodes the five predefined XML entities plus numeric (`&#nn;` / `&#xhh;`) references.
 *
 * @param s - The escaped string.
 * @returns The decoded string.
 * @since 1.0.4
 */
export function unescapeXml(s: string): string {
	if (s.indexOf('&') === -1) return s;
	return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|lt|gt|amp|quot|apos);/g, (m, g: string) => {
		switch (g) {
			case 'lt':
				return '<';
			case 'gt':
				return '>';
			case 'amp':
				return '&';
			case 'quot':
				return '"';
			case 'apos':
				return "'";
		}
		const code =
			g[1] === 'x' || g[1] === 'X'
				? Number.parseInt(g.slice(2), 16)
				: Number.parseInt(g.slice(1), 10);
		return Number.isFinite(code) ? String.fromCodePoint(code) : m;
	});
}

/**
 * Escapes character data for a text node (`&`, `<`, `>`).
 *
 * @param s - The raw text.
 * @returns The escaped text.
 * @since 1.0.4
 */
export function escapeText(s: string): string {
	return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * Escapes an attribute value (`&`, `<`, `>`, `"`).
 *
 * @param s - The raw attribute value.
 * @returns The escaped value, safe inside double quotes.
 * @since 1.0.4
 */
export function escapeAttr(s: string): string {
	return s
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}
