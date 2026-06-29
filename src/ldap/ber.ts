/**
 * @fileoverview A minimal BER/DER reader and writer scoped to the LDAP wire format.
 *
 * LDAP (RFC 4511) encodes every message as a BER-encoded `LDAPMessage`, a tree of
 * tag-length-value triples. This module implements just enough of BER to build and parse
 * those messages: definite-length encoding (short and long form), the universal tags LDAP
 * uses (INTEGER, ENUMERATED, OCTET STRING, BOOLEAN, SEQUENCE, SET), and the APPLICATION and
 * context-specific class tags the protocol layers on top. It is not a general ASN.1 codec;
 * indefinite lengths and the bulk of the universal type space are intentionally absent.
 *
 * The {@link BerWriter} composes children bottom-up into byte buffers, and {@link BerReader}
 * walks a buffer with a cursor, handing out sub-cursors for constructed values. Together they
 * give the LDAP and filter codecs a small, testable foundation.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */

/** Universal BER tag for INTEGER. */
export const TAG_INTEGER = 0x02;
/** Universal BER tag for OCTET STRING. */
export const TAG_OCTET_STRING = 0x04;
/** Universal BER tag for BOOLEAN. */
export const TAG_BOOLEAN = 0x01;
/** Universal BER tag for ENUMERATED. */
export const TAG_ENUMERATED = 0x0a;
/** Universal BER tag for a constructed SEQUENCE. */
export const TAG_SEQUENCE = 0x30;
/** Universal BER tag for a constructed SET. */
export const TAG_SET = 0x31;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Builds an APPLICATION-class tag byte.
 *
 * @param n - The application tag number (0..30).
 * @param constructed - Whether the value is constructed (a SEQUENCE-like body) or primitive.
 * @returns The single tag byte (class bits `01`, constructed bit set when requested).
 * @since 1.0.0
 * @example
 * ```typescript
 * applicationTag(0, true); // 0x60: BindRequest [APPLICATION 0]
 * ```
 */
export function applicationTag(n: number, constructed: boolean): number {
	return 0x40 | (constructed ? 0x20 : 0x00) | (n & 0x1f);
}

/**
 * Builds a context-specific tag byte.
 *
 * @param n - The context tag number (0..30).
 * @param constructed - Whether the value is constructed or primitive.
 * @returns The single tag byte (class bits `10`, constructed bit set when requested).
 * @since 1.0.0
 * @example
 * ```typescript
 * contextTag(0, false); // 0x80: simple-auth credential in a BindRequest
 * contextTag(0, true); // 0xA0: the `and` filter
 * ```
 */
export function contextTag(n: number, constructed: boolean): number {
	return 0x80 | (constructed ? 0x20 : 0x00) | (n & 0x1f);
}

// encodes a definite length: short form below 128, else long form (length-of-length + bytes)
function encodeLength(len: number): Uint8Array {
	if (len < 0x80) return new Uint8Array([len]);
	const bytes: number[] = [];
	let n = len;
	while (n > 0) {
		bytes.unshift(n & 0xff);
		n >>= 8;
	}
	return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

// minimal two's-complement big-endian encoding of a signed integer (LDAP ints are small)
function encodeIntContent(value: number): Uint8Array {
	if (!Number.isSafeInteger(value)) {
		throw new RangeError(`BER integer out of safe range: ${value}`);
	}
	const bytes: number[] = [];
	let n = value;
	if (n === 0) return new Uint8Array([0]);
	const negative = n < 0;
	// build little-endian magnitude bytes, then fix sign/padding
	do {
		bytes.unshift(n & 0xff);
		n = Math.floor(n / 256);
	} while (n !== 0 && n !== -1);
	if (negative) {
		// ensure the high bit is set so the value reads back as negative
		if ((bytes[0]! & 0x80) === 0) bytes.unshift(0xff);
	} else if ((bytes[0]! & 0x80) !== 0) {
		// pad so a positive value is not misread as negative
		bytes.unshift(0x00);
	}
	return new Uint8Array(bytes);
}

/**
 * Composes BER elements as byte buffers, building constructed values from their children.
 *
 * Every method returns a freshly allocated `Uint8Array` containing a complete TLV element, so
 * callers nest them by passing the outputs as children to {@link BerWriter.sequence},
 * {@link BerWriter.set}, or {@link BerWriter.tagged}.
 *
 * @since 1.0.0
 * @example
 * ```typescript
 * const w = new BerWriter();
 * const msg = w.sequence([w.integer(1), w.tagged(applicationTag(0, true), w.integer(3))]);
 * ```
 */
export class BerWriter {
	/**
	 * Encodes a raw TLV with an explicit tag byte and pre-built content.
	 *
	 * @param tag - The single tag byte (use {@link applicationTag}/{@link contextTag} helpers).
	 * @param content - The already-encoded value bytes.
	 * @returns The complete element: tag, length, then content.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * new BerWriter().tagged(contextTag(7, false), new TextEncoder().encode('mail'));
	 * ```
	 */
	tagged(tag: number, content: Uint8Array): Uint8Array {
		const len = encodeLength(content.length);
		const out = new Uint8Array(1 + len.length + content.length);
		out[0] = tag;
		out.set(len, 1);
		out.set(content, 1 + len.length);
		return out;
	}

	/**
	 * Encodes a universal INTEGER.
	 *
	 * @param value - A safe-integer value.
	 * @returns The encoded INTEGER element.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * new BerWriter().integer(3); // version 3
	 * ```
	 */
	integer(value: number): Uint8Array {
		return this.tagged(TAG_INTEGER, encodeIntContent(value));
	}

	/**
	 * Encodes a universal ENUMERATED (same content rules as INTEGER, different tag).
	 *
	 * @param value - The enumerated value.
	 * @returns The encoded ENUMERATED element.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * new BerWriter().enumerated(2); // search scope: subtree
	 * ```
	 */
	enumerated(value: number): Uint8Array {
		return this.tagged(TAG_ENUMERATED, encodeIntContent(value));
	}

	/**
	 * Encodes a universal OCTET STRING.
	 *
	 * @param value - The bytes, or a string encoded as UTF-8.
	 * @returns The encoded OCTET STRING element.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * new BerWriter().octetString('cn=admin');
	 * ```
	 */
	octetString(value: Uint8Array | string): Uint8Array {
		const bytes = typeof value === 'string' ? encoder.encode(value) : value;
		return this.tagged(TAG_OCTET_STRING, bytes);
	}

	/**
	 * Encodes a universal BOOLEAN.
	 *
	 * @param value - The boolean value.
	 * @returns The encoded BOOLEAN element (`0xff` for true, `0x00` for false).
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * new BerWriter().boolean(false); // typesOnly
	 * ```
	 */
	boolean(value: boolean): Uint8Array {
		return this.tagged(TAG_BOOLEAN, new Uint8Array([value ? 0xff : 0x00]));
	}

	/**
	 * Encodes a constructed SEQUENCE from its children.
	 *
	 * @param children - The already-encoded child elements, in order.
	 * @returns The encoded SEQUENCE element (tag `0x30`).
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const w = new BerWriter();
	 * w.sequence([w.octetString('a'), w.octetString('b')]);
	 * ```
	 */
	sequence(children: Uint8Array[]): Uint8Array {
		return this.tagged(TAG_SEQUENCE, concat(children));
	}

	/**
	 * Encodes a constructed SET from its children.
	 *
	 * @param children - The already-encoded child elements.
	 * @returns The encoded SET element (tag `0x31`).
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const w = new BerWriter();
	 * w.set([w.octetString('top'), w.octetString('person')]);
	 * ```
	 */
	set(children: Uint8Array[]): Uint8Array {
		return this.tagged(TAG_SET, concat(children));
	}
}

/** Concatenates a list of byte buffers into one. */
function concat(parts: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const p of parts) total += p.length;
	const out = new Uint8Array(total);
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}

/** A single parsed BER element: its tag byte, value bytes, and a reader over the value. */
export interface BerElement {
	/** The element's tag byte. */
	tag: number;
	/** The element's raw value bytes (the V of the TLV). */
	content: Uint8Array;
	/** A reader positioned at the start of {@link BerElement.content}. */
	reader: BerReader;
	/** The full element including tag and length bytes. */
	raw: Uint8Array;
}

/**
 * Walks a BER buffer with a cursor, decoding one element at a time.
 *
 * A reader covers a byte range and advances as elements are read. Constructed values hand back
 * a child reader scoped to their content via {@link BerReader.readElement} or
 * {@link BerReader.sequence}, so nested structures are parsed recursively without copying the
 * whole tree up front.
 *
 * @since 1.0.0
 * @example
 * ```typescript
 * const r = new BerReader(messageBytes);
 * const seq = r.sequence();
 * const messageId = seq.integer();
 * ```
 */
export class BerReader {
	readonly #buf: Uint8Array;
	#pos: number;
	readonly #end: number;

	/**
	 * Creates a reader over a buffer or a slice of one.
	 *
	 * @param buf - The backing buffer.
	 * @param start - Start offset (default 0).
	 * @param end - Exclusive end offset (default `buf.length`).
	 */
	constructor(buf: Uint8Array, start = 0, end = buf.length) {
		this.#buf = buf;
		this.#pos = start;
		this.#end = end;
	}

	/**
	 * Reports whether any unread bytes remain in this reader's range.
	 *
	 * @returns `true` if at least one more element can be read.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * while (seq.hasMore()) seq.readElement();
	 * ```
	 */
	hasMore(): boolean {
		return this.#pos < this.#end;
	}

	/**
	 * Returns the tag byte of the next element without consuming it.
	 *
	 * @returns The next tag byte.
	 * @throws {RangeError} If no bytes remain.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * if (seq.peekTag() === contextTag(0, true)) handleAnd(seq.readElement());
	 * ```
	 */
	peekTag(): number {
		if (this.#pos >= this.#end) throw new RangeError('BER: peek past end of buffer');
		return this.#buf[this.#pos]!;
	}

	/**
	 * Reads and consumes the next element, returning its tag, value, and a child reader.
	 *
	 * @returns The parsed {@link BerElement}.
	 * @throws {RangeError} If the buffer is truncated or the length runs past the range.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const el = reader.readElement();
	 * console.log(el.tag.toString(16));
	 * ```
	 */
	readElement(): BerElement {
		const start = this.#pos;
		if (this.#pos >= this.#end) throw new RangeError('BER: read past end of buffer');
		const tag = this.#buf[this.#pos++]!;
		const len = this.#readLength();
		const contentStart = this.#pos;
		const contentEnd = contentStart + len;
		if (contentEnd > this.#end) {
			throw new RangeError(`BER: element length ${len} exceeds available bytes`);
		}
		this.#pos = contentEnd;
		const content = this.#buf.subarray(contentStart, contentEnd);
		return {
			tag,
			content,
			reader: new BerReader(this.#buf, contentStart, contentEnd),
			raw: this.#buf.subarray(start, contentEnd)
		};
	}

	// reads a definite length; long form encodes the byte count in the low 7 bits of the lead
	#readLength(): number {
		if (this.#pos >= this.#end) throw new RangeError('BER: truncated length');
		const first = this.#buf[this.#pos++]!;
		if (first < 0x80) return first;
		const count = first & 0x7f;
		if (count === 0) throw new RangeError('BER: indefinite length not supported');
		if (count > 4) throw new RangeError('BER: length too large');
		let len = 0;
		for (let i = 0; i < count; i++) {
			if (this.#pos >= this.#end) throw new RangeError('BER: truncated long-form length');
			len = len * 256 + this.#buf[this.#pos++]!;
		}
		return len;
	}

	/**
	 * Reads the next element and asserts it is a SEQUENCE, returning a reader over its body.
	 *
	 * @returns A child reader scoped to the sequence content.
	 * @throws {RangeError} If the next element is not a SEQUENCE.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const body = new BerReader(bytes).sequence();
	 * ```
	 */
	sequence(): BerReader {
		const el = this.readElement();
		if (el.tag !== TAG_SEQUENCE) {
			throw new RangeError(`BER: expected SEQUENCE (0x30), got 0x${el.tag.toString(16)}`);
		}
		return el.reader;
	}

	/**
	 * Reads the next element as a signed INTEGER (or ENUMERATED) value.
	 *
	 * @returns The decoded numeric value.
	 * @throws {RangeError} If the tag is neither INTEGER nor ENUMERATED.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const code = reader.integer();
	 * ```
	 */
	integer(): number {
		const el = this.readElement();
		if (el.tag !== TAG_INTEGER && el.tag !== TAG_ENUMERATED) {
			throw new RangeError(`BER: expected INTEGER/ENUMERATED, got 0x${el.tag.toString(16)}`);
		}
		return decodeIntContent(el.content);
	}

	/**
	 * Reads the next element as an ENUMERATED value (alias of {@link BerReader.integer}).
	 *
	 * @returns The decoded numeric value.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const resultCode = reader.enumerated();
	 * ```
	 */
	enumerated(): number {
		return this.integer();
	}

	/**
	 * Reads the next element as an OCTET STRING, returning its raw bytes.
	 *
	 * @returns The value bytes (a view into the backing buffer).
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const dn = new TextDecoder().decode(reader.octetString());
	 * ```
	 */
	octetString(): Uint8Array {
		return this.readElement().content;
	}

	/**
	 * Reads the next element as an OCTET STRING and decodes it as UTF-8.
	 *
	 * @returns The decoded string.
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * const diagnostic = reader.octetStringText();
	 * ```
	 */
	octetStringText(): string {
		return decoder.decode(this.octetString());
	}
}

// decodes a two's-complement big-endian signed integer
function decodeIntContent(bytes: Uint8Array): number {
	if (bytes.length === 0) return 0;
	let value = bytes[0]! & 0x80 ? -1 : 0;
	for (const b of bytes) value = value * 256 + b;
	return value;
}
