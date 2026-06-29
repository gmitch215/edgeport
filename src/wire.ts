/**
 * @fileoverview RFC 4251 section 5 data type codecs for the SSH protocol.
 *
 * Every SSH packet payload is built from a small set of primitive types: `byte`,
 * `boolean`, `uint32`, `uint64`, `string` (a length-prefixed byte blob), `mpint` (a
 * length-prefixed two's-complement big integer), and `name-list` (a comma-joined ASCII
 * list). {@link SshWriter} serializes them and {@link SshReader} parses them. Getting the
 * `mpint` rules exactly right matters: the exchange hash and every derived key feed
 * `mpint`-encoded values into a hash, so a stray leading byte corrupts the whole session.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { ProtocolError } from './core/errors';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/**
 * Encodes an unsigned big-endian magnitude as an SSH `mpint` body (without the length
 * prefix), applying the RFC 4251 rules: strip leading zero bytes to the minimal form,
 * then prepend a single `0x00` if the high bit of the first byte is set (so the value
 * stays positive). Zero encodes as an empty array.
 *
 * @param magnitude - Big-endian unsigned magnitude bytes.
 * @returns The minimal, sign-corrected mpint body.
 * @since 1.0.0
 */
export function toMpintBody(magnitude: Uint8Array): Uint8Array {
	let start = 0;
	while (start < magnitude.length && magnitude[start] === 0) start++;
	const trimmed = magnitude.subarray(start);
	if (trimmed.length === 0) return new Uint8Array(0);
	if ((trimmed[0]! & 0x80) !== 0) {
		const out = new Uint8Array(trimmed.length + 1);
		out.set(trimmed, 1);
		return out;
	}
	return trimmed.slice();
}

/** Builds an SSH packet payload from RFC 4251 primitive types. */
export class SshWriter {
	#chunks: Uint8Array[] = [];
	#length = 0;

	#push(chunk: Uint8Array): this {
		this.#chunks.push(chunk);
		this.#length += chunk.length;
		return this;
	}

	/** Writes a single byte. */
	byte(n: number): this {
		return this.#push(new Uint8Array([n & 0xff]));
	}

	/** Writes a boolean as `0x01` (true) or `0x00` (false). */
	boolean(b: boolean): this {
		return this.#push(new Uint8Array([b ? 1 : 0]));
	}

	/** Writes a big-endian uint32. */
	uint32(n: number): this {
		const b = new Uint8Array(4);
		new DataView(b.buffer).setUint32(0, n >>> 0, false);
		return this.#push(b);
	}

	/** Writes a big-endian uint64. */
	uint64(n: bigint): this {
		const b = new Uint8Array(8);
		new DataView(b.buffer).setBigUint64(0, BigInt(n), false);
		return this.#push(b);
	}

	/** Writes raw bytes with no length prefix. */
	raw(bytes: Uint8Array): this {
		return this.#push(bytes.slice());
	}

	/** Writes an SSH `string`: a uint32 length prefix followed by the bytes. */
	string(value: Uint8Array | string): this {
		const bytes = typeof value === 'string' ? textEncoder.encode(value) : value;
		this.uint32(bytes.length);
		return this.#push(bytes.slice());
	}

	/** Writes an SSH `mpint` from an unsigned big-endian magnitude. */
	mpint(magnitude: Uint8Array): this {
		return this.string(toMpintBody(magnitude));
	}

	/** Writes an SSH `name-list` (a `string` of comma-joined names). */
	nameList(names: string[]): this {
		return this.string(names.join(','));
	}

	/** Returns the assembled bytes. */
	bytes(): Uint8Array {
		const out = new Uint8Array(this.#length);
		let off = 0;
		for (const c of this.#chunks) {
			out.set(c, off);
			off += c.length;
		}
		return out;
	}
}

/** Parses an SSH packet payload built from RFC 4251 primitive types. */
export class SshReader {
	readonly #buf: Uint8Array;
	readonly #view: DataView;
	#off: number;

	constructor(buf: Uint8Array) {
		this.#buf = buf;
		this.#view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
		this.#off = 0;
	}

	/** Bytes not yet consumed. */
	get remaining(): number {
		return this.#buf.length - this.#off;
	}

	#need(n: number): void {
		if (this.#off + n > this.#buf.length) {
			throw new ProtocolError(`ssh wire: tried to read ${n} bytes with ${this.remaining} left`);
		}
	}

	/** Reads a single byte. */
	byte(): number {
		this.#need(1);
		return this.#buf[this.#off++]!;
	}

	/** Reads a boolean (any non-zero byte is true). */
	boolean(): boolean {
		return this.byte() !== 0;
	}

	/** Reads a big-endian uint32. */
	uint32(): number {
		this.#need(4);
		const n = this.#view.getUint32(this.#off, false);
		this.#off += 4;
		return n;
	}

	/** Reads a big-endian uint64. */
	uint64(): bigint {
		this.#need(8);
		const n = this.#view.getBigUint64(this.#off, false);
		this.#off += 8;
		return n;
	}

	/** Reads `n` raw bytes. */
	raw(n: number): Uint8Array {
		this.#need(n);
		const out = this.#buf.slice(this.#off, this.#off + n);
		this.#off += n;
		return out;
	}

	/** Reads an SSH `string` and returns its bytes. */
	string(): Uint8Array {
		const len = this.uint32();
		return this.raw(len);
	}

	/** Reads an SSH `string` and decodes it as UTF-8. */
	stringUtf8(): string {
		return textDecoder.decode(this.string());
	}

	/** Reads an SSH `mpint` body and returns it verbatim (sign byte included if present). */
	mpint(): Uint8Array {
		return this.string();
	}

	/** Reads an SSH `mpint` as a non-negative bigint. */
	mpintBigInt(): bigint {
		const body = this.string();
		let n = 0n;
		for (const b of body) n = (n << 8n) | BigInt(b);
		return n;
	}

	/** Reads an SSH `name-list` into an array (empty list -> `[]`). */
	nameList(): string[] {
		const s = textDecoder.decode(this.string());
		return s.length === 0 ? [] : s.split(',');
	}
}
