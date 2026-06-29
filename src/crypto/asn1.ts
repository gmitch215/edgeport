/**
 * @fileoverview A minimal DER (ASN.1) reader, just enough to parse PKCS#8
 * `EncryptedPrivateKeyInfo` (PBES2 / PBKDF2 / AES) for encrypted private keys.
 *
 * @internal
 */
import { AuthError } from '../core/errors';

const TAG = { INTEGER: 0x02, OCTET_STRING: 0x04, OID: 0x06, SEQUENCE: 0x30 };

/** A cursor over a DER-encoded byte range. */
export class Der {
	#buf: Uint8Array;
	#off: number;
	#end: number;

	constructor(buf: Uint8Array, off = 0, end = buf.length) {
		this.#buf = buf;
		this.#off = off;
		this.#end = end;
	}

	/** Whether more TLVs remain in this range. */
	hasMore(): boolean {
		return this.#off < this.#end;
	}

	/** The tag of the next TLV without consuming it. */
	peekTag(): number {
		return this.#buf[this.#off]!;
	}

	#byte(): number {
		if (this.#off >= this.#end) throw new AuthError('der: unexpected end of data');
		return this.#buf[this.#off++]!;
	}

	#length(): number {
		let b = this.#byte();
		if (b < 0x80) return b;
		const n = b & 0x7f;
		let len = 0;
		for (let i = 0; i < n; i++) len = len * 256 + this.#byte();
		return len;
	}

	// reads one tag-length-value, returning the value as its own cursor + raw bytes
	#tlv(expected?: number): { tag: number; value: Der; raw: Uint8Array } {
		const tag = this.#byte();
		if (expected !== undefined && tag !== expected) {
			throw new AuthError(
				`der: expected tag 0x${expected.toString(16)}, got 0x${tag.toString(16)}`
			);
		}
		const len = this.#length();
		const start = this.#off;
		this.#off += len;
		if (this.#off > this.#end) throw new AuthError('der: length exceeds bounds');
		return {
			tag,
			value: new Der(this.#buf, start, start + len),
			raw: this.#buf.subarray(start, start + len)
		};
	}

	/** Reads a SEQUENCE and returns a cursor over its contents. */
	sequence(): Der {
		return this.#tlv(TAG.SEQUENCE).value;
	}

	/** Reads an OBJECT IDENTIFIER as a dotted-decimal string. */
	oid(): string {
		const raw = this.#tlv(TAG.OID).raw;
		const parts: number[] = [Math.floor(raw[0]! / 40), raw[0]! % 40];
		let v = 0;
		for (let i = 1; i < raw.length; i++) {
			v = v * 128 + (raw[i]! & 0x7f);
			if ((raw[i]! & 0x80) === 0) {
				parts.push(v);
				v = 0;
			}
		}
		return parts.join('.');
	}

	/** Reads an OCTET STRING. */
	octetString(): Uint8Array {
		return this.#tlv(TAG.OCTET_STRING).raw;
	}

	/** Reads an INTEGER as a number (for small values like iteration counts). */
	integer(): number {
		const raw = this.#tlv(TAG.INTEGER).raw;
		let n = 0;
		for (const b of raw) n = n * 256 + b;
		return n;
	}

	/** Skips the next TLV. */
	skip(): void {
		this.#tlv();
	}
}
