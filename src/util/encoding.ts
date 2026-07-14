/**
 * @fileoverview Byte encoding helpers shared across the protocol modules.
 *
 * Every protocol needs to turn bytes into hex or base64 and back (SSH fingerprints, NATS
 * nonces, MIME attachments, nkey seeds, ...). These are Workers-safe (they use `btoa`/`atob`
 * and `TextEncoder`, never Node's `Buffer`) and pure, so they carry no transport dependency
 * and are published under the `edgeport/util` subpath for consumers too.
 *
 * @author Gregory Mitchell
 * @since 1.0.3
 */
import { ProtocolError } from '../core';

const PROTO = 'util';

/**
 * Encodes bytes as a lowercase hex string.
 *
 * @param bytes - The bytes to encode.
 * @returns The hex string (two characters per byte, no separators).
 * @since 1.0.3
 * @example
 * ```typescript
 * import { toHex } from 'edgeport/util';
 *
 * toHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef])); // 'deadbeef'
 * ```
 */
export function toHex(bytes: Uint8Array): string {
	let out = '';
	for (const b of bytes) out += b.toString(16).padStart(2, '0');
	return out;
}

/**
 * Decodes a hex string into bytes.
 *
 * Whitespace is ignored; the remaining input must be an even number of hex digits.
 *
 * @param hex - The hex string to decode.
 * @returns The decoded bytes.
 * @throws {ProtocolError} If the input has an odd length or a non-hex character.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { fromHex } from 'edgeport/util';
 *
 * fromHex('de ad be ef'); // Uint8Array [0xde, 0xad, 0xbe, 0xef]
 * ```
 */
export function fromHex(hex: string): Uint8Array {
	const clean = hex.replace(/\s+/g, '');
	if (clean.length % 2 !== 0) {
		throw new ProtocolError('hex string has an odd number of digits', { protocol: PROTO });
	}
	const out = new Uint8Array(clean.length / 2);
	for (let i = 0; i < out.length; i++) {
		const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
		if (Number.isNaN(byte)) {
			throw new ProtocolError('hex string has a non-hex character', { protocol: PROTO });
		}
		out[i] = byte;
	}
	return out;
}

/** Options for {@link toBase64}. */
export interface Base64Options {
	/** Emit URL-safe base64 (`-`/`_` instead of `+`/`/`). Defaults to false. */
	urlSafe?: boolean;
	/** Include `=` padding. Defaults to true for standard, false for URL-safe. */
	pad?: boolean;
}

/**
 * Encodes bytes as base64, standard or URL-safe.
 *
 * @param bytes - The bytes to encode.
 * @param opts - `urlSafe` swaps the alphabet to `-`/`_`; `pad` controls `=` padding (defaults
 *   to padded for standard base64 and unpadded for URL-safe, the usual conventions).
 * @returns The base64 string.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { toBase64 } from 'edgeport/util';
 *
 * toBase64(new TextEncoder().encode('hi>?')); // 'aGk+Pw=='
 * toBase64(new TextEncoder().encode('hi>?'), { urlSafe: true }); // 'aGk-Pw'
 * ```
 */
export function toBase64(bytes: Uint8Array, opts: Base64Options = {}): string {
	let bin = '';
	for (const b of bytes) bin += String.fromCharCode(b);
	let out = btoa(bin);
	if (opts.urlSafe) out = out.replace(/\+/g, '-').replace(/\//g, '_');
	const pad = opts.pad ?? !opts.urlSafe;
	if (!pad) out = out.replace(/=+$/, '');
	return out;
}

/**
 * Decodes a base64 string into bytes.
 *
 * Tolerant of input variation: a leading `data:...;base64,` prefix is stripped, both the
 * standard and URL-safe alphabets are accepted, and missing `=` padding is restored before
 * decoding.
 *
 * @param input - The base64 (or base64url, or data-URI) string.
 * @returns The decoded bytes.
 * @throws {ProtocolError} If the input is not valid base64.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { fromBase64 } from 'edgeport/util';
 *
 * new TextDecoder().decode(fromBase64('aGk-Pw')); // 'hi>?'
 * ```
 */
export function fromBase64(input: string): Uint8Array {
	// drop a data-uri prefix if present, then normalize the url-safe alphabet + padding
	let s = input.replace(/^data:[^,]*;base64,/, '').replace(/\s+/g, '');
	s = s.replace(/-/g, '+').replace(/_/g, '/');
	const remainder = s.length % 4;
	if (remainder === 1) {
		throw new ProtocolError('base64 string has an invalid length', { protocol: PROTO });
	}
	if (remainder > 0) s += '='.repeat(4 - remainder);
	let bin: string;
	try {
		bin = atob(s);
	} catch (cause) {
		throw new ProtocolError('input is not valid base64', { protocol: PROTO, cause });
	}
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}
