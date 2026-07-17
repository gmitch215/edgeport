/**
 * @fileoverview UTF-8 and JSON helpers so callers never hand-roll `TextEncoder` / `TextDecoder`.
 *
 * Every protocol that carries a text or JSON payload otherwise makes the caller write
 * `new TextEncoder().encode(...)` / `JSON.parse(new TextDecoder().decode(...))` by hand. These
 * pure helpers collapse that boilerplate into one call each, reusing a single shared encoder and
 * decoder, and are published under `edgeport/util` for consumers too. They follow the same
 * `to*` / `from*` convention as the hex and base64 codecs (`to*` turns bytes into a string form,
 * `from*` turns a string into bytes).
 *
 * @author Gregory Mitchell
 * @since 1.0.4
 */
import { ProtocolError } from '../core';

const PROTO = 'util';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Encodes a string as UTF-8 bytes.
 *
 * The inverse of {@link toUtf8}. Use it instead of `new TextEncoder().encode(s)`.
 *
 * @param s - The string to encode.
 * @returns The UTF-8 bytes.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { fromUtf8 } from 'edgeport/util';
 *
 * fromUtf8('hi'); // Uint8Array [0x68, 0x69]
 * ```
 */
export function fromUtf8(s: string): Uint8Array {
	return encoder.encode(s);
}

/**
 * Decodes UTF-8 bytes into a string.
 *
 * The inverse of {@link fromUtf8}. Use it instead of `new TextDecoder().decode(bytes)`.
 *
 * @param bytes - The UTF-8 bytes to decode.
 * @returns The decoded string.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { toUtf8 } from 'edgeport/util';
 *
 * toUtf8(new Uint8Array([0x68, 0x69])); // 'hi'
 * ```
 */
export function toUtf8(bytes: Uint8Array): string {
	return decoder.decode(bytes);
}

/**
 * Serializes a value to JSON and encodes it as UTF-8 bytes.
 *
 * A one-call replacement for `new TextEncoder().encode(JSON.stringify(value))`, handy for the
 * byte-oriented `publish` / `send` / `writeFile` APIs. Pair with {@link decodeJson} to round-trip.
 *
 * @param value - The value to serialize.
 * @param space - Optional `JSON.stringify` indentation (number of spaces); omit for compact output.
 * @returns The UTF-8 bytes of the JSON text.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { encodeJson } from 'edgeport/util';
 *
 * encodeJson({ ok: true }); // Uint8Array of '{"ok":true}'
 * ```
 */
export function encodeJson(value: unknown, space?: number): Uint8Array {
	return encoder.encode(JSON.stringify(value, null, space));
}

/**
 * Parses JSON from UTF-8 bytes or a string.
 *
 * A one-call replacement for `JSON.parse(new TextDecoder().decode(bytes))` that also accepts a
 * string directly, and reports a bad payload as a uniform {@link ProtocolError} rather than a raw
 * `SyntaxError`.
 *
 * @typeParam T - The expected shape of the decoded value.
 * @param input - The JSON payload, as UTF-8 bytes or a string.
 * @returns The parsed value.
 * @throws {ProtocolError} If the payload is not valid JSON.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { decodeJson } from 'edgeport/util';
 *
 * decodeJson<{ ok: boolean }>(new TextEncoder().encode('{"ok":true}')); // { ok: true }
 * ```
 */
export function decodeJson<T = unknown>(input: Uint8Array | string): T {
	const text = typeof input === 'string' ? input : decoder.decode(input);
	try {
		return JSON.parse(text) as T;
	} catch (cause) {
		throw new ProtocolError('input is not valid json', { protocol: PROTO, cause });
	}
}
