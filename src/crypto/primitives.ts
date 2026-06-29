/**
 * @fileoverview Hash, HMAC, and random-byte primitives, all from Workers WebCrypto.
 *
 * SSH assembles its key schedule and integrity checks from these. No primitive is
 * hand-rolled; each is a thin wrapper over `crypto.subtle` so the byte-exact behavior is
 * the runtime's, validated by the known-answer tests against RFC/NIST vectors.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */

/** A SHA-2 variant name as understood by both SSH and WebCrypto. */
export type HashName = 'SHA-256' | 'SHA-384' | 'SHA-512';

/** Computes a SHA-2 digest of `data`. */
export async function digest(hash: HashName, data: Uint8Array): Promise<Uint8Array> {
	const out = await crypto.subtle.digest(hash, data as BufferSource);
	return new Uint8Array(out);
}

/** Computes `SHA-256(data)`. */
export const sha256 = (data: Uint8Array) => digest('SHA-256', data);
/** Computes `SHA-384(data)`. */
export const sha384 = (data: Uint8Array) => digest('SHA-384', data);
/** Computes `SHA-512(data)`. */
export const sha512 = (data: Uint8Array) => digest('SHA-512', data);

/** Computes `HMAC(hash, key, data)`. */
export async function hmac(hash: HashName, key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
	const cryptoKey = await crypto.subtle.importKey(
		'raw',
		key as BufferSource,
		{ name: 'HMAC', hash },
		false,
		['sign']
	);
	const out = await crypto.subtle.sign('HMAC', cryptoKey, data as BufferSource);
	return new Uint8Array(out);
}

/** Concatenates byte arrays into one. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
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

/** Returns `n` cryptographically random bytes. */
export function randomBytes(n: number): Uint8Array {
	const b = new Uint8Array(n);
	crypto.getRandomValues(b);
	return b;
}

/** Constant-time comparison of two byte arrays. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
	return diff === 0;
}
