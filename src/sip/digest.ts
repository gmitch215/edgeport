/**
 * @fileoverview HTTP Digest access authentication for SIP (RFC 3261 §22, RFC 2617/7616).
 *
 * SIP servers challenge REGISTER/INVITE/MESSAGE with `401`/`407` carrying a `Digest` nonce;
 * the client answers with an `Authorization`/`Proxy-Authorization` header whose `response` is
 * a chained hash of the credentials, nonce, method, and URI. The default algorithm is MD5,
 * which the Workers WebCrypto does NOT provide, so this module ships a small, KAT-verified MD5
 * (RFC 1321) - the same "assemble the primitive the runtime lacks" pattern SSH uses for
 * ChaCha. SHA-256 (RFC 7616) is computed with WebCrypto.
 *
 * @author Gregory Mitchell
 * @since 1.0.3
 */
import { ProtocolError } from '../core';
import { randomHex, toHex } from '../util';

const PROTO = 'sip';
const encoder = new TextEncoder();

// per-round left-rotate amounts (RFC 1321)
const S = [
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
	20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6,
	10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
];

// per-round additive constants K[i] = floor(2^32 * abs(sin(i+1))) (RFC 1321)
const K = [
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
];

function rotl(x: number, c: number): number {
	return ((x << c) | (x >>> (32 - c))) >>> 0;
}

/**
 * Computes the MD5 digest of a byte buffer (RFC 1321).
 *
 * WebCrypto does not offer MD5, so this is a from-scratch implementation, verified against the
 * RFC 1321 test suite. Used for the common `algorithm=MD5` SIP digest path.
 *
 * @param input - The bytes to hash.
 * @returns The 16-byte MD5 digest.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { md5 } from 'edgeport/sip';
 *
 * md5(new TextEncoder().encode('abc')).length; // 16
 * ```
 */
export function md5(input: Uint8Array): Uint8Array {
	// padding: append 0x80, zero-fill to 56 mod 64, then the 64-bit little-endian bit length
	const origLenBits = input.length * 8;
	const withOne = input.length + 1;
	const padded = new Uint8Array(Math.floor((withOne + 8 + 63) / 64) * 64);
	padded.set(input, 0);
	padded[input.length] = 0x80;
	const dv = new DataView(padded.buffer);
	dv.setUint32(padded.length - 8, origLenBits >>> 0, true);
	dv.setUint32(padded.length - 4, Math.floor(origLenBits / 0x100000000) >>> 0, true);

	let a0 = 0x67452301;
	let b0 = 0xefcdab89;
	let c0 = 0x98badcfe;
	let d0 = 0x10325476;

	const M = new Uint32Array(16);
	for (let chunk = 0; chunk < padded.length; chunk += 64) {
		for (let i = 0; i < 16; i++) M[i] = dv.getUint32(chunk + i * 4, true);
		let A = a0;
		let B = b0;
		let C = c0;
		let D = d0;
		for (let i = 0; i < 64; i++) {
			let F: number;
			let g: number;
			if (i < 16) {
				F = (B & C) | (~B & D);
				g = i;
			} else if (i < 32) {
				F = (D & B) | (~D & C);
				g = (5 * i + 1) % 16;
			} else if (i < 48) {
				F = B ^ C ^ D;
				g = (3 * i + 5) % 16;
			} else {
				F = C ^ (B | ~D);
				g = (7 * i) % 16;
			}
			F = (F + A + K[i]! + M[g]!) >>> 0;
			A = D;
			D = C;
			C = B;
			B = (B + rotl(F, S[i]!)) >>> 0;
		}
		a0 = (a0 + A) >>> 0;
		b0 = (b0 + B) >>> 0;
		c0 = (c0 + C) >>> 0;
		d0 = (d0 + D) >>> 0;
	}

	const out = new Uint8Array(16);
	const odv = new DataView(out.buffer);
	odv.setUint32(0, a0, true);
	odv.setUint32(4, b0, true);
	odv.setUint32(8, c0, true);
	odv.setUint32(12, d0, true);
	return out;
}

/** MD5 of a string (UTF-8), rendered as lowercase hex. */
function md5Hex(data: string): string {
	return toHex(md5(encoder.encode(data)));
}

/** SHA-256 of a string (UTF-8), rendered as lowercase hex, via WebCrypto. */
async function sha256Hex(data: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', encoder.encode(data));
	return toHex(new Uint8Array(digest));
}

// dispatches the digest hash by algorithm name (md5 / md5-sess / sha-256 / sha-256-sess)
function hashHex(algorithm: string, data: string): Promise<string> {
	const alg = algorithm.toLowerCase();
	if (alg.startsWith('md5')) return Promise.resolve(md5Hex(data));
	if (alg.startsWith('sha-256')) return sha256Hex(data);
	return Promise.reject(
		new ProtocolError(`unsupported SIP digest algorithm: ${algorithm}`, { protocol: PROTO })
	);
}

/**
 * A parsed `Digest` authentication challenge from a `WWW-Authenticate` / `Proxy-Authenticate`
 * header.
 *
 * @since 1.0.3
 */
export interface DigestChallenge {
	/** The authentication realm. */
	realm: string;
	/** The server nonce. */
	nonce: string;
	/** The quality-of-protection list as sent (e.g. `'auth'` or `'auth,auth-int'`), if any. */
	qop?: string;
	/** The algorithm (e.g. `MD5`, `SHA-256`), if the server named one. */
	algorithm?: string;
	/** The opaque value to echo back, if any. */
	opaque?: string;
}

// splits a comma-separated k=v list, honoring quoted values that may contain commas
function splitAuthParams(s: string): Record<string, string> {
	const out: Record<string, string> = {};
	let i = 0;
	const n = s.length;
	while (i < n) {
		while (i < n && (s[i] === ' ' || s[i] === ',')) i++;
		const eq = s.indexOf('=', i);
		if (eq < 0) break;
		const key = s.slice(i, eq).trim().toLowerCase();
		let j = eq + 1;
		let value: string;
		if (s[j] === '"') {
			j++;
			let v = '';
			while (j < n && s[j] !== '"') {
				if (s[j] === '\\' && j + 1 < n) j++;
				v += s[j];
				j++;
			}
			value = v;
			j++; // closing quote
		} else {
			const end = s.indexOf(',', j);
			value = (end < 0 ? s.slice(j) : s.slice(j, end)).trim();
			j = end < 0 ? n : end;
		}
		out[key] = value;
		i = j;
	}
	return out;
}

/**
 * Parses a `Digest` challenge header value.
 *
 * @param headerValue - The value of a `WWW-Authenticate` or `Proxy-Authenticate` header.
 * @returns The parsed challenge.
 * @throws {ProtocolError} If it is not a Digest challenge or lacks realm/nonce.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { parseChallenge } from 'edgeport/sip';
 *
 * parseChallenge('Digest realm="a", nonce="b", qop="auth"').nonce; // 'b'
 * ```
 */
export function parseChallenge(headerValue: string): DigestChallenge {
	const trimmed = headerValue.trim();
	if (!/^digest\b/i.test(trimmed)) {
		throw new ProtocolError('not a Digest authentication challenge', { protocol: PROTO });
	}
	const params = splitAuthParams(trimmed.slice(trimmed.indexOf(' ') + 1));
	if (!params.realm || !params.nonce) {
		throw new ProtocolError('Digest challenge missing realm or nonce', { protocol: PROTO });
	}
	return {
		realm: params.realm,
		nonce: params.nonce,
		qop: params.qop,
		algorithm: params.algorithm,
		opaque: params.opaque
	};
}

// picks 'auth' from a qop list when offered; auth-int is not supported here
function pickQop(qop: string | undefined): 'auth' | undefined {
	if (!qop) return undefined;
	return qop
		.split(',')
		.map((q) => q.trim().toLowerCase())
		.includes('auth')
		? 'auth'
		: undefined;
}

/** Inputs for {@link computeDigestResponse}. */
export interface DigestParams {
	/** The account username. */
	username: string;
	/** The account password. */
	password: string;
	/** The SIP method being authenticated (e.g. `REGISTER`). */
	method: string;
	/** The digest URI (the Request-URI of the challenged request). */
	uri: string;
	/** The parsed server challenge. */
	challenge: DigestChallenge;
	/** Client nonce; a random one is generated when omitted. */
	cnonce?: string;
	/** Nonce count as 8 hex digits; defaults to `00000001`. */
	nc?: string;
}

/**
 * Computes the `Authorization` / `Proxy-Authorization` header value for a Digest challenge.
 *
 * Implements RFC 2617 (MD5, MD5-sess) and RFC 7616 (SHA-256, SHA-256-sess) with `qop=auth`,
 * falling back to the legacy RFC 2069 construction when the server offers no `qop`.
 *
 * @param params - Credentials, the request method/URI, and the parsed challenge.
 * @returns The full `Digest ...` header value to send back.
 * @throws {ProtocolError} If the challenge names an unsupported algorithm.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { computeDigestResponse, parseChallenge } from 'edgeport/sip';
 *
 * const header = await computeDigestResponse({
 * 	username: 'alice',
 * 	password: 'secret',
 * 	method: 'REGISTER',
 * 	uri: 'sip:example.com',
 * 	challenge: parseChallenge(wwwAuthenticate)
 * });
 * ```
 */
export async function computeDigestResponse(params: DigestParams): Promise<string> {
	const algorithm = params.challenge.algorithm ?? 'MD5';
	const alg = algorithm.toLowerCase();
	const sess = alg.endsWith('-sess');
	const qop = pickQop(params.challenge.qop);
	const cnonce = params.cnonce ?? randomHex(8);
	const nc = params.nc ?? '00000001';
	const nonce = params.challenge.nonce;

	let ha1 = await hashHex(alg, `${params.username}:${params.challenge.realm}:${params.password}`);
	if (sess) ha1 = await hashHex(alg, `${ha1}:${nonce}:${cnonce}`);
	const ha2 = await hashHex(alg, `${params.method}:${params.uri}`);
	const response = qop
		? await hashHex(alg, `${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
		: await hashHex(alg, `${ha1}:${nonce}:${ha2}`);

	const parts = [
		`username="${params.username}"`,
		`realm="${params.challenge.realm}"`,
		`nonce="${nonce}"`,
		`uri="${params.uri}"`,
		`response="${response}"`
	];
	if (params.challenge.algorithm) parts.push(`algorithm=${params.challenge.algorithm}`);
	if (qop) parts.push(`qop=${qop}`, `nc=${nc}`, `cnonce="${cnonce}"`);
	if (params.challenge.opaque !== undefined) parts.push(`opaque="${params.challenge.opaque}"`);
	return `Digest ${parts.join(', ')}`;
}
