/**
 * @fileoverview NATS nkey decoding and ed25519 signing for the Cloudflare Workers runtime.
 *
 * NATS nkeys are base32-encoded (RFC 4648, no padding) ed25519 key material framed with a
 * one- or two-byte role prefix and a trailing CRC-16 (XMODEM) checksum. This module decodes a
 * seed string (the `S...` form), recovers the role and the raw 32-byte ed25519 seed, derives
 * the matching public nkey string, and signs the server nonce using WebCrypto's Ed25519.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { AuthError } from '../core';

const PROTO = 'nats';

// RFC 4648 base32 alphabet, no padding
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B32_LOOKUP: Record<string, number> = {};
for (let i = 0; i < B32_ALPHABET.length; i++) B32_LOOKUP[B32_ALPHABET[i]!] = i;

// nkey role/prefix bytes (the high 5 bits identify the role)
const PREFIX_BYTE_SEED = 18 << 3; // 'S' family marker

// PKCS#8 DER header for an ed25519 private key (RFC 8410); the 32-byte seed follows
const PKCS8_ED25519_HEADER = new Uint8Array([
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
]);

/**
 * Encodes bytes as RFC 4648 base32 without padding.
 *
 * NATS uses unpadded uppercase base32 for every nkey string; this is the inverse of
 * {@link fromBase32}.
 *
 * @param bytes - The bytes to encode.
 * @returns The base32 string (uppercase, no `=` padding).
 * @since 1.0.0
 * @example
 * ```typescript
 * import { toBase32 } from 'edgeport/nats';
 * const s = toBase32(new Uint8Array([0, 1, 2]));
 * ```
 */
export function toBase32(bytes: Uint8Array): string {
	let out = '';
	let bits = 0;
	let value = 0;
	for (const b of bytes) {
		value = (value << 8) | b;
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			out += B32_ALPHABET[(value >>> bits) & 31];
		}
	}
	if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
	return out;
}

/**
 * Decodes an RFC 4648 base32 string (padding tolerated) to bytes.
 *
 * Used to decode an nkey seed or public string back to its prefix + payload + checksum bytes.
 *
 * @param s - The base32 string.
 * @returns The decoded bytes.
 * @throws {AuthError} If the input contains a non-base32 character.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { fromBase32, toBase32 } from 'edgeport/nats';
 * const bytes = fromBase32(toBase32(new Uint8Array([9])));
 * ```
 */
export function fromBase32(s: string): Uint8Array {
	const clean = s.replace(/=+$/, '');
	const out: number[] = [];
	let bits = 0;
	let value = 0;
	for (const ch of clean) {
		const idx = B32_LOOKUP[ch];
		if (idx === undefined) {
			throw new AuthError(`invalid base32 character in nkey: ${ch}`, { protocol: PROTO });
		}
		value = (value << 5) | idx;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			out.push((value >>> bits) & 0xff);
		}
	}
	return new Uint8Array(out);
}

/**
 * Computes the CRC-16/XMODEM checksum NATS appends to every nkey.
 *
 * The polynomial is `0x1021` with a zero initial value; the result is stored little-endian as
 * the last two bytes of a decoded nkey.
 *
 * @param data - The bytes to checksum (prefix + payload, excluding the checksum itself).
 * @returns The 16-bit checksum.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { crc16 } from 'edgeport/nats';
 * const sum = crc16(new Uint8Array([1, 2, 3]));
 * ```
 */
export function crc16(data: Uint8Array): number {
	let crc = 0;
	for (const b of data) {
		crc ^= b << 8;
		for (let i = 0; i < 8; i++) {
			crc = crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1;
			crc &= 0xffff;
		}
	}
	return crc & 0xffff;
}

// decodes an nkey string, verifies its trailing crc16, and returns the payload (without crc)
function decodeChecked(s: string): Uint8Array {
	const raw = fromBase32(s);
	if (raw.length < 3) throw new AuthError('nkey too short', { protocol: PROTO });
	const body = raw.subarray(0, raw.length - 2);
	const got = raw[raw.length - 2]! | (raw[raw.length - 1]! << 8); // little-endian
	if (crc16(body) !== got) throw new AuthError('nkey checksum mismatch', { protocol: PROTO });
	return body;
}

/** A decoded nkey seed: the raw 32-byte ed25519 seed plus the recovered role prefix byte. */
export interface DecodedSeed {
	/** The 32-byte ed25519 seed scalar. */
	seed: Uint8Array;
	/** The role prefix byte (e.g. user keys use `20 << 3`). */
	roleByte: number;
}

/**
 * Decodes a NATS seed string (the `S...` form) into its ed25519 seed and role.
 *
 * The first two decoded bytes pack the seed marker and the role prefix; the next 32 bytes are
 * the ed25519 seed. The CRC-16 is verified before anything is returned.
 *
 * @param seed - The base32 seed string, e.g. `SUAB...`.
 * @returns The 32-byte seed and the recovered role byte.
 * @throws {AuthError} If the string is malformed, fails its checksum, or is not a seed.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { decodeSeed } from 'edgeport/nats';
 * const { seed, roleByte } = decodeSeed('SUAEL6GG2L2HIF7DUGZJGMRUFKXELGGYFMHF76UO2AYBG3K4YLWR3FKC2Q');
 * ```
 */
export function decodeSeed(seed: string): DecodedSeed {
	const body = decodeChecked(seed);
	if (body.length !== 34) throw new AuthError('nkey seed has wrong length', { protocol: PROTO });
	// byte0 packs PREFIX_BYTE_SEED in its high 5 bits and the role's high 3 bits in the low 3
	const b0 = body[0]!;
	const b1 = body[1]!;
	if ((b0 & 0xf8) !== PREFIX_BYTE_SEED) {
		throw new AuthError('nkey is not a seed (bad prefix)', { protocol: PROTO });
	}
	const roleByte = ((b0 & 0x07) << 5) | (b1 >> 3);
	return { seed: body.subarray(2, 34), roleByte };
}

// imports a raw 32-byte ed25519 seed as a WebCrypto signing key (via PKCS#8 wrapping)
async function importSeed(seed32: Uint8Array): Promise<CryptoKey> {
	const der = new Uint8Array(PKCS8_ED25519_HEADER.length + 32);
	der.set(PKCS8_ED25519_HEADER, 0);
	der.set(seed32, PKCS8_ED25519_HEADER.length);
	return crypto.subtle.importKey('pkcs8', der as BufferSource, { name: 'Ed25519' }, true, ['sign']);
}

// exports the 32-byte raw public key (jwk 'x' coordinate) from an ed25519 signing key
async function rawPublicKey(key: CryptoKey): Promise<Uint8Array> {
	const jwk = (await crypto.subtle.exportKey('jwk', key)) as JsonWebKey;
	const x = jwk.x!;
	const bin = atob(x.replace(/-/g, '+').replace(/_/g, '/'));
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

// encodes [roleByte] + pub32 + crc16le as a base32 public nkey string
function encodePublic(roleByte: number, pub32: Uint8Array): string {
	const body = new Uint8Array(1 + pub32.length);
	body[0] = roleByte & 0xff;
	body.set(pub32, 1);
	const sum = crc16(body);
	const full = new Uint8Array(body.length + 2);
	full.set(body, 0);
	full[body.length] = sum & 0xff;
	full[body.length + 1] = (sum >> 8) & 0xff;
	return toBase32(full);
}

// base64url-encodes bytes with no padding (NATS sig format)
function base64url(bytes: Uint8Array): string {
	let bin = '';
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** The public nkey string and a base64url signature produced from a seed. */
export interface SignedNonce {
	/** The public nkey string (e.g. a user key starts with `U`). */
	nkey: string;
	/** The detached ed25519 signature over the nonce, base64url with no padding. */
	sig: string;
}

/**
 * Signs a NATS server nonce with the ed25519 key carried by a seed string.
 *
 * Decodes the seed, derives the public nkey string for its role, and produces a detached
 * ed25519 signature over the raw nonce bytes encoded as base64url without padding. This is the
 * exact pair the NATS `CONNECT` message expects in its `nkey` and `sig` fields.
 *
 * @param seed - The base32 seed string, e.g. `SUAB...`.
 * @param nonce - The raw nonce bytes from the server `INFO` message.
 * @returns The public nkey string and the base64url signature.
 * @throws {AuthError} If the seed is malformed or cannot be imported.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { signNonce } from 'edgeport/nats';
 * const nonce = new TextEncoder().encode('server-nonce');
 * const { nkey, sig } = await signNonce('SUAEL6GG2L2HIF7DUGZJGMRUFKXELGGYFMHF76UO2AYBG3K4YLWR3FKC2Q', nonce);
 * ```
 */
export async function signNonce(seed: string, nonce: Uint8Array): Promise<SignedNonce> {
	const { seed: seed32, roleByte } = decodeSeed(seed);
	const key = await importSeed(seed32);
	const pub32 = await rawPublicKey(key);
	const nkey = encodePublic(roleByte, pub32);
	const sigBytes = new Uint8Array(
		await crypto.subtle.sign({ name: 'Ed25519' }, key, nonce as BufferSource)
	);
	return { nkey, sig: base64url(sigBytes) };
}

/**
 * Parses a NATS credentials (`.creds`) file into its user JWT and nkey seed.
 *
 * The `.creds` format produced by `nsc`/`nats` bundles a `-----BEGIN NATS USER JWT-----`
 * block and a `-----BEGIN USER NKEY SEED-----` block; JWT auth presents the JWT and proves
 * possession by signing the server nonce with the seed.
 *
 * @param creds - The full contents of a `.creds` file.
 * @returns The extracted `jwt` and `seed` strings.
 * @throws {AuthError} If either block is missing.
 * @since 1.0.0
 * @example
 * ```typescript
 * const { jwt, seed } = parseCreds(await readCreds());
 * ```
 */
export function parseCreds(creds: string): { jwt: string; seed: string } {
	const jwt = creds.match(
		/-{3,}BEGIN NATS USER JWT-{3,}\r?\n([\s\S]*?)\r?\n-{3,}END NATS USER JWT-{3,}/
	);
	const seed = creds.match(
		/-{3,}BEGIN USER NKEY SEED-{3,}\r?\n([\s\S]*?)\r?\n-{3,}END USER NKEY SEED-{3,}/
	);
	if (!jwt || !seed)
		throw new AuthError('invalid NATS credentials file (missing JWT or NKEY SEED block)', {
			protocol: PROTO
		});
	return { jwt: jwt[1]!.trim(), seed: seed[1]!.trim() };
}
