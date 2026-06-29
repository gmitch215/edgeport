/**
 * @fileoverview The ECDH exchange hash H (RFC 5656 section 4 / RFC 8731) and the RFC 4253
 * section 7.2 key derivation. Two of the three crypto-assembly risk points live here.
 *
 * For curve25519 and nistp256 the hashed field list uses `string Q_C, string Q_S` (the
 * raw ephemeral public keys) - NOT the classic finite-field DH `mpint e, mpint f` - while
 * K stays an `mpint`. Getting that ordering or any encoding wrong corrupts H and every
 * derived key, which is why a recorded/real handshake is the decisive check.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import type { DirectionKeys } from '../crypto/cipher';
import { concatBytes, digest, type HashName } from '../crypto/primitives';
import { SshWriter } from '../wire';

/** The ordered inputs to the ECDH exchange hash. */
export interface ExchangeHashInputs {
	/** Client identification string (no CRLF). */
	vClient: Uint8Array;
	/** Server identification string (no CRLF). */
	vServer: Uint8Array;
	/** Client SSH_MSG_KEXINIT payload. */
	iClient: Uint8Array;
	/** Server SSH_MSG_KEXINIT payload. */
	iServer: Uint8Array;
	/** Server host key blob (K_S). */
	hostKey: Uint8Array;
	/** Client ephemeral public key (Q_C). */
	qClient: Uint8Array;
	/** Server ephemeral public key (Q_S). */
	qServer: Uint8Array;
	/** Shared secret K as an unsigned big-endian magnitude. */
	sharedSecret: Uint8Array;
}

/**
 * Computes the ECDH exchange hash H.
 *
 * @param hash - The kex hash (SHA-256 for curve25519/nistp256).
 * @param x - The ordered hash inputs.
 * @returns H.
 * @since 1.0.0
 */
export async function computeExchangeHash(
	hash: HashName,
	x: ExchangeHashInputs
): Promise<Uint8Array> {
	const w = new SshWriter()
		.string(x.vClient)
		.string(x.vServer)
		.string(x.iClient)
		.string(x.iServer)
		.string(x.hostKey)
		.string(x.qClient)
		.string(x.qServer)
		.mpint(x.sharedSecret);
	return digest(hash, w.bytes());
}

// the six derivation letters (RFC 4253 section 7.2)
const LETTER = { ivC2S: 0x41, ivS2C: 0x42, keyC2S: 0x43, keyS2C: 0x44, macC2S: 0x45, macS2C: 0x46 };

// K1 = HASH(K || H || letter || sid); Kn = HASH(K || H || K1..Kn-1); truncate to needed
async function expand(
	hash: HashName,
	kEnc: Uint8Array,
	h: Uint8Array,
	sessionId: Uint8Array,
	letter: number,
	needed: number
): Promise<Uint8Array> {
	let out = await digest(hash, concatBytes(kEnc, h, Uint8Array.of(letter), sessionId));
	while (out.length < needed) {
		out = concatBytes(out, await digest(hash, concatBytes(kEnc, h, out)));
	}
	return out.subarray(0, needed);
}

/** The byte lengths each direction needs from the key schedule. */
export interface KeyScheduleSizes {
	ivLen: number;
	keyLen: number;
	macKeyLen: number;
}

/** Both directions' key material. */
export interface SessionKeys {
	c2s: DirectionKeys;
	s2c: DirectionKeys;
}

/**
 * Derives both directions' IV/key/MAC material from K, H, and the session id.
 *
 * @param hash - The kex hash.
 * @param sharedSecret - K as an unsigned big-endian magnitude.
 * @param h - The exchange hash for this kex.
 * @param sessionId - The session identifier (H of the first kex).
 * @param sizes - The byte lengths the negotiated ciphers/MACs need (same both ways).
 * @returns The client-to-server and server-to-client key material.
 * @since 1.0.0
 */
export async function deriveSessionKeys(
	hash: HashName,
	sharedSecret: Uint8Array,
	h: Uint8Array,
	sessionId: Uint8Array,
	sizes: KeyScheduleSizes
): Promise<SessionKeys> {
	const kEnc = new SshWriter().mpint(sharedSecret).bytes(); // K as mpint (length-prefixed)
	const mk = (letter: number, n: number) => expand(hash, kEnc, h, sessionId, letter, n);
	return {
		c2s: {
			iv: await mk(LETTER.ivC2S, sizes.ivLen),
			key: await mk(LETTER.keyC2S, sizes.keyLen),
			macKey: await mk(LETTER.macC2S, sizes.macKeyLen)
		},
		s2c: {
			iv: await mk(LETTER.ivS2C, sizes.ivLen),
			key: await mk(LETTER.keyS2C, sizes.keyLen),
			macKey: await mk(LETTER.macS2C, sizes.macKeyLen)
		}
	};
}
