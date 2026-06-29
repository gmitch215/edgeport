/**
 * @fileoverview The three SSH cipher constructions, assembled from WebCrypto and
 * @noble/ciphers. These are the highest-deception-risk code in the project (plan risk
 * points 3, 4, 5), so each is exercised by a forced live handshake against real servers.
 *
 * - `aes{128,256}-gcm@openssh.com`: 12-byte IV = fixed(4) || invocation_counter(8) that
 *   increments per packet; the 4-byte length is cleartext AAD, not encrypted; the
 *   block-multiple rule includes the length field (RFC 5647).
 * - `aes{128,256}-ctr` + `hmac-sha2-{256,512}`: the length is encrypted; the MAC is over
 *   `uint32 sequence_number || unencrypted_packet`, the sequence number being implicit
 *   per-direction state never sent on the wire.
 * - `chacha20-poly1305@openssh.com`: assembled from raw chacha20 (original 64-bit-nonce
 *   variant) + poly1305; main key (payload) is key[0:32], header key (length) is
 *   key[32:64]; nonce is the 64-bit sequence number; poly key is the counter-0 keystream.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { poly1305 } from '@noble/ciphers/_poly1305.js';
import { chacha20orig } from '@noble/ciphers/chacha.js';
import { ProtocolError } from '../core/errors';
import type { FramedReader } from '../core/framing';
import {
	buildPaddedBody,
	MAX_PACKET_LENGTH,
	readUint32BE,
	uint32BE,
	unwrapBody,
	type PacketCipher
} from './packet';
import { concatBytes, hmac, timingSafeEqual, type HashName } from './primitives';

/** Key/IV/MAC byte lengths a negotiated algorithm pair needs from the key schedule. */
export interface CipherSizes {
	keyLen: number;
	ivLen: number;
	macKeyLen: number;
}

const HMAC_HASH: Record<string, HashName> = {
	'hmac-sha2-256': 'SHA-256',
	'hmac-sha2-512': 'SHA-512'
};
const HMAC_LEN: Record<string, number> = { 'hmac-sha2-256': 32, 'hmac-sha2-512': 64 };

/** Returns the key schedule sizes for a negotiated cipher + MAC algorithm pair. */
export function cipherSizes(cipher: string, mac: string): CipherSizes {
	switch (cipher) {
		case 'aes128-gcm@openssh.com':
			return { keyLen: 16, ivLen: 12, macKeyLen: 0 };
		case 'aes256-gcm@openssh.com':
			return { keyLen: 32, ivLen: 12, macKeyLen: 0 };
		case 'chacha20-poly1305@openssh.com':
			return { keyLen: 64, ivLen: 0, macKeyLen: 0 };
		case 'aes128-ctr':
			return { keyLen: 16, ivLen: 16, macKeyLen: HMAC_LEN[mac] ?? 0 };
		case 'aes256-ctr':
			return { keyLen: 32, ivLen: 16, macKeyLen: HMAC_LEN[mac] ?? 0 };
		default:
			throw new ProtocolError(`unsupported cipher ${cipher}`);
	}
}

/** Per-direction key material produced by the key schedule. */
export interface DirectionKeys {
	iv: Uint8Array;
	key: Uint8Array;
	macKey: Uint8Array;
}

function checkLen(len: number): void {
	if (len < 1 || len > MAX_PACKET_LENGTH)
		throw new ProtocolError(`ssh packet: invalid length ${len}`);
}

// 16-byte big-endian counter incremented by n blocks (for AES-CTR continuation)
function addBlocks(counter: Uint8Array, n: number): Uint8Array {
	const out = counter.slice();
	let carry = n;
	for (let i = out.length - 1; i >= 0 && carry > 0; i--) {
		const sum = out[i]! + (carry & 0xff);
		out[i] = sum & 0xff;
		carry = (carry >>> 8) + (sum >> 8);
	}
	return out;
}

class GcmCipher implements PacketCipher {
	#fixed: Uint8Array;
	#counter: bigint;
	constructor(
		private readonly key: CryptoKey,
		iv: Uint8Array
	) {
		this.#fixed = iv.slice(0, 4);
		this.#counter = new DataView(iv.buffer, iv.byteOffset + 4, 8).getBigUint64(0, false);
	}

	#iv(): Uint8Array {
		const iv = new Uint8Array(12);
		iv.set(this.#fixed, 0);
		new DataView(iv.buffer).setBigUint64(4, this.#counter, false);
		return iv;
	}

	#bump(): void {
		this.#counter = (this.#counter + 1n) & 0xffffffffffffffffn;
	}

	async seal(_seq: number, payload: Uint8Array): Promise<Uint8Array> {
		// openssh aligns the encrypted portion (1 + payload + pad) only; the 4-byte length
		// is AAD and excluded from the block-multiple, hence countLengthField = false
		const body = buildPaddedBody(payload, 16, false);
		const aad = uint32BE(body.length);
		const ct = new Uint8Array(
			await crypto.subtle.encrypt(
				{
					name: 'AES-GCM',
					iv: this.#iv() as BufferSource,
					additionalData: aad as BufferSource,
					tagLength: 128
				},
				this.key,
				body as BufferSource
			)
		);
		this.#bump();
		return concatBytes(aad, ct);
	}

	async open(_seq: number, reader: FramedReader): Promise<Uint8Array> {
		const lenB = await reader.readN(4);
		const len = readUint32BE(lenB);
		checkLen(len);
		const ctTag = await reader.readN(len + 16);
		let pt: Uint8Array;
		try {
			pt = new Uint8Array(
				await crypto.subtle.decrypt(
					{
						name: 'AES-GCM',
						iv: this.#iv() as BufferSource,
						additionalData: lenB as BufferSource,
						tagLength: 128
					},
					this.key,
					ctTag as BufferSource
				)
			);
		} catch (cause) {
			throw new ProtocolError('aes-gcm: packet authentication failed', { protocol: 'ssh', cause });
		}
		this.#bump();
		return unwrapBody(pt);
	}
}

class CtrHmacCipher implements PacketCipher {
	#counter: Uint8Array;
	constructor(
		private readonly key: CryptoKey,
		iv: Uint8Array,
		private readonly macKey: Uint8Array,
		private readonly hash: HashName,
		private readonly macLen: number
	) {
		this.#counter = iv.slice(0, 16);
	}

	async seal(seq: number, payload: Uint8Array): Promise<Uint8Array> {
		const body = buildPaddedBody(payload, 16, true);
		const plaintext = concatBytes(uint32BE(body.length), body);
		const mac = (
			await hmac(this.hash, this.macKey, concatBytes(uint32BE(seq), plaintext))
		).subarray(0, this.macLen);
		const ct = new Uint8Array(
			await crypto.subtle.encrypt(
				{ name: 'AES-CTR', counter: this.#counter as BufferSource, length: 128 },
				this.key,
				plaintext as BufferSource
			)
		);
		this.#counter = addBlocks(this.#counter, plaintext.length / 16);
		return concatBytes(ct, mac);
	}

	async open(seq: number, reader: FramedReader): Promise<Uint8Array> {
		const ct0 = await reader.readN(16);
		const dec0 = new Uint8Array(
			await crypto.subtle.decrypt(
				{ name: 'AES-CTR', counter: this.#counter as BufferSource, length: 128 },
				this.key,
				ct0 as BufferSource
			)
		);
		const len = readUint32BE(dec0);
		checkLen(len);
		const total = 4 + len; // length field + body, both encrypted, block-aligned
		if (total % 16 !== 0) throw new ProtocolError('aes-ctr: packet not block-aligned');
		let plaintext: Uint8Array = dec0;
		if (total > 16) {
			const ctRest = await reader.readN(total - 16);
			const decRest = new Uint8Array(
				await crypto.subtle.decrypt(
					{ name: 'AES-CTR', counter: addBlocks(this.#counter, 1) as BufferSource, length: 128 },
					this.key,
					ctRest as BufferSource
				)
			);
			plaintext = concatBytes(dec0, decRest);
		}
		this.#counter = addBlocks(this.#counter, total / 16);
		const mac = await reader.readN(this.macLen);
		const expect = (
			await hmac(this.hash, this.macKey, concatBytes(uint32BE(seq), plaintext))
		).subarray(0, this.macLen);
		if (!timingSafeEqual(mac, expect)) throw new ProtocolError('aes-ctr: bad MAC');
		return unwrapBody(plaintext.subarray(4));
	}
}

class ChachaPolyCipher implements PacketCipher {
	#kMain: Uint8Array; // payload key (key[0:32])
	#kHeader: Uint8Array; // length key (key[32:64])
	constructor(key: Uint8Array) {
		this.#kMain = key.slice(0, 32);
		this.#kHeader = key.slice(32, 64);
	}

	// 8-byte big-endian sequence number (uint32 seq, high 4 bytes zero)
	#nonce(seq: number): Uint8Array {
		const n = new Uint8Array(8);
		new DataView(n.buffer).setUint32(4, seq >>> 0, false);
		return n;
	}

	async seal(seq: number, payload: Uint8Array): Promise<Uint8Array> {
		const body = buildPaddedBody(payload, 8, false);
		const nonce = this.#nonce(seq);
		const lenCt = chacha20orig(this.#kHeader, nonce, uint32BE(body.length));
		// counter-0 block yields the poly key; the body rides on counter 1 (prepend a zero block)
		const ks = chacha20orig(this.#kMain, nonce, concatBytes(new Uint8Array(64), body));
		const polyKey = ks.subarray(0, 32);
		const payloadCt = ks.subarray(64);
		const tag = poly1305(concatBytes(lenCt, payloadCt), polyKey);
		return concatBytes(lenCt, payloadCt, tag);
	}

	async open(seq: number, reader: FramedReader): Promise<Uint8Array> {
		const lenCt = await reader.readN(4);
		const nonce = this.#nonce(seq);
		const len = readUint32BE(chacha20orig(this.#kHeader, nonce, lenCt));
		checkLen(len);
		const payloadCt = await reader.readN(len);
		const tag = await reader.readN(16);
		const polyKey = chacha20orig(this.#kMain, nonce, new Uint8Array(64)).subarray(0, 32);
		const expect = poly1305(concatBytes(lenCt, payloadCt), polyKey);
		if (!timingSafeEqual(tag, expect)) throw new ProtocolError('chacha20-poly1305: bad MAC');
		const body = chacha20orig(
			this.#kMain,
			nonce,
			concatBytes(new Uint8Array(64), payloadCt)
		).subarray(64);
		return unwrapBody(body);
	}
}

/**
 * Builds a {@link PacketCipher} for one direction from the negotiated algorithm names and
 * the derived key material.
 *
 * @param cipher - The negotiated encryption algorithm name.
 * @param mac - The negotiated MAC algorithm name (ignored for AEAD ciphers).
 * @param keys - The per-direction key/IV/MAC material from the key schedule.
 * @returns A cipher that seals and opens packets for that direction.
 * @since 1.0.0
 */
export async function createPacketCipher(
	cipher: string,
	mac: string,
	keys: DirectionKeys
): Promise<PacketCipher> {
	switch (cipher) {
		case 'aes128-gcm@openssh.com':
		case 'aes256-gcm@openssh.com': {
			const key = await crypto.subtle.importKey('raw', keys.key as BufferSource, 'AES-GCM', false, [
				'encrypt',
				'decrypt'
			]);
			return new GcmCipher(key, keys.iv);
		}
		case 'chacha20-poly1305@openssh.com':
			return new ChachaPolyCipher(keys.key);
		case 'aes128-ctr':
		case 'aes256-ctr': {
			const hash = HMAC_HASH[mac];
			const macLen = HMAC_LEN[mac];
			if (!hash || !macLen) throw new ProtocolError(`unsupported mac ${mac}`);
			const key = await crypto.subtle.importKey('raw', keys.key as BufferSource, 'AES-CTR', false, [
				'encrypt',
				'decrypt'
			]);
			return new CtrHmacCipher(key, keys.iv, keys.macKey, hash, macLen);
		}
		default:
			throw new ProtocolError(`unsupported cipher ${cipher}`);
	}
}
