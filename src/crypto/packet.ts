/**
 * @fileoverview SSH binary packet protocol (RFC 4253 section 6) and the cipher seam.
 *
 * A {@link PacketCipher} owns the full on-wire framing for one direction, because the
 * three negotiated constructions differ in exactly that framing: AES-GCM leaves the
 * length field in the clear as AAD, AES-CTR+HMAC encrypts it and MACs the plaintext with
 * an implicit sequence number, and chacha20-poly1305@openssh encrypts the length under a
 * separate key. {@link NoneCipher} is the plaintext framing used before NEWKEYS.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { ProtocolError } from '../core/errors';
import type { FramedReader } from '../core/framing';
import { randomBytes } from './primitives';

/** Largest packet length we will accept, to bound allocations (RFC 4253 suggests 35000). */
export const MAX_PACKET_LENGTH = 1024 * 1024;

/** Encrypts and decrypts whole SSH packets for one direction. */
export interface PacketCipher {
	/** Serializes one outgoing packet from its payload, including framing/MAC/tag. */
	seal(seq: number, payload: Uint8Array): Promise<Uint8Array>;
	/** Reads and decrypts one incoming packet, returning just the payload. */
	open(seq: number, reader: FramedReader): Promise<Uint8Array>;
}

/**
 * Builds the cleartext `padding_length || payload || padding` body with RFC 4253 padding.
 *
 * @param payload - The packet payload.
 * @param blockSize - Alignment block size (max(cipher block, 8)).
 * @param countLengthField - Whether the 4-byte length field counts toward the alignment
 *   (true for RFC 4253 / GCM, false for chacha20-poly1305@openssh).
 * @returns The padded body; its length is the packet's `packet_length` value.
 * @since 1.0.0
 */
export function buildPaddedBody(
	payload: Uint8Array,
	blockSize: number,
	countLengthField: boolean
): Uint8Array {
	const base = (countLengthField ? 4 : 0) + 1 + payload.length;
	let pad = blockSize - (base % blockSize);
	if (pad < 4) pad += blockSize; // RFC 4253: at least 4 padding bytes
	const body = new Uint8Array(1 + payload.length + pad);
	body[0] = pad;
	body.set(payload, 1);
	body.set(randomBytes(pad), 1 + payload.length);
	return body;
}

/** Extracts the payload from a decrypted `padding_length || payload || padding` body. */
export function unwrapBody(body: Uint8Array): Uint8Array {
	const padLen = body[0]!;
	if (padLen + 1 > body.length) throw new ProtocolError('ssh packet: padding length exceeds body');
	return body.subarray(1, body.length - padLen);
}

/** Reads a big-endian uint32 from the first four bytes. */
export function readUint32BE(b: Uint8Array): number {
	return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, false);
}

/** Writes `n` as a 4-byte big-endian array. */
export function uint32BE(n: number): Uint8Array {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n >>> 0, false);
	return b;
}

/** Plaintext packet framing used before keys are exchanged (8-byte alignment, no MAC). */
export class NoneCipher implements PacketCipher {
	async seal(_seq: number, payload: Uint8Array): Promise<Uint8Array> {
		const body = buildPaddedBody(payload, 8, true);
		const out = new Uint8Array(4 + body.length);
		out.set(uint32BE(body.length), 0);
		out.set(body, 4);
		return out;
	}

	async open(_seq: number, reader: FramedReader): Promise<Uint8Array> {
		const len = readUint32BE(await reader.readN(4));
		if (len < 1 || len > MAX_PACKET_LENGTH) {
			throw new ProtocolError(`ssh packet: invalid length ${len}`);
		}
		return unwrapBody(await reader.readN(len));
	}
}
