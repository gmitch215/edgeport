/**
 * @fileoverview ECDH over NIST P-256 for `ecdh-sha2-nistp256` (RFC 5656), via WebCrypto.
 *
 * The ephemeral public key Q is the uncompressed SEC1 point (0x04 || X || Y); the shared
 * secret K is the derived x-coordinate, fed to the exchange hash as an mpint.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { ProtocolError } from '../core/errors';

/** An ephemeral P-256 keypair: the private key and the uncompressed public point. */
export interface P256KeyPair {
	privateKey: CryptoKey;
	publicKey: Uint8Array;
}

/** Generates an ephemeral P-256 keypair. */
export async function generateKeyPair(): Promise<P256KeyPair> {
	const pair = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
		'deriveBits'
	])) as CryptoKeyPair;
	const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
	return { privateKey: pair.privateKey, publicKey };
}

/**
 * Derives the 32-byte shared secret (the x-coordinate) from our private key and the
 * server's uncompressed public point.
 *
 * @param privateKey - Our ephemeral private key.
 * @param peerPublicKey - The server's uncompressed public point (65 bytes).
 * @returns The 32-byte shared secret K.
 * @throws {ProtocolError} If the peer point cannot be imported.
 * @since 1.0.0
 */
export async function deriveShared(
	privateKey: CryptoKey,
	peerPublicKey: Uint8Array
): Promise<Uint8Array> {
	let peer: CryptoKey;
	try {
		peer = await crypto.subtle.importKey(
			'raw',
			peerPublicKey as BufferSource,
			{ name: 'ECDH', namedCurve: 'P-256' },
			false,
			[]
		);
	} catch (cause) {
		throw new ProtocolError('nistp256: invalid server public point', { protocol: 'ssh', cause });
	}
	const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: peer }, privateKey, 256);
	return new Uint8Array(bits);
}
