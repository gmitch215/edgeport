/**
 * @fileoverview X25519 key exchange for `curve25519-sha256`, via WebCrypto `deriveBits`.
 *
 * The client generates an ephemeral X25519 keypair, sends the 32-byte public key as Q_C,
 * and derives the shared secret K from the server's Q_S. K is then fed into the exchange
 * hash and key schedule as an `mpint` (see the kex hash module). The raw `deriveBits`
 * behavior is pinned by the RFC 7748 known-answer test.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { ProtocolError } from '../core/errors';

/** An ephemeral X25519 keypair: the private {@link CryptoKey} and the 32-byte public key. */
export interface X25519KeyPair {
	privateKey: CryptoKey;
	publicKey: Uint8Array;
}

/** Generates an ephemeral X25519 keypair. */
export async function generateKeyPair(): Promise<X25519KeyPair> {
	const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, true, [
		'deriveBits'
	])) as CryptoKeyPair;
	const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
	return { privateKey: pair.privateKey, publicKey };
}

/**
 * Derives the 32-byte X25519 shared secret from our private key and the peer's raw public
 * key. Rejects (per RFC 8731) if the result is all zero, which signals a small-order
 * point attack.
 *
 * @param privateKey - Our ephemeral private key.
 * @param peerPublicKey - The peer's 32-byte raw public key.
 * @returns The 32-byte shared secret K.
 * @throws {ProtocolError} If the derived secret is all zero.
 * @since 1.0.0
 */
export async function deriveShared(
	privateKey: CryptoKey,
	peerPublicKey: Uint8Array
): Promise<Uint8Array> {
	const peer = await crypto.subtle.importKey(
		'raw',
		peerPublicKey as BufferSource,
		{ name: 'X25519' },
		false,
		[]
	);
	const bits = await crypto.subtle.deriveBits({ name: 'X25519', public: peer }, privateKey, 256);
	const shared = new Uint8Array(bits);
	if (shared.every((b) => b === 0)) {
		throw new ProtocolError('curve25519: derived shared secret is all zero');
	}
	return shared;
}
