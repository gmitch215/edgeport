/**
 * @fileoverview SSH key exchange (exported as `edgeport/kex`): KEXINIT negotiation, the
 * ECDH exchange hash and key schedule, the curve implementations, and the method dispatch
 * that maps a negotiated kex name to its ephemeral keypair and shared-secret derivation.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { ProtocolError } from '../core/errors';
import type { HashName } from '../crypto/primitives';
import * as curve25519 from './curve25519';
import * as nistp256 from './nistp256';

export * from './exchange-hash';
export * from './kexinit';
// the curve implementations share function names (generateKeyPair/deriveShared), so they
// are exposed as namespaces rather than flattened
export { curve25519, nistp256 };

/** A key-exchange method instance with its ephemeral key and derivation. */
export interface KexMethod {
	readonly hash: HashName;
	/** Our ephemeral public key (Q_C). */
	readonly publicKey: Uint8Array;
	/** Derives the shared secret magnitude K from the server's Q_S. */
	deriveSecret(peerPublicKey: Uint8Array): Promise<Uint8Array>;
}

/**
 * Creates the negotiated key-exchange method.
 *
 * @param name - The negotiated kex algorithm name.
 * @returns A ready {@link KexMethod} (its ephemeral keypair is already generated).
 * @throws {ProtocolError} For an unsupported kex name.
 * @since 1.0.0
 */
export async function createKex(name: string): Promise<KexMethod> {
	switch (name) {
		case 'curve25519-sha256':
		case 'curve25519-sha256@libssh.org': {
			const pair = await curve25519.generateKeyPair();
			return {
				hash: 'SHA-256',
				publicKey: pair.publicKey,
				deriveSecret: (peer) => curve25519.deriveShared(pair.privateKey, peer)
			};
		}
		case 'ecdh-sha2-nistp256': {
			const pair = await nistp256.generateKeyPair();
			return {
				hash: 'SHA-256',
				publicKey: pair.publicKey,
				deriveSecret: (peer) => nistp256.deriveShared(pair.privateKey, peer)
			};
		}
		default:
			throw new ProtocolError(`unsupported kex ${name}`);
	}
}
