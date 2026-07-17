/**
 * @fileoverview SASL client mechanisms for XMPP: PLAIN and SCRAM-SHA-1 / SCRAM-SHA-256.
 *
 * PLAIN is a single base64 blob. SCRAM (RFC 5802) is a challenge-response exchange that never
 * puts the password on the wire: the client and server prove knowledge of a PBKDF2-salted
 * password through HMAC signatures, and the client verifies the server in turn. Everything here
 * is pure and transport-free - it produces and consumes the base64-less message strings, and the
 * XMPP module wraps them in `<auth>` / `<response>` stanzas. All crypto is Workers WebCrypto
 * (`crypto.subtle`), which supports HMAC + digest for SHA-1/SHA-256 and PBKDF2 for both.
 *
 * @author Gregory Mitchell
 * @since 1.0.4
 */
import { ProtocolError } from '../core';
import { fromBase64, randomHex, toBase64 } from '../util';

const PROTO = 'xmpp';
const encoder = new TextEncoder();

/**
 * Builds the SASL PLAIN response: `base64(authzid \0 authcid \0 password)`.
 *
 * @param authcid - The authentication identity (typically the JID localpart).
 * @param password - The account password.
 * @param authzid - The optional authorization identity (empty by default).
 * @returns The base64 payload for an `<auth mechanism='PLAIN'>` stanza.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { saslPlain } from 'edgeport/xmpp';
 *
 * saslPlain('juliet', 'r0m30'); // base64 of "\0juliet\0r0m30"
 * ```
 */
export function saslPlain(authcid: string, password: string, authzid = ''): string {
	return toBase64(encoder.encode(`${authzid}\0${authcid}\0${password}`));
}

/** A SCRAM mechanism supported by this client. */
export type ScramMechanism = 'SCRAM-SHA-1' | 'SCRAM-SHA-256';

/**
 * A SCRAM client state machine, produced by {@link scramClient}.
 *
 * Drive it in three steps: send {@link ScramClient.clientFirst}, feed the server's first message
 * to {@link ScramClient.handleServerFirst} and send what it returns, then check the server's final
 * message with {@link ScramClient.verifyServerFinal}. The XMPP module base64-wraps each string.
 *
 * @since 1.0.4
 */
export interface ScramClient {
	/** The negotiated mechanism. */
	readonly mechanism: ScramMechanism;
	/** The client-first message (`n,,n=user,r=nonce`) sent in `<auth>`. */
	readonly clientFirst: string;
	/** The client-first-bare portion (`n=user,r=nonce`), used to build the auth message. */
	readonly clientFirstBare: string;
	/** The client nonce this exchange was seeded with. */
	readonly clientNonce: string;
	/**
	 * Processes the server-first message and returns the client-final message (with proof).
	 *
	 * @param serverFirst - The decoded server-first message (`r=..,s=..,i=..`).
	 * @returns The client-final message (`c=biws,r=..,p=..`).
	 * @throws {ProtocolError} If the server nonce does not extend the client nonce, or the
	 *   message is malformed.
	 */
	handleServerFirst(serverFirst: string): Promise<string>;
	/**
	 * Verifies the server-final message's signature (`v=..`).
	 *
	 * @param serverFinal - The decoded server-final message.
	 * @throws {ProtocolError} If the server reported an error or its signature does not match.
	 */
	verifyServerFinal(serverFinal: string): Promise<void>;
}

/**
 * Creates a {@link ScramClient} for a mechanism, username, and password.
 *
 * @param mechanism - `'SCRAM-SHA-1'` or `'SCRAM-SHA-256'`.
 * @param username - The authentication identity (SCRAM saslname-escaped internally).
 * @param password - The account password.
 * @param opts - Optional fixed client nonce (for reproducible tests); random otherwise.
 * @returns The client state machine.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { scramClient } from 'edgeport/xmpp';
 *
 * const c = scramClient('SCRAM-SHA-256', 'user', 'pencil');
 * const clientFinal = await c.handleServerFirst(serverFirst);
 * await c.verifyServerFinal(serverFinal);
 * ```
 */
export function scramClient(
	mechanism: ScramMechanism,
	username: string,
	password: string,
	opts?: { nonce?: string }
): ScramClient {
	const hash: 'SHA-1' | 'SHA-256' = mechanism === 'SCRAM-SHA-256' ? 'SHA-256' : 'SHA-1';
	const clientNonce = opts?.nonce ?? randomHex(24);
	const gs2Header = 'n,,';
	const clientFirstBare = `n=${saslName(username)},r=${clientNonce}`;
	const clientFirst = gs2Header + clientFirstBare;
	let serverSignatureB64 = '';

	return {
		mechanism,
		clientFirst,
		clientFirstBare,
		clientNonce,
		async handleServerFirst(serverFirst: string): Promise<string> {
			const attrs = parseScram(serverFirst);
			const combinedNonce = attrs['r'];
			const saltB64 = attrs['s'];
			const iterStr = attrs['i'];
			if (!combinedNonce || !saltB64 || !iterStr) {
				throw new ProtocolError('scram: malformed server-first message', { protocol: PROTO });
			}
			if (!combinedNonce.startsWith(clientNonce)) {
				throw new ProtocolError('scram: server nonce does not extend client nonce', {
					protocol: PROTO
				});
			}
			const salt = fromBase64(saltB64);
			const iterations = Number.parseInt(iterStr, 10);
			if (!Number.isInteger(iterations) || iterations <= 0) {
				throw new ProtocolError('scram: invalid iteration count', { protocol: PROTO });
			}

			const saltedPassword = await hi(encoder.encode(password), salt, iterations, hash);
			const clientKey = await hmac(saltedPassword, encoder.encode('Client Key'), hash);
			const storedKey = await digest(clientKey, hash);
			// gs2 header with no channel binding base64s to the well-known "biws"
			const channelBinding = toBase64(encoder.encode(gs2Header));
			const clientFinalNoProof = `c=${channelBinding},r=${combinedNonce}`;
			const authMessage = `${clientFirstBare},${serverFirst},${clientFinalNoProof}`;
			const clientSignature = await hmac(storedKey, encoder.encode(authMessage), hash);
			const clientProof = xor(clientKey, clientSignature);

			const serverKey = await hmac(saltedPassword, encoder.encode('Server Key'), hash);
			const serverSignature = await hmac(serverKey, encoder.encode(authMessage), hash);
			serverSignatureB64 = toBase64(serverSignature);

			return `${clientFinalNoProof},p=${toBase64(clientProof)}`;
		},
		async verifyServerFinal(serverFinal: string): Promise<void> {
			const attrs = parseScram(serverFinal);
			if (attrs['e'] !== undefined) {
				throw new ProtocolError(`scram: server error: ${attrs['e']}`, { protocol: PROTO });
			}
			if (attrs['v'] !== serverSignatureB64) {
				throw new ProtocolError('scram: server signature mismatch', { protocol: PROTO });
			}
		}
	};
}

/**
 * PBKDF2 as SCRAM's `Hi(str, salt, i)`: the salted-password derivation.
 *
 * Exposed for byte-exact known-answer tests against the RFC 5802 vectors.
 *
 * @param password - The UTF-8 password bytes.
 * @param salt - The salt bytes (already base64-decoded).
 * @param iterations - The iteration count.
 * @param hash - The underlying hash (`'SHA-1'` or `'SHA-256'`).
 * @returns The salted password (20 bytes for SHA-1, 32 for SHA-256).
 * @since 1.0.4
 */
export async function hi(
	password: Uint8Array,
	salt: Uint8Array,
	iterations: number,
	hash: 'SHA-1' | 'SHA-256'
): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey(
		'raw',
		password as BufferSource,
		{ name: 'PBKDF2' },
		false,
		['deriveBits']
	);
	const bits = await crypto.subtle.deriveBits(
		{ name: 'PBKDF2', salt: salt as BufferSource, iterations, hash },
		key,
		hash === 'SHA-256' ? 256 : 160
	);
	return new Uint8Array(bits);
}

// HMAC(key, data) with the given SHA variant
async function hmac(
	key: Uint8Array,
	data: Uint8Array,
	hash: 'SHA-1' | 'SHA-256'
): Promise<Uint8Array> {
	const k = await crypto.subtle.importKey(
		'raw',
		key as BufferSource,
		{ name: 'HMAC', hash },
		false,
		['sign']
	);
	const out = await crypto.subtle.sign('HMAC', k, data as BufferSource);
	return new Uint8Array(out);
}

// H(data) with the given SHA variant
async function digest(data: Uint8Array, hash: 'SHA-1' | 'SHA-256'): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest(hash, data as BufferSource));
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
	const out = new Uint8Array(a.length);
	for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
	return out;
}

// SCRAM saslname escaping: ',' -> =2C and '=' -> =3D (order matters: '=' first)
function saslName(name: string): string {
	return name.replace(/=/g, '=3D').replace(/,/g, '=2C');
}

// splits a SCRAM message (`k=v,k=v,...`) into a map, keeping '=' inside each value intact
function parseScram(msg: string): Record<string, string> {
	const out: Record<string, string> = {};
	for (const part of msg.split(',')) {
		const eq = part.indexOf('=');
		if (eq === -1) continue;
		out[part.slice(0, eq)] = part.slice(eq + 1);
	}
	return out;
}
