/**
 * @fileoverview SSH public-key parsing, host-key signature verification, and user-key
 * signing for publickey auth. Covers Ed25519, ECDSA-P256, and RSA-SHA2-256/512.
 *
 * All signature and key blobs use the SSH wire encoding (RFC 4253/5656/8332). ECDSA needs
 * the extra hop of converting between WebCrypto's raw r||s and SSH's `mpint r, mpint s`.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { AuthError, ProtocolError } from '../core/errors';
import { SshReader, SshWriter } from '../wire';

function stripLeadingZeros(b: Uint8Array): Uint8Array {
	let i = 0;
	while (i < b.length - 1 && b[i] === 0) i++;
	return b.subarray(i);
}

function leftPad(b: Uint8Array, len: number): Uint8Array {
	if (b.length === len) return b;
	const out = new Uint8Array(len);
	out.set(b.subarray(Math.max(0, b.length - len)), Math.max(0, len - b.length));
	return out;
}

function b64url(b: Uint8Array): string {
	let bin = '';
	for (const x of b) bin += String.fromCharCode(x);
	return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// converts an SSH ecdsa signature blob (mpint r, mpint s) to WebCrypto raw r||s
function sshEcdsaToRaw(blob: Uint8Array): Uint8Array {
	const r = new SshReader(blob);
	const rr = leftPad(stripLeadingZeros(r.mpint()), 32);
	const ss = leftPad(stripLeadingZeros(r.mpint()), 32);
	const out = new Uint8Array(64);
	out.set(rr, 0);
	out.set(ss, 32);
	return out;
}

// converts WebCrypto raw r||s into an SSH ecdsa signature blob (mpint r, mpint s)
function rawToSshEcdsa(raw: Uint8Array): Uint8Array {
	return new SshWriter().mpint(raw.subarray(0, 32)).mpint(raw.subarray(32, 64)).bytes();
}

/**
 * Verifies a server host-key signature over the exchange hash H.
 *
 * @param algorithm - The negotiated host-key algorithm name.
 * @param hostKeyBlob - The server host key blob (K_S).
 * @param signatureBlob - The signature blob from KEX_ECDH_REPLY.
 * @param data - The signed data (the exchange hash H).
 * @returns Whether the signature is valid.
 * @throws {ProtocolError} If the blob types are malformed or unsupported.
 * @since 1.0.0
 */
export async function verifyHostSignature(
	algorithm: string,
	hostKeyBlob: Uint8Array,
	signatureBlob: Uint8Array,
	data: Uint8Array
): Promise<boolean> {
	const sig = new SshReader(signatureBlob);
	const sigType = sig.stringUtf8();
	const sigBytes = sig.string();

	switch (algorithm) {
		case 'ssh-ed25519': {
			const k = new SshReader(hostKeyBlob);
			if (k.stringUtf8() !== 'ssh-ed25519') throw new ProtocolError('host key type mismatch');
			const pub = k.string();
			const key = await crypto.subtle.importKey(
				'raw',
				pub as BufferSource,
				{ name: 'Ed25519' },
				false,
				['verify']
			);
			return crypto.subtle.verify(
				{ name: 'Ed25519' },
				key,
				sigBytes as BufferSource,
				data as BufferSource
			);
		}
		case 'ecdsa-sha2-nistp256': {
			const k = new SshReader(hostKeyBlob);
			k.stringUtf8(); // "ecdsa-sha2-nistp256"
			k.stringUtf8(); // "nistp256"
			const point = k.string();
			const key = await crypto.subtle.importKey(
				'raw',
				point as BufferSource,
				{ name: 'ECDSA', namedCurve: 'P-256' },
				false,
				['verify']
			);
			return crypto.subtle.verify(
				{ name: 'ECDSA', hash: 'SHA-256' },
				key,
				sshEcdsaToRaw(sigBytes) as BufferSource,
				data as BufferSource
			);
		}
		case 'rsa-sha2-256':
		case 'rsa-sha2-512': {
			const k = new SshReader(hostKeyBlob);
			k.stringUtf8(); // "ssh-rsa"
			const e = stripLeadingZeros(k.mpint());
			const n = stripLeadingZeros(k.mpint());
			const hash = algorithm === 'rsa-sha2-512' ? 'SHA-512' : 'SHA-256';
			const key = await crypto.subtle.importKey(
				'jwk',
				{ kty: 'RSA', n: b64url(n), e: b64url(e), ext: true },
				{ name: 'RSASSA-PKCS1-v1_5', hash },
				false,
				['verify']
			);
			if (sigType !== algorithm)
				throw new ProtocolError(`host sig type ${sigType} != ${algorithm}`);
			return crypto.subtle.verify(
				'RSASSA-PKCS1-v1_5',
				key,
				sigBytes as BufferSource,
				data as BufferSource
			);
		}
		default:
			throw new ProtocolError(`unsupported host key algorithm ${algorithm}`);
	}
}

/** A loaded user key able to produce its public blob and sign auth requests. */
export interface UserKey {
	/** The publickey auth algorithm name (e.g. `ssh-ed25519`, `rsa-sha2-512`). */
	readonly algorithm: string;
	/** The SSH public-key blob advertised to the server. */
	readonly publicBlob: Uint8Array;
	/** Signs `data`, returning the full SSH signature blob. */
	sign(data: Uint8Array): Promise<Uint8Array>;
}

function pemToDer(pem: string): Uint8Array {
	const body = pem
		.replace(/-----BEGIN [^-]+-----/g, '')
		.replace(/-----END [^-]+-----/g, '')
		.replace(/\s+/g, '');
	const bin = atob(body);
	const der = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
	return der;
}

function b64urlToBytes(s: string): Uint8Array {
	const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

// builds a UserKey from an extractable private CryptoKey, deriving the public blob via JWK
async function fromPrivateCryptoKey(
	priv: CryptoKey,
	rsaHash: 'SHA-256' | 'SHA-512' = 'SHA-512'
): Promise<UserKey> {
	const jwk = (await crypto.subtle.exportKey('jwk', priv)) as JsonWebKey;
	if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
		const pub = b64urlToBytes(jwk.x!);
		const publicBlob = new SshWriter().string('ssh-ed25519').string(pub).bytes();
		return {
			algorithm: 'ssh-ed25519',
			publicBlob,
			async sign(data) {
				const raw = new Uint8Array(
					await crypto.subtle.sign({ name: 'Ed25519' }, priv, data as BufferSource)
				);
				return new SshWriter().string('ssh-ed25519').string(raw).bytes();
			}
		};
	}
	if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
		const point = new Uint8Array(65);
		point[0] = 0x04;
		point.set(leftPad(b64urlToBytes(jwk.x!), 32), 1);
		point.set(leftPad(b64urlToBytes(jwk.y!), 32), 33);
		const publicBlob = new SshWriter()
			.string('ecdsa-sha2-nistp256')
			.string('nistp256')
			.string(point)
			.bytes();
		return {
			algorithm: 'ecdsa-sha2-nistp256',
			publicBlob,
			async sign(data) {
				const raw = new Uint8Array(
					await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, data as BufferSource)
				);
				const inner = rawToSshEcdsa(raw);
				return new SshWriter().string('ecdsa-sha2-nistp256').string(inner).bytes();
			}
		};
	}
	if (jwk.kty === 'RSA') {
		const e = b64urlToBytes(jwk.e!);
		const n = b64urlToBytes(jwk.n!);
		const publicBlob = new SshWriter().string('ssh-rsa').mpint(e).mpint(n).bytes();
		const alg = rsaHash === 'SHA-512' ? 'rsa-sha2-512' : 'rsa-sha2-256';
		return {
			algorithm: alg,
			publicBlob,
			async sign(data) {
				const raw = new Uint8Array(
					await crypto.subtle.sign('RSASSA-PKCS1-v1_5', priv, data as BufferSource)
				);
				return new SshWriter().string(alg).string(raw).bytes();
			}
		};
	}
	throw new ProtocolError(`unsupported private key type ${jwk.kty}`);
}

// imports a PKCS8 PEM by trying each supported algorithm (PKCS8 carries the OID, but the
// WebCrypto import needs the algorithm named up front, so we attempt each)
async function importPkcs8(der: Uint8Array): Promise<CryptoKey> {
	const attempts: {
		name: string;
		params: EcKeyImportParams | RsaHashedImportParams | Algorithm;
	}[] = [
		{ name: 'Ed25519', params: { name: 'Ed25519' } },
		{ name: 'ECDSA', params: { name: 'ECDSA', namedCurve: 'P-256' } },
		{ name: 'RSA', params: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' } }
	];
	for (const a of attempts) {
		try {
			return await crypto.subtle.importKey('pkcs8', der as BufferSource, a.params as any, true, [
				'sign'
			]);
		} catch {
			// try the next algorithm
		}
	}
	throw new AuthError('could not parse private key (expected PKCS8 Ed25519, EC P-256, or RSA)');
}

/**
 * Loads a user private key for publickey authentication.
 *
 * @param input - A PKCS8 PEM (`{ pem }`) or an extractable private {@link CryptoKey}.
 * @returns A {@link UserKey} that can sign auth requests.
 * @throws {AuthError} If the key cannot be parsed.
 * @since 1.0.0
 */
export async function loadUserKey(
	input: { pem: string; passphrase?: string } | CryptoKey
): Promise<UserKey> {
	if (input instanceof CryptoKey) return fromPrivateCryptoKey(input);
	if (input.passphrase) throw new AuthError('encrypted private keys are not supported');
	const priv = await importPkcs8(pemToDer(input.pem));
	return fromPrivateCryptoKey(priv);
}
