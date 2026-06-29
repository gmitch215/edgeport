/**
 * @fileoverview Decrypts PBES2 `EncryptedPrivateKeyInfo` (RFC 5958 / PKCS#8) into a plain
 * PKCS#8 DER, using only WebCrypto: PBKDF2 to derive the key, then AES-CBC or AES-GCM.
 *
 * This handles the modern `openssl pkcs8 -topk8 -v2 ...` output
 * (`-----BEGIN ENCRYPTED PRIVATE KEY-----`). The unencrypted result is then imported by
 * the caller via `crypto.subtle.importKey('pkcs8', ...)`.
 *
 * @internal
 */
import { AuthError } from '../core/errors';
import { Der } from './asn1';

const OID_PBES2 = '1.2.840.113549.1.5.13';
const OID_PBKDF2 = '1.2.840.113549.1.5.12';

const PRF: Record<string, string> = {
	'1.2.840.113549.2.7': 'SHA-1',
	'1.2.840.113549.2.9': 'SHA-256',
	'1.2.840.113549.2.10': 'SHA-384',
	'1.2.840.113549.2.11': 'SHA-512'
};

const SCHEME: Record<string, { name: 'AES-CBC' | 'AES-GCM'; keyLen: number }> = {
	'2.16.840.1.101.3.4.1.2': { name: 'AES-CBC', keyLen: 16 },
	'2.16.840.1.101.3.4.1.22': { name: 'AES-CBC', keyLen: 24 },
	'2.16.840.1.101.3.4.1.42': { name: 'AES-CBC', keyLen: 32 },
	'2.16.840.1.101.3.4.1.6': { name: 'AES-GCM', keyLen: 16 },
	'2.16.840.1.101.3.4.1.26': { name: 'AES-GCM', keyLen: 24 },
	'2.16.840.1.101.3.4.1.46': { name: 'AES-GCM', keyLen: 32 }
};

/**
 * Decrypts a PBES2 `EncryptedPrivateKeyInfo` DER into unencrypted PKCS#8 DER.
 *
 * @param der - The encrypted PKCS#8 DER.
 * @param passphrase - The passphrase.
 * @returns The decrypted PKCS#8 DER.
 * @throws {AuthError} On an unsupported scheme or a wrong passphrase.
 * @since 1.0.0
 */
export async function decryptPkcs8(der: Uint8Array, passphrase: string): Promise<Uint8Array> {
	const root = new Der(der).sequence();
	const algId = root.sequence();
	if (algId.oid() !== OID_PBES2)
		throw new AuthError('unsupported encrypted key (only PBES2 PKCS#8)');

	const params = algId.sequence();
	const kdf = params.sequence();
	if (kdf.oid() !== OID_PBKDF2) throw new AuthError('unsupported key derivation (only PBKDF2)');

	const kdfParams = kdf.sequence();
	const salt = kdfParams.octetString();
	const iterations = kdfParams.integer();
	let keyLenHint: number | undefined;
	let prf = 'SHA-1';
	while (kdfParams.hasMore()) {
		const tag = kdfParams.peekTag();
		if (tag === 0x02) keyLenHint = kdfParams.integer();
		else if (tag === 0x30) prf = PRF[kdfParams.sequence().oid()] ?? 'SHA-1';
		else kdfParams.skip();
	}

	const enc = params.sequence();
	const scheme = SCHEME[enc.oid()];
	if (!scheme) throw new AuthError('unsupported PBES2 cipher (expected AES-CBC or AES-GCM)');
	const iv = scheme.name === 'AES-CBC' ? enc.octetString() : enc.sequence().octetString();
	const encData = root.octetString();

	const baseKey = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(passphrase) as BufferSource,
		'PBKDF2',
		false,
		['deriveBits']
	);
	const bits = await crypto.subtle.deriveBits(
		{ name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: prf },
		baseKey,
		(keyLenHint ?? scheme.keyLen) * 8
	);
	const aesKey = await crypto.subtle.importKey('raw', bits, scheme.name, false, ['decrypt']);
	try {
		const algo =
			scheme.name === 'AES-CBC'
				? { name: 'AES-CBC', iv: iv as BufferSource }
				: { name: 'AES-GCM', iv: iv as BufferSource, tagLength: 128 };
		return new Uint8Array(await crypto.subtle.decrypt(algo, aesKey, encData as BufferSource));
	} catch (cause) {
		throw new AuthError('could not decrypt private key (wrong passphrase?)', { cause });
	}
}
