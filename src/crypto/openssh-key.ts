/**
 * @fileoverview Parses the `openssh-key-v1` private-key format (the `ssh-keygen` default,
 * `-----BEGIN OPENSSH PRIVATE KEY-----`), encrypted or not, and reconstructs a signing
 * {@link CryptoKey}.
 *
 * Encrypted keys derive their cipher key/IV with bcrypt_pbkdf (the `bcrypt-pbkdf`
 * dependency) and are decrypted with AES-CTR. Supported inner key types: Ed25519,
 * ECDSA-P256, and RSA. The `aes*-gcm`/`chacha20-poly1305` key ciphers and non-bcrypt KDFs
 * are rejected with a clear error.
 *
 * @internal
 */
import bcrypt from 'bcrypt-pbkdf';
import { AuthError } from '../core/errors';
import { SshReader } from '../wire';

const MAGIC = 'openssh-key-v1\0';

const KEY_CIPHER: Record<string, { keyLen: number; ivLen: number }> = {
	none: { keyLen: 0, ivLen: 0 },
	'aes128-ctr': { keyLen: 16, ivLen: 16 },
	'aes256-ctr': { keyLen: 32, ivLen: 16 }
};

function b64url(b: Uint8Array): string {
	let bin = '';
	for (const x of b) bin += String.fromCharCode(x);
	return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function strip(b: Uint8Array): Uint8Array {
	let i = 0;
	while (i < b.length - 1 && b[i] === 0) i++;
	return b.subarray(i);
}

function bytesToBn(b: Uint8Array): bigint {
	let n = 0n;
	for (const x of b) n = (n << 8n) | BigInt(x);
	return n;
}

function bnToBytes(n: bigint): Uint8Array {
	if (n === 0n) return new Uint8Array([0]);
	const out: number[] = [];
	while (n > 0n) {
		out.unshift(Number(n & 0xffn));
		n >>= 8n;
	}
	return new Uint8Array(out);
}

function leftPad(b: Uint8Array, len: number): Uint8Array {
	if (b.length >= len) return b;
	const out = new Uint8Array(len);
	out.set(b, len - b.length);
	return out;
}

// reconstructs a signing CryptoKey from the decrypted private-key blob (positioned at the
// key type string)
async function importPrivate(r: SshReader): Promise<CryptoKey> {
	const type = r.stringUtf8();
	switch (type) {
		case 'ssh-ed25519': {
			const pub = r.string(); // 32 bytes
			const priv = r.string(); // 64 bytes (seed || pub)
			const seed = priv.subarray(0, 32);
			return crypto.subtle.importKey(
				'jwk',
				{
					kty: 'OKP',
					crv: 'Ed25519',
					d: b64url(seed),
					x: b64url(pub),
					key_ops: ['sign'],
					ext: true
				},
				{ name: 'Ed25519' },
				true,
				['sign']
			);
		}
		case 'ecdsa-sha2-nistp256': {
			r.stringUtf8(); // "nistp256"
			const q = r.string(); // 0x04 || X(32) || Y(32)
			const d = leftPad(strip(r.mpint()), 32);
			return crypto.subtle.importKey(
				'jwk',
				{
					kty: 'EC',
					crv: 'P-256',
					d: b64url(d),
					x: b64url(q.subarray(1, 33)),
					y: b64url(q.subarray(33, 65)),
					key_ops: ['sign'],
					ext: true
				},
				{ name: 'ECDSA', namedCurve: 'P-256' },
				true,
				['sign']
			);
		}
		case 'ssh-rsa': {
			const n = bytesToBn(r.mpint());
			const e = bytesToBn(r.mpint());
			const d = bytesToBn(r.mpint());
			const iqmp = strip(r.mpint());
			const p = bytesToBn(r.mpint());
			const q = bytesToBn(r.mpint());
			const dp = d % (p - 1n);
			const dq = d % (q - 1n);
			return crypto.subtle.importKey(
				'jwk',
				{
					kty: 'RSA',
					n: b64url(strip(bnToBytes(n))),
					e: b64url(strip(bnToBytes(e))),
					d: b64url(strip(bnToBytes(d))),
					p: b64url(strip(bnToBytes(p))),
					q: b64url(strip(bnToBytes(q))),
					dp: b64url(strip(bnToBytes(dp))),
					dq: b64url(strip(bnToBytes(dq))),
					qi: b64url(iqmp),
					key_ops: ['sign'],
					ext: true
				},
				{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
				true,
				['sign']
			);
		}
		default:
			throw new AuthError(`unsupported OpenSSH key type ${type}`);
	}
}

/**
 * Parses an `openssh-key-v1` blob (the bytes inside the PEM armor) and returns a signing
 * private key.
 *
 * @param blob - The decoded key bytes.
 * @param passphrase - The passphrase, required iff the key is encrypted.
 * @returns The reconstructed private key.
 * @throws {AuthError} On an unsupported cipher/KDF, a missing/wrong passphrase, or a bad type.
 * @since 1.0.0
 */
export async function parseOpenSshKey(blob: Uint8Array, passphrase?: string): Promise<CryptoKey> {
	const magic = new TextDecoder().decode(blob.subarray(0, MAGIC.length));
	if (magic !== MAGIC) throw new AuthError('not an openssh-key-v1 private key');
	const r = new SshReader(blob.subarray(MAGIC.length));
	const cipherName = r.stringUtf8();
	const kdfName = r.stringUtf8();
	const kdfOptions = r.string();
	r.uint32(); // number of keys (assume 1)
	r.string(); // public key blob
	let priv = r.string(); // the (possibly encrypted) private section

	const cipher = KEY_CIPHER[cipherName];
	if (!cipher)
		throw new AuthError(`unsupported OpenSSH key cipher ${cipherName} (use none or aes256-ctr)`);

	if (cipherName !== 'none') {
		if (kdfName !== 'bcrypt') throw new AuthError(`unsupported OpenSSH KDF ${kdfName}`);
		if (!passphrase) throw new AuthError('this key is encrypted; a passphrase is required');
		const opts = new SshReader(kdfOptions);
		const salt = opts.string();
		const rounds = opts.uint32();
		const material = new Uint8Array(cipher.keyLen + cipher.ivLen);
		const pass = new TextEncoder().encode(passphrase);
		// bcrypt_pbkdf fills `material` with key||iv
		bcrypt.pbkdf(pass, pass.length, salt, salt.length, material, material.length, rounds);
		const key = await crypto.subtle.importKey(
			'raw',
			material.subarray(0, cipher.keyLen) as BufferSource,
			'AES-CTR',
			false,
			['decrypt']
		);
		priv = new Uint8Array(
			await crypto.subtle.decrypt(
				{ name: 'AES-CTR', counter: material.subarray(cipher.keyLen) as BufferSource, length: 128 },
				key,
				priv as BufferSource
			)
		);
	}

	const pr = new SshReader(priv);
	if (pr.uint32() !== pr.uint32()) {
		throw new AuthError('could not decrypt OpenSSH key (wrong passphrase?)');
	}
	return importPrivate(pr);
}
