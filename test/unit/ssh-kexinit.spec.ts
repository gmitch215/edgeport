import { describe, expect, it } from 'vitest';
import { ProtocolError } from '../../src/core/errors';
import { buildKexInit, negotiate, parseKexInit } from '../../src/kex';

// a server KEXINIT offering a typical modern set
function serverLists(overrides: Partial<Record<string, string[]>> = {}) {
	const base = {
		kex: ['curve25519-sha256', 'ecdh-sha2-nistp256'],
		hostKey: ['ssh-ed25519', 'rsa-sha2-512'],
		cipher: ['aes256-gcm@openssh.com', 'chacha20-poly1305@openssh.com', 'aes256-ctr'],
		mac: ['hmac-sha2-256'],
		comp: ['none']
	};
	const c = { ...base, ...overrides };
	// reuse buildKexInit shape by parsing a server payload we construct via the same writer
	return parseKexInit(
		buildKexInit({ kex: c.kex, hostKey: c.hostKey, cipher: c.cipher, mac: c.mac })
	);
}

describe('KEXINIT negotiation', () => {
	it('round-trips build/parse', () => {
		const lists = parseKexInit(buildKexInit());
		expect(lists.kex).toContain('curve25519-sha256');
		expect(lists.cipherC2S).toContain('aes256-gcm@openssh.com');
	});

	it('picks the first client-preferred common algorithm', () => {
		const neg = negotiate(serverLists());
		expect(neg.kex).toBe('curve25519-sha256');
		expect(neg.hostKey).toBe('ssh-ed25519');
		expect(neg.cipherC2S).toBe('aes256-gcm@openssh.com');
	});

	it('leaves the MAC empty for AEAD ciphers', () => {
		const neg = negotiate(serverLists());
		expect(neg.macC2S).toBe('');
		expect(neg.macS2C).toBe('');
	});

	it('negotiates a MAC when a non-AEAD cipher wins', () => {
		const neg = negotiate(serverLists({ cipher: ['aes256-ctr'] }));
		expect(neg.cipherC2S).toBe('aes256-ctr');
		expect(neg.macC2S).toBe('hmac-sha2-256');
	});

	it('fails cleanly when no cipher is shared', () => {
		expect(() => negotiate(serverLists({ cipher: ['3des-cbc', 'blowfish-cbc'] }))).toThrow(
			ProtocolError
		);
	});

	it('honors a client cipher override (forcing one path)', () => {
		const neg = negotiate(serverLists(), { cipher: ['chacha20-poly1305@openssh.com'] });
		expect(neg.cipherC2S).toBe('chacha20-poly1305@openssh.com');
	});
});
