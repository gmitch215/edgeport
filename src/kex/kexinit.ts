/**
 * @fileoverview SSH_MSG_KEXINIT build/parse and algorithm negotiation (RFC 4253 7.1).
 *
 * Negotiation is a pure function over the two algorithm name-lists, so it is fully
 * unit-tested - including the clean failure when no cipher is shared (never a hang).
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { Msg } from '../constants';
import { ProtocolError } from '../core/errors';
import { randomBytes } from '../crypto/primitives';
import { SshReader, SshWriter } from '../wire';

/** Our supported algorithms, in client preference order. */
export const CLIENT_ALGORITHMS = {
	kex: ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256'],
	hostKey: ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-512', 'rsa-sha2-256'],
	cipher: [
		'aes256-gcm@openssh.com',
		'aes128-gcm@openssh.com',
		'chacha20-poly1305@openssh.com',
		'aes256-ctr',
		'aes128-ctr'
	],
	mac: ['hmac-sha2-256', 'hmac-sha2-512'],
	compression: ['none']
} as const;

/** Per-direction algorithm preference overrides for a connection. */
export interface AlgorithmPrefs {
	kex?: string[];
	hostKey?: string[];
	cipher?: string[];
	mac?: string[];
}

/** The algorithm name-lists parsed from a peer's KEXINIT. */
export interface KexInitLists {
	kex: string[];
	hostKey: string[];
	cipherC2S: string[];
	cipherS2C: string[];
	macC2S: string[];
	macS2C: string[];
	compC2S: string[];
	compS2C: string[];
}

/** The algorithms chosen by negotiation. */
export interface Negotiated {
	kex: string;
	hostKey: string;
	cipherC2S: string;
	cipherS2C: string;
	macC2S: string;
	macS2C: string;
	compC2S: string;
	compS2C: string;
}

/** Builds our SSH_MSG_KEXINIT payload using the given preferences. */
export function buildKexInit(prefs: AlgorithmPrefs = {}): Uint8Array {
	const kex = prefs.kex ?? [...CLIENT_ALGORITHMS.kex];
	const hostKey = prefs.hostKey ?? [...CLIENT_ALGORITHMS.hostKey];
	const cipher = prefs.cipher ?? [...CLIENT_ALGORITHMS.cipher];
	const mac = prefs.mac ?? [...CLIENT_ALGORITHMS.mac];
	const comp = [...CLIENT_ALGORITHMS.compression];
	return new SshWriter()
		.byte(Msg.KEXINIT)
		.raw(randomBytes(16))
		.nameList(kex)
		.nameList(hostKey)
		.nameList(cipher)
		.nameList(cipher)
		.nameList(mac)
		.nameList(mac)
		.nameList(comp)
		.nameList(comp)
		.nameList([])
		.nameList([])
		.boolean(false)
		.uint32(0)
		.bytes();
}

/** Parses a peer SSH_MSG_KEXINIT payload into its name-lists. */
export function parseKexInit(payload: Uint8Array): KexInitLists {
	const r = new SshReader(payload);
	if (r.byte() !== Msg.KEXINIT) throw new ProtocolError('expected SSH_MSG_KEXINIT');
	r.raw(16); // cookie
	const lists: KexInitLists = {
		kex: r.nameList(),
		hostKey: r.nameList(),
		cipherC2S: r.nameList(),
		cipherS2C: r.nameList(),
		macC2S: r.nameList(),
		macS2C: r.nameList(),
		compC2S: r.nameList(),
		compS2C: r.nameList()
	};
	r.nameList(); // languages c2s
	r.nameList(); // languages s2c
	return lists;
}

// first client-preferred name that the server also offers
function pick(category: string, client: readonly string[], server: string[]): string {
	const match = client.find((name) => server.includes(name));
	if (!match) {
		throw new ProtocolError(
			`no common ${category}: offered [${client.join(', ')}], server has [${server.join(', ')}]`
		);
	}
	return match;
}

// AEAD ciphers carry their own MAC, so no separate mac algorithm is negotiated for them
function isAead(cipher: string): boolean {
	return cipher.endsWith('-gcm@openssh.com') || cipher === 'chacha20-poly1305@openssh.com';
}

/**
 * Negotiates the algorithm set from the server's KEXINIT and our preferences. Client
 * preference order wins (as a client should).
 *
 * @param server - The server's parsed KEXINIT lists.
 * @param prefs - Optional client preference overrides.
 * @returns The negotiated algorithms.
 * @throws {ProtocolError} If any required category has no common algorithm.
 * @since 1.0.0
 */
export function negotiate(server: KexInitLists, prefs: AlgorithmPrefs = {}): Negotiated {
	const cKex = prefs.kex ?? CLIENT_ALGORITHMS.kex;
	const cHost = prefs.hostKey ?? CLIENT_ALGORITHMS.hostKey;
	const cCipher = prefs.cipher ?? CLIENT_ALGORITHMS.cipher;
	const cMac = prefs.mac ?? CLIENT_ALGORITHMS.mac;

	const cipherC2S = pick('cipher c2s', cCipher, server.cipherC2S);
	const cipherS2C = pick('cipher s2c', cCipher, server.cipherS2C);
	return {
		kex: pick('kex', cKex, server.kex),
		hostKey: pick('host key', cHost, server.hostKey),
		cipherC2S,
		cipherS2C,
		macC2S: isAead(cipherC2S) ? '' : pick('mac c2s', cMac, server.macC2S),
		macS2C: isAead(cipherS2C) ? '' : pick('mac s2c', cMac, server.macS2C),
		compC2S: pick('compression c2s', CLIENT_ALGORITHMS.compression, server.compC2S),
		compS2C: pick('compression s2c', CLIENT_ALGORITHMS.compression, server.compS2C)
	};
}
