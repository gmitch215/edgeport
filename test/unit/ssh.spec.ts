import { describe, expect, it } from 'vitest';
import { authenticate, type PacketTransport } from '../../src/auth';
import { Msg } from '../../src/constants';
import { AuthError, ConnectionError, ProtocolError } from '../../src/core/errors';
import { StreamFramedReader } from '../../src/core/framing';
import {
	cipherSizes,
	concatBytes,
	createPacketCipher,
	loadUserKey,
	verifyHostSignature,
	type DirectionKeys
} from '../../src/crypto';
import { buildPaddedBody, NoneCipher, unwrapBody } from '../../src/crypto/packet';
import { buildKexInit, negotiate, nistp256, parseKexInit } from '../../src/kex';
import { SshTransport } from '../../src/ssh/transport/transport';
import { SshReader, SshWriter, toMpintBody } from '../../src/wire';
import osshEc from '../fixtures/ecdsa_openssh?raw';
import osshEd from '../fixtures/ed25519_openssh?raw';
import osshEdEnc from '../fixtures/ed25519_openssh_enc?raw';
import pkcs8Enc from '../fixtures/ed25519_pkcs8_enc.pem?raw';
import osshRsa from '../fixtures/rsa_openssh?raw';
import { mockConnection } from '../mock-socket';
import { toHex } from '../util';

describe('wire codecs (RFC 4251)', () => {
	const hex = (bytes: Uint8Array) =>
		[...bytes].map((b) => b.toString(16).padStart(2, '0')).join(' ');
	const fromHex = (s: string) => new Uint8Array(s.split(/\s+/).map((h) => parseInt(h, 16)));

	describe('mpint encoding (RFC 4251 section 5 examples)', () => {
		it('encodes 0 as an empty body', () => {
			expect(hex(new SshWriter().mpint(fromHex('00')).bytes())).toBe('00 00 00 00');
		});

		it('encodes 0x09a378f9b2e332a7 verbatim (high bit clear)', () => {
			const v = fromHex('09 a3 78 f9 b2 e3 32 a7');
			expect(hex(new SshWriter().mpint(v).bytes())).toBe('00 00 00 08 09 a3 78 f9 b2 e3 32 a7');
		});

		it('prepends 0x00 to 0x80 (high bit set)', () => {
			expect(hex(new SshWriter().mpint(fromHex('80')).bytes())).toBe('00 00 00 02 00 80');
		});

		it('strips leading zeros then sign-pads 0xdeadbeef', () => {
			expect(hex(toMpintBody(fromHex('00 00 de ad be ef')))).toBe('00 de ad be ef');
		});
	});

	describe('SshWriter / SshReader round-trips', () => {
		it('round-trips byte, boolean, uint32, uint64', () => {
			const buf = new SshWriter()
				.byte(0x1f)
				.boolean(true)
				.uint32(0xdeadbeef)
				.uint64(0x0102030405060708n)
				.bytes();
			const r = new SshReader(buf);
			expect(r.byte()).toBe(0x1f);
			expect(r.boolean()).toBe(true);
			expect(r.uint32()).toBe(0xdeadbeef);
			expect(r.uint64()).toBe(0x0102030405060708n);
			expect(r.remaining).toBe(0);
		});

		it('round-trips strings and name-lists', () => {
			const buf = new SshWriter()
				.string('ssh-userauth')
				.nameList(['curve25519-sha256', 'ecdh-sha2-nistp256'])
				.nameList([])
				.bytes();
			const r = new SshReader(buf);
			expect(r.stringUtf8()).toBe('ssh-userauth');
			expect(r.nameList()).toEqual(['curve25519-sha256', 'ecdh-sha2-nistp256']);
			expect(r.nameList()).toEqual([]);
		});

		it('round-trips an mpint as a bigint', () => {
			const buf = new SshWriter().mpint(fromHex('80')).bytes();
			expect(new SshReader(buf).mpintBigInt()).toBe(0x80n);
		});

		it('throws ProtocolError when reading past the end', () => {
			const r = new SshReader(fromHex('00 00 00 04 01 02'));
			expect(() => r.string()).toThrow();
		});
	});
});

describe('binary packet framing', () => {
	const streamOf = (b: Uint8Array) =>
		new ReadableStream<Uint8Array>({
			start(c) {
				c.enqueue(b);
				c.close();
			}
		});

	describe('binary packet framing', () => {
		it('pads to an 8-byte multiple with >= 4 padding bytes', () => {
			for (let len = 0; len < 40; len++) {
				const body = buildPaddedBody(new Uint8Array(len), 8, true);
				const padLen = body[0]!;
				expect(padLen).toBeGreaterThanOrEqual(4);
				expect((4 + body.length) % 8).toBe(0); // length field counted
				expect(unwrapBody(body)).toHaveLength(len);
			}
		});

		it('aligns the encrypted portion when the length field is excluded', () => {
			const body = buildPaddedBody(new Uint8Array(10), 16, false);
			expect(body.length % 16).toBe(0);
		});

		it('NoneCipher seals then opens a payload unchanged', async () => {
			const payload = new TextEncoder().encode('the quick brown fox');
			const cipher = new NoneCipher();
			const wire = await cipher.seal(0, payload);
			const got = await cipher.open(0, new StreamFramedReader(streamOf(wire)));
			expect(new TextDecoder().decode(got)).toBe('the quick brown fox');
		});
	});
});

describe('cipher constructions', () => {
	const seq = (n: number) => new Uint8Array(n).map((_, i) => (i * 7 + 3) & 0xff);
	const streamOf = (b: Uint8Array) =>
		new ReadableStream<Uint8Array>({
			start(c) {
				c.enqueue(b);
				c.close();
			}
		});

	function keysFor(cipher: string, mac: string): DirectionKeys {
		const s = cipherSizes(cipher, mac);
		return { iv: seq(s.ivLen), key: seq(s.keyLen), macKey: seq(s.macKeyLen) };
	}

	const CASES: [string, string][] = [
		['aes256-gcm@openssh.com', ''],
		['aes128-gcm@openssh.com', ''],
		['chacha20-poly1305@openssh.com', ''],
		['aes256-ctr', 'hmac-sha2-256'],
		['aes128-ctr', 'hmac-sha2-512']
	];

	describe('cipher round-trip and tamper rejection', () => {
		for (const [cipher, mac] of CASES) {
			it(`${cipher}: seals and opens multiple packets in order`, async () => {
				const sender = await createPacketCipher(cipher, mac, keysFor(cipher, mac));
				const receiver = await createPacketCipher(cipher, mac, keysFor(cipher, mac));
				const payloads = [new Uint8Array(0), seq(1), seq(15), seq(16), seq(200)];
				const wires: Uint8Array[] = [];
				for (let i = 0; i < payloads.length; i++)
					wires.push(await sender.seal(i, payloads[i] as Uint8Array));
				const reader = new StreamFramedReader(streamOf(concatBytes(...wires)));
				for (let i = 0; i < payloads.length; i++) {
					const expected = payloads[i] as Uint8Array;
					expect([...(await receiver.open(i, reader))]).toEqual([...expected]);
				}
			});

			it(`${cipher}: rejects a tampered ciphertext`, async () => {
				const sender = await createPacketCipher(cipher, mac, keysFor(cipher, mac));
				const receiver = await createPacketCipher(cipher, mac, keysFor(cipher, mac));
				const wire = await sender.seal(0, seq(64));
				wire[wire.length - 1]! ^= 0xff; // flip a tag/MAC byte
				await expect(
					receiver.open(0, new StreamFramedReader(streamOf(wire)))
				).rejects.toBeInstanceOf(ProtocolError);
			});

			it(`${cipher}: rejects an out-of-order packet`, async () => {
				const sender = await createPacketCipher(cipher, mac, keysFor(cipher, mac));
				const receiver = await createPacketCipher(cipher, mac, keysFor(cipher, mac));
				await sender.seal(0, seq(32)); // advance the sender to counter/seq 1
				const second = await sender.seal(1, seq(32));
				// delivering the second packet first desyncs the GCM counter / chacha nonce / ctr state
				await expect(
					receiver.open(0, new StreamFramedReader(streamOf(second)))
				).rejects.toBeInstanceOf(ProtocolError);
			});
		}
	});
});

describe('host and user keys', () => {
	const data = new TextEncoder().encode('exchange-hash-stand-in');

	async function genPrivate(kind: 'ed25519' | 'ecdsa' | 'rsa'): Promise<CryptoKey> {
		if (kind === 'ed25519') {
			return (
				(await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
					'sign',
					'verify'
				])) as CryptoKeyPair
			).privateKey;
		}
		if (kind === 'ecdsa') {
			return (
				(await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
					'sign',
					'verify'
				])) as CryptoKeyPair
			).privateKey;
		}
		return (
			(await crypto.subtle.generateKey(
				{
					name: 'RSASSA-PKCS1-v1_5',
					modulusLength: 2048,
					publicExponent: new Uint8Array([1, 0, 1]),
					hash: 'SHA-512'
				},
				true,
				['sign', 'verify']
			)) as CryptoKeyPair
		).privateKey;
	}

	describe('user-key sign <-> host-key verify round-trip', () => {
		for (const kind of ['ed25519', 'ecdsa', 'rsa'] as const) {
			it(`${kind}: a fresh signature verifies, a tampered message does not`, async () => {
				const key = await loadUserKey(await genPrivate(kind));
				const sig = await key.sign(data);
				expect(await verifyHostSignature(key.algorithm, key.publicBlob, sig, data)).toBe(true);

				const tampered = data.slice();
				tampered[0]! ^= 0xff;
				expect(await verifyHostSignature(key.algorithm, key.publicBlob, sig, tampered)).toBe(false);
			});
		}
	});

	describe('loadUserKey', () => {
		it('parses a PKCS8 PEM (ed25519) and signs verifiably', async () => {
			const pem = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPPGnP1OPdTdAUzAf5iM/AsZ//kp00OKoDxsi/zPEmiL
-----END PRIVATE KEY-----`;
			const key = await loadUserKey({ pem });
			expect(key.algorithm).toBe('ssh-ed25519');
			const sig = await key.sign(data);
			expect(await verifyHostSignature('ssh-ed25519', key.publicBlob, sig, data)).toBe(true);
		});

		it('rejects an unparseable key with AuthError', async () => {
			await expect(
				loadUserKey({ pem: '-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5\n-----END PRIVATE KEY-----' })
			).rejects.toBeInstanceOf(AuthError);
		});
	});
});

describe('KEXINIT negotiation', () => {
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
});

describe('nistp256 kex', () => {
	it('derives a matching shared secret on both ends', async () => {
		const a = await nistp256.generateKeyPair();
		const b = await nistp256.generateKeyPair();
		const ab = await nistp256.deriveShared(a.privateKey, b.publicKey);
		const ba = await nistp256.deriveShared(b.privateKey, a.publicKey);
		expect(ab).toHaveLength(32);
		expect(toHex(ab)).toBe(toHex(ba));
	});

	it('rejects an invalid peer point', async () => {
		const a = await nistp256.generateKeyPair();
		await expect(nistp256.deriveShared(a.privateKey, new Uint8Array(65))).rejects.toBeTruthy();
	});
});

describe('authentication', () => {
	const serviceAccept = () =>
		new SshWriter().byte(Msg.SERVICE_ACCEPT).string('ssh-userauth').bytes();
	const success = () => new SshWriter().byte(Msg.USERAUTH_SUCCESS).bytes();
	const failure = () =>
		new SshWriter().byte(Msg.USERAUTH_FAILURE).nameList(['publickey']).boolean(false).bytes();
	const banner = () => new SshWriter().byte(Msg.USERAUTH_BANNER).string('hi').string('en').bytes();
	const infoRequest = () =>
		new SshWriter()
			.byte(Msg.USERAUTH_INFO_REQUEST)
			.string('')
			.string('')
			.string('')
			.uint32(1)
			.string('Password:')
			.boolean(false)
			.bytes();

	// a mock transport: scripted server replies (FIFO), recorded client sends, optional disconnect
	function mockTransport(replies: Uint8Array[], disconnectWhenDrained = false) {
		const sent: Uint8Array[] = [];
		const queue = [...replies];
		const t = {
			sessionId: new Uint8Array(32),
			async send(p: Uint8Array) {
				sent.push(p);
			},
			async read(): Promise<Uint8Array> {
				if (queue.length === 0) {
					if (disconnectWhenDrained) throw new ConnectionError('connection closed');
					throw new ConnectionError('no more scripted replies');
				}
				return queue.shift()!;
			}
		};
		return { t: t as PacketTransport, sent };
	}

	const typeOf = (p: Uint8Array) => new SshReader(p).byte();

	describe('authenticate', () => {
		it('succeeds with password and sends the right requests', async () => {
			const { t, sent } = mockTransport([serviceAccept(), success()]);
			await authenticate(t, { username: 'u', password: 'p' });
			expect(typeOf(sent[0]!)).toBe(Msg.SERVICE_REQUEST);
			expect(typeOf(sent[1]!)).toBe(Msg.USERAUTH_REQUEST);
		});

		it('throws AuthError when password is rejected', async () => {
			const { t } = mockTransport([serviceAccept(), failure()]);
			await expect(authenticate(t, { username: 'u', password: 'bad' })).rejects.toBeInstanceOf(
				AuthError
			);
		});

		it('throws AuthError when no method is supplied', async () => {
			const { t } = mockTransport([serviceAccept()]);
			await expect(authenticate(t, { username: 'u' })).rejects.toBeInstanceOf(AuthError);
		});

		it('skips USERAUTH_BANNER before the result', async () => {
			const { t } = mockTransport([serviceAccept(), banner(), success()]);
			await expect(authenticate(t, { username: 'u', password: 'p' })).resolves.toBeUndefined();
		});

		it('drives keyboard-interactive prompts and responds', async () => {
			const { t, sent } = mockTransport([serviceAccept(), infoRequest(), success()]);
			let seen: string[] = [];
			await authenticate(t, {
				username: 'u',
				onKeyboardInteractive: async (prompts) => {
					seen = prompts.map((p) => p.prompt);
					return ['otp-123'];
				}
			});
			expect(seen).toEqual(['Password:']);
			expect(typeOf(sent[sent.length - 1]!)).toBe(Msg.USERAUTH_INFO_RESPONSE);
		});

		it('rejects with ProtocolError if the service is not accepted', async () => {
			const { t } = mockTransport([success()]); // wrong reply to SERVICE_REQUEST
			await expect(authenticate(t, { username: 'u', password: 'p' })).rejects.toBeInstanceOf(
				ProtocolError
			);
		});

		it('propagates a spontaneous disconnect mid-authentication', async () => {
			const { t } = mockTransport([serviceAccept()], true); // drops after accepting the service
			await expect(authenticate(t, { username: 'u', password: 'p' })).rejects.toBeInstanceOf(
				ConnectionError
			);
		});
	});
});

describe('transport', () => {
	it('throws ConnectionError on SSH_MSG_DISCONNECT', async () => {
		const { socket, server } = mockConnection();
		const transport = new SshTransport(socket);
		const none = new NoneCipher();
		const disconnect = new SshWriter()
			.byte(Msg.DISCONNECT)
			.uint32(11)
			.string('bye')
			.string('')
			.bytes();
		await server.write(await none.seal(0, disconnect));
		await expect(transport.read()).rejects.toBeInstanceOf(ConnectionError);
	});

	it('skips IGNORE and DEBUG packets and returns the next real one', async () => {
		const { socket, server } = mockConnection();
		const transport = new SshTransport(socket);
		const none = new NoneCipher();
		await server.write(
			await none.seal(0, new SshWriter().byte(Msg.IGNORE).string('noise').bytes())
		);
		await server.write(
			await none.seal(
				1,
				new SshWriter().byte(Msg.DEBUG).boolean(false).string('dbg').string('').bytes()
			)
		);
		await server.write(await none.seal(2, new SshWriter().byte(Msg.NEWKEYS).bytes()));
		const p = await transport.read();
		expect(p[0]).toBe(Msg.NEWKEYS);
	});
});

describe('encrypted private keys', () => {
	const data = new TextEncoder().encode('exchange-hash-stand-in');

	async function signsAndVerifies(pem: string, passphrase?: string): Promise<boolean> {
		const key = await loadUserKey({ pem, passphrase });
		const sig = await key.sign(data);
		return verifyHostSignature(key.algorithm, key.publicBlob, sig, data);
	}

	describe('encrypted PKCS#8 (PBES2)', () => {
		it('decrypts with the passphrase and signs verifiably', async () => {
			expect(await signsAndVerifies(pkcs8Enc, 'secret')).toBe(true);
		});

		it('rejects a wrong passphrase with AuthError', async () => {
			await expect(loadUserKey({ pem: pkcs8Enc, passphrase: 'nope' })).rejects.toBeInstanceOf(
				AuthError
			);
		});

		it('requires a passphrase', async () => {
			await expect(loadUserKey({ pem: pkcs8Enc })).rejects.toBeInstanceOf(AuthError);
		});
	});

	describe('OpenSSH private-key format', () => {
		it('loads an unencrypted ed25519 key', async () => {
			expect(await signsAndVerifies(osshEd)).toBe(true);
		});

		it('loads an unencrypted ecdsa-p256 key', async () => {
			expect(await signsAndVerifies(osshEc)).toBe(true);
		});

		it('loads an unencrypted rsa key', async () => {
			expect(await signsAndVerifies(osshRsa)).toBe(true);
		});

		it('decrypts a bcrypt-encrypted ed25519 key with the passphrase', async () => {
			expect(await signsAndVerifies(osshEdEnc, 'secret')).toBe(true);
		});

		it('rejects a wrong passphrase with AuthError', async () => {
			await expect(loadUserKey({ pem: osshEdEnc, passphrase: 'nope' })).rejects.toBeInstanceOf(
				AuthError
			);
		});

		it('requires a passphrase for an encrypted key', async () => {
			await expect(loadUserKey({ pem: osshEdEnc })).rejects.toBeInstanceOf(AuthError);
		});
	});
});
