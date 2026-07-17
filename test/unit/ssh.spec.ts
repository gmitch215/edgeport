import { describe, expect, it, vi } from 'vitest';
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
import { sudo, sudoExec } from '../../src/ssh';
import { SshConnection, type ChannelExit } from '../../src/ssh/connection';
import * as sshIndex from '../../src/ssh/index';
import { Session, type SshChannelHandle, type SshSession } from '../../src/ssh/index';
import { assertSafeDeletePath, shellQuote } from '../../src/ssh/shell-quote';
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

// shared channel/session doubles for the sudo + command-helper suites
const dec = new TextDecoder();
const enc = new TextEncoder();

interface CannedExec {
	stdout?: string;
	stderr?: string;
	code?: number;
}

// a stub channel handle that records writes and serves canned stdout/stderr/exit
function stubChannel(opts: {
	stdout?: Uint8Array;
	stderr?: Uint8Array;
	exit?: ChannelExit;
}): SshChannelHandle & { writes: Uint8Array[]; eofCalled: boolean; closeCalled: boolean } {
	const writes: Uint8Array[] = [];
	const oneChunk = (data?: Uint8Array) =>
		new ReadableStream<Uint8Array>({
			start(c) {
				if (data && data.length) c.enqueue(data);
				c.close();
			}
		});
	const handle = {
		writes,
		eofCalled: false,
		closeCalled: false,
		stdout: oneChunk(opts.stdout),
		stderr: oneChunk(opts.stderr),
		exit: Promise.resolve(opts.exit ?? { code: 0, signal: null }),
		async write(data: Uint8Array) {
			writes.push(data);
		},
		async eof() {
			handle.eofCalled = true;
		},
		async close() {
			handle.closeCalled = true;
		},
		[Symbol.asyncDispose]: async () => {}
	};
	return handle;
}

// === sudo (was test/unit/ssh-sudo.spec.ts) ===

// a fake session capturing the execStream command and handing back a stub channel
function fakeSession(channel: ReturnType<typeof stubChannel>): SshSession & { commands: string[] } {
	const commands: string[] = [];
	const session = {
		commands,
		async execStream(command: string) {
			commands.push(command);
			return channel;
		},
		exec: async () => {
			throw new Error('not used');
		},
		shell: async () => {
			throw new Error('not used');
		},
		subsystem: async () => {
			throw new Error('not used');
		},
		forwardOut: async () => {
			throw new Error('not used');
		},
		rekey: async () => {},
		close: async () => {},
		[Symbol.asyncDispose]: async () => {}
	};
	return session as unknown as SshSession & { commands: string[] };
}

describe('sudo', () => {
	it("prefixes sudo -S -p '' and feeds the password + newline to stdin", async () => {
		const ch = stubChannel({ stdout: new TextEncoder().encode('root\n') });
		const session = fakeSession(ch);

		const result = await sudo(session, 'whoami', { password: 'hunter2' });

		expect(session.commands).toEqual(["sudo -S -p '' whoami"]);
		expect(ch.writes).toHaveLength(1);
		expect(dec.decode(ch.writes[0])).toBe('hunter2\n');
		expect(ch.eofCalled).toBe(true);
		expect(ch.closeCalled).toBe(true);
		expect(dec.decode(result.stdout)).toBe('root\n');
		expect(result.code).toBe(0);
	});

	it('returns the channel exit code and stderr', async () => {
		const ch = stubChannel({
			stderr: new TextEncoder().encode('denied'),
			exit: { code: 1, signal: null }
		});
		const session = fakeSession(ch);

		const result = await sudo(session, 'reboot', { password: 'pw' });

		expect(result.code).toBe(1);
		expect(dec.decode(result.stderr)).toBe('denied');
	});

	it('coerces a null exit code (signal exit) to 0', async () => {
		const ch = stubChannel({ exit: { code: null, signal: 'KILL' } });
		const session = fakeSession(ch);

		const result = await sudo(session, 'whoami', { password: 'pw' });

		expect(result.code).toBe(0);
	});
});

describe('sudoExec', () => {
	it('throws when neither sudoPassword nor password is set', async () => {
		await expect(
			sudoExec({ hostname: 'h', username: 'u', command: 'id -u' })
		).rejects.toBeInstanceOf(ProtocolError);
	});

	it('throws with a clear message mentioning the sudo password', async () => {
		await expect(sudoExec({ hostname: 'h', username: 'u', command: 'id -u' })).rejects.toThrow(
			/sudo password/i
		);
	});

	it('defaults sudoPassword to the SSH login password (credential reuse)', async () => {
		const ch = stubChannel({ stdout: new TextEncoder().encode('0\n') });
		const session = fakeSession(ch);
		// stub connect so no socket opens; sudoExec must thread the login password into sudo
		const spy = vi.spyOn(sshIndex, 'connect').mockResolvedValue(session);
		try {
			const result = await sudoExec({
				hostname: 'h',
				username: 'u',
				password: 'login-pw',
				command: 'id -u'
			});
			expect(session.commands).toEqual(["sudo -S -p '' id -u"]);
			expect(dec.decode(ch.writes[0])).toBe('login-pw\n');
			expect(dec.decode(result.stdout)).toBe('0\n');
		} finally {
			spy.mockRestore();
		}
	});

	it('prefers an explicit sudoPassword over the login password', async () => {
		const ch = stubChannel({});
		const session = fakeSession(ch);
		const spy = vi.spyOn(sshIndex, 'connect').mockResolvedValue(session);
		try {
			await sudoExec({
				hostname: 'h',
				username: 'u',
				password: 'login-pw',
				sudoPassword: 'sudo-pw',
				command: 'whoami'
			});
			expect(dec.decode(ch.writes[0])).toBe('sudo-pw\n');
		} finally {
			spy.mockRestore();
		}
	});
});

// === command helpers (was test/unit/ssh-commands.spec.ts) ===

// a real Session (so the helper bodies under test run for real) with exec/execStream
// overridden on the instance to record the command line and return canned results. the
// fake `conn` is never touched because every helper routes through this.exec/this.execStream.
function makeSession(canned: CannedExec | (() => CannedExec) = {}) {
	const execCommands: string[] = [];
	const streamCommands: string[] = [];
	const session = new Session({} as never) as unknown as SshSession & {
		execCommands: string[];
		streamCommands: string[];
		lastChannel: ReturnType<typeof stubChannel> | null;
	};
	session.execCommands = execCommands;
	session.streamCommands = streamCommands;
	session.lastChannel = null;
	session.exec = async (command: string) => {
		execCommands.push(command);
		const c = typeof canned === 'function' ? canned() : canned;
		return {
			stdout: enc.encode(c.stdout ?? ''),
			stderr: enc.encode(c.stderr ?? ''),
			code: c.code ?? 0
		};
	};
	session.execStream = async (command: string) => {
		streamCommands.push(command);
		const c = typeof canned === 'function' ? canned() : canned;
		const lastChannel = stubChannel({ exit: { code: c.code ?? 0, signal: null } });
		session.lastChannel = lastChannel;
		return lastChannel;
	};
	return session;
}

describe('shell-quote', () => {
	it('wraps a plain arg in single quotes', () => {
		expect(shellQuote('abc')).toBe(`'abc'`);
	});
	it('quotes spaces', () => {
		expect(shellQuote('a b')).toBe(`'a b'`);
	});
	it('escapes embedded single quotes as the classic sequence', () => {
		expect(shellQuote("it's")).toBe(`'it'\\''s'`);
	});
	it('leaves $ and ; inert inside the quotes', () => {
		expect(shellQuote('$(x); y')).toBe(`'$(x); y'`);
	});
});

describe('assertSafeDeletePath', () => {
	it.each(['', '   ', '/', '~', '.', '..', ' / '])('rejects %j', (target) => {
		expect(() => assertSafeDeletePath(target)).toThrow(ProtocolError);
	});
	it('allows a normal path', () => {
		expect(() => assertSafeDeletePath('/tmp/build')).not.toThrow();
	});
});

describe('run', () => {
	it('decodes and trims stdout by default', async () => {
		const s = makeSession({ stdout: '  hello\n' });
		expect(await s.run('echo hi')).toBe('hello');
	});
	it('does not trim when trim:false', async () => {
		const s = makeSession({ stdout: 'a\n' });
		expect(await s.run('cat', { trim: false })).toBe('a\n');
	});
	it('throws ProtocolError with exit code and stderr on nonzero', async () => {
		const s = makeSession({ stderr: 'boom', code: 7 });
		await expect(s.run('false')).rejects.toBeInstanceOf(ProtocolError);
		await expect(s.run('false')).rejects.toThrow(/exited 7/);
		await expect(s.run('false')).rejects.toThrow(/boom/);
	});
});

describe('test / exists', () => {
	it('test maps code 0 to true', async () => {
		const s = makeSession({ code: 0 });
		expect(await s.test('true')).toBe(true);
	});
	it('test maps nonzero to false', async () => {
		const s = makeSession({ code: 1 });
		expect(await s.test('false')).toBe(false);
	});
	it('exists runs test -e on the quoted path', async () => {
		const s = makeSession({ code: 0 });
		expect(await s.exists('/etc/hosts')).toBe(true);
		expect(s.execCommands).toEqual([`test -e '/etc/hosts'`]);
	});
});

describe('mkdirp', () => {
	it('builds mkdir -p with a quoted path', async () => {
		const s = makeSession();
		await s.mkdirp('/srv/a b');
		expect(s.execCommands).toEqual([`mkdir -p '/srv/a b'`]);
	});
	it('adds -m with octal mode', async () => {
		const s = makeSession();
		await s.mkdirp('/srv/app', { mode: 0o755 });
		expect(s.execCommands).toEqual([`mkdir -p -m 755 '/srv/app'`]);
	});
});

describe('rm', () => {
	it('builds rm -- with quoted paths', async () => {
		const s = makeSession();
		await s.rm('/tmp/x');
		expect(s.execCommands).toEqual([`rm -- '/tmp/x'`]);
	});
	it('adds -r and -f and supports an array', async () => {
		const s = makeSession();
		await s.rm(['/tmp/a', '/tmp/b'], { recursive: true, force: true });
		expect(s.execCommands).toEqual([`rm -r -f -- '/tmp/a' '/tmp/b'`]);
	});
	it('refuses a dangerous path before running anything', async () => {
		const s = makeSession();
		await expect(s.rm(['/tmp/ok', '/'])).rejects.toBeInstanceOf(ProtocolError);
		expect(s.execCommands).toEqual([]);
	});
});

describe('chmod', () => {
	it('renders a numeric mode as octal', async () => {
		const s = makeSession();
		await s.chmod('/srv/run.sh', 0o755);
		expect(s.execCommands).toEqual([`chmod 755 -- '/srv/run.sh'`]);
	});
	it('passes a string mode through and supports -R + array', async () => {
		const s = makeSession();
		await s.chmod(['/a', '/b'], 'u+x', { recursive: true });
		expect(s.execCommands).toEqual([`chmod -R u+x -- '/a' '/b'`]);
	});
});

describe('stat', () => {
	it('builds a portable GNU-or-BSD stat command', async () => {
		const s = makeSession({ stdout: 'g 1024 81a4 1700000000 regular file\n' });
		await s.stat('/etc/hosts');
		expect(s.execCommands).toEqual([
			`stat -c 'g %s %f %Y %F' '/etc/hosts' 2>/dev/null || stat -f 'b %z %p %m %HT' '/etc/hosts'`
		]);
	});
	it('parses the GNU (linux) form: tag g, hex mode', async () => {
		// %f for a regular file with 0644 is 0x81a4; %F is "regular file"
		const s = makeSession({ stdout: 'g 1024 81a4 1700000000 regular file\n' });
		const st = await s.stat('/etc/hosts');
		expect(st.size).toBe(1024);
		expect(st.mode).toBe(0x81a4);
		expect(st.mtime).toBe(1700000000);
		expect(st.isDirectory).toBe(false);
		expect(st.isSymlink).toBe(false);
	});
	it('parses the BSD (macos) form: tag b, octal mode, title-case type', async () => {
		// BSD %p is octal (100644 == 0x81a4); %HT is "Regular File"
		const s = makeSession({ stdout: 'b 1024 100644 1700000000 Regular File\n' });
		const st = await s.stat('/etc/hosts');
		expect(st.size).toBe(1024);
		expect(st.mode).toBe(0x81a4);
		expect(st.mtime).toBe(1700000000);
		expect(st.isDirectory).toBe(false);
		expect(st.isSymlink).toBe(false);
	});
	it('detects a directory on both GNU and BSD output', async () => {
		const gnu = makeSession({ stdout: 'g 4096 41ed 1700000000 directory\n' });
		expect((await gnu.stat('/srv')).isDirectory).toBe(true);
		const bsd = makeSession({ stdout: 'b 4096 40755 1700000000 Directory\n' });
		expect((await bsd.stat('/srv')).isDirectory).toBe(true);
	});
	it('detects a symlink (multi-word type) on both GNU and BSD output', async () => {
		const gnu = makeSession({ stdout: 'g 7 a1ff 1700000000 symbolic link\n' });
		const gst = await gnu.stat('/srv/link');
		expect(gst.isSymlink).toBe(true);
		expect(gst.isDirectory).toBe(false);
		const bsd = makeSession({ stdout: 'b 7 120755 1700000000 Symbolic Link\n' });
		expect((await bsd.stat('/srv/link')).isSymlink).toBe(true);
	});
});

describe('df', () => {
	it('runs df -Pk and parses POSIX columns, skipping the header', async () => {
		const out = [
			'Filesystem 1024-blocks Used Available Capacity Mounted on',
			'/dev/sda1 102400 51200 51200 50% /',
			'tmpfs 2048 0 2048 0% /run'
		].join('\n');
		const s = makeSession({ stdout: out });
		const rows = await s.df();
		expect(s.execCommands).toEqual(['df -Pk']);
		expect(rows).toHaveLength(2);
		expect(rows[0]).toEqual({
			filesystem: '/dev/sda1',
			sizeKb: 102400,
			usedKb: 51200,
			availKb: 51200,
			usePercent: 50,
			mountedOn: '/'
		});
		expect(rows[1]!.mountedOn).toBe('/run');
	});
	it('appends a quoted path when given', async () => {
		const s = makeSession({
			stdout:
				'Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1 1 0 100% /srv\n'
		});
		await s.df('/srv/app');
		expect(s.execCommands).toEqual([`df -Pk '/srv/app'`]);
	});
});

describe('which', () => {
	it('returns the trimmed path on success', async () => {
		const s = makeSession({ stdout: '/usr/bin/git\n', code: 0 });
		expect(await s.which('git')).toBe('/usr/bin/git');
		expect(s.execCommands).toEqual([`command -v 'git'`]);
	});
	it('returns null when not found', async () => {
		const s = makeSession({ code: 1 });
		expect(await s.which('nope')).toBeNull();
	});
});

describe('readTextFile', () => {
	it('runs cat -- on the quoted path without trimming', async () => {
		const s = makeSession({ stdout: 'line1\nline2\n' });
		expect(await s.readTextFile('/etc/hosts')).toBe('line1\nline2\n');
		expect(s.execCommands).toEqual([`cat -- '/etc/hosts'`]);
	});
});

describe('writeTextFile', () => {
	it('opens cat > on the quoted path and feeds content to stdin then eofs', async () => {
		const s = makeSession();
		await s.writeTextFile('/srv/.env', 'PORT=8080\n');
		expect(s.streamCommands).toEqual([`cat > '/srv/.env'`]);
		expect(s.lastChannel!.writes).toHaveLength(1);
		expect(dec.decode(s.lastChannel!.writes[0])).toBe('PORT=8080\n');
		expect(s.lastChannel!.eofCalled).toBe(true);
		expect(s.lastChannel!.closeCalled).toBe(true);
	});
	it('uses cat >> when append is set', async () => {
		const s = makeSession();
		await s.writeTextFile('/srv/log', 'x\n', { append: true });
		expect(s.streamCommands).toEqual([`cat >> '/srv/log'`]);
	});
	it('throws ProtocolError on a nonzero exit', async () => {
		const s = makeSession({ code: 1 });
		await expect(s.writeTextFile('/root/locked', 'x')).rejects.toBeInstanceOf(ProtocolError);
	});
});

describe('spawnDetached', () => {
	it('wraps the command in nohup sh -c with redirected stdio and & (portable, not setsid)', async () => {
		const s = makeSession();
		await s.spawnDetached('/srv/worker');
		expect(s.execCommands).toEqual([
			`nohup sh -c '/srv/worker' >/dev/null 2>/dev/null </dev/null &`
		]);
	});
	it('honors custom stdout/stderr targets', async () => {
		const s = makeSession();
		await s.spawnDetached('/srv/worker', { stdout: '/var/log/w.log', stderr: '/var/log/w.err' });
		expect(s.execCommands).toEqual([
			`nohup sh -c '/srv/worker' >/var/log/w.log 2>/var/log/w.err </dev/null &`
		]);
	});
});

class FakeTransport {
	readonly sent: Uint8Array[] = [];
	#inbox: Uint8Array[] = [];
	#waiters: ((p: Uint8Array) => void)[] = [];

	send(payload: Uint8Array): Promise<void> {
		this.sent.push(payload);
		return Promise.resolve();
	}
	// channel data path (held during rekey in the real transport; immediate here)
	sendData(payload: Uint8Array): Promise<void> {
		this.sent.push(payload);
		return Promise.resolve();
	}
	requestRekey(): Promise<void> {
		return Promise.resolve();
	}
	close(): Promise<void> {
		return Promise.resolve();
	}
	read(): Promise<Uint8Array> {
		const p = this.#inbox.shift();
		if (p) return Promise.resolve(p);
		return new Promise((r) => this.#waiters.push(r));
	}

	/** test hook: deliver one inbound packet to the pump */
	inject(p: Uint8Array): void {
		const w = this.#waiters.shift();
		if (w) w(p);
		else this.#inbox.push(p);
	}
}

const tick = () => new Promise((r) => setTimeout(r, 0));

function channelOpenConfirmation(localId: number, remoteId: number): Uint8Array {
	return new SshWriter()
		.byte(Msg.CHANNEL_OPEN_CONFIRMATION)
		.uint32(localId)
		.uint32(remoteId)
		.uint32(2 * 1024 * 1024) // send window
		.uint32(32 * 1024) // max packet
		.bytes();
}

function channelClosePacket(recipient: number): Uint8Array {
	return new SshWriter().byte(Msg.CHANNEL_CLOSE).uint32(recipient).bytes();
}

// the local id in the client's CHANNEL_OPEN: byte, string(type), uint32(localId)
function localIdOf(open: Uint8Array): number {
	const r = new SshReader(open);
	r.byte();
	r.stringUtf8();
	return r.uint32();
}

const countCloses = (sent: Uint8Array[]) => sent.filter((p) => p[0] === Msg.CHANNEL_CLOSE).length;

async function openChannel(t: FakeTransport, conn: SshConnection, remoteId: number) {
	const openP = conn.openSession();
	await tick(); // let openSession emit its CHANNEL_OPEN
	const opens = t.sent.filter((p) => p[0] === Msg.CHANNEL_OPEN);
	const open = opens[opens.length - 1]; // the one this call just emitted
	if (!open) throw new Error('no CHANNEL_OPEN was sent');
	t.inject(channelOpenConfirmation(localIdOf(open), remoteId));
	return { ch: await openP, localId: localIdOf(open) };
}

describe('SshChannel close handshake (RFC 4254 5.3)', () => {
	// the reported reuse bug: a client-initiated close that then echoed a SECOND CHANNEL_CLOSE
	// when the server replied; the server had already freed the channel and dropped the connection
	it('client-initiated close sends exactly one CHANNEL_CLOSE, no duplicate on the server reply', async () => {
		const t = new FakeTransport();
		const conn = new SshConnection(t as unknown as SshTransport);
		const { ch, localId } = await openChannel(t, conn, 100);

		await ch.close();
		expect(countCloses(t.sent)).toBe(1); // we sent our one close

		// server now sends its own close for our channel; we must NOT answer with a second one
		t.inject(channelClosePacket(localId));
		await ch.exit;
		expect(countCloses(t.sent)).toBe(1); // still exactly one
	});

	it('server-initiated close is answered with exactly one CHANNEL_CLOSE', async () => {
		const t = new FakeTransport();
		const conn = new SshConnection(t as unknown as SshTransport);
		const { ch, localId } = await openChannel(t, conn, 101);

		t.inject(channelClosePacket(localId));
		await ch.exit;
		expect(countCloses(t.sent)).toBe(1); // we echoed exactly one close
	});

	it('calling close() twice still sends only one CHANNEL_CLOSE (idempotent)', async () => {
		const t = new FakeTransport();
		const conn = new SshConnection(t as unknown as SshTransport);
		const { ch } = await openChannel(t, conn, 102);

		await ch.close();
		await ch.close();
		expect(countCloses(t.sent)).toBe(1);
	});

	it('reusing the connection across many open/close cycles never double-closes', async () => {
		const t = new FakeTransport();
		const conn = new SshConnection(t as unknown as SshTransport);

		for (let i = 0; i < 5; i++) {
			const { ch, localId } = await openChannel(t, conn, 200 + i);
			await ch.close(); // client closes first each round
			t.inject(channelClosePacket(localId)); // server replies
			await ch.exit;
		}
		// 5 channels, one close each - never a duplicate that would drop the connection
		expect(countCloses(t.sent)).toBe(5);
	});
});

describe('ssh key fingerprint', () => {
	it('formats the OpenSSH SHA256 fingerprint of a key blob (KAT)', async () => {
		// SHA-256("abc") base64 (standard alphabet, unpadded) is a fixed, ssh-keygen-compatible vector
		const abc = new TextEncoder().encode('abc');
		expect(await sshIndex.fingerprint(abc)).toBe(
			'SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0'
		);

		const bytes16 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
		expect(await sshIndex.fingerprint(bytes16)).toBe(
			'SHA256:vkXLJgW/Nr695oSEGijw/UPGmFCj3OX+26aZKO46iZE'
		);
	});

	it('always yields the SHA256: prefix with 43 unpadded base64 chars', async () => {
		const fp = await sshIndex.fingerprint(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
		expect(fp).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
	});
});
