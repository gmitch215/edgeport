/**
 * @fileoverview The SSH transport layer: version exchange, key exchange, NEWKEYS, and
 * encrypted packet I/O with per-direction sequence numbers (RFC 4253).
 *
 * The handshake walks VERSION -> KEXINIT -> ECDH -> verify host signature over H ->
 * NEWKEYS, then installs the negotiated ciphers. Sequence numbers count every binary
 * packet from the first and never reset, which the chacha/ctr constructions depend on.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { Msg } from '../../constants';
import { ConnectionError, ProtocolError } from '../../core/errors';
import type { FramedReader, FramedWriter } from '../../core/framing';
import type { CoreSocket } from '../../core/socket';
import { cipherSizes, createPacketCipher } from '../../crypto/cipher';
import { verifyHostSignature } from '../../crypto/keys';
import { NoneCipher, type PacketCipher } from '../../crypto/packet';
import { computeExchangeHash, deriveSessionKeys } from '../../kex/exchange-hash';
import { createKex } from '../../kex/index';
import { buildKexInit, negotiate, parseKexInit, type AlgorithmPrefs } from '../../kex/kexinit';
import { SshReader, SshWriter } from '../../wire';
import { readIdentification, sendIdentification } from './identification';

/** Host-key verification hook for pinning (TOFU by default). */
export interface HostKeyVerifier {
	/** Returns whether to trust the server's host key (e.g. compare against a pinned key). */
	verify(keyType: string, key: Uint8Array): boolean | Promise<boolean>;
}

/** Options controlling the transport handshake. */
export interface TransportOptions {
	algorithms?: AlgorithmPrefs;
	hostKey?: HostKeyVerifier;
}

/** The SSH transport: owns the socket, the active ciphers, and the packet sequence. */
export class SshTransport {
	readonly #reader: FramedReader;
	readonly #writer: FramedWriter;
	#tx: PacketCipher = new NoneCipher();
	#rx: PacketCipher = new NoneCipher();
	#txSeq = 0;
	#rxSeq = 0;
	/** The session identifier (H of the first kex); set after the handshake. */
	sessionId!: Uint8Array;

	constructor(private readonly socket: CoreSocket) {
		this.#reader = socket.reader;
		this.#writer = socket.writer;
	}

	/** Sends one binary packet (encrypting once keys are installed). */
	async send(payload: Uint8Array): Promise<void> {
		await this.#writer.write(await this.#tx.seal(this.#txSeq, payload));
		this.#txSeq = (this.#txSeq + 1) >>> 0;
	}

	/** Reads one binary packet, transparently skipping IGNORE/DEBUG. */
	async read(): Promise<Uint8Array> {
		for (;;) {
			const payload = await this.#rx.open(this.#rxSeq, this.#reader);
			this.#rxSeq = (this.#rxSeq + 1) >>> 0;
			const type = payload[0];
			if (type === Msg.IGNORE || type === Msg.DEBUG) continue;
			if (type === Msg.DISCONNECT) {
				const r = new SshReader(payload);
				r.byte();
				const code = r.uint32();
				const msg = r.stringUtf8();
				throw new ConnectionError(`server disconnected (${code}): ${msg}`, { protocol: 'ssh' });
			}
			return payload;
		}
	}

	// reads packets until one of the wanted type arrives (skipping global requests etc.)
	async #readExpect(type: number): Promise<Uint8Array> {
		for (;;) {
			const p = await this.read();
			if (p[0] === type) return p;
			// answer unhandled global requests so the server does not stall
			if (p[0] === Msg.GLOBAL_REQUEST) {
				await this.send(new SshWriter().byte(Msg.REQUEST_FAILURE).bytes());
				continue;
			}
			if (p[0] === Msg.UNIMPLEMENTED) continue;
			throw new ProtocolError(`expected SSH message ${type}, got ${p[0]}`);
		}
	}

	/** Runs the full client handshake to the point of installed session keys. */
	async handshake(opts: TransportOptions = {}): Promise<void> {
		const vClient = await sendIdentification(this.#writer);
		const vServer = await readIdentification(this.#reader);

		const iClient = buildKexInit(opts.algorithms);
		await this.send(iClient);
		const iServer = await this.#readExpect(Msg.KEXINIT);
		const neg = negotiate(parseKexInit(iServer), opts.algorithms);

		const kex = await createKex(neg.kex);
		await this.send(new SshWriter().byte(Msg.KEX_ECDH_INIT).string(kex.publicKey).bytes());

		const reply = new SshReader(await this.#readExpect(Msg.KEX_ECDH_REPLY));
		reply.byte();
		const hostKey = reply.string();
		const qServer = reply.string();
		const signature = reply.string();

		const sharedSecret = await kex.deriveSecret(qServer);
		const h = await computeExchangeHash(kex.hash, {
			vClient,
			vServer,
			iClient,
			iServer,
			hostKey,
			qClient: kex.publicKey,
			qServer,
			sharedSecret
		});

		const sigOk = await verifyHostSignature(neg.hostKey, hostKey, signature, h);
		if (!sigOk) throw new ProtocolError('server host key signature verification failed');
		if (opts.hostKey) {
			const accepted = await opts.hostKey.verify(neg.hostKey, hostKey);
			if (!accepted)
				throw new ConnectionError('host key rejected by verifier', { protocol: 'ssh' });
		}

		this.sessionId = h;
		await this.send(new SshWriter().byte(Msg.NEWKEYS).bytes());
		await this.#readExpect(Msg.NEWKEYS);

		await this.#installKeys(neg, kex.hash, sharedSecret, h);
	}

	async #installKeys(
		neg: ReturnType<typeof negotiate>,
		hash: Parameters<typeof deriveSessionKeys>[0],
		sharedSecret: Uint8Array,
		h: Uint8Array
	): Promise<void> {
		// both directions derive from the same K/H; sizes match since we use symmetric prefs
		const sizesC2S = cipherSizes(neg.cipherC2S, neg.macC2S);
		const sizesS2C = cipherSizes(neg.cipherS2C, neg.macS2C);
		const keysC2S = await deriveSessionKeys(hash, sharedSecret, h, this.sessionId, sizesC2S);
		const keysS2C = await deriveSessionKeys(hash, sharedSecret, h, this.sessionId, sizesS2C);
		this.#tx = await createPacketCipher(neg.cipherC2S, neg.macC2S, keysC2S.c2s);
		this.#rx = await createPacketCipher(neg.cipherS2C, neg.macS2C, keysS2C.s2c);
	}

	/** Closes the underlying socket. */
	close(): Promise<void> {
		return this.socket.close();
	}
}
