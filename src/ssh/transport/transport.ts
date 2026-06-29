/**
 * @fileoverview The SSH transport layer: version exchange, key exchange (initial and
 * in-session re-exchange), NEWKEYS, and encrypted packet I/O with per-direction sequence
 * numbers (RFC 4253, including section 9 rekeying).
 *
 * The kex flow is shared between the initial handshake and rekey. On rekey the session
 * identifier stays the first H; new keys derive from the new K/H. `read()` transparently
 * handles an inbound KEXINIT (server-initiated rekey); a byte threshold or `requestRekey()`
 * drives client-initiated rekey. Sends are serialized (seal + write + sequence number must
 * be atomic) and application data is held while a rekey is in flight, per section 7.1.
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

// in-flight rekey bookkeeping
interface Rekey {
	ourKexInit: Uint8Array;
	sent: boolean;
	promise: Promise<void>;
	resolve: () => void;
	reject: (e: unknown) => void;
}

/** 1 GiB: a conservative default rekey threshold (OpenSSH's RekeyLimit default). */
const DEFAULT_REKEY_BYTES = 1 << 30;

/** The SSH transport: owns the socket, the active ciphers, and the packet sequence. */
export class SshTransport {
	readonly #reader: FramedReader;
	readonly #writer: FramedWriter;
	#tx: PacketCipher = new NoneCipher();
	#rx: PacketCipher = new NoneCipher();
	#txSeq = 0;
	#rxSeq = 0;
	#opts: TransportOptions = {};
	#vClient: Uint8Array = new Uint8Array(0);
	#vServer: Uint8Array = new Uint8Array(0);
	#installed = false;
	#bytesSinceKex = 0;
	#rekey: Rekey | null = null;
	#rekeyGate: Promise<void> | null = null;
	#writeChain: Promise<void> = Promise.resolve();
	/** Re-exchange keys after roughly this many bytes flow; 0 disables auto-rekey. */
	rekeyThresholdBytes = DEFAULT_REKEY_BYTES;
	/** The session identifier (H of the first kex); set after the handshake. */
	sessionId!: Uint8Array;

	constructor(private readonly socket: CoreSocket) {
		this.#reader = socket.reader;
		this.#writer = socket.writer;
	}

	/**
	 * Sends one binary packet. Seal + write + sequence-number increment run atomically (no
	 * two packets may interleave), and kex/control packets are never gated.
	 */
	send(payload: Uint8Array): Promise<void> {
		const task = this.#writeChain.then(async () => {
			await this.#writer.write(await this.#tx.seal(this.#txSeq, payload));
			this.#txSeq = (this.#txSeq + 1) >>> 0;
			this.#account(payload.length);
		});
		this.#writeChain = task.catch(() => {});
		return task;
	}

	/** Sends application (channel) data, holding it until any in-flight rekey completes. */
	async sendData(payload: Uint8Array): Promise<void> {
		if (this.#rekeyGate) await this.#rekeyGate;
		return this.send(payload);
	}

	// low-level read: decrypt one packet, advance the sequence, surface DISCONNECT, skip noise
	async #readRaw(): Promise<Uint8Array> {
		for (;;) {
			const payload = await this.#rx.open(this.#rxSeq, this.#reader);
			this.#rxSeq = (this.#rxSeq + 1) >>> 0;
			this.#account(payload.length);
			const type = payload[0];
			if (type === Msg.IGNORE || type === Msg.DEBUG) continue;
			if (type === Msg.DISCONNECT) {
				const r = new SshReader(payload);
				r.byte();
				throw new ConnectionError(`server disconnected (${r.uint32()}): ${r.stringUtf8()}`, {
					protocol: 'ssh'
				});
			}
			return payload;
		}
	}

	/** Reads one packet, transparently performing a rekey if the server sends KEXINIT. */
	async read(): Promise<Uint8Array> {
		for (;;) {
			const p = await this.#readRaw();
			if (p[0] === Msg.KEXINIT) {
				await this.#doRekey(p);
				continue;
			}
			return p;
		}
	}

	// reads until a specific kex/control message; answers global requests so we don't stall
	async #expect(type: number): Promise<Uint8Array> {
		for (;;) {
			const p = await this.#readRaw();
			if (p[0] === type) return p;
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
		this.#opts = opts;
		this.#vClient = await sendIdentification(this.#writer);
		this.#vServer = await readIdentification(this.#reader);

		const iClient = buildKexInit(opts.algorithms);
		await this.send(iClient);
		const iServer = await this.#expect(Msg.KEXINIT);
		await this.#completeKex(iClient, iServer, true);
	}

	// the shared kex flow: ECDH -> verify host signature over H -> NEWKEYS -> install keys
	async #completeKex(iClient: Uint8Array, iServer: Uint8Array, initial: boolean): Promise<void> {
		const neg = negotiate(parseKexInit(iServer), this.#opts.algorithms);
		const kex = await createKex(neg.kex);
		await this.send(new SshWriter().byte(Msg.KEX_ECDH_INIT).string(kex.publicKey).bytes());

		const reply = new SshReader(await this.#expect(Msg.KEX_ECDH_REPLY));
		reply.byte();
		const hostKey = reply.string();
		const qServer = reply.string();
		const signature = reply.string();

		const sharedSecret = await kex.deriveSecret(qServer);
		const h = await computeExchangeHash(kex.hash, {
			vClient: this.#vClient,
			vServer: this.#vServer,
			iClient,
			iServer,
			hostKey,
			qClient: kex.publicKey,
			qServer,
			sharedSecret
		});

		if (!(await verifyHostSignature(neg.hostKey, hostKey, signature, h))) {
			throw new ProtocolError('server host key signature verification failed');
		}
		if (initial) {
			this.sessionId = h;
			if (this.#opts.hostKey && !(await this.#opts.hostKey.verify(neg.hostKey, hostKey))) {
				throw new ConnectionError('host key rejected by verifier', { protocol: 'ssh' });
			}
		}

		await this.send(new SshWriter().byte(Msg.NEWKEYS).bytes());
		await this.#expect(Msg.NEWKEYS);

		// both directions derive from the same K/H but always the original session id
		const keysC2S = await deriveSessionKeys(
			kex.hash,
			sharedSecret,
			h,
			this.sessionId,
			cipherSizes(neg.cipherC2S, neg.macC2S)
		);
		const keysS2C = await deriveSessionKeys(
			kex.hash,
			sharedSecret,
			h,
			this.sessionId,
			cipherSizes(neg.cipherS2C, neg.macS2C)
		);
		this.#tx = await createPacketCipher(neg.cipherC2S, neg.macC2S, keysC2S.c2s);
		this.#rx = await createPacketCipher(neg.cipherS2C, neg.macS2C, keysS2C.s2c);
		this.#installed = true;
		this.#bytesSinceKex = 0;
	}

	// counts traffic and triggers a client-initiated rekey past the byte threshold
	#account(n: number): void {
		if (!this.#installed) return;
		this.#bytesSinceKex += n;
		if (
			this.rekeyThresholdBytes > 0 &&
			this.#bytesSinceKex > this.rekeyThresholdBytes &&
			!this.#rekey
		) {
			this.#bytesSinceKex = 0;
			// auto-rekey failures surface via the read/write path; don't leak an unhandled rejection
			void this.requestRekey().catch(() => {});
		}
	}

	#beginRekey(): Rekey {
		let resolve!: () => void;
		let reject!: (e: unknown) => void;
		const promise = new Promise<void>((res, rej) => {
			resolve = res;
			reject = rej;
		});
		const rekey: Rekey = {
			ourKexInit: buildKexInit(this.#opts.algorithms),
			sent: false,
			promise,
			resolve,
			reject
		};
		this.#rekey = rekey;
		this.#rekeyGate = promise; // hold application data until rekey resolves
		return rekey;
	}

	/**
	 * Initiates a key re-exchange (client-side), or returns the in-flight one. Resolves once
	 * new keys are installed.
	 *
	 * @returns A promise that settles when the rekey completes.
	 * @since 1.0.0
	 */
	requestRekey(): Promise<void> {
		const rekey = this.#rekey ?? this.#beginRekey();
		if (!rekey.sent) {
			rekey.sent = true;
			this.send(rekey.ourKexInit).catch((e) => this.#finishRekey(rekey, e));
		}
		return rekey.promise;
	}

	#finishRekey(rekey: Rekey, err?: unknown): void {
		if (this.#rekey !== rekey) return;
		this.#rekey = null;
		this.#rekeyGate = null;
		if (err) rekey.reject(err);
		else rekey.resolve();
	}

	// drives a key re-exchange after a KEXINIT arrives (server- or client-initiated)
	async #doRekey(serverKexInit: Uint8Array): Promise<void> {
		const rekey = this.#rekey ?? this.#beginRekey();
		if (!rekey.sent) {
			rekey.sent = true;
			await this.send(rekey.ourKexInit);
		}
		try {
			await this.#completeKex(rekey.ourKexInit, serverKexInit, false);
			this.#finishRekey(rekey);
		} catch (err) {
			this.#finishRekey(rekey, err);
			throw err;
		}
	}

	/** Closes the underlying socket. */
	close(): Promise<void> {
		return this.socket.close();
	}
}
