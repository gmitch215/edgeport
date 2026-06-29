/**
 * @fileoverview An MQTT v3.1.1 client (publish / subscribe with QoS 0-2) for the Cloudflare
 * Workers runtime.
 *
 * MQTT is a binary control protocol over a reliable stream: a fixed header (type nibble plus a
 * remaining-length varint) followed by a variable header and payload. This module runs the
 * CONNECT/CONNACK handshake, then drives a background read pump that routes inbound PUBLISH frames
 * to subscribers, completes the QoS 1 (PUBACK) and QoS 2 (PUBREC -> PUBREL -> PUBCOMP) handshakes,
 * and keeps the link alive with periodic PINGREQ. It carries the same control packets over either
 * a core {@link CoreSocket} framed TCP stream or a WebSocket binary channel (subprotocol `mqtt`)
 * through a small {@link MqttTransport} adapter, so the session logic is transport-agnostic.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import {
	AuthError,
	ConnectionError,
	ProtocolError,
	connect as coreConnect,
	type CoreSocket,
	type FramedReader,
	type FramedWriter
} from '../core';
import { connect as wsConnect, type WsConnection } from '../ws';
import {
	PacketType,
	decodePacket,
	decodeRemainingLength,
	encodeConnect,
	encodeDisconnect,
	encodePingReq,
	encodePubAck,
	encodePubComp,
	encodePubRec,
	encodePubRel,
	encodePublish,
	encodeSubscribe,
	encodeUnsubscribe,
	type DecodedPacket
} from './packet';

export * from './packet';

const DEFAULT_MQTT_PORT = 1883;
const DEFAULT_KEEPALIVE_SECONDS = 60;
const PROTO = 'mqtt';

const encoder = new TextEncoder();

/**
 * A scheduler for the keep-alive timer, matching the shape of the global timer functions.
 *
 * Injected through the internal entry point so a unit test can drive the keep-alive interval with
 * a fake clock and assert a PINGREQ on the wire without waiting real time. Defaults to
 * `globalThis.setInterval` / `clearInterval`.
 *
 * @since 1.0.0
 */
export interface MqttScheduler {
	/** Schedules `fn` to run every `ms` milliseconds; returns a handle for {@link clear}. */
	set(fn: () => void, ms: number): unknown;
	/** Cancels a timer created by {@link set}. */
	clear(handle: unknown): void;
}

const defaultScheduler: MqttScheduler = {
	set: (fn, ms) => setInterval(fn, ms),
	clear: (handle) => clearInterval(handle as ReturnType<typeof setInterval>)
};

/**
 * A transport-agnostic packet pipe used by the MQTT session.
 *
 * Both the TCP ({@link CoreSocket}) and WebSocket transports implement this so the session encodes
 * and decodes the same control packets over either. `readPacket` resolves the next complete packet
 * or `null` at end of stream; `writePacket` sends one already-encoded packet.
 *
 * @since 1.0.0
 */
export interface MqttTransport {
	/** Reads the next complete control packet, or `null` once the peer closes. */
	readPacket(): Promise<DecodedPacket | null>;
	/** Sends one encoded control packet. */
	writePacket(bytes: Uint8Array): Promise<void>;
	/** Closes the underlying transport. */
	close(): Promise<void>;
}

/**
 * Options for {@link connect}.
 *
 * @since 1.0.0
 */
export interface MqttConnectOptions {
	/** Remote broker host (ignored when `transport: 'ws'`; use {@link connectWebSocket}). */
	hostname: string;
	/** Remote port; defaults to 1883. */
	port?: number;
	/**
	 * Transport security:
	 * - `'off'`: plaintext TCP.
	 * - `'implicit'`: TLS from the first byte (typically port 8883).
	 * - `'starttls'`: plaintext, upgraded to TLS before CONNECT.
	 *
	 * Defaults to `'off'`.
	 */
	tls?: 'off' | 'implicit' | 'starttls';
	/** Client identifier; a random one is generated when omitted. */
	clientId?: string;
	/** Username for credential auth. */
	username?: string;
	/** Password for credential auth. */
	password?: string;
	/** Keep-alive interval in seconds (default 60); 0 disables keep-alive PINGREQs. */
	keepAliveSeconds?: number;
	/** Read deadline in milliseconds for the connect handshake. */
	timeoutMs?: number;
	/** Whether the broker should start a clean session (default true). */
	cleanSession?: boolean;
	/**
	 * Last Will and Testament: the broker publishes this if the client drops without a clean
	 * DISCONNECT (e.g. `close({ graceful: false })`), enabling offline detection.
	 */
	will?: { topic: string; payload: string | Uint8Array; qos?: 0 | 1 | 2; retain?: boolean };
	/** Transport to use; `'tcp'` (default) or `'ws'` for MQTT-over-WebSocket. */
	transport?: 'tcp' | 'ws';
	/** WebSocket URL, required when `transport: 'ws'`. */
	url?: string;
	/** Optional timer override for the keep-alive loop (mainly for testing). */
	scheduler?: MqttScheduler;
}

/**
 * A delivered application message, yielded by a {@link MqttSubscription}.
 *
 * @since 1.0.0
 */
export interface MqttMessage {
	/** The topic the message was published to. */
	topic: string;
	/** The raw payload bytes. */
	payload: Uint8Array;
	/** The QoS the message was delivered at. */
	qos: 0 | 1 | 2;
}

/**
 * An active subscription that yields {@link MqttMessage}s as they arrive.
 *
 * Iterate it with `for await`; the loop ends when {@link unsubscribe} is called or the session
 * closes. It is an `AsyncDisposable`, so `await using` unsubscribes automatically.
 *
 * @since 1.0.0
 */
export interface MqttSubscription extends AsyncIterable<MqttMessage>, AsyncDisposable {
	/** The topic filter this subscription matches. */
	readonly topicFilter: string;
	/**
	 * Stops the subscription (UNSUBSCRIBE) and ends the iterator.
	 *
	 * @returns Resolves once the UNSUBACK is received.
	 */
	unsubscribe(): Promise<void>;
}

/**
 * A live MQTT session over a single transport.
 *
 * Obtain one from {@link connect} or {@link connectWebSocket}. A background pump reads packets and
 * routes them, so publishing, subscribing, and the QoS acknowledgement handshakes can all be in
 * flight at once. It is an `AsyncDisposable`, so `await using` closes it cleanly.
 *
 * @since 1.0.0
 */
export interface MqttSession extends AsyncDisposable {
	/**
	 * Publishes a message to a topic.
	 *
	 * For QoS 0 this resolves once the PUBLISH is written. For QoS 1 it resolves on the PUBACK,
	 * and for QoS 2 on the PUBCOMP, so the returned promise tracks broker confirmation.
	 *
	 * @param topic - The topic to publish to.
	 * @param payload - The message body (a string is UTF-8 encoded).
	 * @param opts - Optional QoS (default 0) and retain flag.
	 * @returns Resolves once the publish is confirmed at the requested QoS.
	 * @throws {ConnectionError} If the session is closed.
	 */
	publish(
		topic: string,
		payload: Uint8Array | string,
		opts?: { qos?: 0 | 1 | 2; retain?: boolean }
	): Promise<void>;
	/**
	 * Subscribes to a topic filter.
	 *
	 * Sends a SUBSCRIBE and returns a subscription whose async iterator yields matching messages.
	 * The SUBACK is awaited lazily; the first iteration (or {@link MqttSubscription.unsubscribe})
	 * observes any broker rejection.
	 *
	 * @param topicFilter - The topic filter (may contain `+` / `#` wildcards).
	 * @param opts - Optional maximum QoS to request (default 0).
	 * @returns A subscription async iterable.
	 */
	subscribe(topicFilter: string, opts?: { qos?: 0 | 1 | 2 }): MqttSubscription;
	/**
	 * Unsubscribes from a topic filter and ends its subscription.
	 *
	 * @param topicFilter - The filter previously passed to {@link subscribe}.
	 * @returns Resolves once the UNSUBACK is received.
	 */
	unsubscribe(topicFilter: string): Promise<void>;
	/**
	 * Closes the connection. By default sends a clean DISCONNECT; pass `{ graceful: false }`
	 * to drop the socket without one, which makes the broker publish the Last Will (used to
	 * simulate an unexpected device disconnect).
	 *
	 * @param opts - `graceful` (default true): whether to send DISCONNECT first.
	 * @returns Resolves once the transport is closed.
	 */
	close(opts?: { graceful?: boolean }): Promise<void>;
}

// single-consumer push/pull queue backing one subscription's async iterator
class MessageQueue {
	#queue: MqttMessage[] = [];
	#waiters: ((r: IteratorResult<MqttMessage>) => void)[] = [];
	#done = false;

	push(msg: MqttMessage): void {
		if (this.#done) return;
		const waiter = this.#waiters.shift();
		if (waiter) waiter({ value: msg, done: false });
		else this.#queue.push(msg);
	}

	end(): void {
		if (this.#done) return;
		this.#done = true;
		for (const waiter of this.#waiters) waiter({ value: undefined, done: true });
		this.#waiters = [];
	}

	next(): Promise<IteratorResult<MqttMessage>> {
		const msg = this.#queue.shift();
		if (msg) return Promise.resolve({ value: msg, done: false });
		if (this.#done) return Promise.resolve({ value: undefined, done: true });
		return new Promise((resolve) => this.#waiters.push(resolve));
	}
}

class Subscription implements MqttSubscription {
	readonly topicFilter: string;
	readonly #queue = new MessageQueue();
	readonly #onUnsub: (filter: string) => Promise<void>;

	constructor(topicFilter: string, onUnsub: (filter: string) => Promise<void>) {
		this.topicFilter = topicFilter;
		this.#onUnsub = onUnsub;
	}

	deliver(msg: MqttMessage): void {
		this.#queue.push(msg);
	}

	// pump-side close: ends the iterator without writing UNSUBSCRIBE (transport is gone)
	stop(): void {
		this.#queue.end();
	}

	async unsubscribe(): Promise<void> {
		this.#queue.end();
		await this.#onUnsub(this.topicFilter);
	}

	[Symbol.asyncIterator](): AsyncIterator<MqttMessage> {
		return { next: () => this.#queue.next() };
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.unsubscribe();
	}
}

// a promise whose resolve/reject are exposed, used to await an ack keyed by packet id
interface Deferred<T> {
	promise: Promise<T>;
	resolve: (value: T) => void;
	reject: (err: Error) => void;
}

function deferred<T>(): Deferred<T> {
	let resolve!: (value: T) => void;
	let reject!: (err: Error) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

class MqttSessionImpl implements MqttSession {
	readonly #transport: MqttTransport;
	readonly #keepAliveSeconds: number;
	readonly #scheduler: MqttScheduler;
	readonly #subs = new Map<string, Subscription>();
	// packet id -> waiter, for PUBACK / SUBACK / UNSUBACK / PUBCOMP correlation
	readonly #acks = new Map<number, Deferred<DecodedPacket>>();
	#packetId = 0;
	#closed = false;
	#pumpError: Error | null = null;
	#keepAliveHandle: unknown = null;
	// liveness flag flipped by any inbound packet; not yet enforced but tracked per spec
	#lastActivity = Date.now();

	constructor(transport: MqttTransport, keepAliveSeconds: number, scheduler: MqttScheduler) {
		this.#transport = transport;
		this.#keepAliveSeconds = keepAliveSeconds;
		this.#scheduler = scheduler;
	}

	// allocates the next packet id in 1..65535, skipping ids still awaiting an ack
	#nextPacketId(): number {
		for (let i = 0; i < 0xffff; i++) {
			this.#packetId = (this.#packetId % 0xffff) + 1;
			if (!this.#acks.has(this.#packetId)) return this.#packetId;
		}
		throw new ProtocolError('exhausted mqtt packet identifiers', { protocol: PROTO });
	}

	#assertOpen(): void {
		if (this.#closed) throw new ConnectionError('mqtt session is closed', { protocol: PROTO });
		if (this.#pumpError) throw this.#pumpError;
	}

	// starts the keep-alive PINGREQ loop unless keep-alive is disabled
	startKeepAlive(): void {
		if (this.#keepAliveSeconds <= 0) return;
		this.#keepAliveHandle = this.#scheduler.set(() => {
			if (this.#closed) return;
			// fire-and-forget; ordering is preserved by the single writer
			void this.#transport.writePacket(encodePingReq()).catch(() => {});
		}, this.#keepAliveSeconds * 1000);
	}

	// starts the background read loop; resolves when the transport ends or errors
	startPump(): void {
		void this.#pump();
	}

	async #pump(): Promise<void> {
		try {
			for (;;) {
				const pkt = await this.#transport.readPacket();
				if (pkt === null) break;
				this.#lastActivity = Date.now();
				await this.#dispatch(pkt);
			}
		} catch (err) {
			if (!this.#closed) this.#pumpError = err as Error;
		} finally {
			const reason =
				this.#pumpError ?? new ConnectionError('mqtt connection closed', { protocol: PROTO });
			for (const waiter of this.#acks.values()) waiter.reject(reason);
			this.#acks.clear();
			this.#endAll();
		}
	}

	async #dispatch(pkt: DecodedPacket): Promise<void> {
		switch (pkt.type) {
			case PacketType.PUBLISH:
				await this.#handlePublish(pkt);
				return;
			case PacketType.PUBACK:
			case PacketType.SUBACK:
			case PacketType.UNSUBACK:
			case PacketType.PUBCOMP:
				this.#resolveAck(pkt.packetId, pkt);
				return;
			case PacketType.PUBREC: {
				// qos2 sender path: broker received our PUBLISH, release it
				await this.#transport.writePacket(encodePubRel(pkt.packetId));
				return;
			}
			case PacketType.PUBREL: {
				// qos2 receiver path: complete the inbound delivery handshake
				await this.#transport.writePacket(encodePubComp(pkt.packetId));
				return;
			}
			case PacketType.PINGRESP:
				return; // liveness already noted by #lastActivity
			case PacketType.DISCONNECT:
				this.#endAll();
				return;
			default:
				throw new ProtocolError(`unexpected packet from broker: ${pkt.type}`, { protocol: PROTO });
		}
	}

	// routes an inbound PUBLISH to matching subscriptions and runs the QoS ack handshake
	async #handlePublish(pkt: Extract<DecodedPacket, { type: PacketType.PUBLISH }>): Promise<void> {
		const msg: MqttMessage = { topic: pkt.topic, payload: pkt.payload, qos: pkt.qos };
		for (const sub of this.#subs.values()) {
			if (topicMatches(sub.topicFilter, pkt.topic)) sub.deliver(msg);
		}
		if (pkt.qos === 1 && pkt.packetId !== undefined) {
			await this.#transport.writePacket(encodePubAck(pkt.packetId));
		} else if (pkt.qos === 2 && pkt.packetId !== undefined) {
			// answer PUBREC; the broker's PUBREL is completed in #dispatch
			await this.#transport.writePacket(encodePubRec(pkt.packetId));
		}
	}

	#resolveAck(packetId: number, pkt: DecodedPacket): void {
		const waiter = this.#acks.get(packetId);
		if (waiter) {
			this.#acks.delete(packetId);
			waiter.resolve(pkt);
		}
	}

	// registers an ack waiter for a packet id and returns its promise
	#awaitAck(packetId: number): Promise<DecodedPacket> {
		const d = deferred<DecodedPacket>();
		this.#acks.set(packetId, d);
		return d.promise;
	}

	#endAll(): void {
		for (const sub of this.#subs.values()) sub.stop();
		this.#subs.clear();
	}

	async publish(
		topic: string,
		payload: Uint8Array | string,
		opts?: { qos?: 0 | 1 | 2; retain?: boolean }
	): Promise<void> {
		this.#assertOpen();
		const body = typeof payload === 'string' ? encoder.encode(payload) : payload;
		const qos = opts?.qos ?? 0;
		if (qos === 0) {
			await this.#transport.writePacket(
				encodePublish({ topic, payload: body, qos, retain: opts?.retain })
			);
			return;
		}
		const packetId = this.#nextPacketId();
		const ack = this.#awaitAck(packetId);
		await this.#transport.writePacket(
			encodePublish({ topic, payload: body, qos, retain: opts?.retain, packetId })
		);
		// qos1 resolves on PUBACK; qos2 resolves on PUBCOMP (PUBREC->PUBREL handled by the pump)
		await ack;
	}

	subscribe(topicFilter: string, opts?: { qos?: 0 | 1 | 2 }): MqttSubscription {
		this.#assertOpen();
		const qos = opts?.qos ?? 0;
		const sub = new Subscription(topicFilter, (f) => this.#sendUnsubscribe(f));
		this.#subs.set(topicFilter, sub);
		const packetId = this.#nextPacketId();
		const ack = this.#awaitAck(packetId);
		void this.#transport
			.writePacket(encodeSubscribe(packetId, [{ topicFilter, qos }]))
			.then(() => ack)
			.then((pkt) => {
				// a SUBACK return code >= 0x80 is a broker rejection
				if (pkt.type === PacketType.SUBACK && pkt.returnCodes.some((rc) => rc >= 0x80)) {
					sub.stop();
					this.#subs.delete(topicFilter);
				}
			})
			.catch(() => {
				sub.stop();
				this.#subs.delete(topicFilter);
			});
		return sub;
	}

	async #sendUnsubscribe(topicFilter: string): Promise<void> {
		this.#subs.delete(topicFilter);
		if (this.#closed) return;
		const packetId = this.#nextPacketId();
		const ack = this.#awaitAck(packetId);
		await this.#transport.writePacket(encodeUnsubscribe(packetId, [topicFilter]));
		await ack;
	}

	async unsubscribe(topicFilter: string): Promise<void> {
		this.#assertOpen();
		const sub = this.#subs.get(topicFilter);
		if (sub) {
			await sub.unsubscribe();
			return;
		}
		await this.#sendUnsubscribe(topicFilter);
	}

	async close(opts?: { graceful?: boolean }): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		if (this.#keepAliveHandle !== null) this.#scheduler.clear(this.#keepAliveHandle);
		this.#endAll();
		// graceful (default) sends DISCONNECT; an abrupt close lets the broker fire the will
		if (opts?.graceful !== false) {
			try {
				await this.#transport.writePacket(encodeDisconnect());
			} catch {
				// peer may already be gone; close the transport regardless
			}
		}
		await this.#transport.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

// matches an mqtt topic filter (with + / # wildcards) against a concrete topic
function topicMatches(filter: string, topic: string): boolean {
	if (filter === topic) return true;
	const f = filter.split('/');
	const t = topic.split('/');
	for (let i = 0; i < f.length; i++) {
		const seg = f[i];
		if (seg === '#') return true; // multi-level wildcard matches the rest
		if (seg === '+') {
			if (t[i] === undefined) return false;
			continue;
		}
		if (seg !== t[i]) return false;
	}
	return f.length === t.length;
}

// builds a CoreSocket-backed transport that frames packets off the byte stream
function coreTransport(socket: CoreSocket, timeoutMs?: number): MqttTransport {
	let reader: FramedReader = socket.reader;
	let writer: FramedWriter = socket.writer;
	return {
		async readPacket(): Promise<DecodedPacket | null> {
			try {
				const first = await reader.readN(1);
				// read the remaining-length varint one byte at a time (1-4 bytes)
				const lenBytes: number[] = [];
				for (let i = 0; i < 4; i++) {
					const b = (await reader.readN(1))[0]!;
					lenBytes.push(b);
					if ((b & 0x80) === 0) break;
				}
				const rl = decodeRemainingLength(new Uint8Array(lenBytes), 0);
				const body = rl.value > 0 ? await reader.readN(rl.value, timeoutMs) : new Uint8Array(0);
				const packet = new Uint8Array(1 + lenBytes.length + body.length);
				packet[0] = first[0]!;
				packet.set(lenBytes, 1);
				packet.set(body, 1 + lenBytes.length);
				return decodePacket(packet);
			} catch (err) {
				// a clean stream end surfaces as ConnectionError from readN; treat it as EOF
				if (err instanceof ConnectionError) return null;
				throw err;
			}
		},
		writePacket(bytes: Uint8Array): Promise<void> {
			return writer.write(bytes);
		},
		async close(): Promise<void> {
			void reader;
			void writer;
			await socket.close();
		}
	};
}

// builds a WebSocket-backed transport; reassembles binary frames into whole packets
function wsTransport(ws: WsConnection): MqttTransport {
	const iter = ws[Symbol.asyncIterator]();
	// carry buffer in case a packet spans multiple ws binary frames
	let carry = new Uint8Array(0);

	function append(chunk: Uint8Array): void {
		const next = new Uint8Array(carry.length + chunk.length);
		next.set(carry, 0);
		next.set(chunk, carry.length);
		carry = next;
	}

	// returns one full packet from the carry buffer, or null if not yet complete
	function tryTakePacket(): Uint8Array | null {
		if (carry.length < 2) return null;
		let rl: { value: number; bytesUsed: number };
		try {
			rl = decodeRemainingLength(carry, 1);
		} catch {
			return null; // varint not fully arrived
		}
		const total = 1 + rl.bytesUsed + rl.value;
		if (carry.length < total) return null;
		const packet = carry.slice(0, total);
		carry = carry.slice(total);
		return packet;
	}

	return {
		async readPacket(): Promise<DecodedPacket | null> {
			for (;;) {
				const ready = tryTakePacket();
				if (ready) return decodePacket(ready);
				const { value, done } = await iter.next();
				if (done) return null;
				if (value.type === 'binary') append(value.data);
				// text frames are not valid mqtt-over-ws; ignore them
			}
		},
		writePacket(bytes: Uint8Array): Promise<void> {
			ws.send(bytes);
			return Promise.resolve();
		},
		close(): Promise<void> {
			ws.close(1000, 'mqtt disconnect');
			return Promise.resolve();
		}
	};
}

// 16 random hex chars for a client id when the caller does not supply one
function randomClientId(): string {
	const bytes = new Uint8Array(8);
	crypto.getRandomValues(bytes);
	return 'edgeport-' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Runs the MQTT CONNECT handshake and read pump over an already-built {@link MqttTransport}.
 *
 * Sends CONNECT, awaits CONNACK, maps a bad-credentials return code (4 or 5) to {@link AuthError}
 * and any other non-zero code to {@link ProtocolError}, then starts the background pump and the
 * keep-alive loop. The transport-specific {@link connect} / {@link connectWebSocket} wrappers build
 * the transport and call this; tests build a transport over a mock socket and call it directly.
 *
 * @param transport - A connected packet transport.
 * @param opts - Connection and credential options.
 * @returns The live session.
 * @throws {AuthError} If the broker rejects the credentials.
 * @throws {ProtocolError} If the broker returns another non-zero CONNACK code or malformed bytes.
 * @internal
 */
export async function _connectOverTransport(
	transport: MqttTransport,
	opts: MqttConnectOptions
): Promise<MqttSession> {
	const keepAliveSeconds = opts.keepAliveSeconds ?? DEFAULT_KEEPALIVE_SECONDS;
	const connect = encodeConnect({
		clientId: opts.clientId ?? randomClientId(),
		keepAliveSeconds,
		cleanSession: opts.cleanSession ?? true,
		username: opts.username,
		password: opts.password,
		will: opts.will
	});
	await transport.writePacket(connect);

	const connack = await transport.readPacket();
	// a null packet means the stream ended (the broker hung up) - a connection failure, not a
	// protocol violation; only a wrong packet type is a real protocol error
	if (connack === null) {
		throw new ConnectionError('connection closed before CONNACK', { protocol: PROTO });
	}
	if (connack.type !== PacketType.CONNACK) {
		throw new ProtocolError('expected CONNACK from broker', { protocol: PROTO });
	}
	const rc = connack.returnCode;
	if (rc === 4 || rc === 5) {
		throw new AuthError(`broker rejected credentials (CONNACK code ${rc})`, { protocol: PROTO });
	}
	if (rc !== 0) {
		throw new ProtocolError(`broker refused connection (CONNACK code ${rc})`, { protocol: PROTO });
	}

	const session = new MqttSessionImpl(
		transport,
		keepAliveSeconds,
		opts.scheduler ?? defaultScheduler
	);
	session.startPump();
	session.startKeepAlive();
	return session;
}

/**
 * Runs the MQTT handshake over an already-connected {@link CoreSocket}.
 *
 * Wraps the socket in a TCP packet transport, then defers to {@link _connectOverTransport}. Public
 * {@link connect} dials the core transport (and optionally upgrades to TLS) before calling this;
 * unit tests call it directly with a mock socket.
 *
 * @param socket - A connected core socket (already TLS when `tls: 'implicit'`).
 * @param opts - Connection and credential options.
 * @returns The live session.
 * @throws {AuthError} If the broker rejects the credentials.
 * @throws {ProtocolError} If the broker speaks the protocol incorrectly.
 * @internal
 */
export function _connectOverSocket(
	socket: CoreSocket,
	opts: MqttConnectOptions
): Promise<MqttSession> {
	return _connectOverTransport(coreTransport(socket, opts.timeoutMs), opts);
}

/**
 * Connects to an MQTT broker over TCP, performs the handshake, and returns a live session.
 *
 * Dials the core transport (implicit TLS when `tls: 'implicit'`, a STARTTLS-style upgrade when
 * `tls: 'starttls'`, otherwise plaintext), sends CONNECT, and waits for CONNACK so an auth failure
 * surfaces here. When `transport: 'ws'` is set, this delegates to {@link connectWebSocket} using
 * `opts.url`. A background pump then routes inbound messages to subscriptions.
 *
 * @param opts - Connection and credential options.
 * @returns The live session.
 * @throws {AuthError} If the broker rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the broker speaks the protocol incorrectly.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { connect } from 'edgeport/mqtt';
 *
 * await using mqtt = await connect({ hostname: 'broker.example.com', username: 'u', password: 'p' });
 * await using sub = mqtt.subscribe('sensors/+/temp', { qos: 1 });
 * await mqtt.publish('sensors/1/temp', '21.5', { qos: 1 });
 * for await (const msg of sub) {
 * 	console.log(msg.topic, new TextDecoder().decode(msg.payload));
 * 	break;
 * }
 * ```
 */
export async function connect(opts: MqttConnectOptions): Promise<MqttSession> {
	if (opts.transport === 'ws') {
		if (!opts.url) {
			throw new ConnectionError('transport: ws requires a url', { protocol: PROTO });
		}
		return connectWebSocket(opts.url, opts);
	}
	const port = opts.port ?? DEFAULT_MQTT_PORT;
	const implicit = opts.tls === 'implicit';
	let socket = await coreConnect({
		hostname: opts.hostname,
		port,
		tls: implicit ? 'on' : 'starttls',
		connectTimeoutMs: opts.timeoutMs
	});
	try {
		if (opts.tls === 'starttls') {
			socket = socket.startTls({ expectedServerHostname: opts.hostname });
		}
		return await _connectOverSocket(socket, opts);
	} catch (err) {
		await socket.close().catch(() => {});
		throw err;
	}
}

/**
 * Connects to an MQTT broker over WebSocket (subprotocol `mqtt`) and returns a live session.
 *
 * Opens the WebSocket with the `mqtt` subprotocol, wraps it in a binary-frame packet transport,
 * and runs the same CONNECT/CONNACK handshake and read pump as the TCP path. The WS carries the
 * identical MQTT control packets as binary frames. Use this for brokers fronted by a WebSocket
 * listener, or set `transport: 'ws'` with a `url` on {@link connect}.
 *
 * @param url - The `ws://` or `wss://` broker endpoint.
 * @param opts - Connection and credential options (the `hostname` field is unused here).
 * @returns The live session.
 * @throws {AuthError} If the broker rejects the credentials.
 * @throws {ConnectionError} If the WebSocket upgrade fails.
 * @throws {ProtocolError} If the broker speaks the protocol incorrectly.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { connectWebSocket } from 'edgeport/mqtt';
 *
 * await using mqtt = await connectWebSocket('wss://broker.example.com/mqtt', { hostname: 'broker' });
 * await mqtt.publish('a/b', 'hello');
 * ```
 */
export async function connectWebSocket(
	url: string,
	opts: Omit<MqttConnectOptions, 'hostname' | 'transport' | 'url'> = {}
): Promise<MqttSession> {
	const ws = await wsConnect(url, { protocols: ['mqtt'] });
	try {
		// hostname is unused on the WS path (the URL carries it); satisfy the shared type
		return await _connectOverTransport(wsTransport(ws), { ...opts, hostname: '' });
	} catch (err) {
		ws.close();
		throw err;
	}
}

/**
 * Builds an {@link MqttTransport} from a pre-opened {@link WsConnection}.
 *
 * Exposed so callers who already hold a WebSocket (or tests with a fake one) can run the MQTT
 * session over it without a fresh upgrade. The session reassembles binary frames into whole
 * control packets, so a packet may span several frames or several packets may share one.
 *
 * @param ws - An open WebSocket-like connection carrying binary MQTT frames.
 * @returns A transport ready for {@link _connectOverTransport}.
 * @internal
 */
export function _wsTransport(ws: WsConnection): MqttTransport {
	return wsTransport(ws);
}
