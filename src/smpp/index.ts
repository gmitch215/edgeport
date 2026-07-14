/**
 * @fileoverview An SMPP v3.4 client (ESME) for the Cloudflare Workers runtime.
 *
 * SMPP (Short Message Peer-to-Peer) is the protocol carriers and SMS aggregators speak to an
 * SMSC to send and receive text messages. It is a binary request/response protocol over a
 * reliable stream: every PDU is a 16-byte header (`command_length` first) plus a body, and
 * requests are correlated to responses by `sequence_number`. This module runs the bind
 * handshake (transmitter / receiver / transceiver), then drives a background read pump that
 * correlates `submit_sm_resp`s to their submissions, routes inbound `deliver_sm` PDUs (mobile
 * originated messages and SMSC delivery receipts) to an async iterator, answers each with a
 * `deliver_sm_resp`, replies to the SMSC's `enquire_link`, and keeps the link alive with its
 * own periodic `enquire_link`.
 *
 * The transport is the shared core ({@link import('../core').connect}); this module never
 * touches `cloudflare:sockets` directly. {@link connect} returns a reusable
 * {@link SmppSession}; {@link sendMessage} is the one-shot convenience that binds, submits one
 * message, and unbinds.
 *
 * @author Gregory Mitchell
 * @since 1.0.3
 */
import {
	AuthError,
	ConnectionError,
	ProtocolError,
	TimeoutError,
	connect as coreConnect,
	type CoreSocket,
	type FramedReader,
	type FramedWriter
} from '../core';
import {
	Command,
	CommandStatus,
	DataCoding,
	ESM_DELIVERY_RECEIPT,
	HEADER_LENGTH,
	MAX_PDU_LENGTH,
	MAX_SHORT_MESSAGE,
	Npi,
	Tag,
	Ton,
	decodeHeader,
	decodePdu,
	encodeBind,
	encodeDeliverSmResp,
	encodeEmpty,
	encodeGenericNack,
	encodeSubmitSm,
	parseDeliveryReceipt,
	type DecodedPdu,
	type DeliveryReceipt,
	type SmPdu,
	type Tlv
} from './pdu';

export * from './pdu';

const PROTO = 'smpp';
const DEFAULT_SMPP_PORT = 2775;
const DEFAULT_ENQUIRE_LINK_SECONDS = 30;

const decoder = new TextDecoder();

/** How an ESME binds to the SMSC: send-only, receive-only, or bidirectional. */
export type BindMode = 'transmitter' | 'receiver' | 'transceiver';

/**
 * A scheduler for the keep-alive timer, matching the shape of the global timer functions.
 *
 * Injected through the internal entry point so a unit test can drive the `enquire_link`
 * interval with a fake clock. Defaults to `globalThis.setInterval` / `clearInterval`.
 *
 * @since 1.0.3
 */
export interface SmppScheduler {
	/** Schedules `fn` to run every `ms` milliseconds; returns a handle for {@link clear}. */
	set(fn: () => void, ms: number): unknown;
	/** Cancels a timer created by {@link set}. */
	clear(handle: unknown): void;
}

const defaultScheduler: SmppScheduler = {
	set: (fn, ms) => setInterval(fn, ms),
	clear: (handle) => clearInterval(handle as ReturnType<typeof setInterval>)
};

/**
 * Options for {@link connect}.
 *
 * @since 1.0.3
 */
export interface SmppConnectOptions {
	/** SMSC hostname (also used for TLS certificate validation). */
	hostname: string;
	/** TCP port; defaults to 2775. */
	port?: number;
	/**
	 * Transport security:
	 * - `'off'` (default): plaintext TCP.
	 * - `'implicit'`: TLS from the first byte (typically port 3550 / a carrier-specified port).
	 *
	 * SMPP has no in-band STARTTLS, so only plaintext and implicit TLS are offered.
	 */
	tls?: 'off' | 'implicit';
	/** The ESME system id used to bind. */
	systemId: string;
	/** The bind password. */
	password?: string;
	/** The ESME system type (e.g. `'SMPP'`); usually left empty. */
	systemType?: string;
	/** Bind mode; defaults to `'transceiver'` (send and receive over one session). */
	bindMode?: BindMode;
	/** The ESME address Type-of-Number; defaults to unknown. */
	addrTon?: number;
	/** The ESME address Numbering-Plan-Indicator; defaults to unknown. */
	addrNpi?: number;
	/** The address range the ESME serves; usually empty. */
	addressRange?: string;
	/** The interface version to advertise; defaults to 0x34 (v3.4). */
	interfaceVersion?: number;
	/** Keep-alive `enquire_link` interval in seconds (default 30); 0 disables it. */
	enquireLinkSeconds?: number;
	/** Per-response read deadline in milliseconds. */
	timeoutMs?: number;
	/** Optional timer override for the keep-alive loop (mainly for testing). */
	scheduler?: SmppScheduler;
}

/**
 * Options for {@link SmppSession.submit}.
 *
 * @since 1.0.3
 */
export interface SubmitOptions {
	/** Source address (the sender id or MSISDN). */
	source?: string;
	/** Source address Type-of-Number; defaults to {@link Ton.International}. */
	sourceTon?: number;
	/** Source address Numbering-Plan-Indicator; defaults to {@link Npi.Isdn}. */
	sourceNpi?: number;
	/** Destination address (the recipient MSISDN). */
	destination: string;
	/** Destination address Type-of-Number; defaults to {@link Ton.International}. */
	destTon?: number;
	/** Destination address Numbering-Plan-Indicator; defaults to {@link Npi.Isdn}. */
	destNpi?: number;
	/**
	 * The message body. A string is encoded per `dataCoding` (ASCII/Latin-1 for the default
	 * coding, UTF-16BE for {@link DataCoding.Ucs2}); pass a `Uint8Array` for full control.
	 */
	message: string | Uint8Array;
	/** The `data_coding` byte; defaults to {@link DataCoding.Default}. */
	dataCoding?: number;
	/** The `esm_class` byte; defaults to 0. */
	esmClass?: number;
	/**
	 * Request an SMSC delivery receipt. `true` sets `registered_delivery` to 1; pass a number
	 * for finer control over the flag bits.
	 */
	registeredDelivery?: boolean | number;
	/** The `service_type`; usually empty. */
	serviceType?: string;
	/** The `priority_flag`; defaults to 0. */
	priorityFlag?: number;
	/** The `validity_period` (empty for the SMSC default). */
	validityPeriod?: string;
	/** The `schedule_delivery_time` (empty for immediate). */
	scheduleDeliveryTime?: string;
	/** Extra optional parameters (TLVs) appended to the PDU. */
	tlvs?: Tlv[];
}

/**
 * An inbound message from the SMSC, yielded by {@link SmppSession.messages}.
 *
 * A `deliver_sm` carries either a mobile-originated message (`esm_class` 0) or an SMSC
 * delivery receipt (`esm_class` has the {@link ESM_DELIVERY_RECEIPT} bit). Check
 * {@link isDeliveryReceipt} and use {@link receipt} to parse the receipt fields.
 *
 * @since 1.0.3
 */
export interface SmppDeliverMessage {
	/** Source address of the inbound message. */
	source: string;
	/** Destination address of the inbound message. */
	destination: string;
	/** The `data_coding` the message was delivered with. */
	dataCoding: number;
	/** The raw `esm_class` byte. */
	esmClass: number;
	/** The raw message body octets. */
	payload: Uint8Array;
	/** Whether the `esm_class` flags this as an SMSC delivery receipt. */
	isDeliveryReceipt: boolean;
	/** The `sequence_number` of the `deliver_sm` (already acknowledged by the session). */
	sequence: number;
	/** Any optional parameters (TLVs) carried on the PDU. */
	tlvs: Tlv[];
	/**
	 * Decodes the payload as text (UTF-16BE for UCS2, otherwise UTF-8/Latin-1).
	 *
	 * @returns The decoded message body.
	 */
	text(): string;
	/**
	 * Parses the payload as an SMSC delivery receipt.
	 *
	 * Only meaningful when {@link isDeliveryReceipt} is true, but it runs the tolerant parser
	 * regardless, so a non-receipt body simply yields an object of undefined fields.
	 *
	 * @returns The parsed delivery-receipt fields.
	 */
	receipt(): DeliveryReceipt;
}

/**
 * A live SMPP session over a single bound transport.
 *
 * Obtain one from {@link connect}. A background pump reads PDUs and routes them, so a
 * submission's response, inbound deliveries, and the keep-alive exchange can all be in flight
 * at once. It is an `AsyncDisposable`, so `await using` unbinds and closes it cleanly.
 *
 * @since 1.0.3
 */
export interface SmppSession extends AsyncDisposable {
	/** The SMSC's system id, as returned in the bind response. */
	readonly systemId: string;
	/** The mode this session bound with. */
	readonly bindMode: BindMode;
	/**
	 * Submits a short message and resolves with the SMSC-assigned message id.
	 *
	 * Sends `submit_sm` and awaits its `submit_sm_resp`. A message body larger than 254 octets
	 * is carried in a `message_payload` TLV automatically. Only valid on a transmitter or
	 * transceiver bind.
	 *
	 * @param opts - Source/destination addresses, the body, and delivery options.
	 * @returns The `message_id` assigned by the SMSC.
	 * @throws {ProtocolError} If the bind is receive-only, or the SMSC rejects the submission.
	 * @throws {TimeoutError} If no response arrives within the configured deadline.
	 * @throws {ConnectionError} If the session is closed.
	 */
	submit(opts: SubmitOptions): Promise<string>;
	/**
	 * Returns an async iterable of inbound {@link SmppDeliverMessage}s (MO messages and delivery
	 * receipts). Iterate it with `for await`; it ends when the session closes or the SMSC
	 * unbinds. Intended for a single consumer.
	 *
	 * @returns The delivery stream.
	 */
	messages(): AsyncIterable<SmppDeliverMessage>;
	/**
	 * Sends an `enquire_link` and awaits its response (an explicit liveness check on top of the
	 * automatic keep-alive).
	 *
	 * @returns Resolves once the `enquire_link_resp` arrives.
	 * @throws {TimeoutError} If no response arrives within the configured deadline.
	 * @throws {ConnectionError} If the session is closed.
	 */
	enquireLink(): Promise<void>;
	/**
	 * Sends `unbind` and awaits `unbind_resp` (best-effort), without closing the socket.
	 *
	 * @returns Resolves once the unbind round-trip completes or fails.
	 */
	unbind(): Promise<void>;
	/** Sends a best-effort `unbind` and closes the underlying socket. */
	close(): Promise<void>;
}

// a promise whose resolve/reject are exposed, used to await a response keyed by sequence
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

// single-consumer push/pull queue backing the deliveries async iterator
class MessageQueue<T> {
	#queue: T[] = [];
	#waiters: ((r: IteratorResult<T>) => void)[] = [];
	#done = false;

	push(item: T): void {
		if (this.#done) return;
		const waiter = this.#waiters.shift();
		if (waiter) waiter({ value: item, done: false });
		else this.#queue.push(item);
	}

	end(): void {
		if (this.#done) return;
		this.#done = true;
		for (const waiter of this.#waiters) waiter({ value: undefined, done: true });
		this.#waiters = [];
	}

	next(): Promise<IteratorResult<T>> {
		const item = this.#queue.shift();
		if (item !== undefined) return Promise.resolve({ value: item, done: false });
		if (this.#done) return Promise.resolve({ value: undefined, done: true });
		return new Promise((resolve) => this.#waiters.push(resolve));
	}
}

// deadline race for a response promise; TimeoutError when it elapses
function withTimeout<T>(promise: Promise<T>, ms: number | undefined): Promise<T> {
	if (ms === undefined) return promise;
	let timer: ReturnType<typeof setTimeout>;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(
			() => reject(new TimeoutError('smpp response timed out', { protocol: PROTO })),
			ms
		);
	});
	return Promise.race([promise, timeout]).finally(() => clearTimeout(timer)) as Promise<T>;
}

// encodes a message string per its data coding (UCS2 -> UTF-16BE, else Latin-1/ASCII)
function encodeMessage(text: string, dataCoding: number): Uint8Array {
	if (dataCoding === DataCoding.Ucs2) {
		const out = new Uint8Array(text.length * 2);
		const dv = new DataView(out.buffer);
		for (let i = 0; i < text.length; i++) dv.setUint16(i * 2, text.charCodeAt(i), false);
		return out;
	}
	// default alphabet / IA5 / Latin-1: one byte per code unit (non-ASCII needs UCS2)
	const out = new Uint8Array(text.length);
	for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
	return out;
}

// decodes an inbound body per its data coding
function decodeMessage(payload: Uint8Array, dataCoding: number): string {
	if (dataCoding === DataCoding.Ucs2) {
		const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
		let out = '';
		for (let i = 0; i + 1 < payload.length; i += 2)
			out += String.fromCharCode(dv.getUint16(i, false));
		return out;
	}
	return decoder.decode(payload);
}

// reads one full PDU off a framed reader; null on a clean end of stream
async function readRawPdu(reader: FramedReader, timeoutMs?: number): Promise<Uint8Array | null> {
	try {
		const lenBytes = await reader.readN(4, timeoutMs);
		const commandLength = new DataView(
			lenBytes.buffer,
			lenBytes.byteOffset,
			lenBytes.byteLength
		).getUint32(0, false);
		if (commandLength < HEADER_LENGTH || commandLength > MAX_PDU_LENGTH) {
			throw new ProtocolError(`invalid smpp command_length ${commandLength}`, { protocol: PROTO });
		}
		const rest =
			commandLength > 4 ? await reader.readN(commandLength - 4, timeoutMs) : new Uint8Array(0);
		const full = new Uint8Array(commandLength);
		full.set(lenBytes, 0);
		full.set(rest, 4);
		return full;
	} catch (err) {
		// a clean stream end surfaces as ConnectionError from readN; treat it as EOF
		if (err instanceof ConnectionError) return null;
		throw err;
	}
}

// maps a bind command_status to the right error type (auth-ish codes -> AuthError)
function bindStatusError(status: number): Error {
	if (
		status === CommandStatus.ESME_RINVPASWD ||
		status === CommandStatus.ESME_RINVSYSID ||
		status === CommandStatus.ESME_RBINDFAIL
	) {
		return new AuthError(`smpp bind rejected (status 0x${status.toString(16)})`, {
			protocol: PROTO
		});
	}
	return new ProtocolError(`smpp bind failed (status 0x${status.toString(16)})`, {
		protocol: PROTO
	});
}

function statusError(what: string, status: number): ProtocolError {
	return new ProtocolError(`smpp ${what} failed (status 0x${status.toString(16)})`, {
		protocol: PROTO
	});
}

interface SessionConfig {
	bindMode: BindMode;
	systemId: string;
	enquireLinkSeconds: number;
	scheduler: SmppScheduler;
	timeoutMs?: number;
}

class SmppSessionImpl implements SmppSession {
	readonly systemId: string;
	readonly bindMode: BindMode;
	readonly #socket: CoreSocket;
	readonly #reader: FramedReader;
	readonly #writer: FramedWriter;
	readonly #enquireLinkSeconds: number;
	readonly #scheduler: SmppScheduler;
	readonly #timeoutMs?: number;
	readonly #pending = new Map<number, Deferred<DecodedPdu>>();
	readonly #queue = new MessageQueue<SmppDeliverMessage>();
	#sequence = 1; // bind used sequence 1; the next request is 2
	#closed = false;
	#pumpError: Error | null = null;
	#keepAliveHandle: unknown = null;

	constructor(socket: CoreSocket, config: SessionConfig) {
		this.#socket = socket;
		this.#reader = socket.reader;
		this.#writer = socket.writer;
		this.systemId = config.systemId;
		this.bindMode = config.bindMode;
		this.#enquireLinkSeconds = config.enquireLinkSeconds;
		this.#scheduler = config.scheduler;
		this.#timeoutMs = config.timeoutMs;
	}

	// allocates the next sequence in 1..0x7fffffff, skipping ones still awaiting a response
	#nextSequence(): number {
		for (let i = 0; i < 0x7fffffff; i++) {
			this.#sequence = this.#sequence >= 0x7fffffff ? 1 : this.#sequence + 1;
			if (!this.#pending.has(this.#sequence)) return this.#sequence;
		}
		throw new ProtocolError('exhausted smpp sequence numbers', { protocol: PROTO });
	}

	#assertOpen(): void {
		if (this.#closed) throw new ConnectionError('smpp session is closed', { protocol: PROTO });
		if (this.#pumpError) throw this.#pumpError;
	}

	#write(bytes: Uint8Array): Promise<void> {
		return this.#writer.write(bytes);
	}

	#awaitResponse(sequence: number): Promise<DecodedPdu> {
		const d = deferred<DecodedPdu>();
		this.#pending.set(sequence, d);
		return d.promise;
	}

	#resolve(sequence: number, pdu: DecodedPdu): void {
		const waiter = this.#pending.get(sequence);
		if (waiter) {
			this.#pending.delete(sequence);
			waiter.resolve(pdu);
		}
	}

	#reject(sequence: number, err: Error): void {
		const waiter = this.#pending.get(sequence);
		if (waiter) {
			this.#pending.delete(sequence);
			waiter.reject(err);
		}
	}

	// begins the read pump and the keep-alive loop
	_start(): void {
		void this.#pump();
		if (this.#enquireLinkSeconds > 0) {
			this.#keepAliveHandle = this.#scheduler.set(() => {
				if (this.#closed) return;
				// fire-and-forget; the matching resp is a no-op in #dispatch
				void this.#write(encodeEmpty(Command.EnquireLink, this.#nextSequence())).catch(() => {});
			}, this.#enquireLinkSeconds * 1000);
		}
	}

	async #pump(): Promise<void> {
		try {
			for (;;) {
				const raw = await readRawPdu(this.#reader);
				if (raw === null) break;
				let pdu: DecodedPdu;
				try {
					pdu = decodePdu(raw);
				} catch (err) {
					if (err instanceof ProtocolError) {
						// unsupported/malformed pdu: nack it by sequence and keep going
						const header = decodeHeader(raw);
						await this.#write(
							encodeGenericNack(header.sequence, CommandStatus.ESME_RINVCMDID)
						).catch(() => {});
						continue;
					}
					throw err;
				}
				await this.#dispatch(pdu);
			}
		} catch (err) {
			if (!this.#closed) this.#pumpError = err as Error;
		} finally {
			const reason =
				this.#pumpError ?? new ConnectionError('smpp connection closed', { protocol: PROTO });
			for (const waiter of this.#pending.values()) waiter.reject(reason);
			this.#pending.clear();
			this.#queue.end();
		}
	}

	async #dispatch(pdu: DecodedPdu): Promise<void> {
		switch (pdu.command) {
			case Command.SubmitSmResp:
			case Command.UnbindResp:
			case Command.EnquireLinkResp:
				this.#resolve(pdu.sequence, pdu);
				return;
			case Command.GenericNack:
				// a nack correlates to the request that provoked it
				this.#reject(
					pdu.sequence,
					new ProtocolError(`smsc returned generic_nack (status 0x${pdu.status.toString(16)})`, {
						protocol: PROTO
					})
				);
				return;
			case Command.DeliverSm: {
				// the ESME must acknowledge every deliver_sm before routing it onward
				await this.#write(encodeDeliverSmResp(pdu.sequence, CommandStatus.ESME_ROK));
				this.#queue.push(toDeliverMessage(pdu));
				return;
			}
			case Command.EnquireLink:
				await this.#write(encodeEmpty(Command.EnquireLinkResp, pdu.sequence));
				return;
			case Command.Unbind:
				// the smsc wants to close; ack and end deliveries (the socket close follows)
				await this.#write(encodeEmpty(Command.UnbindResp, pdu.sequence));
				this.#queue.end();
				return;
			default:
				// a response/request we do not initiate; nack defensively
				await this.#write(encodeGenericNack(pdu.sequence, CommandStatus.ESME_RINVCMDID));
				return;
		}
	}

	async submit(opts: SubmitOptions): Promise<string> {
		this.#assertOpen();
		if (this.bindMode === 'receiver') {
			throw new ProtocolError('cannot submit on a receiver-only bind', { protocol: PROTO });
		}
		const dataCoding = opts.dataCoding ?? DataCoding.Default;
		const body =
			typeof opts.message === 'string' ? encodeMessage(opts.message, dataCoding) : opts.message;
		const tlvs = [...(opts.tlvs ?? [])];
		let shortMessage = body;
		// a body over the single-octet-string limit rides in a message_payload TLV instead
		if (body.length > MAX_SHORT_MESSAGE) {
			tlvs.push({ tag: Tag.MessagePayload, value: body });
			shortMessage = new Uint8Array(0);
		}
		const registeredDelivery =
			typeof opts.registeredDelivery === 'boolean'
				? opts.registeredDelivery
					? 1
					: 0
				: (opts.registeredDelivery ?? 0);

		const sequence = this.#nextSequence();
		const response = this.#awaitResponse(sequence);
		await this.#write(
			encodeSubmitSm(sequence, {
				serviceType: opts.serviceType,
				sourceAddrTon: opts.sourceTon ?? Ton.International,
				sourceAddrNpi: opts.sourceNpi ?? Npi.Isdn,
				sourceAddr: opts.source ?? '',
				destAddrTon: opts.destTon ?? Ton.International,
				destAddrNpi: opts.destNpi ?? Npi.Isdn,
				destinationAddr: opts.destination,
				esmClass: opts.esmClass ?? 0,
				priorityFlag: opts.priorityFlag ?? 0,
				scheduleDeliveryTime: opts.scheduleDeliveryTime,
				validityPeriod: opts.validityPeriod,
				registeredDelivery,
				dataCoding,
				shortMessage,
				tlvs
			})
		);

		const resp = await withTimeout(response, this.#timeoutMs);
		if (resp.command !== Command.SubmitSmResp) {
			throw new ProtocolError(`expected submit_sm_resp, got 0x${resp.command.toString(16)}`, {
				protocol: PROTO
			});
		}
		if (resp.status !== CommandStatus.ESME_ROK) throw statusError('submit_sm', resp.status);
		return resp.messageId;
	}

	messages(): AsyncIterable<SmppDeliverMessage> {
		const queue = this.#queue;
		return {
			[Symbol.asyncIterator](): AsyncIterator<SmppDeliverMessage> {
				return { next: () => queue.next() };
			}
		};
	}

	async enquireLink(): Promise<void> {
		this.#assertOpen();
		const sequence = this.#nextSequence();
		const response = this.#awaitResponse(sequence);
		await this.#write(encodeEmpty(Command.EnquireLink, sequence));
		await withTimeout(response, this.#timeoutMs);
	}

	async unbind(): Promise<void> {
		if (this.#closed) return;
		const sequence = this.#nextSequence();
		const response = this.#awaitResponse(sequence);
		await this.#write(encodeEmpty(Command.Unbind, sequence));
		try {
			await withTimeout(response, this.#timeoutMs);
		} catch {
			// best-effort; the socket close below is what actually frees the session
		}
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		if (this.#keepAliveHandle !== null) this.#scheduler.clear(this.#keepAliveHandle);
		this.#queue.end();
		try {
			await this.#write(encodeEmpty(Command.Unbind, this.#nextSequence()));
		} catch {
			// peer may already be gone; closing the socket is what matters
		}
		await this.#socket.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

// builds the public delivery message from a decoded deliver_sm pdu
function toDeliverMessage(pdu: SmPdu): SmppDeliverMessage {
	// a long inbound message rides in message_payload; prefer it over the empty short_message
	const mp = pdu.tlvs.find((t) => t.tag === Tag.MessagePayload);
	const payload = mp ? mp.value : pdu.shortMessage;
	const text = () => decodeMessage(payload, pdu.dataCoding);
	return {
		source: pdu.sourceAddr,
		destination: pdu.destinationAddr,
		dataCoding: pdu.dataCoding,
		esmClass: pdu.esmClass,
		payload,
		isDeliveryReceipt: (pdu.esmClass & ESM_DELIVERY_RECEIPT) !== 0,
		sequence: pdu.sequence,
		tlvs: pdu.tlvs,
		text,
		receipt: () => parseDeliveryReceipt(text())
	};
}

/**
 * Runs the SMPP bind handshake over an already-connected {@link CoreSocket} and returns a live
 * session.
 *
 * Writes the bind PDU for the requested mode, reads the bind response, maps a bad
 * password / system id / bind-failed status to {@link AuthError} and any other non-zero status
 * to {@link ProtocolError}, then starts the background pump and keep-alive. Public
 * {@link connect} dials the transport (and optionally upgrades to TLS) before calling this;
 * unit tests call it directly with a mock socket.
 *
 * @param socket - A connected core socket (already TLS when `tls: 'implicit'`).
 * @param opts - Bind and session options.
 * @returns The live session.
 * @throws {AuthError} If the SMSC rejects the credentials.
 * @throws {ProtocolError} If the SMSC returns another non-zero bind status or a wrong PDU.
 * @throws {ConnectionError} If the connection ends before the bind response.
 * @internal
 */
export async function _connectOverSocket(
	socket: CoreSocket,
	opts: SmppConnectOptions
): Promise<SmppSession> {
	const bindMode = opts.bindMode ?? 'transceiver';
	const command =
		bindMode === 'transmitter'
			? Command.BindTransmitter
			: bindMode === 'receiver'
				? Command.BindReceiver
				: Command.BindTransceiver;
	const expected =
		bindMode === 'transmitter'
			? Command.BindTransmitterResp
			: bindMode === 'receiver'
				? Command.BindReceiverResp
				: Command.BindTransceiverResp;

	await socket.writer.write(
		encodeBind(command, 1, {
			systemId: opts.systemId,
			password: opts.password,
			systemType: opts.systemType,
			interfaceVersion: opts.interfaceVersion,
			addrTon: opts.addrTon,
			addrNpi: opts.addrNpi,
			addressRange: opts.addressRange
		})
	);

	const raw = await readRawPdu(socket.reader, opts.timeoutMs);
	if (raw === null) {
		throw new ConnectionError('smpp connection closed before the bind response', {
			protocol: PROTO
		});
	}
	const resp = decodePdu(raw);
	if (resp.command === Command.GenericNack) throw statusError('bind', resp.status);
	if (resp.command !== expected) {
		throw new ProtocolError(
			`expected bind response 0x${expected.toString(16)}, got 0x${resp.command.toString(16)}`,
			{ protocol: PROTO }
		);
	}
	if (resp.status !== CommandStatus.ESME_ROK) throw bindStatusError(resp.status);

	const session = new SmppSessionImpl(socket, {
		bindMode,
		systemId: resp.systemId,
		enquireLinkSeconds: opts.enquireLinkSeconds ?? DEFAULT_ENQUIRE_LINK_SECONDS,
		scheduler: opts.scheduler ?? defaultScheduler,
		timeoutMs: opts.timeoutMs
	});
	session._start();
	return session;
}

/**
 * Connects to an SMSC over TCP, binds as an ESME, and returns a live session.
 *
 * Dials the core transport (implicit TLS when `tls: 'implicit'`, otherwise plaintext), binds in
 * the requested mode, and waits for the bind response so an auth failure surfaces here. A
 * background pump then correlates responses and routes inbound `deliver_sm`s to
 * {@link SmppSession.messages}.
 *
 * @param opts - Connection and bind options.
 * @returns The live session.
 * @throws {AuthError} If the SMSC rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the SMSC speaks the protocol incorrectly.
 * @since 1.0.3
 *
 * @example
 * ```typescript
 * import { connect, DataCoding } from 'edgeport/smpp';
 *
 * await using smpp = await connect({
 * 	hostname: 'smsc.example.com',
 * 	systemId: 'esme',
 * 	password: env.SMPP_PW,
 * 	bindMode: 'transceiver'
 * });
 *
 * const id = await smpp.submit({
 * 	source: 'EDGEPORT',
 * 	destination: '12065550111',
 * 	message: 'hello from a Worker',
 * 	registeredDelivery: true
 * });
 *
 * for await (const inbound of smpp.messages()) {
 * 	if (inbound.isDeliveryReceipt) {
 * 		const r = inbound.receipt();
 * 		if (r.id === id && r.stat === 'DELIVRD') break;
 * 	}
 * }
 * ```
 */
export async function connect(opts: SmppConnectOptions): Promise<SmppSession> {
	const port = opts.port ?? DEFAULT_SMPP_PORT;
	const socket = await coreConnect({
		hostname: opts.hostname,
		port,
		tls: opts.tls === 'implicit' ? 'on' : 'off',
		connectTimeoutMs: opts.timeoutMs
	});
	try {
		return await _connectOverSocket(socket, opts);
	} catch (err) {
		await socket.close().catch(() => {});
		throw err;
	}
}

/**
 * Sends a single message in one call: bind, submit, unbind.
 *
 * A convenience wrapper over {@link connect} + {@link SmppSession.submit} for the fire-once
 * case; it binds as a transmitter by default (override with `bindMode`). The session is always
 * closed, even if the submission throws.
 *
 * @param opts - Connection/bind options merged with the submission fields.
 * @returns The SMSC-assigned `message_id`.
 * @throws {AuthError} If the SMSC rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the SMSC rejects the submission.
 * @since 1.0.3
 *
 * @example
 * ```typescript
 * import { sendMessage } from 'edgeport/smpp';
 *
 * const id = await sendMessage({
 * 	hostname: 'smsc.example.com',
 * 	systemId: 'esme',
 * 	password: env.SMPP_PW,
 * 	source: 'EDGEPORT',
 * 	destination: '12065550111',
 * 	message: 'one-shot SMS from the edge'
 * });
 * ```
 */
export async function sendMessage(opts: SmppConnectOptions & SubmitOptions): Promise<string> {
	const session = await connect({ ...opts, bindMode: opts.bindMode ?? 'transmitter' });
	try {
		return await session.submit(opts);
	} finally {
		await session.close();
	}
}
