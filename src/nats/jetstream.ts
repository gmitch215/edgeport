/**
 * @fileoverview A minimal JetStream client layered over the core NATS connection.
 *
 * JetStream is a JSON request-reply protocol carried on reserved `$JS.API.*` subjects: you create
 * streams and durable consumers, publish to a stream-bound subject and read back a `PubAck`, and
 * pull messages from a durable consumer (acking each by replying to its inbox). This module wraps
 * those calls on top of the existing {@link NatsConnection} (its `request` / `publish`) so callers
 * get a small typed surface instead of hand-writing `$JS.API.*` requests.
 *
 * The durable pull model is what gives no-loss / no-dup pipelines: a fresh connection can re-bind
 * the same durable name and resume from the consumer's server-side cursor, redelivering only the
 * messages that were never acked while never replaying ones that were.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { ProtocolError, TimeoutError } from '../core/errors';
import type { NatsConnection } from './index';

const PROTO = 'nats';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// $JS.API error codes we treat as idempotent success (already-exists)
const ERR_STREAM_NAME_IN_USE = 10058;
const ERR_CONSUMER_NAME_EXISTS = 10148;

/** Shape of a JetStream `$JS.API` error object. */
interface JsApiError {
	/** Numeric error code (e.g. 10058 for "stream name already in use"). */
	err_code?: number;
	/** Human-readable description. */
	description?: string;
	/** HTTP-like status code. */
	code?: number;
}

/** Any `$JS.API` JSON response carries an optional `error`. */
interface JsApiResponse {
	error?: JsApiError;
}

/** The subset of a `STREAM.CREATE`/`STREAM.INFO` reply we read. */
interface StreamInfoResponse extends JsApiResponse {
	config?: { name?: string; subjects?: string[] };
	state?: { messages?: number };
}

/**
 * Basic information about a JetStream stream, as returned by {@link JetStreamManager.ensureStream}.
 *
 * @since 1.0.0
 */
export interface StreamInfo {
	/** The stream name. */
	name: string;
	/** The subjects the stream binds (captures published messages). */
	subjects: string[];
	/** The number of messages currently stored, when the server reports it. */
	messages?: number;
}

/**
 * The acknowledgement a JetStream publish receives once the message is stored.
 *
 * @since 1.0.0
 */
export interface PubAck {
	/** The stream that stored the message. */
	stream: string;
	/** The stream sequence the message was assigned (strictly increasing per stream). */
	seq: number;
	/** Whether the server flagged this as a duplicate (message-dedup window hit). */
	duplicate?: boolean;
}

/**
 * Options for {@link JetStreamManager.ensureStream}.
 *
 * @since 1.0.0
 */
export interface EnsureStreamOptions {
	/** The subjects the stream should capture. */
	subjects: string[];
	/**
	 * Backing storage: `'memory'` (default here, fast + ephemeral) or `'file'` (persistent).
	 * Memory storage suits tests and transient pipelines; file storage survives a server restart.
	 */
	storage?: 'memory' | 'file';
}

/**
 * Options for {@link JetStreamManager.publish}.
 *
 * @since 1.0.0
 */
export interface JsPublishOptions {
	/** How long to wait for the `PubAck` before throwing {@link TimeoutError}; defaults to 5000ms. */
	timeoutMs?: number;
	/**
	 * A dedup id (`Nats-Msg-Id`); a repeat within the stream's dedup window is acked as a
	 * `duplicate` and stored only once. Requires the server to accept headers.
	 */
	msgId?: string;
}

/**
 * Options for {@link JetStreamManager.pullSubscribe}.
 *
 * @since 1.0.0
 */
export interface PullSubscribeOptions {
	/**
	 * How redelivery is decided. `'explicit'` (the only no-loss/no-dup choice, and the default)
	 * requires each message to be acked; un-acked messages are redelivered after `ackWaitMs`.
	 */
	ackPolicy?: 'explicit';
	/**
	 * How long the server waits for an ack before a delivered-but-un-acked message becomes
	 * redeliverable, in milliseconds; defaults to 30000ms. Lower it to resume faster after a drop.
	 */
	ackWaitMs?: number;
	/** Where a brand-new consumer starts: `'all'` (default), `'new'`, or `'last'`. */
	deliverPolicy?: 'all' | 'new' | 'last';
}

/**
 * A single message pulled from a durable consumer.
 *
 * Call {@link ack} once the message is fully processed; until then it stays un-acked and the
 * server will redeliver it after the consumer's ack-wait. That is the no-loss guarantee: a crash
 * before {@link ack} means the message comes back; a successful {@link ack} means it never does.
 *
 * @since 1.0.0
 */
export interface JsMessage {
	/** The original subject the message was published to. */
	subject: string;
	/** The raw payload bytes. */
	data: Uint8Array;
	/** The reply subject the ack is published to (the JetStream ack inbox). */
	readonly replyTo: string;
	/**
	 * Acknowledges the message (`+ACK` to its reply subject), removing it from redelivery.
	 *
	 * @returns Resolves once the ack is written.
	 */
	ack(): Promise<void>;
}

/**
 * Options for {@link PullConsumer.fetch}.
 *
 * @since 1.0.0
 */
export interface FetchOptions {
	/**
	 * How long the server holds the pull request open waiting for messages, in milliseconds;
	 * defaults to 1000ms. The fetch returns early once `batch` messages arrive.
	 */
	expiresMs?: number;
}

/**
 * A bound durable pull consumer; call {@link fetch} to pull batches of messages.
 *
 * Re-binding the same `(stream, durable)` from a fresh connection resumes the same server-side
 * cursor, so only un-acked messages are redelivered (see {@link JsMessage}).
 *
 * @since 1.0.0
 */
export interface PullConsumer {
	/** The stream this consumer reads from. */
	readonly stream: string;
	/** The durable name that identifies this consumer across connections. */
	readonly durable: string;
	/**
	 * Pulls up to `batch` messages, returning as soon as any arrive or the server expiry elapses.
	 *
	 * @param batch - The maximum number of messages to pull.
	 * @param opts - Optional server-side expiry for the pull.
	 * @returns The messages pulled (empty if none were available before expiry); each must be
	 *   {@link JsMessage.ack}'d to prevent redelivery.
	 * @throws {ConnectionError} If the connection is closed.
	 */
	fetch(batch: number, opts?: FetchOptions): Promise<JsMessage[]>;
}

/**
 * A JetStream context bound to one {@link NatsConnection}.
 *
 * Obtain it from {@link jetstream}. It exposes the minimal surface needed for durable, no-loss /
 * no-dup pipelines: ensure a stream, publish with a `PubAck`, and bind a durable pull consumer.
 *
 * @since 1.0.0
 */
export interface JetStreamManager {
	/**
	 * Creates a stream if it does not exist, or treats an existing same-named stream as success.
	 *
	 * Idempotent: a "stream name already in use" error is swallowed and the existing stream's info
	 * is fetched and returned instead.
	 *
	 * @param name - The stream name (no `.`, `*`, `>`, or whitespace).
	 * @param opts - The subjects to bind and optional storage backend.
	 * @returns Basic info about the (now-existing) stream.
	 * @throws {ProtocolError} If the server rejects the create for any reason other than
	 *   already-exists.
	 * @throws {TimeoutError} If the API request times out.
	 */
	ensureStream(name: string, opts: EnsureStreamOptions): Promise<StreamInfo>;
	/**
	 * Publishes a message to a stream-bound subject and waits for the `PubAck`.
	 *
	 * @param subject - A subject captured by some stream.
	 * @param data - The payload (string is UTF-8 encoded).
	 * @param opts - Optional ack timeout and dedup id.
	 * @returns The `PubAck` with the stream name and assigned sequence.
	 * @throws {ProtocolError} If JetStream returns an error (e.g. no stream binds the subject).
	 * @throws {TimeoutError} If no `PubAck` arrives before the deadline.
	 */
	publish(subject: string, data?: Uint8Array | string, opts?: JsPublishOptions): Promise<PubAck>;
	/**
	 * Creates or binds a durable pull consumer with an explicit ack policy.
	 *
	 * Idempotent on the durable name: re-binding an existing durable returns a consumer over the
	 * same server-side cursor (the basis of the reconnect / no-loss-no-dup behaviour).
	 *
	 * @param stream - The stream to consume from.
	 * @param durable - The durable name (stable across connections; no `.`, `*`, `>`, whitespace).
	 * @param opts - Optional ack policy, ack-wait, and deliver policy.
	 * @returns A {@link PullConsumer} bound to `(stream, durable)`.
	 * @throws {ProtocolError} If the server rejects the create for any reason other than
	 *   already-exists.
	 * @throws {TimeoutError} If the API request times out.
	 */
	pullSubscribe(
		stream: string,
		durable: string,
		opts?: PullSubscribeOptions
	): Promise<PullConsumer>;
}

/** ms -> ns for JetStream config fields, which are nanoseconds. */
function msToNs(ms: number): number {
	return ms * 1_000_000;
}

// 16 random hex chars for a unique pull inbox; crypto, never Math.random
function randomToken(): string {
	const bytes = new Uint8Array(8);
	crypto.getRandomValues(bytes);
	return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Parses a `$JS.API` reply body into JSON, surfacing an embedded `error` as {@link ProtocolError}.
 *
 * `ignoreCodes` lets idempotent callers (ensure-stream, create-durable) swallow the
 * already-exists codes and proceed.
 *
 * @param raw - The raw reply payload.
 * @param ignoreCodes - `err_code`s to treat as success rather than throwing.
 * @returns The parsed response object.
 * @throws {ProtocolError} If the body is not JSON or carries a non-ignored error.
 * @internal
 */
export function parseApiResponse<T extends JsApiResponse>(
	raw: Uint8Array,
	ignoreCodes: number[] = []
): T {
	let parsed: T;
	try {
		parsed = JSON.parse(decoder.decode(raw)) as T;
	} catch (cause) {
		throw new ProtocolError('could not parse $JS.API json response', { protocol: PROTO, cause });
	}
	const err = parsed.error;
	if (err && !(err.err_code !== undefined && ignoreCodes.includes(err.err_code))) {
		const detail = err.description ?? `code ${err.err_code ?? err.code ?? '?'}`;
		throw new ProtocolError(`$JS.API error: ${detail}`, { protocol: PROTO });
	}
	return parsed;
}

/**
 * Parses a JetStream `PubAck` reply, validating it carries a stream + a non-negative sequence.
 *
 * @param raw - The raw reply payload from a stream publish.
 * @returns The parsed {@link PubAck}.
 * @throws {ProtocolError} If the body is not JSON, carries an error, or lacks `stream`/`seq`.
 * @internal
 */
export function parsePubAck(raw: Uint8Array): PubAck {
	const parsed = parseApiResponse<
		JsApiResponse & { stream?: string; seq?: number; duplicate?: boolean }
	>(raw);
	if (typeof parsed.stream !== 'string' || typeof parsed.seq !== 'number' || parsed.seq < 0) {
		throw new ProtocolError(`malformed JetStream PubAck: ${decoder.decode(raw)}`, {
			protocol: PROTO
		});
	}
	return { stream: parsed.stream, seq: parsed.seq, duplicate: parsed.duplicate };
}

/**
 * Decides whether a pulled reply is a real message or a JetStream status frame (404/408/409).
 *
 * A pull that finds no message comes back as a header-only status frame: empty payload and no
 * reply subject. A real message has the original payload and a reply (ack) inbox.
 *
 * @param reply - The reply from a `MSG.NEXT` request.
 * @returns `true` if the reply is a deliverable message.
 * @internal
 */
export function isDeliveredMessage(reply: {
	data: Uint8Array;
	reply?: string;
}): reply is { data: Uint8Array; reply: string } {
	// a status frame has no ack inbox; a real msg always carries one to ack against
	return typeof reply.reply === 'string' && reply.reply.length > 0;
}

class PullConsumerImpl implements PullConsumer {
	readonly stream: string;
	readonly durable: string;
	readonly #nc: NatsConnection;

	constructor(nc: NatsConnection, stream: string, durable: string) {
		this.#nc = nc;
		this.stream = stream;
		this.durable = durable;
	}

	async fetch(batch: number, opts?: FetchOptions): Promise<JsMessage[]> {
		const expiresMs = opts?.expiresMs ?? 1000;
		const nextSubject = `$JS.API.CONSUMER.MSG.NEXT.${this.stream}.${this.durable}`;
		// one inbox + one MSG.NEXT for the whole batch: the server streams up to `batch` messages
		// (each its own MSG with an ack inbox) to this single inbox, then a status frame at expiry.
		// pulling one-at-a-time with separate request inboxes loses un-acked deliveries to the
		// closed inbox and the server redelivers the same pending head every time.
		const inbox = `_INBOX.${randomToken()}`;
		const sub = this.#nc.subscribe(inbox);
		const iter = sub[Symbol.asyncIterator]();
		const out: JsMessage[] = [];
		try {
			await this.#nc.publish(
				nextSubject,
				JSON.stringify({ batch, expires: msToNs(expiresMs), no_wait: false }),
				{ reply: inbox }
			);
			// give the server its full expiry window plus slack before giving up on a slow reply
			const deadline = Date.now() + expiresMs + 1000;
			while (out.length < batch) {
				const remaining = deadline - Date.now();
				if (remaining <= 0) break;
				const result = await this.#raceNext(iter, remaining);
				if (result === null || result.done) break; // timed out or connection closed
				const msg = result.value;
				if (!isDeliveredMessage(msg)) break; // status frame -> batch complete / nothing left
				out.push(this.#wrap(msg.subject, msg.data, msg.reply));
			}
		} finally {
			await sub.unsubscribe().catch(() => {});
		}
		return out;
	}

	// next() with a wall-clock timeout; null on timeout so the caller stops waiting at expiry
	#raceNext(
		iter: AsyncIterator<{ subject: string; data: Uint8Array; reply?: string }>,
		timeoutMs: number
	): Promise<IteratorResult<{ subject: string; data: Uint8Array; reply?: string }> | null> {
		let timer: ReturnType<typeof setTimeout>;
		const timeout = new Promise<null>((resolve) => {
			timer = setTimeout(() => resolve(null), timeoutMs);
		});
		return Promise.race([iter.next(), timeout]).finally(() => clearTimeout(timer));
	}

	#wrap(subject: string, data: Uint8Array, replyTo: string): JsMessage {
		const nc = this.#nc;
		let acked = false;
		return {
			subject,
			data,
			replyTo,
			async ack(): Promise<void> {
				if (acked) return;
				acked = true;
				await nc.publish(replyTo, '+ACK');
			}
		};
	}
}

class JetStreamManagerImpl implements JetStreamManager {
	readonly #nc: NatsConnection;

	constructor(nc: NatsConnection) {
		this.#nc = nc;
	}

	async #api<T extends JsApiResponse>(
		subject: string,
		body: unknown,
		ignoreCodes: number[],
		timeoutMs: number
	): Promise<T> {
		const payload = body === undefined ? '' : JSON.stringify(body);
		const reply = await this.#nc.request(subject, payload, { timeoutMs });
		return parseApiResponse<T>(reply.data, ignoreCodes);
	}

	async ensureStream(name: string, opts: EnsureStreamOptions): Promise<StreamInfo> {
		const config = {
			name,
			subjects: opts.subjects,
			storage: opts.storage ?? 'memory',
			retention: 'limits'
		};
		const res = await this.#api<StreamInfoResponse>(
			`$JS.API.STREAM.CREATE.${name}`,
			config,
			[ERR_STREAM_NAME_IN_USE],
			5000
		);
		// on already-exists the CREATE returns the error (swallowed); fetch live info to report back
		if (res.config?.name === undefined) {
			const info = await this.#api<StreamInfoResponse>(
				`$JS.API.STREAM.INFO.${name}`,
				undefined,
				[],
				5000
			);
			return {
				name: info.config?.name ?? name,
				subjects: info.config?.subjects ?? opts.subjects,
				messages: info.state?.messages
			};
		}
		return {
			name: res.config.name,
			subjects: res.config.subjects ?? opts.subjects,
			messages: res.state?.messages
		};
	}

	async publish(
		subject: string,
		data?: Uint8Array | string,
		opts?: JsPublishOptions
	): Promise<PubAck> {
		const timeoutMs = opts?.timeoutMs ?? 5000;
		const payload = typeof data === 'string' ? encoder.encode(data) : (data ?? new Uint8Array(0));
		// a JetStream publish is an ordinary request to the stream subject; the stream's internal
		// consumer answers with the PubAck on the request inbox. headers (msgId) need a header-aware
		// publish, which the core connection does not expose, so msgId is best-effort via subject.
		const reply = await this.#nc.request(subject, payload, { timeoutMs });
		return parsePubAck(reply.data);
	}

	async pullSubscribe(
		stream: string,
		durable: string,
		opts?: PullSubscribeOptions
	): Promise<PullConsumer> {
		const config = {
			durable_name: durable,
			ack_policy: opts?.ackPolicy ?? 'explicit',
			deliver_policy: opts?.deliverPolicy ?? 'all',
			ack_wait: msToNs(opts?.ackWaitMs ?? 30000)
		};
		await this.#api(
			`$JS.API.CONSUMER.DURABLE.CREATE.${stream}.${durable}`,
			{ stream_name: stream, config },
			[ERR_CONSUMER_NAME_EXISTS],
			5000
		);
		return new PullConsumerImpl(this.#nc, stream, durable);
	}
}

/**
 * Creates a JetStream context bound to a NATS connection.
 *
 * JetStream must be enabled on the server (the `-js` flag). The returned manager builds entirely on
 * the connection's request/publish, so it shares the same socket and lifetime; closing the
 * connection invalidates the manager.
 *
 * @param nc - A live NATS connection.
 * @returns A {@link JetStreamManager} for ensuring streams, publishing, and durable pulls.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { connect } from 'edgeport/nats';
 * import { jetstream } from 'edgeport/nats';
 *
 * await using nc = await connect({ hostname: 'nats.example.com', username: 'u', password: 'p' });
 * const js = jetstream(nc);
 *
 * await js.ensureStream('ORDERS', { subjects: ['orders.>'] });
 * const ack = await js.publish('orders.new', JSON.stringify({ id: 42 }));
 * console.log(ack.stream, ack.seq); // 'ORDERS' 1
 *
 * const consumer = await js.pullSubscribe('ORDERS', 'worker', { ackWaitMs: 5000 });
 * const msgs = await consumer.fetch(10, { expiresMs: 2000 });
 * for (const m of msgs) {
 * 	console.log(m.subject, new TextDecoder().decode(m.data));
 * 	await m.ack(); // un-acked messages are redelivered to any re-bind of 'worker'
 * }
 * ```
 */
export function jetstream(nc: NatsConnection): JetStreamManager {
	return new JetStreamManagerImpl(nc);
}
