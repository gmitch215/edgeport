/**
 * @fileoverview A Redis client (commands, pipelining, transactions, and Pub/Sub) for the
 * Cloudflare Workers runtime.
 *
 * Redis speaks RESP over TCP: the client writes an array of bulk strings and the server writes
 * back one self-describing reply per command, in order. That ordering is what makes pipelining
 * work, and it is how this module correlates replies - a background pump reads frames and hands
 * each to the next waiting command, while Pub/Sub deliveries are routed to their subscriptions
 * instead. The wire codec lives in {@link module:redis/resp}; this module owns the connection,
 * the handshake, and the typed command surface. It builds on the shared core transport and never
 * touches the runtime socket API directly.
 *
 * The protocol version changes what replies look like, so it is explicit rather than negotiated.
 * `protocol: 2` (the default) works against every Redis ever shipped and authenticates with
 * `AUTH`. `protocol: 3` sends `HELLO 3`, which needs Redis 6 or newer, and buys two things: the
 * richer reply types (maps, sets, doubles, booleans) and out-of-band `>` pushes, which let a
 * subscribed connection keep running ordinary commands - something RESP2 forbids.
 *
 * @author Gregory Mitchell
 * @since 1.0.6
 */
import {
	AuthError,
	ConnectionError,
	ProtocolError,
	connect as coreConnect,
	type CoreSocket,
	type EdgeportError,
	type FramedReader,
	type FramedWriter
} from '../core';
import {
	encodeCommand,
	encodeCommands,
	makeReply,
	readReply,
	respToNative,
	type RedisArg,
	type RedisNative,
	type RedisReply,
	type RespValue
} from './resp';

export * from './resp';

const DEFAULT_REDIS_PORT = 6379;
const PROTO = 'redis';

const decoder = new TextDecoder();

// pubsub frames the pump must route rather than hand to a waiting command
const MESSAGE_KINDS = new Set(['message', 'pmessage', 'smessage']);
const CONFIRM_KINDS = new Set([
	'subscribe',
	'unsubscribe',
	'psubscribe',
	'punsubscribe',
	'ssubscribe',
	'sunsubscribe'
]);

// the only commands a RESP2 server accepts once the connection is in subscriber mode
const SUBSCRIBER_ALLOWED = new Set([
	'SUBSCRIBE',
	'UNSUBSCRIBE',
	'PSUBSCRIBE',
	'PUNSUBSCRIBE',
	'SSUBSCRIBE',
	'SUNSUBSCRIBE',
	'PING',
	'QUIT',
	'RESET'
]);

/**
 * Options for {@link connect}.
 *
 * @since 1.0.6
 */
export interface RedisConnectOptions {
	/** Remote Redis host. */
	hostname: string;
	/** Remote port; defaults to 6379. */
	port?: number;
	/**
	 * Transport security:
	 * - `'off'` (default): plaintext.
	 * - `'implicit'`: TLS from the first byte, for a server with `tls-port` configured.
	 *
	 * Redis has no in-band upgrade, so there is no `'starttls'` mode.
	 */
	tls?: 'off' | 'implicit';
	/** ACL username (Redis 6+); pair with {@link password}. Omit for a `requirepass`-only server. */
	username?: string;
	/** Password for `AUTH`, or for the `HELLO ... AUTH` clause when `protocol: 3`. */
	password?: string;
	/** Database index to `SELECT` after authenticating. */
	db?: number;
	/**
	 * RESP protocol version: `2` (default) or `3`.
	 *
	 * RESP2 works against every Redis version. RESP3 requires Redis 6 or newer and is not
	 * negotiated down - an older server fails the connect rather than silently falling back,
	 * because the two versions return different reply shapes for the same command.
	 */
	protocol?: 2 | 3;
	/** Connection name to register (`HELLO ... SETNAME` or `CLIENT SETNAME`). */
	clientName?: string;
	/** Read deadline in milliseconds for the connect handshake. */
	timeoutMs?: number;
}

/** Options for {@link RedisSession.set}. */
export interface RedisSetOptions {
	/** Expire the key after this many seconds (`EX`). */
	ex?: number;
	/** Expire the key after this many milliseconds (`PX`). */
	px?: number;
	/** Expire the key at this UNIX time in seconds (`EXAT`). */
	exat?: number;
	/** Expire the key at this UNIX time in milliseconds (`PXAT`). */
	pxat?: number;
	/** Retain the key's existing TTL (`KEEPTTL`). */
	keepTtl?: boolean;
	/** Only set the key if it does not already exist (`NX`). */
	nx?: boolean;
	/** Only set the key if it already exists (`XX`). */
	xx?: boolean;
}

/** Options for {@link RedisSession.scan} and {@link RedisSession.scanIterator}. */
export interface RedisScanOptions {
	/** Glob-style pattern to match keys against (`MATCH`). */
	match?: string;
	/** Hint for how many keys to examine per round trip (`COUNT`). */
	count?: number;
	/** Only return keys of this type (`TYPE`), e.g. `'string'` or `'hash'`. */
	type?: string;
}

/** One page of a {@link RedisSession.scan}. */
export interface RedisScanPage {
	/** The cursor to pass to the next call; `'0'` once the scan is complete. */
	cursor: string;
	/** The keys found in this page (may be empty even when the scan is not finished). */
	keys: string[];
}

/** A sorted-set member with its score. */
export interface RedisScoreEntry {
	/** The member. */
	member: string;
	/** Its score. */
	score: number;
}

/** Options for {@link RedisSession.eval} and {@link RedisSession.evalSha}. */
export interface RedisEvalOptions {
	/** Keys the script touches; they become `KEYS[1..n]`. */
	keys?: string[];
	/** Extra arguments; they become `ARGV[1..n]`. */
	args?: RedisArg[];
}

/**
 * A message delivered to a {@link RedisSubscription}.
 *
 * @since 1.0.6
 */
export interface RedisMessage {
	/** The channel the message was published to. */
	channel: string;
	/** The pattern that matched, for a {@link RedisSession.psubscribe} delivery. */
	pattern?: string;
	/** The raw payload bytes. */
	payload: Uint8Array;
	/**
	 * Decodes the payload as UTF-8 text.
	 *
	 * @returns The payload as a string.
	 */
	text(): string;
	/**
	 * Decodes the payload as UTF-8 then parses it as JSON.
	 *
	 * @typeParam T - The expected shape of the decoded value.
	 * @returns The parsed value.
	 * @throws {ProtocolError} If the payload is not valid JSON.
	 */
	json<T = unknown>(): T;
}

/**
 * An active subscription that yields {@link RedisMessage}s as they arrive.
 *
 * Iterate it with `for await`; the loop ends when {@link unsubscribe} is called or the connection
 * closes. It is an `AsyncDisposable`, so `await using` unsubscribes automatically.
 *
 * @since 1.0.6
 */
export interface RedisSubscription extends AsyncIterable<RedisMessage>, AsyncDisposable {
	/** The channels (or patterns) this subscription covers. */
	readonly channels: readonly string[];
	/** Whether the entries in {@link channels} are patterns rather than exact channel names. */
	readonly pattern: boolean;
	/**
	 * Stops the subscription and ends the iterator.
	 *
	 * Only the channels no other subscription still holds are unsubscribed on the server.
	 *
	 * @returns Resolves once the server confirms.
	 */
	unsubscribe(): Promise<void>;
}

/**
 * A live Redis connection over a single socket.
 *
 * Obtain one from {@link connect}. A background pump reads replies and routes them, so commands,
 * pipelines, and Pub/Sub deliveries can all be in flight at once. It is an `AsyncDisposable`, so
 * `await using` closes it cleanly.
 *
 * {@link send} runs any command, which is the escape hatch for everything the typed methods below
 * do not cover (streams, cluster commands, module commands, `CONFIG`, ...).
 *
 * @since 1.0.6
 */
export interface RedisSession extends AsyncDisposable {
	/** The RESP version in use on this connection. */
	readonly protocol: 2 | 3;
	/** The server properties from the `HELLO` handshake; only populated when `protocol: 3`. */
	readonly serverInfo: Record<string, RedisNative> | undefined;
	/** How many channels and patterns the connection is currently subscribed to. */
	readonly subscriptionCount: number;

	/**
	 * Runs one command and returns its reply.
	 *
	 * @param args - The command name followed by its arguments.
	 * @returns The reply.
	 * @throws {AuthError} If the server rejects the command for want of authorization.
	 * @throws {ProtocolError} If the server replies with an error.
	 * @throws {ConnectionError} If the connection is closed.
	 * @example
	 * ```typescript
	 * const reply = await redis.send('SET', 'greeting', 'hello');
	 * reply.text(); // 'OK'
	 * ```
	 */
	send(...args: RedisArg[]): Promise<RedisReply>;
	/**
	 * Runs several commands in one round trip and returns their replies in order.
	 *
	 * Unlike {@link send}, a command that fails does not throw: its reply carries the message on
	 * {@link RedisReply.error} so one failure does not discard the other results. Reading such a
	 * reply's value throws, so a failure cannot be mistaken for data.
	 *
	 * @param commands - The commands to run, in order.
	 * @returns One reply per command.
	 * @throws {ConnectionError} If the connection is closed.
	 */
	pipeline(commands: readonly (readonly RedisArg[])[]): Promise<RedisReply[]>;
	/**
	 * Runs several commands atomically in a `MULTI` / `EXEC` transaction.
	 *
	 * Like {@link pipeline}, a per-command failure surfaces on that reply's
	 * {@link RedisReply.error} rather than throwing.
	 *
	 * @param commands - The commands to queue, in order.
	 * @returns One reply per command, as returned by `EXEC`.
	 * @throws {ProtocolError} If the server rejects a command at queue time and aborts the
	 *   transaction, or if the transaction is discarded.
	 * @throws {ConnectionError} If the connection is closed.
	 */
	multi(commands: readonly (readonly RedisArg[])[]): Promise<RedisReply[]>;

	/**
	 * Gets a key's value as raw bytes.
	 *
	 * @param key - The key to read.
	 * @returns The bytes, or null if the key does not exist.
	 */
	get(key: string): Promise<Uint8Array | null>;
	/**
	 * Gets a key's value as UTF-8 text.
	 *
	 * @param key - The key to read.
	 * @returns The value, or null if the key does not exist.
	 */
	getText(key: string): Promise<string | null>;
	/**
	 * Sets a key, optionally with an expiry or an existence condition.
	 *
	 * @param key - The key to write.
	 * @param value - The value (a string is UTF-8 encoded).
	 * @param opts - Expiry and `NX` / `XX` options.
	 * @returns True if the key was set; false when `nx` or `xx` prevented it.
	 */
	set(key: string, value: RedisArg, opts?: RedisSetOptions): Promise<boolean>;
	/**
	 * Deletes keys.
	 *
	 * @param keys - The keys to delete.
	 * @returns How many keys were removed.
	 */
	del(...keys: string[]): Promise<number>;
	/**
	 * Counts how many of the given keys exist.
	 *
	 * @param keys - The keys to test.
	 * @returns The number that exist (counting duplicates separately, as Redis does).
	 */
	exists(...keys: string[]): Promise<number>;
	/**
	 * Gets several keys at once.
	 *
	 * @param keys - The keys to read.
	 * @returns One entry per key, null where the key does not exist.
	 */
	mget(keys: readonly string[]): Promise<(string | null)[]>;
	/**
	 * Sets several keys at once.
	 *
	 * @param entries - Key-to-value pairs to write.
	 * @returns Resolves once the server confirms.
	 */
	mset(entries: Record<string, RedisArg>): Promise<void>;
	/**
	 * Increments a key by one.
	 *
	 * @param key - The key to increment.
	 * @returns The value after the increment.
	 */
	incr(key: string): Promise<number>;
	/**
	 * Increments a key by an integer amount.
	 *
	 * @param key - The key to increment.
	 * @param by - The amount to add (may be negative).
	 * @returns The value after the increment.
	 */
	incrBy(key: string, by: number): Promise<number>;
	/**
	 * Decrements a key by one.
	 *
	 * @param key - The key to decrement.
	 * @returns The value after the decrement.
	 */
	decr(key: string): Promise<number>;
	/**
	 * Sets a key's time to live.
	 *
	 * @param key - The key to expire.
	 * @param seconds - Seconds until expiry.
	 * @returns True if the timeout was set, false if the key does not exist.
	 */
	expire(key: string, seconds: number): Promise<boolean>;
	/**
	 * Reads a key's remaining time to live.
	 *
	 * @param key - The key to inspect.
	 * @returns Seconds remaining, `-1` if the key has no expiry, `-2` if it does not exist.
	 */
	ttl(key: string): Promise<number>;
	/**
	 * Lists every key matching a pattern.
	 *
	 * `KEYS` walks the whole keyspace, which blocks the server on a large database; prefer
	 * {@link scanIterator} outside of small datasets and one-off tooling.
	 *
	 * @param pattern - A glob-style pattern, e.g. `'session:*'`.
	 * @returns The matching keys.
	 */
	keys(pattern: string): Promise<string[]>;
	/**
	 * Reads one page of the keyspace.
	 *
	 * @param opts - Cursor and filter options; omit `cursor` to start a new scan.
	 * @returns The page's keys and the cursor for the next call.
	 */
	scan(opts?: RedisScanOptions & { cursor?: string }): Promise<RedisScanPage>;
	/**
	 * Walks the whole keyspace one page at a time, yielding each key.
	 *
	 * @param opts - Filter options passed to each underlying `SCAN`.
	 * @returns An async iterable of keys.
	 * @example
	 * ```typescript
	 * for await (const key of redis.scanIterator({ match: 'session:*' })) {
	 * 	await redis.del(key);
	 * }
	 * ```
	 */
	scanIterator(opts?: RedisScanOptions): AsyncIterableIterator<string>;

	/**
	 * Gets a hash field as raw bytes.
	 *
	 * @param key - The hash key.
	 * @param field - The field to read.
	 * @returns The bytes, or null if the field or key does not exist.
	 */
	hget(key: string, field: string): Promise<Uint8Array | null>;
	/**
	 * Gets a hash field as UTF-8 text.
	 *
	 * @param key - The hash key.
	 * @param field - The field to read.
	 * @returns The value, or null if the field or key does not exist.
	 */
	hgetText(key: string, field: string): Promise<string | null>;
	/**
	 * Sets one or more hash fields.
	 *
	 * @param key - The hash key.
	 * @param entries - Field-to-value pairs to write.
	 * @returns How many fields were newly added.
	 */
	hset(key: string, entries: Record<string, RedisArg>): Promise<number>;
	/**
	 * Deletes hash fields.
	 *
	 * @param key - The hash key.
	 * @param fields - The fields to remove.
	 * @returns How many fields were removed.
	 */
	hdel(key: string, ...fields: string[]): Promise<number>;
	/**
	 * Reads a whole hash.
	 *
	 * Normalizes the RESP2 flat array and the RESP3 map into the same object.
	 *
	 * @param key - The hash key.
	 * @returns The fields as a string-to-string object; empty if the key does not exist.
	 */
	hgetall(key: string): Promise<Record<string, string>>;

	/**
	 * Prepends values to a list.
	 *
	 * @param key - The list key.
	 * @param values - The values to prepend.
	 * @returns The list's length afterwards.
	 */
	lpush(key: string, ...values: RedisArg[]): Promise<number>;
	/**
	 * Appends values to a list.
	 *
	 * @param key - The list key.
	 * @param values - The values to append.
	 * @returns The list's length afterwards.
	 */
	rpush(key: string, ...values: RedisArg[]): Promise<number>;
	/**
	 * Removes and returns the first element of a list.
	 *
	 * @param key - The list key.
	 * @returns The element as text, or null if the list is empty.
	 */
	lpop(key: string): Promise<string | null>;
	/**
	 * Removes and returns the last element of a list.
	 *
	 * @param key - The list key.
	 * @returns The element as text, or null if the list is empty.
	 */
	rpop(key: string): Promise<string | null>;
	/**
	 * Reads a range of a list.
	 *
	 * @param key - The list key.
	 * @param start - First index (0-based; negative counts from the end).
	 * @param stop - Last index, inclusive (`-1` for the final element).
	 * @returns The elements as text.
	 */
	lrange(key: string, start: number, stop: number): Promise<string[]>;
	/**
	 * Reads a list's length.
	 *
	 * @param key - The list key.
	 * @returns The number of elements; 0 if the key does not exist.
	 */
	llen(key: string): Promise<number>;

	/**
	 * Adds members to a set.
	 *
	 * @param key - The set key.
	 * @param members - The members to add.
	 * @returns How many members were newly added.
	 */
	sadd(key: string, ...members: RedisArg[]): Promise<number>;
	/**
	 * Removes members from a set.
	 *
	 * @param key - The set key.
	 * @param members - The members to remove.
	 * @returns How many members were removed.
	 */
	srem(key: string, ...members: RedisArg[]): Promise<number>;
	/**
	 * Reads every member of a set.
	 *
	 * @param key - The set key.
	 * @returns The members as text; empty if the key does not exist.
	 */
	smembers(key: string): Promise<string[]>;
	/**
	 * Tests set membership.
	 *
	 * @param key - The set key.
	 * @param member - The member to test.
	 * @returns True if the member is in the set.
	 */
	sismember(key: string, member: RedisArg): Promise<boolean>;

	/**
	 * Adds scored members to a sorted set.
	 *
	 * @param key - The sorted-set key.
	 * @param entries - Member-to-score pairs.
	 * @returns How many members were newly added.
	 */
	zadd(key: string, entries: Record<string, number>): Promise<number>;
	/**
	 * Removes members from a sorted set.
	 *
	 * @param key - The sorted-set key.
	 * @param members - The members to remove.
	 * @returns How many members were removed.
	 */
	zrem(key: string, ...members: RedisArg[]): Promise<number>;
	/**
	 * Reads a range of a sorted set by rank.
	 *
	 * @param key - The sorted-set key.
	 * @param start - First rank (0-based; negative counts from the end).
	 * @param stop - Last rank, inclusive (`-1` for the last member).
	 * @param opts - Pass `rev` to order from highest score to lowest.
	 * @returns The members as text, in score order.
	 */
	zrange(key: string, start: number, stop: number, opts?: { rev?: boolean }): Promise<string[]>;
	/**
	 * Reads a range of a sorted set by rank, with each member's score.
	 *
	 * Normalizes the RESP2 flat array and the RESP3 member-score pairs into the same shape.
	 *
	 * @param key - The sorted-set key.
	 * @param start - First rank (0-based; negative counts from the end).
	 * @param stop - Last rank, inclusive (`-1` for the last member).
	 * @param opts - Pass `rev` to order from highest score to lowest.
	 * @returns The members with their scores, in score order.
	 */
	zrangeWithScores(
		key: string,
		start: number,
		stop: number,
		opts?: { rev?: boolean }
	): Promise<RedisScoreEntry[]>;

	/**
	 * Runs a Lua script on the server.
	 *
	 * @param script - The script source.
	 * @param opts - The script's `KEYS` and `ARGV`.
	 * @returns The script's reply.
	 * @throws {ProtocolError} If the script raises an error.
	 */
	eval(script: string, opts?: RedisEvalOptions): Promise<RedisReply>;
	/**
	 * Runs a Lua script the server has already cached, by its SHA1.
	 *
	 * @param sha - The script's SHA1, as returned by `SCRIPT LOAD`.
	 * @param opts - The script's `KEYS` and `ARGV`.
	 * @returns The script's reply.
	 * @throws {ProtocolError} If the script is not cached (`NOSCRIPT`) or raises an error.
	 */
	evalSha(sha: string, opts?: RedisEvalOptions): Promise<RedisReply>;

	/**
	 * Publishes a message to a channel.
	 *
	 * @param channel - The channel to publish to.
	 * @param message - The payload (a string is UTF-8 encoded).
	 * @returns How many subscribers received it.
	 */
	publish(channel: string, message: RedisArg): Promise<number>;
	/**
	 * Publishes a value as JSON to a channel.
	 *
	 * @param channel - The channel to publish to.
	 * @param value - The value to serialize and publish.
	 * @returns How many subscribers received it.
	 */
	publishJson(channel: string, value: unknown): Promise<number>;
	/**
	 * Subscribes to one or more channels.
	 *
	 * Resolves once the server has confirmed every channel, so a publish issued afterwards is
	 * guaranteed to be delivered. On a `protocol: 2` connection this puts the socket into
	 * subscriber mode, where Redis rejects ordinary commands until every subscription is
	 * released; `protocol: 3` has no such restriction.
	 *
	 * @param channels - The channels to subscribe to.
	 * @returns The subscription.
	 * @throws {ProtocolError} If no channels are given.
	 */
	subscribe(...channels: string[]): Promise<RedisSubscription>;
	/**
	 * Subscribes to one or more glob-style channel patterns.
	 *
	 * @param patterns - The patterns to subscribe to, e.g. `'news.*'`.
	 * @returns The subscription; each delivery carries the matched `pattern`.
	 * @throws {ProtocolError} If no patterns are given.
	 */
	psubscribe(...patterns: string[]): Promise<RedisSubscription>;

	/**
	 * Pings the server.
	 *
	 * @param message - Optional payload the server echoes back.
	 * @returns `'PONG'`, or the echoed message.
	 */
	ping(message?: string): Promise<string>;
	/**
	 * Switches the connection to another database index.
	 *
	 * @param db - The database index.
	 * @returns Resolves once the server confirms.
	 */
	select(db: number): Promise<void>;
	/**
	 * Reads the server's `INFO` report, parsed into fields.
	 *
	 * @param section - Optional section to limit the report to, e.g. `'memory'`.
	 * @returns The report's `key:value` lines as an object (section headers are dropped).
	 */
	info(section?: string): Promise<Record<string, string>>;
	/**
	 * Closes the connection and ends every subscription.
	 *
	 * @returns Resolves once the socket is closed.
	 */
	close(): Promise<void>;
}

// a single-consumer push/pull queue backing one subscription's async iterator
class MessageQueue {
	#queue: RedisMessage[] = [];
	#waiters: ((r: IteratorResult<RedisMessage>) => void)[] = [];
	#done = false;

	push(msg: RedisMessage): void {
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

	next(): Promise<IteratorResult<RedisMessage>> {
		const msg = this.#queue.shift();
		if (msg) return Promise.resolve({ value: msg, done: false });
		if (this.#done) return Promise.resolve({ value: undefined, done: true });
		return new Promise((resolve) => this.#waiters.push(resolve));
	}
}

class Subscription implements RedisSubscription {
	readonly channels: readonly string[];
	readonly pattern: boolean;
	readonly #queue = new MessageQueue();
	readonly #onUnsub: (sub: Subscription) => Promise<void>;

	constructor(
		channels: readonly string[],
		pattern: boolean,
		onUnsub: (sub: Subscription) => Promise<void>
	) {
		this.channels = channels;
		this.pattern = pattern;
		this.#onUnsub = onUnsub;
	}

	deliver(msg: RedisMessage): void {
		this.#queue.push(msg);
	}

	// pump-side close: ends the iterator without writing UNSUBSCRIBE (socket is gone)
	stop(): void {
		this.#queue.end();
	}

	async unsubscribe(): Promise<void> {
		await this.#onUnsub(this);
		this.#queue.end();
	}

	[Symbol.asyncIterator](): AsyncIterator<RedisMessage> {
		return { next: () => this.#queue.next() };
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.unsubscribe();
	}
}

interface Pending {
	resolve(reply: RedisReply): void;
	reject(err: Error): void;
}

class RedisSessionImpl implements RedisSession {
	readonly protocol: 2 | 3;
	readonly serverInfo: Record<string, RedisNative> | undefined;
	readonly #socket: CoreSocket;
	readonly #reader: FramedReader;
	readonly #writer: FramedWriter;
	readonly #pending: Pending[] = [];
	readonly #channelSubs = new Map<string, Set<Subscription>>();
	readonly #patternSubs = new Map<string, Set<Subscription>>();
	// server-reported channel+pattern count, and how many confirmations are still in flight;
	// together they tell the pump when a RESP2 array may be a pubsub frame rather than a reply
	#subscribed = 0;
	#confirmsInFlight = 0;
	#closed = false;
	#pumpError: Error | null = null;

	constructor(
		socket: CoreSocket,
		protocol: 2 | 3,
		serverInfo: Record<string, RedisNative> | undefined
	) {
		this.#socket = socket;
		this.#reader = socket.reader;
		this.#writer = socket.writer;
		this.protocol = protocol;
		this.serverInfo = serverInfo;
	}

	get subscriptionCount(): number {
		return this.#subscribed;
	}

	// #region pump

	startPump(): void {
		void this.#pump();
	}

	async #pump(): Promise<void> {
		try {
			for (;;) this.#route(await readReply(this.#reader));
		} catch (err) {
			if (!this.#closed) this.#pumpError = err as Error;
		} finally {
			const reason =
				this.#pumpError ?? new ConnectionError('redis connection closed', { protocol: PROTO });
			const pending = this.#pending.splice(0, this.#pending.length);
			for (const p of pending) p.reject(reason);
			this.#endSubscriptions();
		}
	}

	// hands a frame to the subscriptions it belongs to, or to the next waiting command
	#route(value: RespValue): void {
		const kind = this.#pubsubKind(value);
		if (kind !== null) {
			const elements = (value as { value: RespValue[] }).value;
			if (MESSAGE_KINDS.has(kind)) {
				this.#deliver(kind, elements);
				return;
			}
			// a subscribe/unsubscribe confirmation: authoritative count, and the command's reply
			this.#subscribed = replyToNumber(elements[elements.length - 1]);
			if (this.#confirmsInFlight > 0) this.#confirmsInFlight--;
			this.#pending.shift()?.resolve(makeReply(value));
			return;
		}
		// an unrecognized RESP3 push (e.g. client-side-caching invalidation) is out-of-band and
		// must not be handed to a waiting command
		if (value.kind === 'push') return;
		this.#pending.shift()?.resolve(makeReply(value));
	}

	// the pubsub kind of a frame, or null when it is an ordinary reply. RESP3 marks pubsub with
	// the push type; RESP2 reuses arrays, which are only ambiguous outside subscriber mode - and
	// there Redis refuses every command that could return one.
	#pubsubKind(value: RespValue): string | null {
		if (value.kind !== 'push' && value.kind !== 'array') return null;
		if (value.kind === 'array' && this.#subscribed === 0 && this.#confirmsInFlight === 0) {
			return null;
		}
		const first = value.value[0];
		if (value.value.length < 3 || first === undefined) return null;
		const kind =
			first.kind === 'bulk'
				? decoder.decode(first.value)
				: first.kind === 'string'
					? first.value
					: null;
		if (kind === null) return null;
		return MESSAGE_KINDS.has(kind) || CONFIRM_KINDS.has(kind) ? kind : null;
	}

	// message: [kind, channel, payload]; pmessage: [kind, pattern, channel, payload]
	#deliver(kind: string, elements: RespValue[]): void {
		const patterned = kind === 'pmessage';
		const pattern = patterned ? replyToText(elements[1]) : undefined;
		const channel = replyToText(elements[patterned ? 2 : 1]);
		const payload = replyToBytes(elements[patterned ? 3 : 2]);
		const targets = patterned ? this.#patternSubs.get(pattern!) : this.#channelSubs.get(channel);
		if (!targets) return;
		const msg: RedisMessage = {
			channel,
			pattern,
			payload,
			text: () => decoder.decode(payload),
			json: <T = unknown>(): T => {
				try {
					return JSON.parse(decoder.decode(payload)) as T;
				} catch (cause) {
					throw new ProtocolError('redis message payload is not valid json', {
						protocol: PROTO,
						cause
					});
				}
			}
		};
		for (const sub of targets) sub.deliver(msg);
	}

	#endSubscriptions(): void {
		for (const set of [...this.#channelSubs.values(), ...this.#patternSubs.values()]) {
			for (const sub of set) sub.stop();
		}
		this.#channelSubs.clear();
		this.#patternSubs.clear();
	}

	// #endregion

	// #region command plumbing

	#assertOpen(): void {
		if (this.#closed) throw new ConnectionError('redis connection is closed', { protocol: PROTO });
		if (this.#pumpError) throw this.#pumpError;
	}

	// RESP2 locks a subscribed connection down to the pubsub verbs; fail with a clear message
	// rather than letting the server reject the command
	#assertAllowed(commands: readonly (readonly RedisArg[])[]): void {
		if (this.protocol !== 2 || this.#subscribed === 0) return;
		for (const args of commands) {
			const name = String(args[0] ?? '').toUpperCase();
			if (!SUBSCRIBER_ALLOWED.has(name)) {
				throw new ProtocolError(
					`${name} is not allowed while a RESP2 connection is subscribed; unsubscribe first or connect with protocol: 3`,
					{ protocol: PROTO }
				);
			}
		}
	}

	// writes a frame and awaits the `count` replies it will produce. the waiters are queued
	// synchronously before the write is issued, so concurrent callers stay correlated in order.
	async #exchange(frame: Uint8Array, count: number): Promise<RedisReply[]> {
		const waiters: Pending[] = [];
		const replies: Promise<RedisReply>[] = [];
		for (let i = 0; i < count; i++) {
			replies.push(
				new Promise<RedisReply>((resolve, reject) => {
					const waiter = { resolve, reject };
					waiters.push(waiter);
					this.#pending.push(waiter);
				})
			);
		}
		const all = Promise.all(replies);
		try {
			await this.#writer.write(frame);
		} catch (cause) {
			const err = new ConnectionError('failed to write redis command', { protocol: PROTO, cause });
			for (const waiter of waiters) {
				const at = this.#pending.indexOf(waiter);
				if (at >= 0) this.#pending.splice(at, 1);
				waiter.reject(err);
			}
			void all.catch(() => {});
			throw err;
		}
		return all;
	}

	async send(...args: RedisArg[]): Promise<RedisReply> {
		this.#assertOpen();
		this.#assertAllowed([args]);
		const [reply] = await this.#exchange(encodeCommand(args), 1);
		if (reply!.error !== undefined) throw replyError(reply!.error);
		return reply!;
	}

	async pipeline(commands: readonly (readonly RedisArg[])[]): Promise<RedisReply[]> {
		this.#assertOpen();
		this.#assertAllowed(commands);
		if (commands.length === 0) return [];
		return await this.#exchange(encodeCommands(commands), commands.length);
	}

	async multi(commands: readonly (readonly RedisArg[])[]): Promise<RedisReply[]> {
		this.#assertOpen();
		this.#assertAllowed(commands);
		if (commands.length === 0) return [];
		const frame = encodeCommands([['MULTI'], ...commands, ['EXEC']]);
		const replies = await this.#exchange(frame, commands.length + 2);
		const exec = replies[replies.length - 1]!;
		if (exec.error !== undefined) throw replyError(exec.error);
		if (exec.isNull) {
			throw new ProtocolError('redis transaction was discarded', { protocol: PROTO });
		}
		return exec.items();
	}

	// #endregion

	// #region strings and keys

	async get(key: string): Promise<Uint8Array | null> {
		const reply = await this.send('GET', key);
		return reply.isNull ? null : reply.bytes();
	}

	async getText(key: string): Promise<string | null> {
		const reply = await this.send('GET', key);
		return reply.isNull ? null : reply.text();
	}

	async set(key: string, value: RedisArg, opts: RedisSetOptions = {}): Promise<boolean> {
		const args: RedisArg[] = ['SET', key, value];
		if (opts.ex !== undefined) args.push('EX', opts.ex);
		if (opts.px !== undefined) args.push('PX', opts.px);
		if (opts.exat !== undefined) args.push('EXAT', opts.exat);
		if (opts.pxat !== undefined) args.push('PXAT', opts.pxat);
		if (opts.keepTtl) args.push('KEEPTTL');
		if (opts.nx) args.push('NX');
		if (opts.xx) args.push('XX');
		const reply = await this.send(...args);
		return !reply.isNull;
	}

	async del(...keys: string[]): Promise<number> {
		return (await this.send('DEL', ...keys)).number();
	}

	async exists(...keys: string[]): Promise<number> {
		return (await this.send('EXISTS', ...keys)).number();
	}

	async mget(keys: readonly string[]): Promise<(string | null)[]> {
		const reply = await this.send('MGET', ...keys);
		return reply.items().map((r) => (r.isNull ? null : r.text()));
	}

	async mset(entries: Record<string, RedisArg>): Promise<void> {
		await this.send('MSET', ...Object.entries(entries).flat());
	}

	async incr(key: string): Promise<number> {
		return (await this.send('INCR', key)).number();
	}

	async incrBy(key: string, by: number): Promise<number> {
		return (await this.send('INCRBY', key, by)).number();
	}

	async decr(key: string): Promise<number> {
		return (await this.send('DECR', key)).number();
	}

	async expire(key: string, seconds: number): Promise<boolean> {
		return (await this.send('EXPIRE', key, seconds)).boolean();
	}

	async ttl(key: string): Promise<number> {
		return (await this.send('TTL', key)).number();
	}

	async keys(pattern: string): Promise<string[]> {
		return (await this.send('KEYS', pattern)).strings();
	}

	async scan(opts: RedisScanOptions & { cursor?: string } = {}): Promise<RedisScanPage> {
		const args: RedisArg[] = ['SCAN', opts.cursor ?? '0'];
		if (opts.match !== undefined) args.push('MATCH', opts.match);
		if (opts.count !== undefined) args.push('COUNT', opts.count);
		if (opts.type !== undefined) args.push('TYPE', opts.type);
		const [cursor, keys] = (await this.send(...args)).items();
		return { cursor: cursor!.text(), keys: keys!.strings() };
	}

	async *scanIterator(opts: RedisScanOptions = {}): AsyncIterableIterator<string> {
		let cursor = '0';
		do {
			const page = await this.scan({ ...opts, cursor });
			yield* page.keys;
			cursor = page.cursor;
		} while (cursor !== '0');
	}

	// #endregion

	// #region hashes

	async hget(key: string, field: string): Promise<Uint8Array | null> {
		const reply = await this.send('HGET', key, field);
		return reply.isNull ? null : reply.bytes();
	}

	async hgetText(key: string, field: string): Promise<string | null> {
		const reply = await this.send('HGET', key, field);
		return reply.isNull ? null : reply.text();
	}

	async hset(key: string, entries: Record<string, RedisArg>): Promise<number> {
		return (await this.send('HSET', key, ...Object.entries(entries).flat())).number();
	}

	async hdel(key: string, ...fields: string[]): Promise<number> {
		return (await this.send('HDEL', key, ...fields)).number();
	}

	async hgetall(key: string): Promise<Record<string, string>> {
		return (await this.send('HGETALL', key)).map();
	}

	// #endregion

	// #region lists

	async lpush(key: string, ...values: RedisArg[]): Promise<number> {
		return (await this.send('LPUSH', key, ...values)).number();
	}

	async rpush(key: string, ...values: RedisArg[]): Promise<number> {
		return (await this.send('RPUSH', key, ...values)).number();
	}

	async lpop(key: string): Promise<string | null> {
		const reply = await this.send('LPOP', key);
		return reply.isNull ? null : reply.text();
	}

	async rpop(key: string): Promise<string | null> {
		const reply = await this.send('RPOP', key);
		return reply.isNull ? null : reply.text();
	}

	async lrange(key: string, start: number, stop: number): Promise<string[]> {
		return (await this.send('LRANGE', key, start, stop)).strings();
	}

	async llen(key: string): Promise<number> {
		return (await this.send('LLEN', key)).number();
	}

	// #endregion

	// #region sets

	async sadd(key: string, ...members: RedisArg[]): Promise<number> {
		return (await this.send('SADD', key, ...members)).number();
	}

	async srem(key: string, ...members: RedisArg[]): Promise<number> {
		return (await this.send('SREM', key, ...members)).number();
	}

	async smembers(key: string): Promise<string[]> {
		return (await this.send('SMEMBERS', key)).strings();
	}

	async sismember(key: string, member: RedisArg): Promise<boolean> {
		return (await this.send('SISMEMBER', key, member)).boolean();
	}

	// #endregion

	// #region sorted sets

	async zadd(key: string, entries: Record<string, number>): Promise<number> {
		const args: RedisArg[] = ['ZADD', key];
		for (const [member, score] of Object.entries(entries)) args.push(score, member);
		return (await this.send(...args)).number();
	}

	async zrem(key: string, ...members: RedisArg[]): Promise<number> {
		return (await this.send('ZREM', key, ...members)).number();
	}

	async zrange(
		key: string,
		start: number,
		stop: number,
		opts: { rev?: boolean } = {}
	): Promise<string[]> {
		const args: RedisArg[] = ['ZRANGE', key, start, stop];
		if (opts.rev) args.push('REV');
		return (await this.send(...args)).strings();
	}

	async zrangeWithScores(
		key: string,
		start: number,
		stop: number,
		opts: { rev?: boolean } = {}
	): Promise<RedisScoreEntry[]> {
		const args: RedisArg[] = ['ZRANGE', key, start, stop];
		if (opts.rev) args.push('REV');
		args.push('WITHSCORES');
		const items = (await this.send(...args)).items();
		// RESP3 pairs each member with its score; RESP2 returns one flat member/score list
		if (items.length > 0 && isAggregateKind(items[0]!.raw.kind)) {
			return items.map((pair) => {
				const [member, score] = pair.items();
				return { member: member!.text(), score: score!.number() };
			});
		}
		const out: RedisScoreEntry[] = [];
		for (let i = 0; i + 1 < items.length; i += 2) {
			out.push({ member: items[i]!.text(), score: items[i + 1]!.number() });
		}
		return out;
	}

	// #endregion

	// #region scripting

	eval(script: string, opts: RedisEvalOptions = {}): Promise<RedisReply> {
		return this.send('EVAL', script, ...evalArgs(opts));
	}

	evalSha(sha: string, opts: RedisEvalOptions = {}): Promise<RedisReply> {
		return this.send('EVALSHA', sha, ...evalArgs(opts));
	}

	// #endregion

	// #region pub/sub

	async publish(channel: string, message: RedisArg): Promise<number> {
		return (await this.send('PUBLISH', channel, message)).number();
	}

	publishJson(channel: string, value: unknown): Promise<number> {
		return this.publish(channel, JSON.stringify(value));
	}

	subscribe(...channels: string[]): Promise<RedisSubscription> {
		return this.#addSubscription(channels, false);
	}

	psubscribe(...patterns: string[]): Promise<RedisSubscription> {
		return this.#addSubscription(patterns, true);
	}

	async #addSubscription(names: string[], pattern: boolean): Promise<RedisSubscription> {
		this.#assertOpen();
		if (names.length === 0) {
			throw new ProtocolError('subscribe needs at least one channel', { protocol: PROTO });
		}
		const registry = pattern ? this.#patternSubs : this.#channelSubs;
		const sub = new Subscription(names, pattern, (s) => this.#removeSubscription(s));
		for (const name of names) {
			const set = registry.get(name) ?? new Set<Subscription>();
			set.add(sub);
			registry.set(name, set);
		}
		try {
			// one confirmation per channel, so the pump must expect that many replies
			this.#confirmsInFlight += names.length;
			const frame = encodeCommand([pattern ? 'PSUBSCRIBE' : 'SUBSCRIBE', ...names]);
			const replies = await this.#exchange(frame, names.length);
			for (const reply of replies) {
				if (reply.error !== undefined) throw replyError(reply.error);
			}
		} catch (err) {
			this.#detach(sub, registry);
			sub.stop();
			throw err;
		}
		return sub;
	}

	// unsubscribes only the names no other subscription still holds
	async #removeSubscription(sub: Subscription): Promise<void> {
		const registry = sub.pattern ? this.#patternSubs : this.#channelSubs;
		const orphaned = this.#detach(sub, registry);
		if (orphaned.length === 0 || this.#closed || this.#pumpError) return;
		this.#confirmsInFlight += orphaned.length;
		const frame = encodeCommand([sub.pattern ? 'PUNSUBSCRIBE' : 'UNSUBSCRIBE', ...orphaned]);
		await this.#exchange(frame, orphaned.length);
	}

	// drops sub from the registry, returning the names left with no subscribers
	#detach(sub: Subscription, registry: Map<string, Set<Subscription>>): string[] {
		const orphaned: string[] = [];
		for (const name of sub.channels) {
			const set = registry.get(name);
			if (!set) continue;
			set.delete(sub);
			if (set.size === 0) {
				registry.delete(name);
				orphaned.push(name);
			}
		}
		return orphaned;
	}

	// #endregion

	// #region connection

	async ping(message?: string): Promise<string> {
		const reply =
			message === undefined ? await this.send('PING') : await this.send('PING', message);
		// a RESP2 subscriber-mode PING answers ['pong', payload] instead of +PONG, and the payload
		// is empty when no message was sent - normalize that back to PONG
		if (reply.raw.kind !== 'array') return reply.text();
		const echoed = reply.strings()[1];
		return message === undefined ? 'PONG' : (echoed ?? '');
	}

	async select(db: number): Promise<void> {
		await this.send('SELECT', db);
	}

	async info(section?: string): Promise<Record<string, string>> {
		const reply =
			section === undefined ? await this.send('INFO') : await this.send('INFO', section);
		return parseInfo(reply.text());
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		this.#endSubscriptions();
		await this.#socket.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}

	// #endregion
}

function isAggregateKind(kind: RespValue['kind']): boolean {
	return kind === 'array' || kind === 'set' || kind === 'push';
}

function evalArgs(opts: RedisEvalOptions): RedisArg[] {
	const keys = opts.keys ?? [];
	return [keys.length, ...keys, ...(opts.args ?? [])];
}

// INFO is a text report of `# Section` headers and key:value lines
function parseInfo(text: string): Record<string, string> {
	const out: Record<string, string> = {};
	for (const line of text.split('\n')) {
		const trimmed = line.trim();
		if (trimmed === '' || trimmed.startsWith('#')) continue;
		const at = trimmed.indexOf(':');
		if (at > 0) out[trimmed.slice(0, at)] = trimmed.slice(at + 1);
	}
	return out;
}

// minimal readers for pubsub frame elements, which are always bulk strings or integers
function replyToText(value: RespValue | undefined): string {
	if (value === undefined) return '';
	if (value.kind === 'bulk' || value.kind === 'verbatim') return decoder.decode(value.value);
	if (value.kind === 'string') return value.value;
	return String(respToNative(value));
}

function replyToBytes(value: RespValue | undefined): Uint8Array {
	if (value === undefined) return new Uint8Array(0);
	if (value.kind === 'bulk' || value.kind === 'verbatim') return value.value;
	return new TextEncoder().encode(replyToText(value));
}

function replyToNumber(value: RespValue | undefined): number {
	if (value === undefined) return 0;
	if (value.kind === 'number' || value.kind === 'double') return value.value;
	const n = Number(replyToText(value));
	return Number.isNaN(n) ? 0 : n;
}

// maps a server error reply onto edgeport's vocabulary by its error prefix
function replyError(message: string): EdgeportError {
	const code = (message.split(' ', 1)[0] ?? '').toUpperCase();
	const authFailure =
		code === 'NOAUTH' ||
		code === 'WRONGPASS' ||
		code === 'NOPERM' ||
		/invalid password|no password is set|without any password/i.test(message);
	return authFailure
		? new AuthError(`redis auth rejected: ${message}`, { protocol: PROTO })
		: new ProtocolError(`redis error reply: ${message}`, { protocol: PROTO });
}

// runs one handshake command directly against the socket, before the pump owns the reader
async function exchangeBeforePump(
	socket: CoreSocket,
	args: readonly RedisArg[],
	timeoutMs: number | undefined
): Promise<RedisReply> {
	await socket.writer.write(encodeCommand(args));
	return makeReply(await readReply(socket.reader, timeoutMs));
}

/**
 * Connects to a Redis server, authenticates, and returns a live session.
 *
 * Dials the core transport, runs the handshake for the requested protocol version (`HELLO 3` for
 * `protocol: 3`, otherwise `AUTH`), optionally selects a database, then starts the background
 * pump that routes replies and Pub/Sub deliveries.
 *
 * @param opts - Connection and credential options.
 * @returns The live session.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the server cannot speak the requested protocol version.
 * @throws {TimeoutError} If the handshake exceeds the deadline.
 * @since 1.0.6
 * @example
 * ```typescript
 * import { connect } from 'edgeport/redis';
 *
 * await using redis = await connect({ hostname: 'redis.example.com', password: env.REDIS_PASSWORD });
 * await redis.set('visits', 0);
 * const visits = await redis.incr('visits');
 * const greeting = await redis.getText('greeting');
 * ```
 */
export async function connect(opts: RedisConnectOptions): Promise<RedisSession> {
	const socket = await coreConnect({
		hostname: opts.hostname,
		port: opts.port ?? DEFAULT_REDIS_PORT,
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
 * Runs the Redis handshake and read pump over an already-connected {@link CoreSocket}.
 *
 * Public {@link connect} dials the transport then calls this; tests call it directly with a mock
 * socket.
 *
 * @param socket - A connected core socket (already TLS when `tls: 'implicit'`).
 * @param opts - Connection and credential options.
 * @returns The live session.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ProtocolError} If the server cannot speak the requested protocol version.
 * @throws {TimeoutError} If the handshake exceeds the deadline.
 * @internal
 */
export async function _connectOverSocket(
	socket: CoreSocket,
	opts: RedisConnectOptions
): Promise<RedisSession> {
	const protocol = opts.protocol ?? 2;
	let serverInfo: Record<string, RedisNative> | undefined;

	if (protocol === 3) {
		const args: RedisArg[] = ['HELLO', '3'];
		if (opts.password !== undefined) {
			args.push('AUTH', opts.username ?? 'default', opts.password);
		}
		if (opts.clientName !== undefined) args.push('SETNAME', opts.clientName);
		const hello = await exchangeBeforePump(socket, args, opts.timeoutMs);
		if (hello.error !== undefined) {
			const code = (hello.error.split(' ', 1)[0] ?? '').toUpperCase();
			if (code === 'NOPROTO' || /unknown command/i.test(hello.error)) {
				throw new ProtocolError(
					`server does not support RESP3 (${hello.error}); connect with protocol: 2`,
					{ protocol: PROTO }
				);
			}
			throw replyError(hello.error);
		}
		const native = hello.value;
		serverInfo =
			typeof native === 'object' && native !== null && !Array.isArray(native)
				? (native as Record<string, RedisNative>)
				: undefined;
	} else {
		if (opts.password !== undefined) {
			const args: RedisArg[] =
				opts.username !== undefined
					? ['AUTH', opts.username, opts.password]
					: ['AUTH', opts.password];
			const auth = await exchangeBeforePump(socket, args, opts.timeoutMs);
			if (auth.error !== undefined) throw replyError(auth.error);
		}
		if (opts.clientName !== undefined) {
			const named = await exchangeBeforePump(
				socket,
				['CLIENT', 'SETNAME', opts.clientName],
				opts.timeoutMs
			);
			if (named.error !== undefined) throw replyError(named.error);
		}
	}

	if (opts.db !== undefined) {
		const selected = await exchangeBeforePump(socket, ['SELECT', opts.db], opts.timeoutMs);
		if (selected.error !== undefined) throw replyError(selected.error);
	}

	const session = new RedisSessionImpl(socket, protocol, serverInfo);
	session.startPump();
	return session;
}

/** Options for the {@link command} one-shot. */
export interface RedisCommandOptions extends RedisConnectOptions {
	/** The command name followed by its arguments. */
	args: RedisArg[];
}

/**
 * Connects, runs a single command, and closes.
 *
 * The one-shot for a Worker that touches Redis once per request. Use {@link connect} when several
 * commands share a connection.
 *
 * @param opts - Connection options plus the command to run.
 * @returns The command's reply.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the server replies with an error.
 * @since 1.0.6
 * @example
 * ```typescript
 * import { command } from 'edgeport/redis';
 *
 * const reply = await command({
 * 	hostname: 'redis.example.com',
 * 	password: env.REDIS_PASSWORD,
 * 	args: ['GET', 'feature:flags']
 * });
 * const flags = reply.isNull ? {} : reply.json<Record<string, boolean>>();
 * ```
 */
export async function command(opts: RedisCommandOptions): Promise<RedisReply> {
	await using session = await connect(opts);
	return await session.send(...opts.args);
}

/** Options for the {@link publish} one-shot. */
export interface RedisPublishOptions extends RedisConnectOptions {
	/** The channel to publish to. */
	channel: string;
	/** The payload (a string is UTF-8 encoded). */
	message: RedisArg;
}

/**
 * Connects, publishes one message to a channel, and closes.
 *
 * @param opts - Connection options plus the channel and payload.
 * @returns How many subscribers received the message.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @since 1.0.6
 * @example
 * ```typescript
 * import { publish } from 'edgeport/redis';
 *
 * await publish({
 * 	hostname: 'redis.example.com',
 * 	channel: 'deploys',
 * 	message: JSON.stringify({ sha: '9f2c1ab', env: 'production' })
 * });
 * ```
 */
export async function publish(opts: RedisPublishOptions): Promise<number> {
	await using session = await connect(opts);
	return await session.publish(opts.channel, opts.message);
}
