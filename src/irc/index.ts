/**
 * @fileoverview An IRC client (RFC 1459 / 2812 with IRCv3 extensions) for the Cloudflare
 * Workers runtime.
 *
 * IRC is a CRLF line protocol: the client registers with `NICK` + `USER` (optionally a `PASS`
 * or an IRCv3 CAP + SASL exchange), then trades commands and numeric replies with the server.
 * This module runs that registration handshake, then drives a background read pump that answers
 * server `PING`s automatically, routes `PRIVMSG`/`NOTICE` (with CTCP parsing) to {@link
 * IrcSession.messages}, surfaces everything else (JOIN/PART/QUIT/NICK/KICK/MODE/TOPIC and
 * numerics) through {@link IrcSession.events}, and resolves the request/reply helpers
 * ({@link IrcSession.names}, {@link IrcSession.topic}, {@link IrcSession.whois}). It builds on
 * the shared core transport and never touches the runtime socket API directly.
 *
 * TLS is implicit-only (`tls: 'implicit'`, port 6697); IRC has no in-band STARTTLS worth
 * supporting for a Workers client. Plaintext is port 6667.
 *
 * @author Gregory Mitchell
 * @since 1.0.4
 */
import {
	AuthError,
	ConnectionError,
	connect as coreConnect,
	ProtocolError,
	TimeoutError,
	type CoreSocket,
	type FramedReader,
	type FramedWriter
} from '../core';
import { toBase64 } from '../util';
import {
	ERR_ERRONEUSNICKNAME,
	ERR_NICKCOLLISION,
	ERR_NICKNAMEINUSE,
	ERR_PASSWDMISMATCH,
	ERR_SASLABORTED,
	ERR_SASLFAIL,
	ERR_SASLTOOLONG,
	ERR_YOUREBANNEDCREEP,
	formatMessage,
	isChannelName,
	parseCtcp,
	parseMessage,
	RPL_ENDOFNAMES,
	RPL_ENDOFWHOIS,
	RPL_LOGGEDIN,
	RPL_NAMREPLY,
	RPL_NOTOPIC,
	RPL_SASLSUCCESS,
	RPL_TOPIC,
	RPL_WELCOME,
	RPL_WHOISACCOUNT,
	RPL_WHOISCHANNELS,
	RPL_WHOISIDLE,
	RPL_WHOISOPERATOR,
	RPL_WHOISSERVER,
	RPL_WHOISUSER,
	type IrcMessage,
	type IrcPrefix
} from './message';

export * from './message';

const PROTO = 'irc';
const DEFAULT_PORT = 6667;
const DEFAULT_TLS_PORT = 6697;
const DEFAULT_TIMEOUT_MS = 15_000;
// keep each PRIVMSG/NOTICE payload well under the 512-byte line limit (prefix + CRLF overhead)
const MAX_LINE_PAYLOAD = 400;

const decoder = new TextDecoder();
const encoder = new TextEncoder();

// membership-prefix characters NAMES may put in front of a nick (op/halfop/voice/owner/admin)
const MEMBERSHIP_PREFIXES = '~&@%+';

/**
 * SASL credentials for the IRCv3 CAP + SASL exchange.
 *
 * @since 1.0.4
 */
export interface IrcSasl {
	/** The account (authcid) to authenticate as. */
	user: string;
	/** The account password. */
	password: string;
	/** The SASL mechanism; only `'PLAIN'` is implemented (the default). */
	mechanism?: 'PLAIN';
}

/**
 * Options for {@link connect}.
 *
 * @since 1.0.4
 */
export interface IrcConnectOptions {
	/** IRC server host to dial (also the TLS certificate identity). */
	hostname: string;
	/** TCP port; defaults to 6667 (plaintext) or 6697 (`tls: 'implicit'`). */
	port?: number;
	/** Transport security: `'off'` (default) plaintext, or `'implicit'` TLS (IRCS). */
	tls?: 'off' | 'implicit';
	/** The nickname to register. */
	nick: string;
	/** The `USER` ident; defaults to {@link nick}. */
	username?: string;
	/** The `USER` realname (gecos); defaults to {@link nick}. */
	realname?: string;
	/** Server password sent via `PASS` before registration, when provided. */
	password?: string;
	/** SASL credentials; triggers the IRCv3 CAP + SASL exchange before registration. */
	sasl?: IrcSasl;
	/** Extra IRCv3 capabilities to request (only those the server offers are `CAP REQ`-ed). */
	caps?: string[];
	/** Per-read deadline in milliseconds for the registration handshake. */
	timeoutMs?: number;
	/** Automatically rejoin a channel when the server `KICK`s us from it. */
	autoRejoin?: boolean;
}

/**
 * A message delivered to {@link IrcSession.messages}: a `PRIVMSG` or `NOTICE`.
 *
 * @since 1.0.4
 */
export interface IrcChatMessage {
	/** The sender's nick (or the raw prefix when it is a servername). */
	from: string;
	/** The message target: a channel name or (for a direct message) our own nick. */
	target: string;
	/** The message text (the CTCP delimiters are stripped when {@link ctcp} is set). */
	text: string;
	/** Whether this was a `PRIVMSG` or a `NOTICE`. */
	type: 'privmsg' | 'notice';
	/** Whether {@link target} is a channel (vs a direct message to us). */
	isChannel: boolean;
	/** IRCv3 message tags (e.g. `time` from server-time); empty when none were sent. */
	tags: Record<string, string>;
	/** The parsed CTCP command/args when the body was CTCP-wrapped (e.g. an `ACTION`). */
	ctcp?: { command: string; args: string };
	/** The underlying parsed message element, for access to the raw prefix/params. */
	element?: IrcMessage;
}

/**
 * An event delivered to {@link IrcSession.events}: anything not routed to
 * {@link IrcSession.messages} (JOIN/PART/QUIT/NICK/KICK/MODE/TOPIC and every numeric reply).
 *
 * @since 1.0.4
 */
export interface IrcEvent {
	/** The command or numeric (uppercased for verbs). */
	command: string;
	/** The parsed source prefix, when the line carried one. */
	prefix?: IrcPrefix;
	/** The positional parameters. */
	params: string[];
	/** IRCv3 message tags; empty when none were sent. */
	tags: Record<string, string>;
	/** The verbatim line as received (without the CRLF). */
	raw: string;
}

/**
 * The structured result of a {@link IrcSession.whois}.
 *
 * @since 1.0.4
 */
export interface IrcWhois {
	/** The queried nick. */
	nick: string;
	/** The ident/user part (RPL_WHOISUSER). */
	user?: string;
	/** The host (RPL_WHOISUSER). */
	host?: string;
	/** The realname / gecos (RPL_WHOISUSER). */
	realname?: string;
	/** The server the user is on (RPL_WHOISSERVER). */
	server?: string;
	/** The server's descriptive info line (RPL_WHOISSERVER). */
	serverInfo?: string;
	/** The channels the user is on, with membership prefixes stripped (RPL_WHOISCHANNELS). */
	channels?: string[];
	/** Seconds the user has been idle (RPL_WHOISIDLE). */
	idleSeconds?: number;
	/** The account the user is logged in as (RPL_WHOISACCOUNT), when identified. */
	account?: string;
	/** Whether the user is a server operator (RPL_WHOISOPERATOR present). */
	operator?: boolean;
}

/**
 * A live IRC session bound to one TCP/TLS connection.
 *
 * Obtain one from {@link connect}. A background pump reads the socket, answers `PING`s, and
 * routes messages/events, so sending and receiving can be in flight at once. It is an
 * `AsyncDisposable`, so `await using` closes it cleanly (sending `QUIT` first).
 *
 * @since 1.0.4
 */
export interface IrcSession extends AsyncDisposable {
	/** Our current nickname (updated when a `NICK` change we make is echoed back). */
	readonly nick: string;
	/**
	 * Joins a channel.
	 *
	 * @param channel - The channel name (e.g. `#ops`).
	 * @param key - The channel key/password, when it is `+k` protected.
	 * @returns Resolves once the `JOIN` is written.
	 */
	join(channel: string, key?: string): Promise<void>;
	/**
	 * Leaves a channel.
	 *
	 * @param channel - The channel name.
	 * @param reason - An optional part message.
	 * @returns Resolves once the `PART` is written.
	 */
	part(channel: string, reason?: string): Promise<void>;
	/**
	 * Sends a `PRIVMSG`, splitting on newlines and chunking overly long lines.
	 *
	 * @param target - A channel or nick.
	 * @param text - The message text (may contain `\n`/`\r\n`; each line is sent separately).
	 * @returns Resolves once every line is written.
	 */
	say(target: string, text: string): Promise<void>;
	/**
	 * Sends a `NOTICE`, splitting on newlines and chunking overly long lines.
	 *
	 * @param target - A channel or nick.
	 * @param text - The notice text.
	 * @returns Resolves once every line is written.
	 */
	notice(target: string, text: string): Promise<void>;
	/**
	 * Sends a CTCP `ACTION` (the `/me` command) to a target.
	 *
	 * @param target - A channel or nick.
	 * @param text - The action text (rendered as `* nick text`).
	 * @returns Resolves once the message is written.
	 */
	action(target: string, text: string): Promise<void>;
	/**
	 * Returns an async iterable of inbound chat messages (`PRIVMSG`/`NOTICE`), with CTCP parsed.
	 *
	 * Each call returns an independent iterator that receives every message from the moment it is
	 * created; `break`ing out of the `for await` releases it. The loop ends when the connection
	 * closes.
	 *
	 * @returns An async iterable of {@link IrcChatMessage}.
	 */
	messages(): AsyncIterable<IrcChatMessage>;
	/**
	 * Returns an async iterable of every non-chat event (JOIN/PART/QUIT/NICK/KICK/MODE/TOPIC and
	 * numerics). Like {@link messages}, each call is an independent broadcast consumer.
	 *
	 * @returns An async iterable of {@link IrcEvent}.
	 */
	events(): AsyncIterable<IrcEvent>;
	/**
	 * Lists the members of a channel (aggregating `RPL_NAMREPLY` until `RPL_ENDOFNAMES`).
	 *
	 * @param channel - The channel to query.
	 * @returns The member nicks, with membership prefixes (`@`, `+`, ...) stripped.
	 * @throws {TimeoutError} If the server does not answer within the session timeout.
	 */
	names(channel: string): Promise<string[]>;
	/**
	 * Gets or sets a channel topic.
	 *
	 * With `text`, sets the topic and resolves once the `TOPIC` is written. Without `text`,
	 * queries the topic and resolves to it (empty string when unset).
	 *
	 * @param channel - The channel.
	 * @param text - The new topic to set, or omit to query.
	 * @returns The current topic when querying; nothing when setting.
	 * @throws {TimeoutError} If a query is not answered within the session timeout.
	 */
	topic(channel: string, text?: string): Promise<string | void>;
	/**
	 * Changes our nickname, resolving once the server echoes the `NICK` back.
	 *
	 * (The current nick is exposed as the read-only {@link IrcSession.nick} property; this is the
	 * mutator, named separately since a property and a method cannot share one name.)
	 *
	 * @param newNick - The new nickname.
	 * @returns Resolves once the change is confirmed.
	 * @throws {AuthError} If the nick is in use or otherwise rejected.
	 * @throws {TimeoutError} If the change is not confirmed within the session timeout.
	 */
	changeNick(newNick: string): Promise<void>;
	/**
	 * Queries WHOIS for a target and returns the aggregated result.
	 *
	 * @param target - The nick to query.
	 * @returns The structured WHOIS info (fields present depend on what the server returns).
	 * @throws {TimeoutError} If WHOIS is not answered within the session timeout.
	 */
	whois(target: string): Promise<IrcWhois>;
	/**
	 * Sends a structured command, applying the trailing-parameter rule to the last argument.
	 *
	 * @param command - The command (e.g. `MODE`).
	 * @param params - The parameters.
	 * @returns Resolves once the line is written.
	 */
	send(command: string, ...params: string[]): Promise<void>;
	/**
	 * Sends a raw pre-formatted line (no CRLF; it is appended). The escape hatch for commands the
	 * typed API does not cover.
	 *
	 * @param line - The line to send verbatim.
	 * @returns Resolves once the line is written.
	 */
	sendRaw(line: string): Promise<void>;
	/**
	 * Sends `QUIT` and closes the connection.
	 *
	 * @param reason - An optional quit message.
	 * @returns Resolves once the socket is closed.
	 */
	close(reason?: string): Promise<void>;
}

// a single-consumer push/pull queue backing one broadcast consumer's async iterator
class Queue<T> {
	#items: T[] = [];
	#waiters: ((r: IteratorResult<T>) => void)[] = [];
	#done = false;

	push(item: T): void {
		if (this.#done) return;
		const w = this.#waiters.shift();
		if (w) w({ value: item, done: false });
		else this.#items.push(item);
	}

	end(): void {
		if (this.#done) return;
		this.#done = true;
		for (const w of this.#waiters) w({ value: undefined, done: true });
		this.#waiters = [];
	}

	next(): Promise<IteratorResult<T>> {
		const item = this.#items.shift();
		if (item !== undefined) return Promise.resolve({ value: item, done: false });
		if (this.#done) return Promise.resolve({ value: undefined, done: true });
		return new Promise((r) => this.#waiters.push(r));
	}
}

// fans one stream out to many independent consumers; each messages()/events() call is one
class Fanout<T> {
	readonly #consumers = new Set<Queue<T>>();

	push(item: T): void {
		for (const q of this.#consumers) q.push(item);
	}

	end(): void {
		for (const q of this.#consumers) q.end();
		this.#consumers.clear();
	}

	consumer(): AsyncIterable<T> {
		const q = new Queue<T>();
		this.#consumers.add(q);
		const remove = () => {
			this.#consumers.delete(q);
			q.end();
		};
		return {
			[Symbol.asyncIterator]: (): AsyncIterator<T> => ({
				next: () => q.next(),
				return: () => {
					remove();
					return Promise.resolve({ value: undefined, done: true });
				}
			})
		};
	}
}

interface Deferred<T> {
	promise: Promise<T>;
	resolve: (v: T) => void;
	reject: (e: Error) => void;
}
function deferred<T>(): Deferred<T> {
	let resolve!: (v: T) => void;
	let reject!: (e: Error) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

// accumulates NAMES/topic replies per channel and holds the callers waiting on them
interface NamesPending {
	names: string[];
	waiters: Deferred<string[]>[];
}
interface WhoisPending {
	info: IrcWhois;
	waiter: Deferred<IrcWhois>;
}

class IrcSessionImpl implements IrcSession {
	#nick: string;
	readonly #socket: CoreSocket;
	readonly #writer: FramedWriter;
	readonly #reader: FramedReader;
	readonly #opts: IrcConnectOptions;
	readonly #timeoutMs: number;
	readonly #messages = new Fanout<IrcChatMessage>();
	readonly #events = new Fanout<IrcEvent>();
	// channels we consider ourselves in, for autoRejoin on kick
	readonly #channels = new Set<string>();
	// per-channel NAMES aggregation keyed by lowercased channel
	readonly #names = new Map<string, NamesPending>();
	// pending topic-get waiters keyed by lowercased channel
	readonly #topicWaiters = new Map<string, Deferred<string>[]>();
	// pending WHOIS aggregation keyed by lowercased nick
	readonly #whois = new Map<string, WhoisPending>();
	// pending nick change (resolved on the echoed NICK, rejected on 43x)
	#nickChange: { target: string; waiter: Deferred<void> } | null = null;
	#closed = false;
	#pumpError: Error | null = null;

	constructor(socket: CoreSocket, opts: IrcConnectOptions, registeredNick: string) {
		this.#socket = socket;
		this.#writer = socket.writer;
		this.#reader = socket.reader;
		this.#opts = opts;
		this.#timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
		this.#nick = registeredNick;
	}

	get nick(): string {
		return this.#nick;
	}

	startPump(): void {
		void this.#pump();
	}

	async #pump(): Promise<void> {
		try {
			for (;;) {
				const raw = await this.#reader.readLine();
				await this.#dispatch(raw);
			}
		} catch (err) {
			if (!this.#closed) this.#pumpError = err as Error;
		} finally {
			this.#endAll();
		}
	}

	async #dispatch(raw: string): Promise<void> {
		if (raw === '') return; // stray blank line (some servers emit keep-alive newlines)
		const msg = parseMessage(raw);
		const cmd = msg.command;

		// server PING must be answered automatically and is not surfaced as event noise
		if (cmd === 'PING') {
			const token = msg.params[msg.params.length - 1];
			await this.#writer.writeLine(token !== undefined ? `PONG :${token}` : 'PONG').catch(() => {});
			return;
		}
		// a server-initiated ERROR ends the connection; classify it like the other protocols
		if (cmd === 'ERROR') {
			this.#pumpError = classifyError(msg.params.join(' '));
			throw this.#pumpError;
		}
		if (cmd === 'PRIVMSG' || cmd === 'NOTICE') {
			this.#routeChat(msg, cmd);
			return;
		}

		// everything else: update internal state, then broadcast as an event
		this.#handleStateful(msg);
		this.#events.push({
			command: cmd,
			prefix: msg.prefix,
			params: msg.params,
			tags: msg.tags ?? {},
			raw
		});
	}

	#routeChat(msg: IrcMessage, cmd: string): void {
		const target = msg.params[0] ?? '';
		const rawText = msg.params[1] ?? '';
		const ctcp = parseCtcp(rawText);
		this.#messages.push({
			from: msg.prefix?.nick ?? msg.prefix?.raw ?? '',
			target,
			text: ctcp ? ctcp.args : rawText,
			type: cmd === 'NOTICE' ? 'notice' : 'privmsg',
			isChannel: isChannelName(target),
			tags: msg.tags ?? {},
			ctcp,
			element: msg
		});
	}

	// updates nick / channel / names / topic / whois state from an inbound non-chat message
	#handleStateful(msg: IrcMessage): void {
		switch (msg.command) {
			case 'NICK': {
				const from = msg.prefix?.nick;
				const to = msg.params[0];
				if (to === undefined) return;
				if (from !== undefined && from === this.#nick) this.#nick = to;
				if (this.#nickChange && from === this.#nickChange.target) {
					this.#nick = to;
					const w = this.#nickChange.waiter;
					this.#nickChange = null;
					w.resolve();
				}
				return;
			}
			case 'KICK': {
				const channel = msg.params[0];
				const who = msg.params[1];
				if (channel && who === this.#nick) {
					this.#channels.delete(channel.toLowerCase());
					if (this.#opts.autoRejoin && !this.#closed) {
						void this.#writer.writeLine(`JOIN ${channel}`).catch(() => {});
						this.#channels.add(channel.toLowerCase());
					}
				}
				return;
			}
			case RPL_NAMREPLY: {
				// params: <me> <=|*|@> <channel> :n1 n2 ...
				const channel = msg.params[2];
				const list = msg.params[msg.params.length - 1] ?? '';
				if (!channel) return;
				const pending = this.#namesFor(channel.toLowerCase());
				for (const raw of list.split(' ')) {
					if (raw) pending.names.push(stripMembershipPrefix(raw));
				}
				return;
			}
			case RPL_ENDOFNAMES: {
				const channel = msg.params[1];
				if (!channel) return;
				const key = channel.toLowerCase();
				const pending = this.#names.get(key);
				if (!pending) return;
				this.#names.delete(key);
				for (const w of pending.waiters) w.resolve(pending.names);
				return;
			}
			case RPL_TOPIC: {
				// params: <me> <channel> :topic
				this.#resolveTopic(msg.params[1], msg.params[msg.params.length - 1] ?? '');
				return;
			}
			case RPL_NOTOPIC: {
				this.#resolveTopic(msg.params[1], '');
				return;
			}
			case RPL_WHOISUSER: {
				const w = this.#whoisFor(msg.params[1]);
				if (!w) return;
				w.info.user = msg.params[2];
				w.info.host = msg.params[3];
				w.info.realname = msg.params[msg.params.length - 1];
				return;
			}
			case RPL_WHOISSERVER: {
				const w = this.#whoisFor(msg.params[1]);
				if (!w) return;
				w.info.server = msg.params[2];
				w.info.serverInfo = msg.params[msg.params.length - 1];
				return;
			}
			case RPL_WHOISOPERATOR: {
				const w = this.#whoisFor(msg.params[1]);
				if (w) w.info.operator = true;
				return;
			}
			case RPL_WHOISIDLE: {
				const w = this.#whoisFor(msg.params[1]);
				if (w) {
					const idle = Number(msg.params[2]);
					if (Number.isFinite(idle)) w.info.idleSeconds = idle;
				}
				return;
			}
			case RPL_WHOISCHANNELS: {
				const w = this.#whoisFor(msg.params[1]);
				if (!w) return;
				const chans = (msg.params[msg.params.length - 1] ?? '')
					.split(' ')
					.filter(Boolean)
					.map(stripMembershipPrefix);
				w.info.channels = [...(w.info.channels ?? []), ...chans];
				return;
			}
			case RPL_WHOISACCOUNT: {
				const w = this.#whoisFor(msg.params[1]);
				if (w) w.info.account = msg.params[2];
				return;
			}
			case RPL_ENDOFWHOIS: {
				const key = (msg.params[1] ?? '').toLowerCase();
				const w = this.#whois.get(key);
				if (!w) return;
				this.#whois.delete(key);
				w.waiter.resolve(w.info);
				return;
			}
			case ERR_NICKNAMEINUSE:
			case ERR_NICKCOLLISION:
			case ERR_ERRONEUSNICKNAME: {
				// reject an in-flight nick change; harmless if none is pending
				if (this.#nickChange) {
					const w = this.#nickChange.waiter;
					this.#nickChange = null;
					w.reject(
						new AuthError(`nick change rejected (${msg.command}): ${msg.params.join(' ')}`, {
							protocol: PROTO
						})
					);
				}
				return;
			}
			default:
				return;
		}
	}

	#namesFor(key: string): NamesPending {
		let pending = this.#names.get(key);
		if (!pending) {
			pending = { names: [], waiters: [] };
			this.#names.set(key, pending);
		}
		return pending;
	}

	#whoisFor(nick: string | undefined): WhoisPending | undefined {
		if (nick === undefined) return undefined;
		return this.#whois.get(nick.toLowerCase());
	}

	#resolveTopic(channel: string | undefined, topic: string): void {
		if (!channel) return;
		const key = channel.toLowerCase();
		const waiters = this.#topicWaiters.get(key);
		if (!waiters || waiters.length === 0) return;
		this.#topicWaiters.delete(key);
		for (const w of waiters) w.resolve(topic);
	}

	#endAll(): void {
		const reason =
			this.#pumpError ?? new ConnectionError('irc connection closed', { protocol: PROTO });
		this.#messages.end();
		this.#events.end();
		for (const pending of this.#names.values()) {
			for (const w of pending.waiters) w.reject(reason);
		}
		this.#names.clear();
		for (const waiters of this.#topicWaiters.values()) {
			for (const w of waiters) w.reject(reason);
		}
		this.#topicWaiters.clear();
		for (const w of this.#whois.values()) w.waiter.reject(reason);
		this.#whois.clear();
		if (this.#nickChange) {
			this.#nickChange.waiter.reject(reason);
			this.#nickChange = null;
		}
	}

	#assertOpen(): void {
		if (this.#closed) throw new ConnectionError('irc session is closed', { protocol: PROTO });
		if (this.#pumpError) throw this.#pumpError;
	}

	// races a reply promise against the session read deadline
	#withTimeout<T>(p: Promise<T>, what: string): Promise<T> {
		const ms = this.#timeoutMs;
		let timer: ReturnType<typeof setTimeout>;
		const t = new Promise<never>((_, reject) => {
			timer = setTimeout(
				() => reject(new TimeoutError(`${what} timed out`, { protocol: PROTO })),
				ms
			);
		});
		return Promise.race([p, t]).finally(() => clearTimeout(timer)) as Promise<T>;
	}

	// ---- public API -----------------------------------------------------------------------

	async join(channel: string, key?: string): Promise<void> {
		this.#assertOpen();
		this.#channels.add(channel.toLowerCase());
		await this.#writer.writeLine(key ? `JOIN ${channel} ${key}` : `JOIN ${channel}`);
	}

	async part(channel: string, reason?: string): Promise<void> {
		this.#assertOpen();
		this.#channels.delete(channel.toLowerCase());
		await this.#writer.writeLine(reason ? `PART ${channel} :${reason}` : `PART ${channel}`);
	}

	say(target: string, text: string): Promise<void> {
		return this.#sendText('PRIVMSG', target, text);
	}

	notice(target: string, text: string): Promise<void> {
		return this.#sendText('NOTICE', target, text);
	}

	async action(target: string, text: string): Promise<void> {
		this.#assertOpen();
		// CTCP ACTION is a single PRIVMSG wrapped in \x01 (newlines flattened to spaces)
		const body = `\x01ACTION ${text.replace(/[\r\n]+/g, ' ')}\x01`;
		await this.#writer.writeLine(`PRIVMSG ${target} :${body}`);
	}

	// splits text on newlines and chunks long lines under the wire limit, one command each
	async #sendText(command: 'PRIVMSG' | 'NOTICE', target: string, text: string): Promise<void> {
		this.#assertOpen();
		for (const line of text.split(/\r\n|\r|\n/)) {
			let remaining = line;
			do {
				const chunk = remaining.slice(0, MAX_LINE_PAYLOAD);
				remaining = remaining.slice(MAX_LINE_PAYLOAD);
				await this.#writer.writeLine(`${command} ${target} :${chunk}`);
			} while (remaining.length > 0);
		}
	}

	messages(): AsyncIterable<IrcChatMessage> {
		return this.#messages.consumer();
	}

	events(): AsyncIterable<IrcEvent> {
		return this.#events.consumer();
	}

	async names(channel: string): Promise<string[]> {
		this.#assertOpen();
		const key = channel.toLowerCase();
		const pending = this.#namesFor(key);
		const d = deferred<string[]>();
		pending.waiters.push(d);
		await this.#writer.writeLine(`NAMES ${channel}`);
		return this.#withTimeout(d.promise, `names(${channel})`);
	}

	async topic(channel: string, text?: string): Promise<string | void> {
		this.#assertOpen();
		if (text !== undefined) {
			await this.#writer.writeLine(`TOPIC ${channel} :${text}`);
			return;
		}
		const key = channel.toLowerCase();
		const d = deferred<string>();
		const waiters = this.#topicWaiters.get(key) ?? [];
		waiters.push(d);
		this.#topicWaiters.set(key, waiters);
		await this.#writer.writeLine(`TOPIC ${channel}`);
		return this.#withTimeout(d.promise, `topic(${channel})`);
	}

	async changeNick(newNick: string): Promise<void> {
		this.#assertOpen();
		if (this.#nickChange) {
			throw new ProtocolError('a nick change is already in flight', { protocol: PROTO });
		}
		const d = deferred<void>();
		this.#nickChange = { target: this.#nick, waiter: d };
		await this.#writer.writeLine(`NICK ${newNick}`);
		return this.#withTimeout(d.promise, `changeNick(${newNick})`);
	}

	async whois(target: string): Promise<IrcWhois> {
		this.#assertOpen();
		const key = target.toLowerCase();
		const d = deferred<IrcWhois>();
		this.#whois.set(key, { info: { nick: target }, waiter: d });
		await this.#writer.writeLine(`WHOIS ${target}`);
		return this.#withTimeout(d.promise, `whois(${target})`);
	}

	async send(command: string, ...params: string[]): Promise<void> {
		this.#assertOpen();
		await this.#writer.writeLine(formatMessage({ command, params }));
	}

	async sendRaw(line: string): Promise<void> {
		this.#assertOpen();
		await this.#writer.writeLine(line);
	}

	async close(reason?: string): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		if (!this.#pumpError) {
			await this.#writer.writeLine(reason ? `QUIT :${reason}` : 'QUIT').catch(() => {});
		}
		this.#endAll();
		await this.#socket.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

// strips a single leading membership-prefix char (@, +, ...) from a NAMES/WHOIS nick
function stripMembershipPrefix(nick: string): string {
	return nick.length > 0 && MEMBERSHIP_PREFIXES.includes(nick[0]!) ? nick.slice(1) : nick;
}

// classifies a server ERROR / registration-failure text into the right error type
function classifyError(text: string): AuthError | ProtocolError {
	const lower = text.toLowerCase();
	const authy =
		lower.includes('password') ||
		lower.includes('sasl') ||
		lower.includes('authenticat') ||
		lower.includes('banned') ||
		lower.includes('not authorized') ||
		lower.includes('access denied');
	const msg = `irc ERROR: ${text}`;
	return authy
		? new AuthError(msg, { protocol: PROTO })
		: new ProtocolError(msg, { protocol: PROTO });
}

// reads lines during the pre-pump handshake, answering PING inline; returns the parsed message
async function readHandshake(
	reader: FramedReader,
	writer: FramedWriter,
	timeoutMs: number
): Promise<IrcMessage> {
	for (;;) {
		const line = await reader.readLine(timeoutMs);
		if (line === '') continue;
		const msg = parseMessage(line);
		if (msg.command === 'PING') {
			const token = msg.params[msg.params.length - 1];
			await writer.writeLine(token !== undefined ? `PONG :${token}` : 'PONG');
			continue;
		}
		return msg;
	}
}

// runs the IRCv3 CAP negotiation + optional SASL PLAIN before NICK/USER
async function negotiateCaps(
	reader: FramedReader,
	writer: FramedWriter,
	opts: IrcConnectOptions,
	timeoutMs: number
): Promise<void> {
	await writer.writeLine('CAP LS 302');

	// CAP LS may be multiline; a `*` param before the cap list means more lines follow
	const offered = new Set<string>();
	for (;;) {
		const msg = await readHandshake(reader, writer, timeoutMs);
		if (msg.command !== 'CAP') continue; // ignore NOTICE/etc. interleaved before the list
		if (msg.params[1] !== 'LS') continue;
		const more = msg.params[2] === '*';
		const capStr = msg.params[msg.params.length - 1] ?? '';
		for (const tok of capStr.split(' ')) {
			if (tok) offered.add(tok.split('=')[0]!);
		}
		if (!more) break;
	}

	const wantSasl = opts.sasl !== undefined;
	if (wantSasl && !offered.has('sasl')) {
		throw new AuthError('server does not offer the sasl capability', { protocol: PROTO });
	}
	const desired: string[] = [];
	if (wantSasl) desired.push('sasl');
	for (const c of opts.caps ?? []) {
		if (offered.has(c) && !desired.includes(c)) desired.push(c);
	}

	if (desired.length > 0) {
		await writer.writeLine(`CAP REQ :${desired.join(' ')}`);
		const ack = await readHandshake(reader, writer, timeoutMs);
		if (ack.command !== 'CAP' || (ack.params[1] !== 'ACK' && ack.params[1] !== 'NAK')) {
			throw new ProtocolError(`expected CAP ACK/NAK, got ${ack.command} ${ack.params.join(' ')}`, {
				protocol: PROTO
			});
		}
		if (ack.params[1] === 'NAK') {
			throw new ProtocolError(`server refused capabilities: ${ack.params[ack.params.length - 1]}`, {
				protocol: PROTO
			});
		}
	}

	if (wantSasl) await runSaslPlain(reader, writer, opts.sasl!, timeoutMs);

	await writer.writeLine('CAP END');
}

// performs the SASL PLAIN exchange (AUTHENTICATE PLAIN -> base64 creds -> 903 / 90x)
async function runSaslPlain(
	reader: FramedReader,
	writer: FramedWriter,
	sasl: IrcSasl,
	timeoutMs: number
): Promise<void> {
	const mechanism = sasl.mechanism ?? 'PLAIN';
	if (mechanism !== 'PLAIN') {
		throw new ProtocolError(`unsupported SASL mechanism: ${mechanism}`, { protocol: PROTO });
	}
	await writer.writeLine('AUTHENTICATE PLAIN');
	// wait for the server's `AUTHENTICATE +` go-ahead
	for (;;) {
		const msg = await readHandshake(reader, writer, timeoutMs);
		if (msg.command === 'AUTHENTICATE') {
			if (msg.params[0] !== '+') {
				throw new ProtocolError(`unexpected AUTHENTICATE reply: ${msg.params.join(' ')}`, {
					protocol: PROTO
				});
			}
			break;
		}
		if (isSaslFailure(msg.command)) throw saslError(msg);
	}
	// PLAIN response: base64(authzid \0 authcid \0 passwd) with an empty authzid
	const payload = toBase64(encoder.encode(`\0${sasl.user}\0${sasl.password}`));
	await writer.writeLine(`AUTHENTICATE ${payload}`);
	for (;;) {
		const msg = await readHandshake(reader, writer, timeoutMs);
		if (msg.command === RPL_LOGGEDIN) continue; // 900: informational, success follows
		if (msg.command === RPL_SASLSUCCESS) return; // 903
		if (isSaslFailure(msg.command)) throw saslError(msg);
		// ignore anything else (NOTICE, CAP echoes) until the terminal numeric
	}
}

function isSaslFailure(command: string): boolean {
	return (
		command === ERR_SASLFAIL ||
		command === ERR_SASLTOOLONG ||
		command === ERR_SASLABORTED ||
		command === '902' // ERR_NICKLOCKED
	);
}

function saslError(msg: IrcMessage): AuthError {
	return new AuthError(`SASL authentication failed (${msg.command}): ${msg.params.join(' ')}`, {
		protocol: PROTO
	});
}

/**
 * Connects to an IRC server, registers, and returns a live session.
 *
 * Dials the core transport (implicit TLS when `tls: 'implicit'`, otherwise plaintext), sends
 * `PASS` if given, runs the IRCv3 CAP + SASL exchange when `sasl` is set, then registers with
 * `NICK` + `USER` and waits for `001` (`RPL_WELCOME`). A `433` (nick in use) or other fatal
 * registration numeric rejects with {@link AuthError}. A background pump then answers `PING`s
 * and routes messages/events.
 *
 * @param opts - Connection, identity, and auth options.
 * @returns The live session.
 * @throws {AuthError} If credentials are rejected or the nick is unavailable.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @throws {TimeoutError} If the handshake exceeds the deadline.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { connect } from 'edgeport/irc';
 *
 * await using irc = await connect({ hostname: 'irc.example.com', nick: 'edgebot' });
 * await irc.join('#edgeport');
 * await irc.say('#edgeport', 'hello from the edge');
 * for await (const m of irc.messages()) {
 * 	if (m.isChannel) console.log(`<${m.from}> ${m.text}`);
 * 	break;
 * }
 * ```
 */
export async function connect(opts: IrcConnectOptions): Promise<IrcSession> {
	const port = opts.port ?? (opts.tls === 'implicit' ? DEFAULT_TLS_PORT : DEFAULT_PORT);
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
 * Runs the IRC registration handshake and read pump over an already-connected {@link CoreSocket}.
 *
 * Sends `PASS` (optional), negotiates CAP + SASL (optional), sends `NICK` + `USER`, and reads
 * until `RPL_WELCOME` (001), answering `PING` and rejecting on fatal registration numerics.
 * Public {@link connect} dials the transport then calls this; unit tests call it directly with a
 * mock socket.
 *
 * @param socket - A connected core socket (already TLS when `tls: 'implicit'`).
 * @param opts - Connection, identity, and auth options.
 * @returns The live session.
 * @throws {AuthError} If credentials are rejected or the nick is unavailable.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @throws {TimeoutError} If the handshake exceeds the deadline.
 * @internal
 */
export async function _connectOverSocket(
	socket: CoreSocket,
	opts: IrcConnectOptions
): Promise<IrcSession> {
	const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const { reader, writer } = socket;
	const username = opts.username ?? opts.nick;
	const realname = opts.realname ?? opts.nick;

	if (opts.password !== undefined) await writer.writeLine(`PASS ${opts.password}`);
	if (opts.sasl !== undefined || (opts.caps && opts.caps.length > 0)) {
		await negotiateCaps(reader, writer, opts, timeoutMs);
	}
	await writer.writeLine(`NICK ${opts.nick}`);
	await writer.writeLine(`USER ${username} 0 * :${realname}`);

	// read until welcome (001); a fatal registration numeric or ERROR rejects the connect
	let registeredNick = opts.nick;
	for (;;) {
		const msg = await readHandshake(reader, writer, timeoutMs);
		if (msg.command === RPL_WELCOME) {
			if (msg.params[0]) registeredNick = msg.params[0];
			break;
		}
		if (msg.command === 'ERROR') throw classifyError(msg.params.join(' '));
		if (
			msg.command === ERR_NICKNAMEINUSE ||
			msg.command === ERR_NICKCOLLISION ||
			msg.command === ERR_YOUREBANNEDCREEP ||
			msg.command === ERR_PASSWDMISMATCH
		) {
			throw new AuthError(`irc registration rejected (${msg.command}): ${msg.params.join(' ')}`, {
				protocol: PROTO
			});
		}
		if (msg.command === ERR_ERRONEUSNICKNAME) {
			throw new ProtocolError(
				`irc rejected the nickname (${msg.command}): ${msg.params.join(' ')}`,
				{
					protocol: PROTO
				}
			);
		}
		// otherwise ignore (NOTICE, 002-005, MOTD, CAP echoes) and keep reading
	}

	const session = new IrcSessionImpl(socket, opts, registeredNick);
	session.startPump();
	return session;
}
