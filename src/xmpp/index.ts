/**
 * @fileoverview An XMPP client (RFC 6120 core + RFC 6121 IM/presence + XEP-0060/PEP pubsub) for
 * the Cloudflare Workers runtime.
 *
 * XMPP streams XML: the client opens a never-closing `<stream:stream>` root and both sides then
 * exchange stanzas (`<message>`, `<presence>`, `<iq>`) as child elements. This module runs the
 * full connect handshake - stream open, optional STARTTLS upgrade + re-open, SASL auth (PLAIN or
 * SCRAM-SHA-1/256, strongest offered), stream re-open, resource binding, and legacy session
 * establishment - then drives a background pump that routes inbound stanzas to async iterators
 * and correlates `<iq>` responses to their requests. It builds on the shared raw-TCP core and
 * never touches the runtime socket API directly.
 *
 * The public surface is concept-based: {@link XmppSession.send} / {@link XmppSession.messages} for
 * chat, {@link XmppSession.setPresence} / {@link XmppSession.presence} for presence,
 * {@link XmppSession.roster} for the contact list, and {@link XmppSession.publish} /
 * {@link XmppSession.subscribeNode} / {@link XmppSession.pubsub} for PEP/pubsub. Raw XML is never
 * required, but {@link XmppSession.sendStanza} / {@link XmppSession.sendXML} plus the re-exported
 * {@link el} / {@link serialize} builders are there when you need it.
 *
 * A long-lived session (to receive inbound stanzas) suits a Durable Object - an open socket keeps
 * a DO alive up to ~15 min. A one-shot {@link sendChat} fits a normal request-scoped Worker.
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
	type FramedWriter
} from '../core';
import { fromBase64, randomHex, toBase64 } from '../util';
import { saslPlain, scramClient, type ScramMechanism } from './sasl';
import {
	el,
	findChild,
	findChildren,
	firstElement,
	localName,
	parseFragment,
	serialize,
	text,
	XmlStreamReader,
	type StreamEvent,
	type XmlElement,
	type XmlNode
} from './xml';

export * from './sasl';
export * from './xml';

const PROTO = 'xmpp';
const DEFAULT_PORT = 5222;
const DEFAULT_TLS_PORT = 5223;
const DEFAULT_TIMEOUT_MS = 10_000;

const NS_STREAM = 'http://etherx.jabber.org/streams';
const NS_CLIENT = 'jabber:client';
const NS_TLS = 'urn:ietf:params:xml:ns:xmpp-tls';
const NS_SASL = 'urn:ietf:params:xml:ns:xmpp-sasl';
const NS_BIND = 'urn:ietf:params:xml:ns:xmpp-bind';
const NS_SESSION = 'urn:ietf:params:xml:ns:xmpp-session';
const NS_ROSTER = 'jabber:iq:roster';
const NS_PUBSUB = 'http://jabber.org/protocol/pubsub';
const NS_PUBSUB_EVENT = 'http://jabber.org/protocol/pubsub#event';
const NS_PING = 'urn:xmpp:ping';
// wrapper namespace for a plain-string pubsub payload (no schema; just a carrier)
const NS_PAYLOAD = 'urn:xmpp:edgeport:payload:0';

const encoder = new TextEncoder();

// SASL mechanisms this client can drive, strongest first
const MECH_PREFERENCE = ['SCRAM-SHA-256', 'SCRAM-SHA-1', 'PLAIN'] as const;

/**
 * A friendly presence state, mapped to XMPP on the wire:
 * `online` = available (no `show`), `away`/`xa` = `show` away/xa, `busy` = `show` dnd,
 * `offline` = `type='unavailable'`, `invisible` = `type='invisible'` (legacy, best-effort).
 *
 * @since 1.0.4
 */
export type PresenceShow = 'online' | 'away' | 'busy' | 'xa' | 'invisible' | 'offline';

/**
 * Timer hooks for the optional keep-alive, matching the global timer API. Injected through the
 * internal entry point so tests can drive it with a fake clock.
 *
 * @since 1.0.4
 */
export interface XmppScheduler {
	/** Schedules `fn` after `ms`; returns a handle for {@link XmppScheduler.clear}. */
	set(fn: () => void, ms: number): unknown;
	/** Cancels a timer created by {@link XmppScheduler.set}. */
	clear(handle: unknown): void;
}

const defaultScheduler: XmppScheduler = {
	set: (fn, ms) => setTimeout(fn, ms),
	clear: (h) => clearTimeout(h as ReturnType<typeof setTimeout>)
};

/**
 * Options for {@link connect}.
 *
 * @since 1.0.4
 */
export interface XmppConnectOptions {
	/** Remote host to dial; defaults to the JID domain. */
	hostname?: string;
	/** Remote port; defaults to 5222 (plaintext/STARTTLS) or 5223 (`tls: 'implicit'`). */
	port?: number;
	/** Bare JID `user@domain` to authenticate as. */
	jid: string;
	/** Account password. */
	password: string;
	/** Requested resource; the server may reassign it. A random one is requested when omitted. */
	resource?: string;
	/** XMPP domain (the `to` of the stream); defaults to the JID domain. */
	domain?: string;
	/**
	 * Transport security:
	 * - `'off'`: plaintext, no STARTTLS.
	 * - `'starttls'` (default): plaintext, upgraded via STARTTLS when the server offers it.
	 * - `'implicit'`: TLS from the first byte (legacy port 5223).
	 */
	tls?: 'off' | 'starttls' | 'implicit';
	/** Forced SASL mechanism order; the first that the server offers is used. */
	mechanisms?: ScramMechanism | 'PLAIN' | (ScramMechanism | 'PLAIN')[];
	/** Per-step read deadline in milliseconds for the connect handshake. */
	timeoutMs?: number;
	/** Whitespace keep-alive interval in seconds; disabled when omitted or `0`. */
	keepAliveSeconds?: number;
	/** Timer override for the keep-alive (mainly for testing). */
	scheduler?: XmppScheduler;
}

/** An inbound chat message delivered to {@link XmppSession.messages}. */
export interface XmppMessage {
	/** The sender's JID (`from`). */
	from: string;
	/** The recipient's JID (`to`). */
	to: string;
	/** The message body text (empty if none). */
	body: string;
	/** The message type (`chat`, `groupchat`, `normal`, `headline`, `error`). */
	type: string;
	/** The message id, if any. */
	id: string;
	/** The subject, when present. */
	subject?: string;
	/** The conversation thread id, when present. */
	thread?: string;
	/** The raw stanza element for anything the concept fields do not cover. */
	element: XmlElement;
}

/** An inbound presence update delivered to {@link XmppSession.presence}. */
export interface XmppPresence {
	/** The sender's JID (`from`). */
	from: string;
	/** The recipient's JID (`to`). */
	to: string;
	/** The presence type (`unavailable`, `subscribe`, `error`, ...); absent = available. */
	type?: string;
	/** The `show` value (`away`, `dnd`, `xa`, `chat`), when present. */
	show?: string;
	/** The free-text status, when present. */
	status?: string;
	/** The numeric priority, when present. */
	priority?: number;
	/** The raw stanza element. */
	element: XmlElement;
}

/** A contact from the roster (RFC 6121 `jabber:iq:roster`). */
export interface RosterItem {
	/** The contact's bare JID. */
	jid: string;
	/** The contact's display name, when set. */
	name?: string;
	/** The subscription state (`none`, `to`, `from`, `both`, `remove`). */
	subscription: string;
	/** The groups the contact belongs to. */
	groups: string[];
}

/** A pubsub/PEP event delivered to {@link XmppSession.pubsub}. */
export interface PubSubEvent {
	/** The publishing entity's JID (`from`). */
	from: string;
	/** The node the item was published to. */
	node: string;
	/** The published item's id, when present. */
	itemId?: string;
	/** The item's payload element, when present. */
	payload?: XmlElement;
	/** The raw `<message>` stanza that carried the event. */
	element: XmlElement;
}

/** Options for {@link XmppSession.send}. */
export interface SendOptions {
	/** The recipient JID. */
	to: string;
	/** The body text. */
	body: string;
	/** The message type; defaults to `chat`. */
	type?: string;
	/** An optional subject. */
	subject?: string;
	/** An optional conversation thread id. */
	thread?: string;
	/** An explicit message id; a random one is generated when omitted. */
	id?: string;
}

/**
 * A live XMPP session bound to one TCP/TLS connection.
 *
 * Obtain one from {@link connect}. A background pump routes inbound stanzas, so sending,
 * receiving, and request-reply can all be in flight at once. It is an `AsyncDisposable`, so
 * `await using` closes it cleanly (sending `</stream:stream>` first).
 *
 * @since 1.0.4
 */
export interface XmppSession extends AsyncDisposable {
	/** The full bound JID (`user@domain/resource`). */
	readonly jid: string;
	/**
	 * Sends a chat message.
	 *
	 * @param opts - Recipient, body, and optional type/subject/thread/id.
	 * @returns The message id that was sent.
	 * @throws {ConnectionError} If the session is closed.
	 */
	send(opts: SendOptions): Promise<string>;
	/**
	 * Broadcasts (or directs) a presence update.
	 *
	 * @param show - The friendly presence state.
	 * @param opts - Optional free-text `status`, numeric `priority`, and directed `to`.
	 * @returns Resolves once the presence stanza is written.
	 * @throws {ConnectionError} If the session is closed.
	 */
	setPresence(
		show: PresenceShow,
		opts?: { status?: string; priority?: number; to?: string }
	): Promise<void>;
	/** Async iterable of inbound chat {@link XmppMessage}s (pubsub events are routed to {@link pubsub}). */
	messages(): AsyncIterable<XmppMessage>;
	/** Async iterable of inbound {@link XmppPresence} updates. */
	presence(): AsyncIterable<XmppPresence>;
	/**
	 * Fetches the roster (contact list).
	 *
	 * @returns The roster items.
	 * @throws {ProtocolError} If the server returns an error.
	 */
	roster(): Promise<RosterItem[]>;
	/**
	 * Adds or updates a roster item.
	 *
	 * @param jid - The contact's bare JID.
	 * @param opts - Optional display `name` and `groups`.
	 * @returns Resolves once the server acknowledges.
	 * @throws {ProtocolError} If the server returns an error.
	 */
	addRosterItem(jid: string, opts?: { name?: string; groups?: string[] }): Promise<void>;
	/**
	 * Removes a roster item.
	 *
	 * @param jid - The contact's bare JID.
	 * @returns Resolves once the server acknowledges.
	 * @throws {ProtocolError} If the server returns an error.
	 */
	removeRosterItem(jid: string): Promise<void>;
	/**
	 * Publishes an item to a pubsub node (PEP on your own account when no `service` is given).
	 *
	 * @param node - The node id.
	 * @param payload - The item payload: an {@link XmlElement}, a raw-XML string (parsed), or plain
	 *   text (wrapped in a carrier element).
	 * @param opts - Optional `service` (publish to a pubsub component instead of PEP) and `itemId`.
	 * @returns The published item's id.
	 * @throws {ProtocolError} If the server returns an error.
	 */
	publish(
		node: string,
		payload: XmlElement | string,
		opts?: { service?: string; itemId?: string }
	): Promise<string>;
	/**
	 * Creates a pubsub node on a service (XEP-0060).
	 *
	 * @param service - The pubsub service (a component JID such as `pubsub.example.com`).
	 * @param node - The node id to create.
	 * @returns Resolves once the node is created.
	 * @throws {ProtocolError} If creation fails (e.g. the node already exists).
	 */
	createNode(service: string, node: string): Promise<void>;
	/**
	 * Subscribes to a pubsub node; events arrive via {@link pubsub}.
	 *
	 * @param service - The pubsub service (a component JID, or your bare JID for PEP).
	 * @param node - The node id.
	 * @returns The subscription id, when the server assigns one.
	 * @throws {ProtocolError} If the server returns an error.
	 */
	subscribeNode(service: string, node: string): Promise<string | undefined>;
	/** Async iterable of inbound {@link PubSubEvent}s. */
	pubsub(): AsyncIterable<PubSubEvent>;
	/**
	 * Sends an `<iq>` request and waits for the correlated response.
	 *
	 * @param type - `'get'` or `'set'`.
	 * @param child - The request payload element (e.g. a `<query>`).
	 * @param opts - Optional `to`, explicit `id`, and per-request `timeoutMs`.
	 * @returns The response `<iq>` element.
	 * @throws {ProtocolError} If the response is an error, or the peer misbehaves.
	 * @throws {TimeoutError} If no response arrives in time.
	 * @throws {ConnectionError} If the session is closed.
	 */
	iq(
		type: 'get' | 'set',
		child: XmlElement,
		opts?: { to?: string; id?: string; timeoutMs?: number }
	): Promise<XmlElement>;
	/**
	 * Sends a raw stanza element (escape hatch).
	 *
	 * @param stanza - An {@link XmlElement}, or a plain `{ name, attrs?, children? }` object.
	 * @returns Resolves once written.
	 * @throws {ConnectionError} If the session is closed.
	 */
	sendStanza(
		stanza: XmlElement | { name: string; attrs?: Record<string, string>; children?: XmlNode[] }
	): Promise<void>;
	/**
	 * Writes a raw XML string to the stream (escape hatch; not validated).
	 *
	 * @param xml - The XML to write verbatim.
	 * @returns Resolves once written.
	 * @throws {ConnectionError} If the session is closed.
	 */
	sendXML(xml: string): Promise<void>;
	/**
	 * Closes the stream (`</stream:stream>`) and the socket.
	 *
	 * @returns Resolves once the socket is closed.
	 */
	close(): Promise<void>;
}

// ---- a single-consumer push/pull queue backing one async iterator ----
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
	iterable(): AsyncIterable<T> {
		const self = this;
		return {
			[Symbol.asyncIterator](): AsyncIterator<T> {
				return { next: () => self.next() };
			}
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

// bare JID: strip the resource
function bareJid(jid: string): string {
	const slash = jid.indexOf('/');
	return slash === -1 ? jid : jid.slice(0, slash);
}
// domain part of a bare/full JID
function jidDomain(jid: string): string {
	const at = jid.indexOf('@');
	const rest = at === -1 ? jid : jid.slice(at + 1);
	const slash = rest.indexOf('/');
	return slash === -1 ? rest : rest.slice(0, slash);
}
// localpart (node) of a JID
function jidLocal(jid: string): string {
	const at = jid.indexOf('@');
	return at === -1 ? jid : jid.slice(0, at);
}

class XmppSessionImpl implements XmppSession {
	jid = '';
	#socket: CoreSocket;
	#writer: FramedWriter;
	#xml: XmlStreamReader;
	readonly #opts: XmppConnectOptions;
	readonly #domain: string;
	#bare = '';
	readonly #scheduler: XmppScheduler;
	readonly #defaultTimeoutMs?: number;
	readonly #messages = new Queue<XmppMessage>();
	readonly #presence = new Queue<XmppPresence>();
	readonly #pubsub = new Queue<PubSubEvent>();
	// pending <iq> requests keyed by id
	readonly #pending = new Map<string, Deferred<XmlElement>>();
	#iqCounter = 0;
	#msgCounter = 0;
	#keepAliveHandle: unknown = null;
	#closed = false;
	#pumpError: Error | null = null;

	constructor(socket: CoreSocket, xml: XmlStreamReader, opts: XmppConnectOptions, domain: string) {
		this.#socket = socket;
		this.#writer = socket.writer;
		this.#xml = xml;
		this.#opts = opts;
		this.#domain = domain;
		this.#scheduler = opts.scheduler ?? defaultScheduler;
		this.#defaultTimeoutMs = opts.timeoutMs;
	}

	// ---- writing ----

	#write(stanza: XmlElement): Promise<void> {
		return this.#writer.write(encoder.encode(serialize(stanza)));
	}

	#assertOpen(): void {
		if (this.#closed) throw new ConnectionError('xmpp session is closed', { protocol: PROTO });
		if (this.#pumpError) throw this.#pumpError;
	}

	// ---- handshake (inline reads; the pump is not running yet) ----

	// writes an <iq> and reads events until the matching response arrives (used pre-pump)
	async #handshakeIq(
		type: 'get' | 'set',
		child: XmlElement,
		timeoutMs: number
	): Promise<XmlElement> {
		const id = `bind-${++this.#iqCounter}-${randomHex(3)}`;
		await this.#write(el('iq', { type, id }, child));
		for (;;) {
			const ev = await this.#xml.readEvent(timeoutMs);
			if (!ev)
				throw new ConnectionError('xmpp stream closed during handshake', { protocol: PROTO });
			if (ev.type !== 'element') continue;
			const st = ev.element;
			if (localName(st.name) === 'iq' && st.attrs['id'] === id) {
				if (st.attrs['type'] === 'error') {
					throw iqError(st, 'xmpp handshake iq rejected');
				}
				return st;
			}
			// ignore any other stanza that races the handshake
		}
	}

	async _bindResource(resource: string | undefined, timeoutMs: number): Promise<string> {
		const bind = el(
			'bind',
			{ xmlns: NS_BIND },
			resource ? el('resource', {}, resource) : undefined
		);
		const res = await this.#handshakeIq('set', bind, timeoutMs);
		const bindEl = findChild(res, 'bind', NS_BIND);
		const jidEl = bindEl ? findChild(bindEl, 'jid') : undefined;
		if (!jidEl) throw new ProtocolError('xmpp bind response missing jid', { protocol: PROTO });
		this.jid = text(jidEl);
		this.#bare = bareJid(this.jid);
		return this.jid;
	}

	async _establishSession(timeoutMs: number): Promise<void> {
		await this.#handshakeIq('set', el('session', { xmlns: NS_SESSION }), timeoutMs);
	}

	// ---- background pump ----

	_startPump(): void {
		void this.#pump();
		if (this.#opts.keepAliveSeconds && this.#opts.keepAliveSeconds > 0) this.#scheduleKeepAlive();
	}

	async #pump(): Promise<void> {
		try {
			for (;;) {
				const ev: StreamEvent | null = await this.#xml.readEvent();
				if (ev === null) break;
				if (ev.type === 'close') break;
				if (ev.type === 'open') continue; // an unexpected stream restart; ignore
				await this.#route(ev.element);
			}
		} catch (err) {
			if (!this.#closed) this.#pumpError = err as Error;
		} finally {
			const reason =
				this.#pumpError ?? new ConnectionError('xmpp connection closed', { protocol: PROTO });
			for (const d of this.#pending.values()) d.reject(reason);
			this.#pending.clear();
			this.#messages.end();
			this.#presence.end();
			this.#pubsub.end();
		}
	}

	async #route(st: XmlElement): Promise<void> {
		switch (localName(st.name)) {
			case 'iq':
				await this.#routeIq(st);
				return;
			case 'message': {
				const event = findChild(st, 'event', NS_PUBSUB_EVENT);
				if (event) {
					this.#pubsub.push(makePubSubEvent(st, event));
					return;
				}
				this.#messages.push(makeMessage(st));
				return;
			}
			case 'presence':
				this.#presence.push(makePresence(st));
				return;
			default:
				return; // stream-level errors and anything else are ignored
		}
	}

	async #routeIq(st: XmlElement): Promise<void> {
		const id = st.attrs['id'];
		const type = st.attrs['type'];
		const waiter = id !== undefined ? this.#pending.get(id) : undefined;
		if (waiter) {
			this.#pending.delete(id!);
			if (type === 'error') waiter.reject(iqError(st, 'xmpp iq error'));
			else waiter.resolve(st);
			return;
		}
		// unsolicited request: ack a ping or roster push, otherwise politely decline
		if (type === 'get' || type === 'set') {
			const from = st.attrs['from'];
			const replyAttrs: Record<string, string> = { type: 'result', id: id ?? '' };
			if (from) replyAttrs['to'] = from;
			const isPing = type === 'get' && findChild(st, 'ping', NS_PING) !== undefined;
			const isRosterPush = type === 'set' && findChild(st, 'query', NS_ROSTER) !== undefined;
			if (isPing || isRosterPush) {
				await this.#write(el('iq', replyAttrs)).catch(() => {});
			} else {
				replyAttrs['type'] = 'error';
				await this.#write(
					el(
						'iq',
						replyAttrs,
						el(
							'error',
							{ type: 'cancel' },
							el('service-unavailable', { xmlns: 'urn:ietf:params:xml:ns:xmpp-stanzas' })
						)
					)
				).catch(() => {});
			}
		}
	}

	#scheduleKeepAlive(): void {
		const ms = (this.#opts.keepAliveSeconds ?? 0) * 1000;
		this.#keepAliveHandle = this.#scheduler.set(() => {
			if (this.#closed || this.#pumpError) return;
			// a single space between stanzas keeps the flow alive without a stanza
			void this.#writer.write(encoder.encode(' ')).catch(() => {});
			this.#scheduleKeepAlive();
		}, ms);
	}

	#withTimeout(p: Promise<XmlElement>, timeoutMs: number, id: string): Promise<XmlElement> {
		let timer: ReturnType<typeof setTimeout>;
		const t = new Promise<never>((_, reject) => {
			timer = setTimeout(() => {
				this.#pending.delete(id);
				reject(new TimeoutError('xmpp iq timed out', { protocol: PROTO }));
			}, timeoutMs);
		});
		return Promise.race([p, t]).finally(() => clearTimeout(timer)) as Promise<XmlElement>;
	}

	// ---- public API ----

	async iq(
		type: 'get' | 'set',
		child: XmlElement,
		opts?: { to?: string; id?: string; timeoutMs?: number }
	): Promise<XmlElement> {
		this.#assertOpen();
		const id = opts?.id ?? `iq-${++this.#iqCounter}-${randomHex(3)}`;
		const attrs: Record<string, string> = { type, id };
		if (opts?.to) attrs['to'] = opts.to;
		const d = deferred<XmlElement>();
		this.#pending.set(id, d);
		try {
			await this.#write(el('iq', attrs, child));
		} catch (err) {
			this.#pending.delete(id);
			throw err;
		}
		return this.#withTimeout(
			d.promise,
			opts?.timeoutMs ?? this.#defaultTimeoutMs ?? DEFAULT_TIMEOUT_MS,
			id
		);
	}

	async send(opts: SendOptions): Promise<string> {
		this.#assertOpen();
		const id = opts.id ?? `msg-${++this.#msgCounter}-${randomHex(3)}`;
		const children: XmlNode[] = [];
		if (opts.subject !== undefined) children.push(el('subject', {}, opts.subject));
		children.push(el('body', {}, opts.body));
		if (opts.thread !== undefined) children.push(el('thread', {}, opts.thread));
		await this.#write(el('message', { to: opts.to, type: opts.type ?? 'chat', id }, children));
		return id;
	}

	async setPresence(
		show: PresenceShow,
		opts?: { status?: string; priority?: number; to?: string }
	): Promise<void> {
		this.#assertOpen();
		const attrs: Record<string, string> = {};
		if (opts?.to) attrs['to'] = opts.to;
		const children: XmlNode[] = [];
		switch (show) {
			case 'online':
				break;
			case 'offline':
				attrs['type'] = 'unavailable';
				break;
			case 'invisible':
				attrs['type'] = 'invisible'; // legacy; servers that ignore it just show available
				break;
			case 'away':
				children.push(el('show', {}, 'away'));
				break;
			case 'busy':
				children.push(el('show', {}, 'dnd'));
				break;
			case 'xa':
				children.push(el('show', {}, 'xa'));
				break;
		}
		if (opts?.status !== undefined) children.push(el('status', {}, opts.status));
		if (opts?.priority !== undefined) children.push(el('priority', {}, String(opts.priority)));
		await this.#write(el('presence', attrs, children));
	}

	messages(): AsyncIterable<XmppMessage> {
		return this.#messages.iterable();
	}
	presence(): AsyncIterable<XmppPresence> {
		return this.#presence.iterable();
	}
	pubsub(): AsyncIterable<PubSubEvent> {
		return this.#pubsub.iterable();
	}

	async roster(): Promise<RosterItem[]> {
		const res = await this.iq('get', el('query', { xmlns: NS_ROSTER }));
		const query = findChild(res, 'query', NS_ROSTER);
		if (!query) return [];
		return findChildren(query, 'item').map((it) => ({
			jid: it.attrs['jid'] ?? '',
			name: it.attrs['name'],
			subscription: it.attrs['subscription'] ?? 'none',
			groups: findChildren(it, 'group').map((g) => text(g))
		}));
	}

	async addRosterItem(jid: string, opts?: { name?: string; groups?: string[] }): Promise<void> {
		const attrs: Record<string, string> = { jid };
		if (opts?.name !== undefined) attrs['name'] = opts.name;
		const groups = (opts?.groups ?? []).map((g) => el('group', {}, g));
		await this.iq('set', el('query', { xmlns: NS_ROSTER }, el('item', attrs, groups)));
	}

	async removeRosterItem(jid: string): Promise<void> {
		await this.iq(
			'set',
			el('query', { xmlns: NS_ROSTER }, el('item', { jid, subscription: 'remove' }))
		);
	}

	async publish(
		node: string,
		payload: XmlElement | string,
		opts?: { service?: string; itemId?: string }
	): Promise<string> {
		const itemId = opts?.itemId ?? `item-${randomHex(4)}`;
		const item = el('item', { id: itemId }, toPayload(payload));
		const pubsub = el('pubsub', { xmlns: NS_PUBSUB }, el('publish', { node }, item));
		const res = await this.iq('set', pubsub, opts?.service ? { to: opts.service } : undefined);
		// the server may echo the assigned id in its <publish><item id=..>
		const ps = findChild(res, 'pubsub', NS_PUBSUB);
		const pub = ps ? findChild(ps, 'publish') : undefined;
		const echoed = pub ? findChild(pub, 'item') : undefined;
		return echoed?.attrs['id'] ?? itemId;
	}

	async createNode(service: string, node: string): Promise<void> {
		await this.iq('set', el('pubsub', { xmlns: NS_PUBSUB }, el('create', { node })), {
			to: service
		});
	}

	async subscribeNode(service: string, node: string): Promise<string | undefined> {
		const sub = el('pubsub', { xmlns: NS_PUBSUB }, el('subscribe', { node, jid: this.#bare }));
		const res = await this.iq('set', sub, { to: service });
		const ps = findChild(res, 'pubsub', NS_PUBSUB);
		const subscription = ps ? findChild(ps, 'subscription') : undefined;
		return subscription?.attrs['subid'];
	}

	async sendStanza(
		stanza: XmlElement | { name: string; attrs?: Record<string, string>; children?: XmlNode[] }
	): Promise<void> {
		this.#assertOpen();
		const norm: XmlElement = {
			name: stanza.name,
			attrs: stanza.attrs ?? {},
			children: stanza.children ?? []
		};
		await this.#write(norm);
	}

	async sendXML(xml: string): Promise<void> {
		this.#assertOpen();
		await this.#writer.write(encoder.encode(xml));
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		if (this.#keepAliveHandle !== null) this.#scheduler.clear(this.#keepAliveHandle);
		if (!this.#pumpError) {
			await this.#writer.write(encoder.encode('</stream:stream>')).catch(() => {});
		}
		this.#messages.end();
		this.#presence.end();
		this.#pubsub.end();
		for (const d of this.#pending.values()) {
			d.reject(new ConnectionError('xmpp session closed', { protocol: PROTO }));
		}
		this.#pending.clear();
		await this.#socket.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

// ---- inbound stanza parsing ----

function childText(parent: XmlElement, name: string): string {
	const c = findChild(parent, name);
	return c ? text(c) : '';
}

function makeMessage(st: XmlElement): XmppMessage {
	const subjectEl = findChild(st, 'subject');
	const threadEl = findChild(st, 'thread');
	return {
		from: st.attrs['from'] ?? '',
		to: st.attrs['to'] ?? '',
		body: childText(st, 'body'),
		type: st.attrs['type'] ?? 'normal',
		id: st.attrs['id'] ?? '',
		subject: subjectEl ? text(subjectEl) : undefined,
		thread: threadEl ? text(threadEl) : undefined,
		element: st
	};
}

function makePresence(st: XmlElement): XmppPresence {
	const showEl = findChild(st, 'show');
	const statusEl = findChild(st, 'status');
	const prioEl = findChild(st, 'priority');
	const prio = prioEl ? Number.parseInt(text(prioEl), 10) : undefined;
	return {
		from: st.attrs['from'] ?? '',
		to: st.attrs['to'] ?? '',
		type: st.attrs['type'],
		show: showEl ? text(showEl) : undefined,
		status: statusEl ? text(statusEl) : undefined,
		priority: prio !== undefined && Number.isFinite(prio) ? prio : undefined,
		element: st
	};
}

function makePubSubEvent(st: XmlElement, event: XmlElement): PubSubEvent {
	const items = findChild(event, 'items');
	const node = items?.attrs['node'] ?? event.attrs['node'] ?? '';
	const item = items ? findChild(items, 'item') : undefined;
	return {
		from: st.attrs['from'] ?? '',
		node,
		itemId: item?.attrs['id'],
		payload: item ? firstElement(item) : undefined,
		element: st
	};
}

// turns a payload argument into an element: element as-is, raw XML string parsed, plain text wrapped
function toPayload(payload: XmlElement | string): XmlElement {
	if (typeof payload !== 'string') return payload;
	if (payload.trimStart().startsWith('<')) return parseFragment(payload);
	return el('payload', { xmlns: NS_PAYLOAD }, payload);
}

// classifies a stanza <error> child: auth conditions -> AuthError, else ProtocolError
function iqError(st: XmlElement, prefix: string): AuthError | ProtocolError {
	const err = findChild(st, 'error');
	let condition = '';
	if (err) {
		const c = firstElement(err);
		if (c) condition = localName(c.name);
	}
	const message = condition ? `${prefix}: ${condition}` : prefix;
	if (
		condition === 'not-authorized' ||
		condition === 'forbidden' ||
		condition === 'registration-required'
	) {
		return new AuthError(message, { protocol: PROTO });
	}
	return new ProtocolError(message, { protocol: PROTO });
}

// ---- handshake helpers ----

function writeStreamOpen(writer: FramedWriter, domain: string): Promise<void> {
	const open =
		`<?xml version='1.0'?>` +
		`<stream:stream to='${domain}' xmlns='${NS_CLIENT}' ` +
		`xmlns:stream='${NS_STREAM}' version='1.0'>`;
	return writer.write(encoder.encode(open));
}

// writes the stream header and reads until <stream:features>, returning it
async function openStream(
	writer: FramedWriter,
	xml: XmlStreamReader,
	domain: string,
	timeoutMs: number
): Promise<XmlElement> {
	await writeStreamOpen(writer, domain);
	for (;;) {
		const ev = await xml.readEvent(timeoutMs);
		if (!ev) throw new ConnectionError('xmpp stream closed before features', { protocol: PROTO });
		if (ev.type === 'element' && localName(ev.element.name) === 'features') return ev.element;
		if (ev.type === 'close')
			throw new ConnectionError('xmpp stream closed by server', { protocol: PROTO });
		// 'open' (stream header) and any other pre-features element are skipped
	}
}

function offersStartTls(features: XmlElement): boolean {
	return findChild(features, 'starttls', NS_TLS) !== undefined;
}

function offersSession(features: XmlElement): boolean {
	const session = findChild(features, 'session', NS_SESSION);
	// RFC 6121 obsoletes session establishment; skip it when the server marks it optional
	return session !== undefined && findChild(session, 'optional') === undefined;
}

function offeredMechanisms(features: XmlElement): string[] {
	const mechs = findChild(features, 'mechanisms', NS_SASL);
	if (!mechs) return [];
	return findChildren(mechs, 'mechanism').map((m) => text(m).trim());
}

// picks the mechanism to use: forced order if given, else strongest offered we support
function chooseMechanism(features: XmlElement, opts: XmppConnectOptions): string {
	const offered = offeredMechanisms(features);
	if (offered.length === 0) {
		throw new AuthError('xmpp server offered no SASL mechanisms', { protocol: PROTO });
	}
	const forced = opts.mechanisms
		? Array.isArray(opts.mechanisms)
			? opts.mechanisms
			: [opts.mechanisms]
		: null;
	const order = forced ?? MECH_PREFERENCE;
	for (const m of order) if (offered.includes(m)) return m;
	throw new AuthError(`xmpp: no supported SASL mechanism offered (server: ${offered.join(', ')})`, {
		protocol: PROTO
	});
}

async function doSasl(
	writer: FramedWriter,
	xml: XmlStreamReader,
	mechanism: string,
	opts: XmppConnectOptions,
	timeoutMs: number
): Promise<void> {
	const authcid = jidLocal(opts.jid);
	const decode = (e: XmlElement) => new TextDecoder().decode(fromBase64(text(e)));

	if (mechanism === 'PLAIN') {
		await writer.write(
			encoder.encode(
				serialize(
					el('auth', { xmlns: NS_SASL, mechanism: 'PLAIN' }, saslPlain(authcid, opts.password))
				)
			)
		);
		const e = await expectElement(xml, timeoutMs);
		if (localName(e.name) === 'success') return;
		if (localName(e.name) === 'failure') throw saslFailure(e);
		throw new ProtocolError(`xmpp SASL: unexpected <${e.name}>`, { protocol: PROTO });
	}

	// SCRAM
	const client = scramClient(mechanism as ScramMechanism, authcid, opts.password);
	await writer.write(
		encoder.encode(
			serialize(
				el('auth', { xmlns: NS_SASL, mechanism }, toBase64(encoder.encode(client.clientFirst)))
			)
		)
	);
	let e = await expectElement(xml, timeoutMs);
	if (localName(e.name) === 'failure') throw saslFailure(e);
	if (localName(e.name) !== 'challenge') {
		throw new ProtocolError(`xmpp SASL: expected challenge, got <${e.name}>`, { protocol: PROTO });
	}
	const clientFinal = await client.handleServerFirst(decode(e));
	await writer.write(
		encoder.encode(
			serialize(el('response', { xmlns: NS_SASL }, toBase64(encoder.encode(clientFinal))))
		)
	);
	e = await expectElement(xml, timeoutMs);
	if (localName(e.name) === 'failure') throw saslFailure(e);
	if (localName(e.name) === 'success') {
		if (text(e).length > 0) await client.verifyServerFinal(decode(e));
		return;
	}
	if (localName(e.name) === 'challenge') {
		// some servers send the server-final as a challenge, then expect an empty response
		await client.verifyServerFinal(decode(e));
		await writer.write(encoder.encode(serialize(el('response', { xmlns: NS_SASL }))));
		const done = await expectElement(xml, timeoutMs);
		if (localName(done.name) === 'success') return;
		throw saslFailure(done);
	}
	throw new ProtocolError(`xmpp SASL: unexpected <${e.name}>`, { protocol: PROTO });
}

// reads the next top-level element (skipping stream open/whitespace)
async function expectElement(xml: XmlStreamReader, timeoutMs: number): Promise<XmlElement> {
	for (;;) {
		const ev = await xml.readEvent(timeoutMs);
		if (!ev) throw new ConnectionError('xmpp stream closed unexpectedly', { protocol: PROTO });
		if (ev.type === 'element') return ev.element;
		if (ev.type === 'close')
			throw new ConnectionError('xmpp stream closed by server', { protocol: PROTO });
	}
}

function saslFailure(e: XmlElement): AuthError {
	const condition = firstElement(e);
	const name = condition ? localName(condition.name) : 'not-authorized';
	return new AuthError(`xmpp SASL failure: ${name}`, { protocol: PROTO });
}

/**
 * Runs the XMPP handshake over an already-connected {@link CoreSocket} and returns a live session.
 *
 * Opens the stream, optionally upgrades via STARTTLS and re-opens, authenticates with SASL, re-opens
 * the stream, binds a resource, and establishes a legacy session when offered - then starts the
 * background pump. Public {@link connect} dials the transport then calls this; unit tests call it
 * directly with a mock socket.
 *
 * @param socket - A connected core socket (already TLS when `tls: 'implicit'`, `'starttls'`-capable
 *   otherwise).
 * @param opts - Connection and credential options.
 * @returns The live, bound session.
 * @throws {AuthError} If the server rejects the credentials or offers no usable mechanism.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @throws {TimeoutError} If a handshake step exceeds the deadline.
 * @internal
 */
export async function _connectOverSocket(
	socket: CoreSocket,
	opts: XmppConnectOptions
): Promise<XmppSession> {
	const domain = opts.domain ?? jidDomain(opts.jid);
	const hostname = opts.hostname ?? domain;
	const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	let active = socket;
	let xml = new XmlStreamReader(active.reader);

	let features = await openStream(active.writer, xml, domain, timeoutMs);

	// STARTTLS upgrade + stream re-open
	if (opts.tls === 'starttls' && offersStartTls(features)) {
		await active.writer.write(encoder.encode(serialize(el('starttls', { xmlns: NS_TLS }))));
		const proceed = await expectElement(xml, timeoutMs);
		if (localName(proceed.name) !== 'proceed') {
			throw new ProtocolError('xmpp STARTTLS not accepted', { protocol: PROTO });
		}
		active = active.startTls({ expectedServerHostname: hostname });
		xml = new XmlStreamReader(active.reader);
		features = await openStream(active.writer, xml, domain, timeoutMs);
	}

	// SASL
	const mechanism = chooseMechanism(features, opts);
	await doSasl(active.writer, xml, mechanism, opts, timeoutMs);

	// stream re-open after successful auth
	features = await openStream(active.writer, xml, domain, timeoutMs);

	// resource binding (+ legacy session establishment)
	const session = new XmppSessionImpl(active, xml, opts, domain);
	await session._bindResource(opts.resource, timeoutMs);
	if (offersSession(features)) await session._establishSession(timeoutMs);

	session._startPump();
	return session;
}

/**
 * Connects to an XMPP server, authenticates, binds a resource, and returns a live session.
 *
 * Dials the core transport (implicit TLS for `tls: 'implicit'`, otherwise plaintext that STARTTLS
 * may upgrade), runs the RFC 6120 handshake, and starts a background pump that routes inbound
 * stanzas. Use `await using` (or {@link XmppSession.close}) to release the connection.
 *
 * @param opts - Connection and credential options.
 * @returns The live session, bound and ready.
 * @throws {AuthError} If the server rejects the credentials.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If the server speaks the protocol incorrectly.
 * @throws {TimeoutError} If the handshake exceeds the deadline.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { connect } from 'edgeport/xmpp';
 *
 * await using xmpp = await connect({
 * 	jid: 'juliet@example.com',
 * 	password: env.XMPP_PW,
 * 	tls: 'starttls'
 * });
 * await xmpp.setPresence('online');
 * await xmpp.send({ to: 'romeo@example.com', body: 'wherefore art thou' });
 * for await (const msg of xmpp.messages()) console.log(msg.from, msg.body);
 * ```
 */
export async function connect(opts: XmppConnectOptions): Promise<XmppSession> {
	const domain = opts.domain ?? jidDomain(opts.jid);
	const hostname = opts.hostname ?? domain;
	const port = opts.port ?? (opts.tls === 'implicit' ? DEFAULT_TLS_PORT : DEFAULT_PORT);
	const implicit = opts.tls === 'implicit';
	const socket = await coreConnect({
		hostname,
		port,
		tls: implicit ? 'on' : opts.tls === 'off' ? 'off' : 'starttls',
		connectTimeoutMs: opts.timeoutMs
	});
	try {
		return await _connectOverSocket(socket, { ...opts, hostname, domain });
	} catch (err) {
		await socket.close().catch(() => {});
		throw err;
	}
}

/**
 * Sends a single chat message in one call: connect, authenticate, send, close.
 *
 * Convenience for a fire-and-forget notification from a request-scoped Worker where you do not need
 * to stay connected. Presence is announced before sending so servers deliver to available contacts.
 *
 * @param opts - Connection/credential options plus the recipient `to` and message `body`.
 * @returns The sent message id.
 * @throws {AuthError} If the credentials are rejected.
 * @throws {ConnectionError} If the connection cannot be established.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { sendChat } from 'edgeport/xmpp';
 *
 * await sendChat({
 * 	jid: 'bot@example.com',
 * 	password: env.XMPP_PW,
 * 	to: 'ops@example.com',
 * 	body: 'deploy finished'
 * });
 * ```
 */
export async function sendChat(
	opts: XmppConnectOptions & { to: string; body: string; type?: string; subject?: string }
): Promise<string> {
	const session = await connect(opts);
	try {
		await session.setPresence('online');
		return await session.send({
			to: opts.to,
			body: opts.body,
			type: opts.type,
			subject: opts.subject
		});
	} finally {
		await session.close();
	}
}
