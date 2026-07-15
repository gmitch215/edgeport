/**
 * @fileoverview A SIP user agent (UAC) over TCP/TLS for the Cloudflare Workers runtime.
 *
 * SIP is the signaling protocol behind VoIP and the chat side of RCS (its Universal Profile
 * rides SIP + MSRP). This module speaks SIP over the raw-TCP core: it REGISTERs (with RFC 5626
 * "outbound" so a listen-less Worker can receive inbound requests on its own connection), sends
 * and receives pager-mode `MESSAGE`s (RFC 3428), probes capabilities with `OPTIONS`, subscribes
 * to presence (`SUBSCRIBE`/`NOTIFY` + PIDF), and sets up session-mode MSRP chats via
 * `INVITE`/SDP. Digest auth (RFC 3261 §22) is handled transparently, including the MD5 that
 * WebCrypto lacks (see `./digest`).
 *
 * TLS is implicit-only (`tls: 'implicit'`); SIP has no in-band STARTTLS. This is a signaling +
 * messaging client: it does not carry RTP/SRTP voice media (UDP, which Workers cannot open) and
 * it does not reach carrier RCS (that is gated behind IMS/SIM provisioning). It targets open
 * SIP infrastructure - Asterisk, FreeSWITCH, Kamailio, OpenSIPS, and cloud SIP trunks.
 *
 * A one-shot `MESSAGE` fits a normal request-scoped Worker. To keep a registration open and
 * receive inbound requests, host the session in a Durable Object (an open socket keeps a DO
 * alive up to ~15 min; refresh REGISTER and reconnect on a DO alarm).
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
import { randomHex } from '../util';
import { computeDigestResponse, parseChallenge, type DigestChallenge } from './digest';
import {
	SipHeaders,
	getParam,
	newBranch,
	newCallId,
	newTag,
	type SipRequest,
	type SipResponse
} from './message';
import { connectMsrp, type MsrpSession } from './msrp';
import { buildMsrpOffer, parseSdp } from './sdp';
import { readMessage, writeMessage } from './transport';

export * from './digest';
export * from './message';
export * from './msrp';
export * from './sdp';
export { readMessage, writeMessage, writePing, writePong } from './transport';

const PROTO = 'sip';
const DEFAULT_PORT = 5060;
const DEFAULT_TLS_PORT = 5061;
const DEFAULT_EXPIRES = 3600;
const USER_AGENT = 'edgeport/1.0';
const decoder = new TextDecoder();

/**
 * A scheduler for the registration-refresh + keep-alive timers, matching the global timer API.
 *
 * Injected through the internal entry point so tests can drive timers with a fake clock.
 *
 * @since 1.0.3
 */
export interface SipScheduler {
	/** Schedules `fn` after `ms`; returns a handle for {@link clear}. */
	set(fn: () => void, ms: number): unknown;
	/** Cancels a timer created by {@link set}. */
	clear(handle: unknown): void;
}

const defaultScheduler: SipScheduler = {
	set: (fn, ms) => setTimeout(fn, ms),
	clear: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>)
};

/**
 * Options for {@link connect}.
 *
 * @since 1.0.3
 */
export interface SipConnectOptions {
	/** SIP server / registrar host to dial (also the TLS certificate identity). */
	hostname: string;
	/** TCP port; defaults to 5060 (plaintext) or 5061 (`tls: 'implicit'`). */
	port?: number;
	/** Transport security: `'off'` (default) plaintext, or `'implicit'` TLS (SIPS). */
	tls?: 'off' | 'implicit';
	/** The SIP domain / realm host; defaults to `hostname`. Used to build the AOR. */
	domain?: string;
	/** The account user part (the AOR user, e.g. `alice` in `sip:alice@domain`). */
	username: string;
	/** The account password (omit for a server that does not challenge). */
	password?: string;
	/** Auth username, if different from {@link username}. */
	authUsername?: string;
	/** Optional display name for the From header. */
	displayName?: string;
	/** Default registration expiry in seconds; defaults to 3600. */
	expiresSeconds?: number;
	/** Per-request read deadline in milliseconds. */
	timeoutMs?: number;
	/** RFC 5626 instance id (a URN); generated when omitted. */
	instanceId?: string;
	/** Timer override for refresh/keep-alive (mainly for testing). */
	scheduler?: SipScheduler;
}

/** An inbound pager-mode message delivered to {@link SipSession.messages}. */
export interface SipInboundMessage {
	/** The From header value. */
	from: string;
	/** The To header value. */
	to: string;
	/** The `Content-Type`, if present. */
	contentType?: string;
	/** The raw body octets. */
	body: Uint8Array;
	/** Decodes the body as UTF-8 text. */
	text(): string;
}

/** The result of an {@link SipSession.options} capability probe. */
export interface OptionsResult {
	/** The final status code. */
	status: number;
	/** Methods from the `Allow` header. */
	allow: string[];
	/** Media/content types from the `Accept` header. */
	accept: string[];
}

/** A presence notification delivered to a {@link PresenceSubscription}. */
export interface PresenceNotification {
	/** The `Subscription-State` header (e.g. `active;expires=3600`, `terminated`). */
	state: string;
	/** The raw notification body (typically `application/pidf+xml`). */
	body: Uint8Array;
	/** Decodes the body as UTF-8 text (the PIDF XML). */
	text(): string;
}

/** A live presence subscription yielding {@link PresenceNotification}s. */
export interface PresenceSubscription extends AsyncIterable<PresenceNotification>, AsyncDisposable {
	/** Ends the subscription (SUBSCRIBE with Expires: 0). */
	unsubscribe(): Promise<void>;
}

/** An established session-mode MSRP chat set up by {@link SipSession.invite}. */
export interface SipChat extends AsyncDisposable {
	/** The underlying MSRP session for send/receive. */
	readonly msrp: MsrpSession;
	/** Sends a text (or byte) message over MSRP. */
	send(body: Uint8Array | string, opts?: { contentType?: string }): Promise<void>;
	/** Async iterable of inbound MSRP messages. */
	messages(): AsyncIterable<import('./msrp').MsrpMessage>;
	/** Ends the call (BYE) and closes the MSRP session. */
	bye(): Promise<void>;
}

/**
 * A live SIP user agent bound to one TCP/TLS connection.
 *
 * Obtain one from {@link connect}. A background pump reads messages, matches responses to
 * requests, routes inbound requests, and answers keep-alive pings. It is an `AsyncDisposable`.
 *
 * @since 1.0.3
 */
export interface SipSession extends AsyncDisposable {
	/** Our address-of-record, `sip:username@domain`. */
	readonly localUri: string;
	/**
	 * Registers the AOR with RFC 5626 outbound so inbound requests arrive on this connection,
	 * authenticating if challenged, and keeps it refreshed until {@link unregister} / {@link close}.
	 *
	 * @param opts - Optional expiry override.
	 * @returns Resolves once the registrar returns 200.
	 * @throws {AuthError} If the credentials are rejected.
	 * @throws {ProtocolError} On a non-2xx registration failure.
	 */
	register(opts?: { expiresSeconds?: number }): Promise<void>;
	/**
	 * Removes the registration (REGISTER with Expires: 0).
	 *
	 * @returns Resolves once the registrar acknowledges.
	 */
	unregister(): Promise<void>;
	/**
	 * Sends a pager-mode `MESSAGE` (RFC 3428) to a target AOR.
	 *
	 * @param to - The recipient (`sip:bob@domain` or a bare `bob`).
	 * @param body - The message text.
	 * @param opts - Optional content type (default `text/plain`) and extra headers.
	 * @returns The final response (200/202 on success).
	 * @throws {AuthError} If the credentials are rejected.
	 * @throws {ProtocolError} On a non-2xx result.
	 */
	message(
		to: string,
		body: string,
		opts?: { contentType?: string; headers?: Record<string, string> }
	): Promise<SipResponse>;
	/**
	 * Probes a target's capabilities with `OPTIONS`.
	 *
	 * @param target - The target URI, or the server itself when omitted.
	 * @returns The status and advertised `Allow`/`Accept` sets.
	 */
	options(target?: string): Promise<OptionsResult>;
	/**
	 * Subscribes to a target's presence (`SUBSCRIBE` + `NOTIFY`, PIDF).
	 *
	 * @param target - The presentity URI.
	 * @param opts - Optional expiry.
	 * @returns A subscription whose iterator yields notifications.
	 */
	subscribePresence(
		target: string,
		opts?: { expiresSeconds?: number }
	): Promise<PresenceSubscription>;
	/**
	 * Places an `INVITE` offering an MSRP message session, and on answer opens the MSRP chat.
	 *
	 * @param target - The callee URI.
	 * @returns The established chat.
	 * @throws {ProtocolError} If the callee declines or offers no MSRP answer.
	 */
	invite(target: string): Promise<SipChat>;
	/** Async iterable of inbound pager-mode {@link SipInboundMessage}s (each auto-answered 200). */
	messages(): AsyncIterable<SipInboundMessage>;
	/** Unregisters (best-effort) and closes the connection. */
	close(): Promise<void>;
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

// a cached digest challenge and the header it maps to (Authorization vs Proxy-Authorization)
interface AuthState {
	headerName: 'Authorization' | 'Proxy-Authorization';
	challenge: DigestChallenge;
	nc: number;
}

class SipSessionImpl implements SipSession {
	readonly localUri: string;
	readonly #socket: CoreSocket;
	readonly #reader: FramedReader;
	readonly #writer: FramedWriter;
	readonly #opts: SipConnectOptions;
	readonly #domain: string;
	readonly #transport: 'TCP' | 'TLS';
	readonly #contactHost: string;
	readonly #instanceId: string;
	readonly #scheduler: SipScheduler;
	readonly #timeoutMs?: number;
	// pending client transactions keyed by our Via branch
	readonly #pending = new Map<string, Deferred<SipResponse>>();
	readonly #inbox = new Queue<SipInboundMessage>();
	// presence subscriptions keyed by Call-ID
	readonly #subscriptions = new Map<string, Queue<PresenceNotification>>();
	#authState: AuthState | null = null;
	// registration dialog identifiers
	readonly #regCallId: string;
	readonly #regFromTag: string;
	#regCseq = 0;
	#regExpires = DEFAULT_EXPIRES;
	#registered = false;
	#refreshHandle: unknown = null;
	#pingHandle: unknown = null;
	#closed = false;
	#pumpError: Error | null = null;

	constructor(socket: CoreSocket, opts: SipConnectOptions) {
		this.#socket = socket;
		this.#reader = socket.reader;
		this.#writer = socket.writer;
		this.#opts = opts;
		this.#domain = opts.domain ?? opts.hostname;
		this.#transport = opts.tls === 'implicit' ? 'TLS' : 'TCP';
		this.#contactHost = `${randomHex(4)}.invalid`; // nominal; Outbound routes over the flow
		this.#instanceId =
			opts.instanceId ??
			`urn:uuid:${randomHex(4)}-${randomHex(2)}-${randomHex(2)}-${randomHex(2)}-${randomHex(6)}`;
		this.#scheduler = opts.scheduler ?? defaultScheduler;
		this.#timeoutMs = opts.timeoutMs;
		this.localUri = `sip:${opts.username}@${this.#domain}`;
		this.#regCallId = newCallId(this.#domain);
		this.#regFromTag = newTag();
	}

	start(): void {
		void this.#pump();
	}

	// ---- outbound request machinery -------------------------------------------------------

	#viaHost(): string {
		return this.#contactHost;
	}

	#contactUri(withOutbound: boolean): string {
		const transport = this.#transport.toLowerCase();
		// RFC 5626: the outbound flow Contact carries ;ob in the URI plus reg-id + instance params
		const uri = withOutbound
			? `sip:${this.#opts.username}@${this.#contactHost};transport=${transport};ob`
			: `sip:${this.#opts.username}@${this.#contactHost};transport=${transport}`;
		let c = `<${uri}>`;
		if (withOutbound) c += `;reg-id=1;+sip.instance="${this.#instanceId}"`;
		return c;
	}

	// normalizes a bare user or full uri into a sip: uri under our domain
	#targetUri(to: string): string {
		if (to.includes(':')) return to; // already a uri
		return `sip:${to}@${this.#domain}`;
	}

	#buildRequest(
		method: string,
		requestUri: string,
		p: {
			callId: string;
			fromTag: string;
			toUri: string;
			toTag?: string;
			cseq: number;
			branch: string;
			extraHeaders?: Record<string, string>;
			contact?: string;
			body?: Uint8Array;
		}
	): SipRequest {
		const headers = new SipHeaders();
		headers.add('Via', `SIP/2.0/${this.#transport} ${this.#viaHost()};branch=${p.branch};rport`);
		headers.add('Max-Forwards', '70');
		const from = this.#opts.displayName
			? `"${this.#opts.displayName}" <${this.localUri}>;tag=${p.fromTag}`
			: `<${this.localUri}>;tag=${p.fromTag}`;
		headers.add('From', from);
		headers.add('To', p.toTag ? `<${p.toUri}>;tag=${p.toTag}` : `<${p.toUri}>`);
		headers.add('Call-ID', p.callId);
		headers.add('CSeq', `${p.cseq} ${method}`);
		if (p.contact) headers.add('Contact', p.contact);
		headers.add('User-Agent', USER_AGENT);
		if (p.extraHeaders) for (const [n, v] of Object.entries(p.extraHeaders)) headers.add(n, v);
		return { kind: 'request', method, uri: requestUri, headers, body: p.body ?? new Uint8Array(0) };
	}

	// sends a request keyed by branch and awaits its final (>= 200) response
	#send(branch: string, msg: SipRequest): Promise<SipResponse> {
		const d = deferred<SipResponse>();
		this.#pending.set(branch, d);
		return writeMessage(this.#writer, msg)
			.then(() => this.#withTimeout(d.promise))
			.catch((err) => {
				this.#pending.delete(branch);
				throw err;
			});
	}

	#withTimeout<T>(p: Promise<T>): Promise<T> {
		const ms = this.#timeoutMs;
		if (ms === undefined) return p;
		let timer: ReturnType<typeof setTimeout>;
		const t = new Promise<never>((_, reject) => {
			timer = setTimeout(
				() => reject(new TimeoutError('SIP response timed out', { protocol: PROTO })),
				ms
			);
		});
		return Promise.race([p, t]).finally(() => clearTimeout(timer)) as Promise<T>;
	}

	// builds the digest header for a request from the cached challenge, bumping nc
	async #authHeader(method: string, uri: string): Promise<{ name: string; value: string } | null> {
		if (!this.#authState || !this.#opts.password) return null;
		this.#authState.nc += 1;
		const nc = this.#authState.nc.toString(16).padStart(8, '0');
		const value = await computeDigestResponse({
			username: this.#opts.authUsername ?? this.#opts.username,
			password: this.#opts.password,
			method,
			uri,
			challenge: this.#authState.challenge,
			nc
		});
		return { name: this.#authState.headerName, value };
	}

	// caches the challenge from a 401/407 for preemptive auth on later requests
	#cacheChallenge(resp: SipResponse): boolean {
		const www = resp.headers.get('WWW-Authenticate');
		const proxy = resp.headers.get('Proxy-Authenticate');
		try {
			if (resp.status === 401 && www) {
				this.#authState = { headerName: 'Authorization', challenge: parseChallenge(www), nc: 0 };
				return true;
			}
			if (resp.status === 407 && proxy) {
				this.#authState = {
					headerName: 'Proxy-Authorization',
					challenge: parseChallenge(proxy),
					nc: 0
				};
				return true;
			}
		} catch {
			return false;
		}
		return false;
	}

	// runs one request with transparent digest retry on a 401/407
	async #request(
		method: string,
		requestUri: string,
		p: {
			callId: string;
			fromTag: string;
			toUri: string;
			toTag?: string;
			startCseq: number;
			extraHeaders?: Record<string, string>;
			contact?: string;
			body?: Uint8Array;
		}
	): Promise<{ response: SipResponse; cseq: number }> {
		this.#assertOpen();
		const attempt = async (cseq: number): Promise<SipResponse> => {
			const branch = newBranch();
			const msg = this.#buildRequest(method, requestUri, { ...p, cseq, branch });
			const auth = await this.#authHeader(method, requestUri);
			if (auth) msg.headers.add(auth.name, auth.value);
			return this.#send(branch, msg);
		};
		let cseq = p.startCseq;
		let response = await attempt(cseq);
		if ((response.status === 401 || response.status === 407) && this.#opts.password) {
			if (this.#cacheChallenge(response)) {
				cseq += 1;
				response = await attempt(cseq);
			}
		}
		return { response, cseq };
	}

	// ---- background read pump -------------------------------------------------------------

	async #pump(): Promise<void> {
		try {
			for (;;) {
				const msg = await readMessage(this.#reader);
				if (msg === null) break;
				if (msg.kind === 'response') this.#onResponse(msg);
				else await this.#onRequest(msg);
			}
		} catch (err) {
			if (!this.#closed) this.#pumpError = err as Error;
		} finally {
			const reason =
				this.#pumpError ?? new ConnectionError('SIP connection closed', { protocol: PROTO });
			for (const w of this.#pending.values()) w.reject(reason);
			this.#pending.clear();
			this.#inbox.end();
			for (const q of this.#subscriptions.values()) q.end();
			this.#subscriptions.clear();
		}
	}

	#onResponse(resp: SipResponse): void {
		const via = resp.headers.get('Via');
		const branch = via ? getParam(via, 'branch') : undefined;
		if (!branch) return;
		if (resp.status < 200) return; // provisional; keep waiting for the final
		const waiter = this.#pending.get(branch);
		if (waiter) {
			this.#pending.delete(branch);
			waiter.resolve(resp);
		}
	}

	async #onRequest(req: SipRequest): Promise<void> {
		switch (req.method) {
			case 'MESSAGE': {
				await this.#respond(req, 200, 'OK');
				const body = req.body;
				this.#inbox.push({
					from: req.headers.get('From') ?? '',
					to: req.headers.get('To') ?? '',
					contentType: req.headers.get('Content-Type'),
					body,
					text: () => decoder.decode(body)
				});
				return;
			}
			case 'NOTIFY': {
				await this.#respond(req, 200, 'OK');
				const callId = req.headers.get('Call-ID');
				const q = callId ? this.#subscriptions.get(callId) : undefined;
				if (q) {
					const body = req.body;
					q.push({
						state: req.headers.get('Subscription-State') ?? '',
						body,
						text: () => decoder.decode(body)
					});
					if (
						(req.headers.get('Subscription-State') ?? '').toLowerCase().startsWith('terminated')
					) {
						q.end();
						this.#subscriptions.delete(callId!);
					}
				}
				return;
			}
			case 'OPTIONS':
				await this.#respond(req, 200, 'OK', {
					Allow: 'INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, NOTIFY'
				});
				return;
			case 'BYE':
				await this.#respond(req, 200, 'OK');
				return;
			case 'INVITE':
				// inbound chat acceptance is out of scope; decline politely
				await this.#respond(req, 488, 'Not Acceptable Here');
				return;
			default:
				await this.#respond(req, 405, 'Method Not Allowed');
				return;
		}
	}

	// echoes the request's dialog headers into a response, adding a To-tag
	async #respond(
		req: SipRequest,
		status: number,
		reason: string,
		extraHeaders?: Record<string, string>,
		body?: Uint8Array
	): Promise<void> {
		const headers = new SipHeaders();
		for (const v of req.headers.getAll('Via')) headers.add('Via', v);
		headers.add('From', req.headers.get('From') ?? '');
		let to = req.headers.get('To') ?? '';
		if (!getParam(to, 'tag')) to += `;tag=${newTag()}`;
		headers.add('To', to);
		headers.add('Call-ID', req.headers.get('Call-ID') ?? '');
		headers.add('CSeq', req.headers.get('CSeq') ?? '');
		if (extraHeaders) for (const [n, v] of Object.entries(extraHeaders)) headers.add(n, v);
		const resp: SipResponse = {
			kind: 'response',
			status,
			reason,
			headers,
			body: body ?? new Uint8Array(0)
		};
		await writeMessage(this.#writer, resp).catch(() => {});
	}

	#assertOpen(): void {
		if (this.#closed) throw new ConnectionError('SIP session is closed', { protocol: PROTO });
		if (this.#pumpError) throw this.#pumpError;
	}

	// ---- public API -----------------------------------------------------------------------

	async register(opts?: { expiresSeconds?: number }): Promise<void> {
		const expires = opts?.expiresSeconds ?? this.#opts.expiresSeconds ?? DEFAULT_EXPIRES;
		this.#regCseq += 1;
		const { response, cseq } = await this.#request('REGISTER', `sip:${this.#domain}`, {
			callId: this.#regCallId,
			fromTag: this.#regFromTag,
			toUri: this.localUri,
			startCseq: this.#regCseq,
			contact: this.#contactUri(true),
			extraHeaders: { Expires: String(expires), Supported: 'path, outbound' }
		});
		// track the exact CSeq the (possibly retried) request consumed
		this.#regCseq = cseq;
		if (response.status === 401 || response.status === 407) {
			throw new AuthError(`SIP registration rejected: ${response.status} ${response.reason}`, {
				protocol: PROTO
			});
		}
		if (response.status < 200 || response.status >= 300) {
			throw new ProtocolError(`SIP REGISTER failed: ${response.status} ${response.reason}`, {
				protocol: PROTO
			});
		}
		// honor the granted expiry (Contact ;expires or the Expires header)
		const granted = this.#grantedExpires(response) ?? expires;
		this.#regExpires = granted;
		this.#registered = true;
		this.#scheduleRefresh(granted);
		this.#startKeepAlive();
	}

	#stopTimers(): void {
		if (this.#refreshHandle !== null) this.#scheduler.clear(this.#refreshHandle);
		if (this.#pingHandle !== null) this.#scheduler.clear(this.#pingHandle);
		this.#refreshHandle = null;
		this.#pingHandle = null;
	}

	// builds and writes a REGISTER with Expires: 0 (fire-and-forget; the reply is not awaited)
	async #writeUnregister(): Promise<void> {
		this.#regCseq += 1;
		const uri = `sip:${this.#domain}`;
		const msg = this.#buildRequest('REGISTER', uri, {
			callId: this.#regCallId,
			fromTag: this.#regFromTag,
			toUri: this.localUri,
			cseq: this.#regCseq,
			branch: newBranch(),
			contact: this.#contactUri(true),
			extraHeaders: { Expires: '0' }
		});
		const auth = await this.#authHeader('REGISTER', uri);
		if (auth) msg.headers.add(auth.name, auth.value);
		await writeMessage(this.#writer, msg).catch(() => {});
	}

	#grantedExpires(resp: SipResponse): number | undefined {
		const contact = resp.headers.get('Contact');
		if (contact) {
			const e = getParam(contact, 'expires');
			if (e && Number.isFinite(Number(e))) return Number(e);
		}
		const exp = resp.headers.get('Expires');
		if (exp && Number.isFinite(Number(exp))) return Number(exp);
		return undefined;
	}

	#scheduleRefresh(expires: number): void {
		if (this.#refreshHandle !== null) this.#scheduler.clear(this.#refreshHandle);
		// refresh at ~90% of the granted lifetime
		const ms = Math.max(1, Math.floor(expires * 0.9)) * 1000;
		this.#refreshHandle = this.#scheduler.set(() => {
			if (this.#closed) return;
			void this.register().catch(() => {});
		}, ms);
	}

	#startKeepAlive(): void {
		if (this.#pingHandle !== null) return;
		// RFC 5626 double-CRLF ping keeps the NAT/flow binding alive
		this.#pingHandle = this.#scheduler.set(() => {
			if (this.#closed) return;
			void this.#writer.write(new Uint8Array([0x0d, 0x0a, 0x0d, 0x0a])).catch(() => {});
		}, 25_000);
	}

	async unregister(): Promise<void> {
		if (!this.#registered) return;
		this.#registered = false;
		this.#stopTimers();
		await this.#writeUnregister();
	}

	async message(
		to: string,
		body: string,
		opts?: { contentType?: string; headers?: Record<string, string> }
	): Promise<SipResponse> {
		const target = this.#targetUri(to);
		const { response } = await this.#request('MESSAGE', target, {
			callId: newCallId(this.#domain),
			fromTag: newTag(),
			toUri: target,
			startCseq: 1,
			extraHeaders: { 'Content-Type': opts?.contentType ?? 'text/plain', ...opts?.headers },
			body: new TextEncoder().encode(body)
		});
		if (response.status === 401 || response.status === 407) {
			throw new AuthError(`SIP MESSAGE auth rejected: ${response.status}`, { protocol: PROTO });
		}
		if (response.status < 200 || response.status >= 300) {
			throw new ProtocolError(`SIP MESSAGE failed: ${response.status} ${response.reason}`, {
				protocol: PROTO
			});
		}
		return response;
	}

	async options(target?: string): Promise<OptionsResult> {
		const uri = target ? this.#targetUri(target) : `sip:${this.#domain}`;
		const { response } = await this.#request('OPTIONS', uri, {
			callId: newCallId(this.#domain),
			fromTag: newTag(),
			toUri: uri,
			startCseq: 1,
			extraHeaders: { Accept: 'application/sdp' }
		});
		const split = (h: string | undefined) =>
			h
				? h
						.split(',')
						.map((s) => s.trim())
						.filter(Boolean)
				: [];
		return {
			status: response.status,
			allow: response.headers.getAll('Allow').flatMap((v) => split(v)),
			accept: response.headers.getAll('Accept').flatMap((v) => split(v))
		};
	}

	async subscribePresence(
		target: string,
		opts?: { expiresSeconds?: number }
	): Promise<PresenceSubscription> {
		const uri = this.#targetUri(target);
		const callId = newCallId(this.#domain);
		const fromTag = newTag();
		const expires = opts?.expiresSeconds ?? 3600;
		const queue = new Queue<PresenceNotification>();
		this.#subscriptions.set(callId, queue);
		const { response } = await this.#request('SUBSCRIBE', uri, {
			callId,
			fromTag,
			toUri: uri,
			startCseq: 1,
			contact: this.#contactUri(false),
			extraHeaders: { Event: 'presence', Accept: 'application/pidf+xml', Expires: String(expires) }
		});
		if (response.status < 200 || response.status >= 300) {
			this.#subscriptions.delete(callId);
			queue.end();
			throw new ProtocolError(`SIP SUBSCRIBE failed: ${response.status} ${response.reason}`, {
				protocol: PROTO
			});
		}
		let cseq = 2;
		const unsubscribe = async (): Promise<void> => {
			queue.end();
			this.#subscriptions.delete(callId);
			await this.#request('SUBSCRIBE', uri, {
				callId,
				fromTag,
				toUri: uri,
				startCseq: cseq,
				contact: this.#contactUri(false),
				extraHeaders: { Event: 'presence', Expires: '0' }
			}).catch(() => {});
			cseq += 2;
		};
		const sub: PresenceSubscription = {
			[Symbol.asyncIterator](): AsyncIterator<PresenceNotification> {
				return { next: () => queue.next() };
			},
			unsubscribe,
			[Symbol.asyncDispose]: () => unsubscribe()
		};
		return sub;
	}

	async invite(target: string): Promise<SipChat> {
		const uri = this.#targetUri(target);
		const callId = newCallId(this.#domain);
		const fromTag = newTag();
		const localPath = `msrp://${this.#contactHost}:2855/${randomHex(8)};tcp`;
		const offer = buildMsrpOffer({ address: this.#contactHost, path: localPath, sessionId: '1' });
		const { response, cseq } = await this.#request('INVITE', uri, {
			callId,
			fromTag,
			toUri: uri,
			startCseq: 1,
			contact: this.#contactUri(false),
			extraHeaders: { 'Content-Type': 'application/sdp' },
			body: new TextEncoder().encode(offer)
		});
		if (response.status < 200 || response.status >= 300) {
			throw new ProtocolError(`SIP INVITE failed: ${response.status} ${response.reason}`, {
				protocol: PROTO
			});
		}
		// ACK the 2xx (in-dialog: To now carries the remote tag)
		const toTag = getParam(response.headers.get('To') ?? '', 'tag');
		await this.#sendAck(uri, callId, fromTag, toTag, cseq);

		const sdp = parseSdp(decoder.decode(response.body));
		const remotePath = sdp.media.find((m) => m.type === 'message')?.attributes.path;
		if (!remotePath) {
			await this.#sendBye(uri, callId, fromTag, toTag, cseq + 1);
			throw new ProtocolError('INVITE answer carried no MSRP path', { protocol: PROTO });
		}
		const msrp = await connectMsrp({ remotePath, localPath, timeoutMs: this.#timeoutMs });
		let byeCseq = cseq + 1;
		const bye = async (): Promise<void> => {
			await msrp.close();
			await this.#sendBye(uri, callId, fromTag, toTag, byeCseq).catch(() => {});
			byeCseq += 1;
		};
		const chat: SipChat = {
			msrp,
			send: (b, o) => msrp.send(b, o),
			messages: () => msrp.messages(),
			bye,
			[Symbol.asyncDispose]: () => bye()
		};
		return chat;
	}

	// ACK is a standalone request within the INVITE dialog (no response expected)
	async #sendAck(
		uri: string,
		callId: string,
		fromTag: string,
		toTag: string | undefined,
		cseq: number
	): Promise<void> {
		const branch = newBranch();
		const msg = this.#buildRequest('ACK', uri, {
			callId,
			fromTag,
			toUri: uri,
			toTag,
			cseq,
			branch
		});
		await writeMessage(this.#writer, msg).catch(() => {});
	}

	async #sendBye(
		uri: string,
		callId: string,
		fromTag: string,
		toTag: string | undefined,
		cseq: number
	): Promise<void> {
		const branch = newBranch();
		const msg = this.#buildRequest('BYE', uri, {
			callId,
			fromTag,
			toUri: uri,
			toTag,
			cseq,
			branch
		});
		await this.#send(branch, msg).catch(() => {});
	}

	messages(): AsyncIterable<SipInboundMessage> {
		const inbox = this.#inbox;
		return {
			[Symbol.asyncIterator](): AsyncIterator<SipInboundMessage> {
				return { next: () => inbox.next() };
			}
		};
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		this.#stopTimers();
		// best-effort un-REGISTER on the way out; do not wait for its reply
		if (this.#registered) {
			this.#registered = false;
			await this.#writeUnregister().catch(() => {});
		}
		this.#inbox.end();
		for (const q of this.#subscriptions.values()) q.end();
		this.#subscriptions.clear();
		for (const w of this.#pending.values()) {
			w.reject(new ConnectionError('SIP session closed', { protocol: PROTO }));
		}
		this.#pending.clear();
		await this.#socket.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

/**
 * Wraps an already-connected core socket in a {@link SipSession}.
 *
 * Public {@link connect} dials the transport then calls this; unit tests call it directly with
 * a mock socket to drive the protocol without a real network.
 *
 * @param socket - A connected core socket (already TLS when `tls: 'implicit'`).
 * @param opts - The session options.
 * @returns A ready session (not yet registered).
 * @internal
 */
export function _sessionFromSocket(socket: CoreSocket, opts: SipConnectOptions): SipSession {
	const session = new SipSessionImpl(socket, opts);
	session.start();
	return session;
}

/**
 * Connects to a SIP server over TCP/TLS and returns a session (not yet registered).
 *
 * Call {@link SipSession.register} to register (and receive inbound requests), or just
 * {@link SipSession.message} / {@link SipSession.options} for a stateless request. Use
 * `await using` (or {@link SipSession.close}) to release the connection.
 *
 * @param opts - Connection and identity options.
 * @returns The live session.
 * @throws {ConnectionError} If the connection cannot be established.
 * @since 1.0.3
 *
 * @example
 * ```typescript
 * import { connect } from 'edgeport/sip';
 *
 * await using ua = await connect({
 * 	hostname: 'sip.example.com',
 * 	username: 'alice',
 * 	password: env.SIP_PW
 * });
 * await ua.register();
 * await ua.message('bob', 'hello over SIP');
 * for await (const m of ua.messages()) console.log(m.from, m.text());
 * ```
 */
export async function connect(opts: SipConnectOptions): Promise<SipSession> {
	const port = opts.port ?? (opts.tls === 'implicit' ? DEFAULT_TLS_PORT : DEFAULT_PORT);
	const socket = await coreConnect({
		hostname: opts.hostname,
		port,
		tls: opts.tls === 'implicit' ? 'on' : 'off',
		connectTimeoutMs: opts.timeoutMs
	});
	try {
		return _sessionFromSocket(socket, opts);
	} catch (err) {
		await socket.close().catch(() => {});
		throw err;
	}
}

/**
 * Sends a single pager-mode `MESSAGE` in one call: connect, (auth on challenge), send, close.
 *
 * This needs no registration - the server challenges the MESSAGE, the client authenticates, and
 * the proxy routes it - so it fits a normal request-scoped Worker.
 *
 * @param opts - Connection/identity options plus the recipient and text.
 * @returns The final response.
 * @throws {AuthError} If the credentials are rejected.
 * @throws {ProtocolError} On a non-2xx result.
 * @since 1.0.3
 *
 * @example
 * ```typescript
 * import { sendMessage } from 'edgeport/sip';
 *
 * await sendMessage({
 * 	hostname: 'sip.example.com',
 * 	username: 'alice',
 * 	password: env.SIP_PW,
 * 	to: 'bob',
 * 	text: 'one-shot SIP message from the edge'
 * });
 * ```
 */
export async function sendMessage(
	opts: SipConnectOptions & { to: string; text: string; contentType?: string }
): Promise<SipResponse> {
	const session = await connect(opts);
	try {
		return await session.message(opts.to, opts.text, { contentType: opts.contentType });
	} finally {
		await session.close();
	}
}
