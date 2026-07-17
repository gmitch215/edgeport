/**
 * @fileoverview A DNS-over-TCP client for the Cloudflare Workers runtime (RFC 1035 + RFC 7766).
 *
 * DNS is a request/response protocol: a 16-bit id correlates each query with its response, and
 * over TCP every message is framed by a 2-byte big-endian length prefix (RFC 7766), which also
 * permits pipelining several queries on one connection and receiving the responses out of order.
 * This module dials the shared core transport, drives a background read pump that decodes framed
 * messages and correlates them to pending queries by id, and exposes three levels of API: the
 * {@link resolve} one-shots (and the typed `resolve4` / `resolveMx` / ... wrappers), a reusable
 * {@link DnsSession} that pipelines queries over one socket, and a raw {@link DnsSession.query}
 * that returns the full structured message (answer + authority + additional). It builds on the
 * core and never touches the runtime socket API directly.
 *
 * **UDP is impossible on Workers** - `cloudflare:sockets` opens TCP only - so this client is
 * TCP-only (DNS-over-TCP), and DNS-over-TLS (`tls: 'implicit'`, port 853) is offered on top.
 *
 * **Default resolver and the Cloudflare-IP block.** The default `hostname` is `1.1.1.1`
 * (`RESOLVERS.cloudflare`) to match the ecosystem's expectations, but a Worker's outbound TCP to
 * Cloudflare's own IP ranges - which include `1.1.1.1` - is blocked by the runtime. **When you
 * run inside a Worker you must pass a non-Cloudflare resolver** (for example `RESOLVERS.google`
 * or `RESOLVERS.quad9`); the `1.1.1.1` default is a convenience for local and other runtimes and
 * is intentionally left unchanged so behavior is predictable.
 *
 * @author Gregory Mitchell
 * @since 1.0.4
 */
import {
	ConnectionError,
	connect as coreConnect,
	ProtocolError,
	TimeoutError,
	type CoreSocket,
	type FramedReader,
	type FramedWriter
} from '../core';
import {
	decodeMessage,
	encodeMessage,
	encodeOptRecord,
	Opcode,
	RecordClass,
	RecordType,
	recordTypeNumber,
	ResponseCode,
	reverseName,
	type CaaRecord,
	type DnsFlags,
	type DnskeyRecord,
	type DnsMessage,
	type DsRecord,
	type MxRecord,
	type NaptrRecord,
	type Question,
	type RecordTypeName,
	type ResourceRecord,
	type RrsigRecord,
	type SoaRecord,
	type SrvRecord,
	type SshfpRecord,
	type SvcbRecord,
	type TlsaRecord
} from './message';

export * from './message';

const PROTO = 'dns';
const DEFAULT_DNS_PORT = 53;
const DEFAULT_DOT_PORT = 853;
const DEFAULT_TIMEOUT_MS = 5000;

/** The default resolver hostname; see the Cloudflare-IP-block note in the module overview. */
export const DEFAULT_RESOLVER = '1.1.1.1';

/**
 * Named public DNS resolvers, as IP addresses.
 *
 * Inside a Worker, `cloudflare` (`1.1.1.1`) is unreachable (the runtime blocks outbound TCP to
 * Cloudflare IPs), so pick `google`, `quad9`, or `opendns` there.
 *
 * @since 1.0.4
 */
export const RESOLVERS = {
	/** Cloudflare (`1.1.1.1`); unreachable from inside a Worker. */
	cloudflare: '1.1.1.1',
	/** Google Public DNS (`8.8.8.8`). */
	google: '8.8.8.8',
	/** Quad9 (`9.9.9.9`). */
	quad9: '9.9.9.9',
	/** OpenDNS (`208.67.222.222`). */
	opendns: '208.67.222.222'
} as const;

/**
 * Maps a queried record TYPE to the return type of {@link resolve} / {@link DnsSession.query}.
 *
 * `A`/`AAAA`/`NS`/`CNAME`/`PTR` return `string[]`; `TXT` returns `string[][]` (each record is an
 * array of its character-strings); the structured types return their record arrays; `SOA` returns
 * a single record or `undefined`; anything else returns {@link ResourceRecord}`[]`.
 *
 * @since 1.0.4
 */
export type ResolveResult<T extends RecordTypeName> = T extends
	'A' | 'AAAA' | 'NS' | 'CNAME' | 'PTR'
	? string[]
	: T extends 'TXT'
		? string[][]
		: T extends 'MX'
			? MxRecord[]
			: T extends 'SRV'
				? SrvRecord[]
				: T extends 'CAA'
					? CaaRecord[]
					: T extends 'SOA'
						? SoaRecord | undefined
						: T extends 'NAPTR'
							? NaptrRecord[]
							: T extends 'SSHFP'
								? SshfpRecord[]
								: T extends 'DS'
									? DsRecord[]
									: T extends 'DNSKEY'
										? DnskeyRecord[]
										: T extends 'TLSA'
											? TlsaRecord[]
											: T extends 'HTTPS' | 'SVCB'
												? SvcbRecord[]
												: T extends 'RRSIG'
													? RrsigRecord[]
													: ResourceRecord[];

/**
 * Options for {@link connect} (a reusable session).
 *
 * @since 1.0.4
 */
export interface DnsConnectOptions {
	/**
	 * Resolver host to dial; defaults to {@link DEFAULT_RESOLVER} (`1.1.1.1`). Inside a Worker,
	 * pass a non-Cloudflare resolver (`RESOLVERS.google` / `RESOLVERS.quad9`) - Cloudflare IPs are
	 * unreachable from the Workers runtime.
	 */
	hostname?: string;
	/** TCP port; defaults to 53 (plaintext) or 853 (`tls: 'implicit'`). */
	port?: number;
	/** Transport; only `'tcp'` is supported (Workers cannot open UDP). Defaults to `'tcp'`. */
	transport?: 'tcp';
	/**
	 * Transport security:
	 * - `'off'` (default): plaintext DNS-over-TCP.
	 * - `'implicit'`: DNS-over-TLS (DoT) from the first byte (port 853).
	 */
	tls?: 'off' | 'implicit';
	/** Per-query read deadline in milliseconds; defaults to 5000. */
	timeoutMs?: number;
}

/**
 * Per-query options for {@link DnsSession.query} and the typed one-shots.
 *
 * @since 1.0.4
 */
export interface QueryOptions {
	/** The record TYPE to ask for; defaults to `A`. */
	type?: RecordTypeName | RecordType | number;
	/** Set the EDNS0 DO bit to request DNSSEC records (adds an OPT record). */
	dnssec?: boolean;
	/** Override the session read deadline for this query, in milliseconds. */
	timeoutMs?: number;
}

/**
 * Options for the {@link resolve} one-shots (connection + query in one call).
 *
 * @since 1.0.4
 */
export interface ResolveOptions {
	/** The record TYPE to resolve; defaults to `A`. */
	type?: RecordTypeName | RecordType | number;
	/**
	 * Resolver to query; defaults to {@link DEFAULT_RESOLVER}. Inside a Worker, pass a
	 * non-Cloudflare resolver (`RESOLVERS.google` / `RESOLVERS.quad9`).
	 */
	server?: string;
	/** Resolver port; defaults to 53 (or 853 with `tls: 'implicit'`). */
	port?: number;
	/** Transport; only `'tcp'` is supported. */
	transport?: 'tcp';
	/** Transport security: `'off'` (default) or `'implicit'` (DNS-over-TLS, port 853). */
	tls?: 'off' | 'implicit';
	/** Set the EDNS0 DO bit to request DNSSEC records. */
	dnssec?: boolean;
	/** Query deadline in milliseconds; defaults to 5000. */
	timeoutMs?: number;
}

/**
 * Options for {@link lookup}.
 *
 * @since 1.0.4
 */
export interface LookupOptions extends ResolveOptions {
	/** Address family: `4` for A only, `6` for AAAA only, `0` (default) tries A then AAAA. */
	family?: 0 | 4 | 6;
}

/** One question for a raw {@link DnsSession.query}. */
export interface QuestionInput {
	/** The domain name to ask about. */
	name: string;
	/** The record TYPE (name or number). */
	type: RecordTypeName | RecordType | number;
	/** The CLASS; defaults to {@link RecordClass.IN}. */
	class?: RecordClass | number;
}

/**
 * A raw DNS query for the level-3 {@link DnsSession.query} path.
 *
 * @since 1.0.4
 */
export interface RawQuery {
	/** Override the 16-bit query id (a random unused id is allocated otherwise). */
	id?: number;
	/** Set the Recursion Desired flag; defaults to true. */
	recursionDesired?: boolean;
	/** The opcode; defaults to {@link Opcode.QUERY}. */
	opcode?: Opcode | number;
	/** Request DNSSEC records via an EDNS0 OPT record with the DO bit set. */
	dnssec?: boolean;
	/** The questions to ask (usually one). */
	questions: QuestionInput[];
}

/**
 * The full structured response returned by the raw {@link DnsSession.query}.
 *
 * @since 1.0.4
 */
export interface DnsResponse {
	/** The response id (matches the query). */
	id: number;
	/** The decoded flags word. */
	flags: DnsFlags;
	/** The response code (exposed as-is; the raw path never throws on an error rcode). */
	rcode: ResponseCode | number;
	/** The echoed question section. */
	question: Question[];
	/** The answer records. */
	answers: ResourceRecord[];
	/** The authority records (e.g. the SOA on an NXDOMAIN, or NS delegations). */
	authority: ResourceRecord[];
	/** The additional records (glue, and the server's OPT record). */
	additional: ResourceRecord[];
}

/**
 * A live DNS session over a single TCP (or TLS) connection.
 *
 * Obtain one from {@link connect}. A background pump reads length-prefixed responses and
 * correlates them to pending queries by id, so several {@link query} calls can be in flight at
 * once (RFC 7766 pipelining). It is an `AsyncDisposable`, so `await using` closes it cleanly.
 *
 * @since 1.0.4
 */
export interface DnsSession extends AsyncDisposable {
	/** The resolver host this session is connected to. */
	readonly hostname: string;
	/** Resolves `A`, `AAAA`, `NS`, `CNAME`, or `PTR` to a string array. */
	query(name: string, type: 'A' | 'AAAA' | 'NS' | 'CNAME' | 'PTR'): Promise<string[]>;
	/** Resolves `TXT` to an array of records, each an array of its character-strings. */
	query(name: string, type: 'TXT'): Promise<string[][]>;
	/** Resolves `MX` records. */
	query(name: string, type: 'MX'): Promise<MxRecord[]>;
	/** Resolves `SRV` records. */
	query(name: string, type: 'SRV'): Promise<SrvRecord[]>;
	/** Resolves `CAA` records. */
	query(name: string, type: 'CAA'): Promise<CaaRecord[]>;
	/** Resolves the `SOA` record (or `undefined` when absent). */
	query(name: string, type: 'SOA'): Promise<SoaRecord | undefined>;
	/** Resolves `NAPTR` records. */
	query(name: string, type: 'NAPTR'): Promise<NaptrRecord[]>;
	/** Resolves `SSHFP` records. */
	query(name: string, type: 'SSHFP'): Promise<SshfpRecord[]>;
	/** Resolves `DS` records. */
	query(name: string, type: 'DS'): Promise<DsRecord[]>;
	/** Resolves `DNSKEY` records. */
	query(name: string, type: 'DNSKEY'): Promise<DnskeyRecord[]>;
	/** Resolves `TLSA` records. */
	query(name: string, type: 'TLSA'): Promise<TlsaRecord[]>;
	/** Resolves `HTTPS` or `SVCB` service-binding records. */
	query(name: string, type: 'HTTPS' | 'SVCB'): Promise<SvcbRecord[]>;
	/** Resolves `RRSIG` records. */
	query(name: string, type: 'RRSIG'): Promise<RrsigRecord[]>;
	/** Resolves the record TYPE named in `opts.type`, with per-query options. */
	query<T extends RecordTypeName>(
		name: string,
		opts: QueryOptions & { type: T }
	): Promise<ResolveResult<T>>;
	/** Resolves with per-query options (numeric or omitted TYPE yields raw records). */
	query(name: string, opts?: QueryOptions): Promise<ResourceRecord[]>;
	/** Resolves a numeric record TYPE to its raw records. */
	query(name: string, type: RecordType | number): Promise<ResourceRecord[]>;
	/** Runs a raw query and returns the full structured message (answer + authority + additional). */
	query(raw: RawQuery): Promise<DnsResponse>;
	/**
	 * Closes the connection and rejects any in-flight queries.
	 *
	 * @returns Resolves once the socket is closed.
	 */
	close(): Promise<void>;
}

// a promise whose resolve/reject are exposed, used to await a response keyed by id
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

// deadline race for a response promise; TimeoutError when it elapses
function withTimeout<T>(promise: Promise<T>, ms: number | undefined): Promise<T> {
	if (ms === undefined) return promise;
	let timer: ReturnType<typeof setTimeout>;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(
			() => reject(new TimeoutError('dns query timed out', { protocol: PROTO })),
			ms
		);
	});
	return Promise.race([promise, timeout]).finally(() => clearTimeout(timer)) as Promise<T>;
}

// frames a bare DNS message with the 2-byte big-endian length prefix (RFC 7766)
function frame(message: Uint8Array): Uint8Array {
	if (message.length > 0xffff) {
		throw new ProtocolError('dns message exceeds the 65535-byte tcp frame limit', {
			protocol: PROTO
		});
	}
	const out = new Uint8Array(message.length + 2);
	out[0] = (message.length >> 8) & 0xff;
	out[1] = message.length & 0xff;
	out.set(message, 2);
	return out;
}

// reads one length-prefixed message off the reader; null on a clean end of stream
async function readMessage(reader: FramedReader): Promise<Uint8Array | null> {
	try {
		const lenBytes = await reader.readN(2);
		const len = (lenBytes[0]! << 8) | lenBytes[1]!;
		if (len === 0) return new Uint8Array(0);
		return await reader.readN(len);
	} catch (err) {
		if (err instanceof ConnectionError) return null;
		throw err;
	}
}

// maps a non-success rcode to an error, or null for NOERROR / NXDOMAIN (which resolve treats as empty)
function rcodeError(rcode: number): ProtocolError | null {
	if (rcode === ResponseCode.NOERROR || rcode === ResponseCode.NXDOMAIN) return null;
	const name = ResponseCode[rcode] ?? String(rcode);
	return new ProtocolError(`dns server returned ${name}`, { protocol: PROTO });
}

// filters a type's records out of an answer section and maps them to the typed resolve shape
function extract(type: number, answers: ResourceRecord[]): unknown {
	if (type === RecordType.ANY) return answers;
	const matched = answers.filter((rr) => rr.type === type);
	if (type === RecordType.SOA) return matched[0]?.data as SoaRecord | undefined;
	switch (type) {
		case RecordType.A:
		case RecordType.AAAA:
		case RecordType.NS:
		case RecordType.CNAME:
		case RecordType.PTR:
		case RecordType.TXT:
		case RecordType.MX:
		case RecordType.SRV:
		case RecordType.CAA:
		case RecordType.NAPTR:
		case RecordType.SSHFP:
		case RecordType.DS:
		case RecordType.DNSKEY:
		case RecordType.TLSA:
		case RecordType.RRSIG:
		case RecordType.SVCB:
		case RecordType.HTTPS:
			return matched.map((rr) => rr.data);
		default:
			return matched;
	}
}

class DnsSessionImpl implements DnsSession {
	readonly hostname: string;
	readonly #socket: CoreSocket;
	readonly #reader: FramedReader;
	readonly #writer: FramedWriter;
	readonly #timeoutMs: number;
	readonly #pending = new Map<number, Deferred<DnsMessage>>();
	#closed = false;
	#pumpError: Error | null = null;

	constructor(socket: CoreSocket, hostname: string, timeoutMs: number) {
		this.#socket = socket;
		this.#reader = socket.reader;
		this.#writer = socket.writer;
		this.hostname = hostname;
		this.#timeoutMs = timeoutMs;
	}

	_start(): void {
		void this.#pump();
	}

	async #pump(): Promise<void> {
		try {
			for (;;) {
				const raw = await readMessage(this.#reader);
				if (raw === null) break;
				let msg: DnsMessage;
				try {
					msg = decodeMessage(raw);
				} catch (err) {
					// reject the specific query if the id is still readable, otherwise drop the frame
					if (raw.length >= 2) {
						const id = (raw[0]! << 8) | raw[1]!;
						this.#reject(id, err as Error);
					}
					continue;
				}
				this.#resolve(msg.id, msg);
			}
		} catch (err) {
			if (!this.#closed) this.#pumpError = err as Error;
		} finally {
			const reason =
				this.#pumpError ?? new ConnectionError('dns connection closed', { protocol: PROTO });
			for (const waiter of this.#pending.values()) waiter.reject(reason);
			this.#pending.clear();
		}
	}

	#resolve(id: number, msg: DnsMessage): void {
		const waiter = this.#pending.get(id);
		if (waiter) {
			this.#pending.delete(id);
			waiter.resolve(msg);
		}
	}

	#reject(id: number, err: Error): void {
		const waiter = this.#pending.get(id);
		if (waiter) {
			this.#pending.delete(id);
			waiter.reject(err);
		}
	}

	#assertOpen(): void {
		if (this.#closed) throw new ConnectionError('dns session is closed', { protocol: PROTO });
		if (this.#pumpError) throw this.#pumpError;
	}

	// picks a random 16-bit id not currently awaiting a response
	#nextId(): number {
		const buf = new Uint16Array(1);
		for (let i = 0; i < 0x20000; i++) {
			crypto.getRandomValues(buf);
			if (!this.#pending.has(buf[0]!)) return buf[0]!;
		}
		throw new ProtocolError('exhausted dns query ids', { protocol: PROTO });
	}

	#buildQuery(
		questions: QuestionInput[],
		opts: { id?: number; recursionDesired?: boolean; opcode?: Opcode | number; dnssec?: boolean }
	): DnsMessage {
		const flags: DnsFlags = {
			qr: false,
			opcode: opts.opcode ?? Opcode.QUERY,
			aa: false,
			tc: false,
			rd: opts.recursionDesired ?? true,
			ra: false,
			z: false,
			ad: false,
			cd: false,
			rcode: ResponseCode.NOERROR
		};
		const question: Question[] = questions.map((q) => ({
			name: q.name,
			type: recordTypeNumber(q.type),
			class: q.class ?? RecordClass.IN
		}));
		const additional: ResourceRecord[] = opts.dnssec ? [encodeOptRecord({ dnssecOk: true })] : [];
		return {
			id: opts.id ?? this.#nextId(),
			flags,
			question,
			answer: [],
			authority: [],
			additional
		};
	}

	async #exchange(message: DnsMessage, timeoutMs: number | undefined): Promise<DnsMessage> {
		this.#assertOpen();
		const d = deferred<DnsMessage>();
		this.#pending.set(message.id, d);
		try {
			await this.#writer.write(frame(encodeMessage(message)));
			return await withTimeout(d.promise, timeoutMs ?? this.#timeoutMs);
		} finally {
			this.#pending.delete(message.id);
		}
	}

	async #queryTyped(name: string, opts: QueryOptions): Promise<unknown> {
		const type = recordTypeNumber(opts.type ?? 'A');
		const message = this.#buildQuery([{ name, type }], { dnssec: opts.dnssec });
		const response = await this.#exchange(message, opts.timeoutMs);
		const err = rcodeError(response.flags.rcode as number);
		if (err) throw err;
		return extract(type, response.answer);
	}

	async #queryRaw(raw: RawQuery): Promise<DnsResponse> {
		const message = this.#buildQuery(raw.questions, {
			id: raw.id,
			recursionDesired: raw.recursionDesired,
			opcode: raw.opcode,
			dnssec: raw.dnssec
		});
		const response = await this.#exchange(message, undefined);
		return {
			id: response.id,
			flags: response.flags,
			rcode: response.flags.rcode,
			question: response.question,
			answers: response.answer,
			authority: response.authority,
			additional: response.additional
		};
	}

	// single implementation backing every query overload; the DnsSession interface carries the
	// narrowed public signatures, so the broad return here is intentional
	query(
		arg1: string | RawQuery,
		arg2?: QueryOptions | RecordTypeName | RecordType | number
	): Promise<any> {
		if (typeof arg1 === 'string') {
			const opts: QueryOptions =
				typeof arg2 === 'object' && arg2 !== null
					? arg2
					: { type: arg2 as RecordTypeName | number };
			return this.#queryTyped(arg1, opts);
		}
		return this.#queryRaw(arg1);
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		await this.#socket.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

/**
 * Starts a DNS session over an already-connected {@link CoreSocket}.
 *
 * There is no DNS handshake, so this just wires up the read pump and returns the session. Public
 * {@link connect} dials the transport (and optionally TLS) before calling this; unit tests call
 * it directly with a mock socket.
 *
 * @param socket - A connected core socket (already TLS when `tls: 'implicit'`).
 * @param opts - Session options (hostname label and per-query timeout).
 * @returns The live session.
 * @internal
 */
export function _connectOverSocket(socket: CoreSocket, opts: DnsConnectOptions = {}): DnsSession {
	const session = new DnsSessionImpl(
		socket,
		opts.hostname ?? DEFAULT_RESOLVER,
		opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
	);
	session._start();
	return session;
}

/**
 * Connects to a DNS resolver over TCP (or TLS) and returns a reusable session.
 *
 * The session pipelines queries over one connection, correlating responses by id. Remember the
 * Cloudflare-IP block: inside a Worker, pass a non-Cloudflare `hostname` (e.g. `RESOLVERS.google`)
 * because the default `1.1.1.1` is unreachable from the Workers runtime.
 *
 * @param opts - Connection options (resolver host/port, TLS, timeout).
 * @returns The live session.
 * @throws {ConnectionError} If the connection cannot be established.
 * @throws {ProtocolError} If an unsupported transport is requested.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { connect, RESOLVERS } from 'edgeport/dns';
 *
 * await using dns = await connect({ hostname: RESOLVERS.google });
 * const ips = await dns.query('example.com', 'A');
 * const mx = await dns.query('example.com', 'MX');
 * ```
 */
export async function connect(opts: DnsConnectOptions = {}): Promise<DnsSession> {
	if (opts.transport !== undefined && opts.transport !== 'tcp') {
		throw new ProtocolError(
			`unsupported dns transport "${opts.transport}" (the Workers runtime supports tcp only)`,
			{ protocol: PROTO }
		);
	}
	const tls = opts.tls ?? 'off';
	const hostname = opts.hostname ?? DEFAULT_RESOLVER;
	const port = opts.port ?? (tls === 'implicit' ? DEFAULT_DOT_PORT : DEFAULT_DNS_PORT);
	const socket = await coreConnect({
		hostname,
		port,
		tls: tls === 'implicit' ? 'on' : 'off',
		connectTimeoutMs: opts.timeoutMs
	});
	try {
		return _connectOverSocket(socket, { ...opts, hostname });
	} catch (err) {
		await socket.close().catch(() => {});
		throw err;
	}
}

// maps resolve options (server-named) to connect options (hostname-named)
function toConnectOptions(opts: ResolveOptions): DnsConnectOptions {
	return {
		hostname: opts.server,
		port: opts.port,
		transport: opts.transport,
		tls: opts.tls,
		timeoutMs: opts.timeoutMs
	};
}

// opens a one-shot session, runs fn, and always closes
async function withSession<R>(
	opts: DnsConnectOptions,
	fn: (session: DnsSession) => Promise<R>
): Promise<R> {
	const session = await connect(opts);
	try {
		return await fn(session);
	} finally {
		await session.close();
	}
}

// one-shot typed query used by resolve and the typed wrappers; returns the untyped result
function oneShot(name: string, opts: ResolveOptions): Promise<unknown> {
	return withSession(toConnectOptions(opts), (session) =>
		(session.query as (n: string, o: QueryOptions) => Promise<unknown>)(name, {
			type: opts.type,
			dnssec: opts.dnssec,
			timeoutMs: opts.timeoutMs
		})
	);
}

/**
 * Resolves a name to `A` records (the default type): the IPv4 addresses as strings.
 *
 * @param name - The domain name.
 * @returns The IPv4 addresses; empty on NXDOMAIN or no records.
 */
export function resolve(name: string): Promise<string[]>;
/** Resolves a name to a string array (`A`/`AAAA`/`NS`/`CNAME`/`PTR`). */
export function resolve(
	name: string,
	type: 'A' | 'AAAA' | 'NS' | 'CNAME' | 'PTR'
): Promise<string[]>;
/** Resolves `TXT` records (each an array of its character-strings). */
export function resolve(name: string, type: 'TXT'): Promise<string[][]>;
/** Resolves `MX` records. */
export function resolve(name: string, type: 'MX'): Promise<MxRecord[]>;
/** Resolves `SRV` records. */
export function resolve(name: string, type: 'SRV'): Promise<SrvRecord[]>;
/** Resolves `CAA` records. */
export function resolve(name: string, type: 'CAA'): Promise<CaaRecord[]>;
/** Resolves the `SOA` record (or `undefined`). */
export function resolve(name: string, type: 'SOA'): Promise<SoaRecord | undefined>;
/** Resolves `NAPTR` records. */
export function resolve(name: string, type: 'NAPTR'): Promise<NaptrRecord[]>;
/** Resolves `SSHFP` records. */
export function resolve(name: string, type: 'SSHFP'): Promise<SshfpRecord[]>;
/** Resolves `DS` records. */
export function resolve(name: string, type: 'DS'): Promise<DsRecord[]>;
/** Resolves `DNSKEY` records. */
export function resolve(name: string, type: 'DNSKEY'): Promise<DnskeyRecord[]>;
/** Resolves `TLSA` records. */
export function resolve(name: string, type: 'TLSA'): Promise<TlsaRecord[]>;
/** Resolves `HTTPS` or `SVCB` service-binding records. */
export function resolve(name: string, type: 'HTTPS' | 'SVCB'): Promise<SvcbRecord[]>;
/** Resolves `RRSIG` records. */
export function resolve(name: string, type: 'RRSIG'): Promise<RrsigRecord[]>;
/** Resolves the type named in `opts.type` (with resolver/tls/dnssec options). */
export function resolve<T extends RecordTypeName>(
	name: string,
	opts: ResolveOptions & { type: T }
): Promise<ResolveResult<T>>;
/** Resolves with options; a numeric or omitted TYPE yields raw records. */
export function resolve(name: string, opts: ResolveOptions): Promise<ResourceRecord[]>;
/** Resolves a numeric record TYPE to its raw records. */
export function resolve(name: string, type: RecordType | number): Promise<ResourceRecord[]>;
/**
 * Resolves a DNS name in a single call, opening and closing a connection around one query.
 *
 * The return type narrows on the requested TYPE (see {@link ResolveResult}); `A` addresses come
 * back as `string[]`, `MX` as {@link MxRecord}`[]`, and so on. NXDOMAIN and "no records" both
 * yield an empty array (never a throw); a server error rcode (`SERVFAIL`, `REFUSED`, ...) throws
 * a {@link ProtocolError}. Pass `server` to choose the resolver - inside a Worker this must be a
 * non-Cloudflare resolver such as `RESOLVERS.google`, because the `1.1.1.1` default is blocked by
 * the runtime.
 *
 * @param name - The domain name to resolve.
 * @param typeOrOpts - A record TYPE (name or number) or a {@link ResolveOptions} object.
 * @returns The resolved records, typed per the TYPE.
 * @throws {ProtocolError} On a server error rcode or a malformed response.
 * @throws {ConnectionError} If the resolver cannot be reached.
 * @throws {TimeoutError} If the query deadline elapses.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { resolve, RESOLVERS } from 'edgeport/dns';
 *
 * const a = await resolve('example.com', 'A'); // string[]
 * const mx = await resolve('example.com', 'MX'); // MxRecord[]
 * const aaaa = await resolve('example.com', { type: 'AAAA', server: RESOLVERS.google });
 * ```
 */
export function resolve(
	name: string,
	typeOrOpts?: RecordTypeName | RecordType | number | ResolveOptions
): Promise<unknown> {
	const opts: ResolveOptions =
		typeof typeOrOpts === 'object' && typeOrOpts !== null
			? typeOrOpts
			: { type: typeOrOpts as RecordTypeName | number | undefined };
	return oneShot(name, opts);
}

/**
 * Resolves the IPv4 (`A`) addresses of a name.
 *
 * @param name - The domain name.
 * @param opts - Resolver/query options.
 * @returns The IPv4 addresses as strings.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { resolve4, RESOLVERS } from 'edgeport/dns';
 *
 * const ips = await resolve4('example.com', { server: RESOLVERS.google });
 * ```
 */
export function resolve4(name: string, opts: ResolveOptions = {}): Promise<string[]> {
	return oneShot(name, { ...opts, type: 'A' }) as Promise<string[]>;
}

/**
 * Resolves the IPv6 (`AAAA`) addresses of a name.
 *
 * @param name - The domain name.
 * @param opts - Resolver/query options.
 * @returns The IPv6 addresses as compressed strings.
 * @since 1.0.4
 */
export function resolve6(name: string, opts: ResolveOptions = {}): Promise<string[]> {
	return oneShot(name, { ...opts, type: 'AAAA' }) as Promise<string[]>;
}

/**
 * Resolves the mail-exchange (`MX`) records of a name.
 *
 * @param name - The domain name.
 * @param opts - Resolver/query options.
 * @returns The MX records.
 * @since 1.0.4
 */
export function resolveMx(name: string, opts: ResolveOptions = {}): Promise<MxRecord[]> {
	return oneShot(name, { ...opts, type: 'MX' }) as Promise<MxRecord[]>;
}

/**
 * Resolves the text (`TXT`) records of a name.
 *
 * @param name - The domain name.
 * @param opts - Resolver/query options.
 * @returns Each TXT record as an array of its character-strings.
 * @since 1.0.4
 */
export function resolveTxt(name: string, opts: ResolveOptions = {}): Promise<string[][]> {
	return oneShot(name, { ...opts, type: 'TXT' }) as Promise<string[][]>;
}

/**
 * Resolves the name-server (`NS`) records of a name.
 *
 * @param name - The domain name.
 * @param opts - Resolver/query options.
 * @returns The name-server host names.
 * @since 1.0.4
 */
export function resolveNs(name: string, opts: ResolveOptions = {}): Promise<string[]> {
	return oneShot(name, { ...opts, type: 'NS' }) as Promise<string[]>;
}

/**
 * Resolves the canonical-name (`CNAME`) records of a name.
 *
 * @param name - The domain name.
 * @param opts - Resolver/query options.
 * @returns The CNAME targets.
 * @since 1.0.4
 */
export function resolveCname(name: string, opts: ResolveOptions = {}): Promise<string[]> {
	return oneShot(name, { ...opts, type: 'CNAME' }) as Promise<string[]>;
}

/**
 * Resolves the start-of-authority (`SOA`) record of a name.
 *
 * @param name - The domain name.
 * @param opts - Resolver/query options.
 * @returns The SOA record, or `undefined` if none is present.
 * @since 1.0.4
 */
export function resolveSoa(
	name: string,
	opts: ResolveOptions = {}
): Promise<SoaRecord | undefined> {
	return oneShot(name, { ...opts, type: 'SOA' }) as Promise<SoaRecord | undefined>;
}

/**
 * Resolves the service-location (`SRV`) records of a name.
 *
 * @param name - The service name (e.g. `_sip._tcp.example.com`).
 * @param opts - Resolver/query options.
 * @returns The SRV records.
 * @since 1.0.4
 */
export function resolveSrv(name: string, opts: ResolveOptions = {}): Promise<SrvRecord[]> {
	return oneShot(name, { ...opts, type: 'SRV' }) as Promise<SrvRecord[]>;
}

/**
 * Resolves the Certification Authority Authorization (`CAA`) records of a name.
 *
 * @param name - The domain name.
 * @param opts - Resolver/query options.
 * @returns The CAA records.
 * @since 1.0.4
 */
export function resolveCaa(name: string, opts: ResolveOptions = {}): Promise<CaaRecord[]> {
	return oneShot(name, { ...opts, type: 'CAA' }) as Promise<CaaRecord[]>;
}

/**
 * Resolves the pointer (`PTR`) records of a name (the raw name, not an IP - see {@link reverse}).
 *
 * @param name - The name to query (often an `.arpa` name).
 * @param opts - Resolver/query options.
 * @returns The PTR target names.
 * @since 1.0.4
 */
export function resolvePtr(name: string, opts: ResolveOptions = {}): Promise<string[]> {
	return oneShot(name, { ...opts, type: 'PTR' }) as Promise<string[]>;
}

/**
 * Resolves the Naming Authority Pointer (`NAPTR`) records of a name.
 *
 * @param name - The domain name.
 * @param opts - Resolver/query options.
 * @returns The NAPTR records.
 * @since 1.0.4
 */
export function resolveNaptr(name: string, opts: ResolveOptions = {}): Promise<NaptrRecord[]> {
	return oneShot(name, { ...opts, type: 'NAPTR' }) as Promise<NaptrRecord[]>;
}

/**
 * Resolves the DANE `TLSA` records of a name (e.g. `_443._tcp.example.com`).
 *
 * @param name - The `_port._proto.host` name.
 * @param opts - Resolver/query options.
 * @returns The TLSA records.
 * @since 1.0.4
 */
export function resolveTlsa(name: string, opts: ResolveOptions = {}): Promise<TlsaRecord[]> {
	return oneShot(name, { ...opts, type: 'TLSA' }) as Promise<TlsaRecord[]>;
}

/**
 * Resolves the SSH fingerprint (`SSHFP`) records of a name.
 *
 * @param name - The host name.
 * @param opts - Resolver/query options.
 * @returns The SSHFP records.
 * @since 1.0.4
 */
export function resolveSshfp(name: string, opts: ResolveOptions = {}): Promise<SshfpRecord[]> {
	return oneShot(name, { ...opts, type: 'SSHFP' }) as Promise<SshfpRecord[]>;
}

/**
 * Resolves the Delegation Signer (`DS`) records of a name.
 *
 * @param name - The domain name.
 * @param opts - Resolver/query options.
 * @returns The DS records.
 * @since 1.0.4
 */
export function resolveDs(name: string, opts: ResolveOptions = {}): Promise<DsRecord[]> {
	return oneShot(name, { ...opts, type: 'DS' }) as Promise<DsRecord[]>;
}

/**
 * Resolves the `DNSKEY` records of a name.
 *
 * @param name - The zone name.
 * @param opts - Resolver/query options.
 * @returns The DNSKEY records.
 * @since 1.0.4
 */
export function resolveDnskey(name: string, opts: ResolveOptions = {}): Promise<DnskeyRecord[]> {
	return oneShot(name, { ...opts, type: 'DNSKEY' }) as Promise<DnskeyRecord[]>;
}

/**
 * Resolves the `HTTPS` service-binding records of a name (RFC 9460).
 *
 * @param name - The host name.
 * @param opts - Resolver/query options.
 * @returns The HTTPS service-binding records.
 * @since 1.0.4
 */
export function resolveHttps(name: string, opts: ResolveOptions = {}): Promise<SvcbRecord[]> {
	return oneShot(name, { ...opts, type: 'HTTPS' }) as Promise<SvcbRecord[]>;
}

/**
 * Reverse-resolves an IP address to its host names via a PTR query.
 *
 * Builds the `in-addr.arpa` (IPv4) or nibble-reversed `ip6.arpa` (IPv6) name and queries it for
 * PTR records.
 *
 * @param ip - The IPv4 or IPv6 address.
 * @param opts - Resolver/query options.
 * @returns The PTR target names; empty if there is no reverse record.
 * @throws {ProtocolError} If `ip` is not a valid address, or on a server error rcode.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { reverse, RESOLVERS } from 'edgeport/dns';
 *
 * const names = await reverse('8.8.8.8', { server: RESOLVERS.google }); // ['dns.google', ...]
 * ```
 */
export function reverse(ip: string, opts: ResolveOptions = {}): Promise<string[]> {
	return oneShot(reverseName(ip), { ...opts, type: 'PTR' }) as Promise<string[]>;
}

/**
 * Node-style lookup: resolves a name to its first address as a string.
 *
 * Tries `A` first (or `AAAA` when `family: 6`), then falls back to the other family when
 * `family` is `0` (the default). Returns `undefined` when the name has no address.
 *
 * @param name - The domain name.
 * @param opts - Resolver options plus an optional address `family` (`0` | `4` | `6`).
 * @returns The first address, or `undefined` if unresolved.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { lookup, RESOLVERS } from 'edgeport/dns';
 *
 * const ip = await lookup('example.com', { server: RESOLVERS.google });
 * ```
 */
export async function lookup(name: string, opts: LookupOptions = {}): Promise<string | undefined> {
	const family = opts.family ?? 0;
	if (family === 6) return (await resolve6(name, opts))[0];
	const a = await resolve4(name, opts);
	if (a.length > 0) return a[0];
	if (family === 4) return undefined;
	return (await resolve6(name, opts))[0];
}

/**
 * Runs a raw DNS query in a single call and returns the full structured response.
 *
 * The level-3 tooling path: it never throws on an error rcode (the rcode is on the result), and
 * it exposes the authority and additional sections. Opens and closes a connection around the one
 * query.
 *
 * @param raw - The raw query (questions, flags, opcode, optional DNSSEC).
 * @param opts - Connection options (resolver host/port, TLS, timeout).
 * @returns The full structured response.
 * @throws {ConnectionError} If the resolver cannot be reached.
 * @throws {ProtocolError} If the response is malformed.
 * @throws {TimeoutError} If the query deadline elapses.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { query, RESOLVERS } from 'edgeport/dns';
 *
 * const res = await query(
 * 	{ questions: [{ name: 'example.com', type: 'A' }], dnssec: true },
 * 	{ hostname: RESOLVERS.quad9 }
 * );
 * console.log(res.rcode, res.answers, res.authority);
 * ```
 */
export function query(raw: RawQuery, opts: DnsConnectOptions = {}): Promise<DnsResponse> {
	return withSession(opts, (session) => session.query(raw));
}
