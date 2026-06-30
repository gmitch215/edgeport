/**
 * @fileoverview An LDAP v3 client (RFC 4511) for the Cloudflare Workers runtime.
 *
 * LDAP is a binary protocol: every request and response is a BER-encoded `LDAPMessage` sent
 * over a single TCP connection. This module speaks the slice of it most Workers need: a simple
 * (DN + password) bind and a subtree/one-level/base search returning entries and their
 * attributes. It supports plaintext (port 389), the StartTLS extended operation, and -- through
 * the sibling `edgeport/ldaps` module -- implicit TLS (port 636).
 *
 * Messages are framed by reading the tag byte, then the definite length (short or long form),
 * then the exact content with {@link FramedReader.readN}. Responses carry the `messageID` of
 * the request that produced them; a search reads `SearchResultEntry` messages until the
 * matching `SearchResultDone` arrives.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import {
	AuthError,
	ProtocolError,
	connect as coreConnect,
	type CoreSocket,
	type FramedReader,
	type FramedWriter
} from '../core';
import { BerReader, BerWriter, applicationTag, contextTag } from './ber';
import { encodeFilter, parseFilter, type Filter } from './filter';

const DEFAULT_LDAP_PORT = 389;
const PROTO = 'ldap';
const STARTTLS_OID = '1.3.6.1.4.1.1466.20037';
const decoder = new TextDecoder();
const writer = new BerWriter();

// LDAP protocolOp application tags (RFC 4511 4.2+)
const OP_BIND_REQUEST = 0;
const OP_BIND_RESPONSE = 1;
const OP_UNBIND_REQUEST = 2;
const OP_SEARCH_REQUEST = 3;
const OP_SEARCH_RESULT_ENTRY = 4;
const OP_SEARCH_RESULT_DONE = 5;
const OP_EXTENDED_REQUEST = 23;
const OP_EXTENDED_RESPONSE = 24;
// simple-auth credential is context [0] primitive within BindRequest
const AUTH_SIMPLE = 0;
// ExtendedRequest requestName is context [0] primitive
const EXT_REQUEST_NAME = 0;

const SCOPE_CODE: Record<SearchScope, number> = { base: 0, one: 1, sub: 2 };
const RESULT_SUCCESS = 0;
const RESULT_SIZE_LIMIT_EXCEEDED = 4;
const RESULT_INVALID_CREDENTIALS = 49;

/** Re-export of the structured {@link Filter} union for callers building filters directly. */
export { encodeFilter, parseFilter } from './filter';
export type {
	AndOrFilter,
	AttributeValueFilter,
	Filter,
	NotFilter,
	PresentFilter,
	SubstringsFilter
} from './filter';

// injection-safe filter builders + escaping helpers
export {
	and,
	approx,
	contains,
	eq,
	escapeDN,
	escapeFilterValue,
	filters,
	gte,
	lte,
	not,
	or,
	present,
	substring
} from './builders';

/** Search scope: a single entry, its immediate children, or the whole subtree. */
export type SearchScope = 'base' | 'one' | 'sub';

/** Options for {@link connect} and {@link search}. */
export interface LdapConnectOptions {
	/** Remote LDAP host. */
	hostname: string;
	/** Remote port; defaults to 389 (or 636 via `edgeport/ldaps`). */
	port?: number;
	/**
	 * Transport security:
	 * - `'off'` (default): plaintext LDAP.
	 * - `'implicit'`: TLS from the first byte (LDAPS).
	 * - `'starttls'`: plaintext, upgraded with the StartTLS extended operation before bind.
	 */
	tls?: 'off' | 'implicit' | 'starttls';
	/**
	 * Hostname the server's TLS certificate must match (server-identity verification). Applies
	 * to the StartTLS upgrade; defaults to {@link LdapConnectOptions.hostname}. For implicit
	 * LDAPS the runtime validates the certificate against the connection hostname directly.
	 */
	expectedServerHostname?: string;
	/** Bind DN; when provided, {@link connect} binds before returning. */
	bindDN?: string;
	/** Bind password; paired with {@link LdapConnectOptions.bindDN}. */
	password?: string;
	/** Per-operation read deadline in milliseconds. */
	timeoutMs?: number;
}

/** Options for {@link LdapSession.search} and the one-shot {@link search}. */
export interface SearchOptions {
	/** The base DN to search under. */
	base: string;
	/** Search scope; defaults to `'sub'`. */
	scope?: SearchScope;
	/** A filter string (RFC 4515) or structured {@link Filter}; defaults to `(objectClass=*)`. */
	filter?: string | Filter;
	/** Attribute names to return; empty or omitted returns all user attributes. */
	attributes?: string[];
	/** Maximum number of entries the server should return (0 = no client-side limit). */
	sizeLimit?: number;
}

/** A single search result: a distinguished name and its attribute values. */
export interface LdapEntry {
	/** The entry's distinguished name. */
	dn: string;
	/** Attribute values keyed by attribute description; values decoded as UTF-8. */
	attributes: Record<string, string[]>;
}

/**
 * An LDAP session over a single connection.
 *
 * Obtain one from {@link connect}. It is an `AsyncDisposable`, so it can be scoped with
 * `await using` to guarantee an unbind and socket close.
 *
 * @since 1.0.0
 */
export interface LdapSession extends AsyncDisposable {
	/**
	 * Performs a simple bind with the given DN and password.
	 *
	 * @param dn - The bind DN.
	 * @param password - The password.
	 * @returns Resolves once the server accepts the bind.
	 * @throws {AuthError} If the credentials are rejected (result code 49).
	 * @throws {ProtocolError} For any other non-success result code.
	 */
	bind(dn: string, password: string): Promise<void>;
	/**
	 * Runs a search and returns every matching entry.
	 *
	 * @param opts - The search parameters.
	 * @returns The matched entries.
	 * @throws {ProtocolError} If the server returns a non-success result in `SearchResultDone`.
	 */
	search(opts: SearchOptions): Promise<LdapEntry[]>;
	/**
	 * Runs a search capped at a single result and returns the first entry, or `null` if none
	 * match. Forces `sizeLimit` to 1 regardless of what `opts` carries.
	 *
	 * @param opts - The search parameters; `sizeLimit` is overridden to 1.
	 * @returns The first matching entry, or `null` when there are none.
	 * @throws {ProtocolError} If the server returns a non-success result in `SearchResultDone`.
	 */
	findOne(opts: SearchOptions): Promise<LdapEntry | null>;
	/** Sends an unbind request and closes the connection. */
	close(): Promise<void>;
}

/**
 * Opens an LDAP connection, optionally upgrading to TLS and binding.
 *
 * When {@link LdapConnectOptions.tls} is `'implicit'` the socket is TLS from the first byte;
 * when `'starttls'` the StartTLS extended operation runs and the socket is upgraded before any
 * bind. If {@link LdapConnectOptions.bindDN} is set, a simple bind is performed before the
 * session is returned.
 *
 * @param opts - Connection options.
 * @returns A ready {@link LdapSession}.
 * @throws {AuthError} If a requested bind is rejected.
 * @throws {ConnectionError} If the connection or TLS upgrade fails.
 * @throws {ProtocolError} If the server misbehaves during StartTLS or bind.
 * @since 1.0.0
 * @example
 * ```typescript
 * await using session = await connect({
 *   hostname: 'ldap.example.com',
 *   bindDN: 'cn=admin,dc=example,dc=com',
 *   password: 'secret'
 * });
 * const users = await session.search({ base: 'dc=example,dc=com', filter: '(uid=jdoe)' });
 * ```
 */
export async function connect(opts: LdapConnectOptions): Promise<LdapSession> {
	const tls = opts.tls ?? 'off';
	const port = opts.port ?? DEFAULT_LDAP_PORT;
	let socket = await coreConnect({
		hostname: opts.hostname,
		port,
		tls: tls === 'implicit' ? 'on' : tls === 'starttls' ? 'starttls' : 'off',
		connectTimeoutMs: opts.timeoutMs
	});

	if (tls === 'starttls') {
		socket = await runStartTls(socket, opts);
	}

	return _sessionOverSocket(socket, opts);
}

/**
 * One-shot search: connect (optionally bind), search, and close in a single call.
 *
 * @param opts - Connection and search options combined.
 * @returns The matched entries.
 * @throws {AuthError} If a requested bind is rejected.
 * @throws {ProtocolError} If the search fails.
 * @since 1.0.0
 * @example
 * ```typescript
 * const entries = await search({
 *   hostname: 'ldap.example.com',
 *   bindDN: 'cn=admin,dc=example,dc=com',
 *   password: 'secret',
 *   base: 'dc=example,dc=com',
 *   filter: '(objectClass=person)'
 * });
 * ```
 */
export async function search(opts: LdapConnectOptions & SearchOptions): Promise<LdapEntry[]> {
	const session = await connect(opts);
	try {
		return await session.search(opts);
	} finally {
		await session.close();
	}
}

/**
 * Options for {@link authenticate}: connection settings plus the user lookup and the candidate
 * password.
 *
 * The service-account credentials used for the lookup are {@link LdapConnectOptions.bindDN} and
 * {@link AuthenticateOptions.bindPassword}; when neither is set the lookup binds anonymously.
 * The top-level {@link AuthenticateOptions.password} is the *user's* candidate password,
 * verified by re-binding as the located entry (it overrides the inherited connect-options
 * `password` so the two roles never collide).
 */
export interface AuthenticateOptions extends LdapConnectOptions {
	/** Base DN to search for the user under. */
	base: string;
	/**
	 * Filter selecting the user entry, as an RFC 4515 string or a structured {@link Filter}.
	 * Prefer a structured filter built from {@link eq}/{@link and} so untrusted usernames cannot
	 * inject filter syntax.
	 */
	userFilter: string | Filter;
	/** The user's candidate password, verified by re-binding as the located entry. */
	password: string;
	/** Service-account password for the lookup bind; omit (with no `bindDN`) to bind anonymously. */
	bindPassword?: string;
	/** Scope for the user lookup; defaults to `'sub'`. */
	scope?: SearchScope;
	/** Attributes to return on the located entry; omitted returns all user attributes. */
	attributes?: string[];
}

/**
 * Authenticates a user by the bind-search-bind pattern.
 *
 * Connects and binds as the service account ({@link LdapConnectOptions.bindDN} /
 * {@link AuthenticateOptions.bindPassword}), or anonymously when no `bindDN` is given; searches
 * under `base` for the entry matching `userFilter` (capped at one result); then re-binds as that
 * entry's DN with the user's {@link AuthenticateOptions.password}. The session is always closed
 * before returning.
 *
 * @param opts - Connection settings, the user lookup, and the candidate password.
 * @returns The matched entry on a successful password bind, or `null` when no entry matches or
 *   the password is wrong.
 * @throws {ConnectionError} If the connection or TLS upgrade fails.
 * @throws {AuthError} If the *service-account* bind is rejected (a wrong user password returns
 *   `null` instead).
 * @throws {ProtocolError} If the server misbehaves during search or bind.
 * @since 1.0.2
 * @example
 * ```typescript
 * const entry = await authenticate({
 *   hostname: 'ldap.example.org',
 *   bindDN: 'cn=admin,dc=example,dc=org',
 *   bindPassword: 'service-secret',
 *   base: 'ou=people,dc=example,dc=org',
 *   userFilter: eq('uid', 'jdoe'),
 *   password: 'the-user-password'
 * });
 * if (entry) {
 *   // authenticated; entry.dn is the bound user
 * }
 * ```
 */
export async function authenticate(opts: AuthenticateOptions): Promise<LdapEntry | null> {
	// service-account (or anonymous) bind to perform the lookup
	const session = await connect({
		hostname: opts.hostname,
		port: opts.port,
		tls: opts.tls,
		expectedServerHostname: opts.expectedServerHostname,
		bindDN: opts.bindDN,
		password: opts.bindDN !== undefined ? (opts.bindPassword ?? '') : undefined,
		timeoutMs: opts.timeoutMs
	});
	try {
		const entry = await session.findOne({
			base: opts.base,
			scope: opts.scope ?? 'sub',
			filter: opts.userFilter,
			attributes: opts.attributes
		});
		if (entry === null) return null;
		try {
			await session.bind(entry.dn, opts.password);
			return entry;
		} catch (err) {
			// wrong password -> bad bind; treat as auth failure, rethrow anything else
			if (err instanceof AuthError) return null;
			throw err;
		}
	} finally {
		await session.close();
	}
}

// runs the StartTLS extended op then upgrades the socket; reader/writer are re-acquired by caller
async function runStartTls(socket: CoreSocket, opts: LdapConnectOptions): Promise<CoreSocket> {
	const msgId = 1;
	// ExtendedRequest [APPLICATION 23] { requestName [0] OID }
	const body = writer.tagged(
		contextTag(EXT_REQUEST_NAME, false),
		new TextEncoder().encode(STARTTLS_OID)
	);
	const req = writer.sequence([
		writer.integer(msgId),
		writer.tagged(applicationTag(OP_EXTENDED_REQUEST, true), body)
	]);
	await socket.writer.write(req);

	const { op, body: respBody } = await readMessage(socket.reader, msgId, opts.timeoutMs);
	if (op !== OP_EXTENDED_RESPONSE) {
		throw new ProtocolError(`StartTLS: expected ExtendedResponse, got op ${op}`, {
			protocol: PROTO
		});
	}
	const code = respBody.enumerated();
	if (code !== RESULT_SUCCESS) {
		const matched = respBody.octetStringText();
		const diag = respBody.octetStringText();
		throw new ProtocolError(`StartTLS rejected (code ${code}): ${diag || matched}`, {
			protocol: PROTO
		});
	}
	return socket.startTls({ expectedServerHostname: opts.expectedServerHostname ?? opts.hostname });
}

/**
 * Builds a session over an already-connected (and, if needed, TLS-upgraded) socket.
 *
 * Public {@link connect} delegates here after handling the transport. Exposed for unit tests
 * that drive a mock socket without a real network.
 *
 * @internal
 * @param socket - The connected core socket.
 * @param opts - The connection options (used for an optional initial bind and timeouts).
 * @returns A ready {@link LdapSession}, bound if {@link LdapConnectOptions.bindDN} was set.
 * @throws {AuthError} If a requested bind is rejected.
 * @since 1.0.0
 * @example
 * ```typescript
 * const { socket } = mockConnection();
 * const session = await _sessionOverSocket(socket, { hostname: 'ldap.test' });
 * ```
 */
export async function _sessionOverSocket(
	socket: CoreSocket,
	opts: LdapConnectOptions
): Promise<LdapSession> {
	const session = new LdapSessionImpl(socket, opts.timeoutMs);
	if (opts.bindDN !== undefined) {
		await session.bind(opts.bindDN, opts.password ?? '');
	}
	return session;
}

class LdapSessionImpl implements LdapSession {
	readonly #socket: CoreSocket;
	readonly #timeoutMs: number | undefined;
	#nextId = 1;

	constructor(socket: CoreSocket, timeoutMs: number | undefined) {
		this.#socket = socket;
		this.#timeoutMs = timeoutMs;
	}

	get #reader(): FramedReader {
		return this.#socket.reader;
	}

	get #writer(): FramedWriter {
		return this.#socket.writer;
	}

	async bind(dn: string, password: string): Promise<void> {
		const id = this.#nextId++;
		// BindRequest [APPLICATION 0] { version, name, authentication [0] simple }
		const body = concat([
			writer.integer(3),
			writer.octetString(dn),
			writer.tagged(contextTag(AUTH_SIMPLE, false), new TextEncoder().encode(password))
		]);
		const req = writer.sequence([
			writer.integer(id),
			writer.tagged(applicationTag(OP_BIND_REQUEST, true), body)
		]);
		await this.#writer.write(req);

		const { op, body: resp } = await readMessage(this.#reader, id, this.#timeoutMs);
		if (op !== OP_BIND_RESPONSE) {
			throw new ProtocolError(`bind: expected BindResponse, got op ${op}`, { protocol: PROTO });
		}
		const code = resp.enumerated();
		if (code === RESULT_SUCCESS) return;
		const matched = resp.octetStringText();
		const diag = resp.octetStringText();
		const message = diag || matched || `result code ${code}`;
		if (code === RESULT_INVALID_CREDENTIALS) {
			throw new AuthError(`bind rejected: ${message}`, { protocol: PROTO });
		}
		throw new ProtocolError(`bind failed (code ${code}): ${message}`, { protocol: PROTO });
	}

	async search(opts: SearchOptions): Promise<LdapEntry[]> {
		return this.#runSearch(opts);
	}

	async findOne(opts: SearchOptions): Promise<LdapEntry | null> {
		// force sizeLimit 1; a server may answer sizeLimitExceeded, which is fine here
		const entries = await this.#runSearch({ ...opts, sizeLimit: 1 });
		return entries[0] ?? null;
	}

	// reads SearchResultEntry messages until the SearchResultDone for this request
	async #runSearch(opts: SearchOptions): Promise<LdapEntry[]> {
		const id = this.#nextId++;
		await this.#writer.write(this.#encodeSearchRequest(id, opts));

		const entries: LdapEntry[] = [];
		for (;;) {
			const { op, body } = await readMessage(this.#reader, id, this.#timeoutMs);
			if (op === OP_SEARCH_RESULT_ENTRY) {
				entries.push(parseSearchEntry(body));
				continue;
			}
			if (op === OP_SEARCH_RESULT_DONE) {
				const code = body.enumerated();
				// sizeLimitExceeded is expected when a sizeLimit truncates the result set
				if (code === RESULT_SUCCESS || code === RESULT_SIZE_LIMIT_EXCEEDED) return entries;
				const matched = body.octetStringText();
				const diag = body.octetStringText();
				throw new ProtocolError(`search failed (code ${code}): ${diag || matched}`, {
					protocol: PROTO
				});
			}
			// SearchResultReference (op 19) and anything else are skipped
		}
	}

	#encodeSearchRequest(id: number, opts: SearchOptions): Uint8Array {
		const scope = SCOPE_CODE[opts.scope ?? 'sub'];
		const filterSrc = opts.filter ?? '(objectClass=*)';
		const filter: Filter = typeof filterSrc === 'string' ? parseFilter(filterSrc) : filterSrc;
		const attrElems = (opts.attributes ?? []).map((a) => writer.octetString(a));
		// SearchRequest [APPLICATION 3] SEQUENCE { base, scope, deref, sizeLimit, timeLimit,
		// typesOnly, filter, attributes }
		const body = concat([
			writer.octetString(opts.base),
			writer.enumerated(scope),
			writer.enumerated(0), // derefAliases: neverDerefAliases
			writer.integer(opts.sizeLimit ?? 0),
			writer.integer(0), // timeLimit
			writer.boolean(false), // typesOnly
			encodeFilter(filter),
			writer.sequence(attrElems)
		]);
		return writer.sequence([
			writer.integer(id),
			writer.tagged(applicationTag(OP_SEARCH_REQUEST, true), body)
		]);
	}

	async close(): Promise<void> {
		try {
			// UnbindRequest [APPLICATION 2] is a null-bodied primitive
			const id = this.#nextId++;
			const req = writer.sequence([
				writer.integer(id),
				writer.tagged(applicationTag(OP_UNBIND_REQUEST, false), new Uint8Array(0))
			]);
			await this.#writer.write(req).catch(() => {});
		} finally {
			await this.#socket.close();
		}
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

/** A parsed LDAPMessage: the protocolOp application tag and a reader over its content. */
interface LdapMessage {
	/** The protocolOp application tag number. */
	op: number;
	/** A reader over the protocolOp content. */
	body: BerReader;
}

/**
 * Reads one full LDAPMessage from the socket and returns its protocolOp.
 *
 * Frames the message by reading the SEQUENCE tag, the definite length header, then the exact
 * content via {@link FramedReader.readN}. Asserts the message ID matches `expectedId`.
 *
 * @param reader - The framed reader over the socket.
 * @param expectedId - The message ID the response must carry.
 * @param timeoutMs - Optional per-read deadline.
 * @returns The protocolOp tag and a reader over its body.
 * @throws {ProtocolError} If the framing is malformed or the message ID does not match.
 * @throws {ConnectionError} If the stream ends mid-message.
 * @since 1.0.0
 * @example
 * ```typescript
 * const { op, body } = await readMessage(socket.reader, 1);
 * ```
 */
async function readMessage(
	reader: FramedReader,
	expectedId: number,
	timeoutMs?: number
): Promise<LdapMessage> {
	const header = await readElementHeader(reader, timeoutMs);
	if (header.tag !== 0x30) {
		throw new ProtocolError(`expected LDAPMessage SEQUENCE, got tag 0x${header.tag.toString(16)}`, {
			protocol: PROTO
		});
	}
	const content = await reader.readN(header.length, timeoutMs);
	const seq = new BerReader(content);
	const id = seq.integer();
	if (id !== expectedId) {
		throw new ProtocolError(`message ID mismatch: expected ${expectedId}, got ${id}`, {
			protocol: PROTO
		});
	}
	const opElem = seq.readElement();
	const op = opElem.tag & 0x1f; // strip class/constructed bits to get the application tag number
	return { op, body: opElem.reader };
}

/** A TLV header: the tag byte and the decoded definite-length content length. */
interface ElementHeader {
	tag: number;
	length: number;
}

// reads tag byte then definite length (short form, or long form with N following bytes)
async function readElementHeader(reader: FramedReader, timeoutMs?: number): Promise<ElementHeader> {
	const tag = (await reader.readN(1, timeoutMs))[0]!;
	const first = (await reader.readN(1, timeoutMs))[0]!;
	if (first < 0x80) return { tag, length: first };
	const count = first & 0x7f;
	if (count === 0) {
		throw new ProtocolError('indefinite-length LDAPMessage not supported', { protocol: PROTO });
	}
	if (count > 4) throw new ProtocolError('LDAPMessage length too large', { protocol: PROTO });
	const lenBytes = await reader.readN(count, timeoutMs);
	let length = 0;
	for (const b of lenBytes) length = length * 256 + b;
	return { tag, length };
}

// SearchResultEntry [APPLICATION 4] { objectName, attributes SEQ OF { type, vals SET OF } }
function parseSearchEntry(body: BerReader): LdapEntry {
	const dn = body.octetStringText();
	const attributes: Record<string, string[]> = {};
	const attrSeq = body.sequence();
	while (attrSeq.hasMore()) {
		const attr = attrSeq.readElement().reader; // PartialAttribute SEQUENCE
		const type = attr.octetStringText();
		const vals: string[] = [];
		const valSet = attr.readElement().reader; // SET OF value
		while (valSet.hasMore()) vals.push(decoder.decode(valSet.octetString()));
		attributes[type] = vals;
	}
	return { dn, attributes };
}

function concat(parts: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const p of parts) total += p.length;
	const out = new Uint8Array(total);
	let off = 0;
	for (const p of parts) {
		out.set(p, off);
		off += p.length;
	}
	return out;
}
