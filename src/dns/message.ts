/**
 * @fileoverview The DNS message wire codec (RFC 1035), pure and transport-free.
 *
 * A DNS message is a fixed 12-byte header (id, a packed flags word, and four section counts)
 * followed by the question section and the answer / authority / additional resource-record
 * sections. This module is pure (no I/O): {@link encodeMessage} serializes a {@link DnsMessage}
 * to a `Uint8Array` and {@link decodeMessage} parses one back, decoding the resource data of the
 * common record types into typed fields while always keeping the raw `rdata` available. All
 * transport, session, and framing concerns live in {@link module:dns}.
 *
 * Two wire quirks the codec keeps straight: a **domain name** is a sequence of length-prefixed
 * labels ending in a zero label, and on decode a label length byte with its top two bits set
 * (`0xC0`) is a **compression pointer** to an earlier offset in the message - {@link decodeName}
 * follows those with a loop guard, {@link encodeName} never emits them (uncompressed is always
 * valid). A **character-string** (used by TXT and NAPTR) is a single length byte then that many
 * bytes, distinct from a name.
 *
 * @author Gregory Mitchell
 * @since 1.0.4
 */
import { ProtocolError } from '../core';
import { fromBase64, fromHex, toBase64, toHex } from '../util';

const PROTO = 'dns';
const encoder = new TextEncoder();

/** Length of the fixed DNS message header in octets. */
export const HEADER_LENGTH = 12;

/** Largest DNS message the TCP length prefix can frame (a `uint16`). */
export const MAX_MESSAGE_LENGTH = 0xffff;

/** Default EDNS0 UDP payload size advertised in an OPT record (RFC 6891). */
export const DEFAULT_UDP_PAYLOAD_SIZE = 4096;

/** Largest single DNS label in octets (RFC 1035 2.3.4). */
export const MAX_LABEL_LENGTH = 63;

/** Largest encoded domain name in octets, including length bytes (RFC 1035 2.3.4). */
export const MAX_NAME_LENGTH = 255;

/**
 * DNS resource-record TYPE values (the subset edgeport understands), as carried in the 16-bit
 * TYPE field of a question or resource record.
 *
 * The codec decodes the resource data of the common types into typed fields; any other type is
 * still returned with its raw `rdata` intact. `ANY` (255) is a query-only QTYPE.
 *
 * @since 1.0.4
 */
export enum RecordType {
	/** IPv4 host address (RFC 1035). */
	A = 1,
	/** Authoritative name server (RFC 1035). */
	NS = 2,
	/** Canonical name / alias (RFC 1035). */
	CNAME = 5,
	/** Start of a zone of authority (RFC 1035). */
	SOA = 6,
	/** Domain-name pointer, used for reverse DNS (RFC 1035). */
	PTR = 12,
	/** Mail exchange (RFC 1035). */
	MX = 15,
	/** Text strings (RFC 1035). */
	TXT = 16,
	/** IPv6 host address (RFC 3596). */
	AAAA = 28,
	/** Server selection: service location (RFC 2782). */
	SRV = 33,
	/** Naming Authority Pointer (RFC 3403). */
	NAPTR = 35,
	/** EDNS0 pseudo-record carrying extension options (RFC 6891). */
	OPT = 41,
	/** Delegation Signer (DNSSEC, RFC 4034). */
	DS = 43,
	/** SSH key fingerprint (RFC 4255). */
	SSHFP = 44,
	/** DNSSEC signature (RFC 4034). */
	RRSIG = 46,
	/** Next Secure record (DNSSEC, RFC 4034). */
	NSEC = 47,
	/** DNS public key (DNSSEC, RFC 4034). */
	DNSKEY = 48,
	/** TLSA certificate association (DANE, RFC 6698). */
	TLSA = 52,
	/** Service binding (RFC 9460). */
	SVCB = 64,
	/** HTTPS service binding (RFC 9460). */
	HTTPS = 65,
	/** Certification Authority Authorization (RFC 8659). */
	CAA = 257,
	/** Query-only: request all record types (QTYPE `*`). */
	ANY = 255
}

/**
 * The string names of the record types {@link resolve} and {@link DnsSession.query} accept.
 *
 * @since 1.0.4
 */
export type RecordTypeName = keyof typeof RecordType;

/**
 * DNS CLASS values. `IN` (Internet) is the only class used in practice.
 *
 * @since 1.0.4
 */
export enum RecordClass {
	/** Internet. */
	IN = 1,
	/** Chaos (rarely used, e.g. `version.bind`). */
	CH = 3,
	/** Hesiod. */
	HS = 4,
	/** No class (used in dynamic-update prerequisites). */
	NONE = 254,
	/** Any class (QCLASS `*`). */
	ANY = 255
}

/**
 * DNS OPCODE values (the query kind, in the flags word).
 *
 * @since 1.0.4
 */
export enum Opcode {
	/** A standard query. */
	QUERY = 0,
	/** An inverse query (obsolete). */
	IQUERY = 1,
	/** A server status request. */
	STATUS = 2,
	/** A zone-change notification (RFC 1996). */
	NOTIFY = 4,
	/** A dynamic update (RFC 2136). */
	UPDATE = 5
}

/**
 * DNS RCODE values (the response status, low 4 bits of the flags word).
 *
 * `NOERROR` is success. The session layer maps `SERVFAIL` / `REFUSED` / `FORMERR` / `NOTIMP` to a
 * {@link ProtocolError} on the typed paths, while `NXDOMAIN` (the name simply has no records) does
 * not throw for {@link resolve}. The raw {@link DnsSession.query} exposes the rcode unchanged.
 *
 * @since 1.0.4
 */
export enum ResponseCode {
	/** No error. */
	NOERROR = 0,
	/** Format error: the server could not interpret the query. */
	FORMERR = 1,
	/** Server failure. */
	SERVFAIL = 2,
	/** Non-existent domain: the queried name does not exist. */
	NXDOMAIN = 3,
	/** Not implemented: the server does not support the requested query. */
	NOTIMP = 4,
	/** Query refused (policy). */
	REFUSED = 5,
	/** A name that should not exist does (dynamic update). */
	YXDOMAIN = 6,
	/** An RR set that should not exist does. */
	YXRRSET = 7,
	/** An RR set that should exist does not. */
	NXRRSET = 8,
	/** The server is not authoritative for the zone. */
	NOTAUTH = 9,
	/** A name is not within the zone. */
	NOTZONE = 10
}

/**
 * The decoded DNS flags word (the 16 bits after the id in the header).
 *
 * @since 1.0.4
 */
export interface DnsFlags {
	/** Query (`false`) or response (`true`). */
	qr: boolean;
	/** The operation code. */
	opcode: Opcode | number;
	/** Authoritative answer (set by the authoritative server). */
	aa: boolean;
	/** Truncated (the message was cut short; over TCP this should be clear per RFC 7766). */
	tc: boolean;
	/** Recursion desired (set by the client to ask the resolver to recurse). */
	rd: boolean;
	/** Recursion available (set by the server if it offers recursion). */
	ra: boolean;
	/** The reserved Z bit (must be zero). */
	z: boolean;
	/** Authentic data (DNSSEC: the resolver vouches the data is validated). */
	ad: boolean;
	/** Checking disabled (DNSSEC: the client accepts unvalidated data). */
	cd: boolean;
	/** The response code. */
	rcode: ResponseCode | number;
}

/** The decoded 12-byte DNS message header. */
export interface DnsHeader {
	/** The 16-bit id correlating a query with its response. */
	id: number;
	/** The decoded flags word. */
	flags: DnsFlags;
	/** Number of entries in the question section. */
	qdcount: number;
	/** Number of resource records in the answer section. */
	ancount: number;
	/** Number of resource records in the authority section. */
	nscount: number;
	/** Number of resource records in the additional section. */
	arcount: number;
}

/** One entry in the question section: the name asked about, its TYPE, and its CLASS. */
export interface Question {
	/** The queried domain name (dot-separated, without a trailing dot). */
	name: string;
	/** The query TYPE. */
	type: RecordType | number;
	/** The query CLASS (almost always {@link RecordClass.IN}). */
	class: RecordClass | number;
}

/** A `{preference, exchange}` mail-exchange record. */
export interface MxRecord {
	/** Lower preference is preferred. */
	preference: number;
	/** The mail server host name. */
	exchange: string;
}

/** A start-of-authority record. */
export interface SoaRecord {
	/** Primary name server for the zone. */
	mname: string;
	/** Responsible party mailbox (with `.` for `@`). */
	rname: string;
	/** Zone serial number. */
	serial: number;
	/** Seconds a secondary waits before refreshing. */
	refresh: number;
	/** Seconds a secondary waits before retrying a failed refresh. */
	retry: number;
	/** Seconds after which a secondary discards the zone if it cannot refresh. */
	expire: number;
	/** Minimum TTL / negative-caching TTL. */
	minimum: number;
}

/** A service-location record (RFC 2782). */
export interface SrvRecord {
	/** Lower priority is preferred. */
	priority: number;
	/** Relative weight among equal-priority targets. */
	weight: number;
	/** The service port on the target host. */
	port: number;
	/** The target host name. */
	target: string;
}

/** A Certification Authority Authorization record (RFC 8659). */
export interface CaaRecord {
	/** The flags octet (bit 7 is the critical flag). */
	flags: number;
	/** The property tag (e.g. `issue`, `issuewild`, `iodef`). */
	tag: string;
	/** The property value. */
	value: string;
}

/** A Naming Authority Pointer record (RFC 3403). */
export interface NaptrRecord {
	/** Processing order (lower first). */
	order: number;
	/** Tie-break preference among equal orders. */
	preference: number;
	/** Flags controlling the rewrite (e.g. `S`, `A`, `U`, `P`). */
	flags: string;
	/** The service field (e.g. `SIP+D2U`). */
	service: string;
	/** The substitution regular expression. */
	regexp: string;
	/** The replacement domain name. */
	replacement: string;
}

/** An SSH key fingerprint record (RFC 4255). */
export interface SshfpRecord {
	/** The key algorithm (1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519). */
	algorithm: number;
	/** The fingerprint type (1=SHA-1, 2=SHA-256). */
	fpType: number;
	/** The fingerprint as a lowercase hex string. */
	fingerprint: string;
}

/** A Delegation Signer record (DNSSEC, RFC 4034). */
export interface DsRecord {
	/** The key tag of the referenced DNSKEY. */
	keyTag: number;
	/** The DNSKEY algorithm. */
	algorithm: number;
	/** The digest algorithm (1=SHA-1, 2=SHA-256, 4=SHA-384). */
	digestType: number;
	/** The digest as a lowercase hex string. */
	digest: string;
}

/** A DNSKEY record (DNSSEC, RFC 4034). */
export interface DnskeyRecord {
	/** The flags field (256=ZSK, 257=KSK). */
	flags: number;
	/** The protocol field (always 3). */
	protocol: number;
	/** The public-key algorithm. */
	algorithm: number;
	/** The public key as a base64 string. */
	publicKey: string;
}

/** A TLSA certificate-association record (DANE, RFC 6698). */
export interface TlsaRecord {
	/** Certificate usage (0-3). */
	usage: number;
	/** Selector (0=full cert, 1=SubjectPublicKeyInfo). */
	selector: number;
	/** Matching type (0=exact, 1=SHA-256, 2=SHA-512). */
	matchingType: number;
	/** The association data as a lowercase hex string. */
	cert: string;
}

/** A DNSSEC signature record (RFC 4034). */
export interface RrsigRecord {
	/** The TYPE this signature covers. */
	typeCovered: number;
	/** The signing algorithm. */
	algorithm: number;
	/** The number of labels in the signed name. */
	labels: number;
	/** The original TTL of the covered RR set. */
	originalTtl: number;
	/** Signature expiration, seconds since the Unix epoch. */
	expiration: number;
	/** Signature inception, seconds since the Unix epoch. */
	inception: number;
	/** The key tag of the signing DNSKEY. */
	keyTag: number;
	/** The signer's domain name. */
	signerName: string;
	/** The signature as a base64 string. */
	signature: string;
}

/** One key/value parameter of an SVCB or HTTPS record (RFC 9460). */
export interface SvcbParam {
	/** The SvcParamKey (0=mandatory, 1=alpn, 3=port, 4=ipv4hint, 6=ipv6hint, ...). */
	key: number;
	/** The raw parameter value bytes. */
	value: Uint8Array;
}

/** A service-binding record, shared by SVCB and HTTPS (RFC 9460). */
export interface SvcbRecord {
	/** The service priority (0 = AliasMode, otherwise ServiceMode). */
	priority: number;
	/** The target name (`.` means "the owner name" in ServiceMode). */
	target: string;
	/** The service parameters, in wire order. */
	params: SvcbParam[];
}

/** One EDNS0 option (a code and its value), carried in an OPT record's rdata. */
export interface EdnsOption {
	/** The option code (e.g. 3=NSID, 8=Client Subnet, 10=Cookie). */
	code: number;
	/** The raw option value bytes. */
	value: Uint8Array;
}

/** The decoded semantics of an OPT pseudo-record (RFC 6891). */
export interface OptData {
	/** The advertised UDP payload size (carried in the CLASS field). */
	udpPayloadSize: number;
	/** The DNSSEC OK (DO) bit: the client understands DNSSEC records. */
	dnssecOk: boolean;
	/** The upper 8 bits of the extended RCODE (carried in the TTL field). */
	extendedRcode: number;
	/** The EDNS version (0 for EDNS0). */
	version: number;
	/** The EDNS options carried in the rdata. */
	options: EdnsOption[];
}

/**
 * The structured resource data of a decoded record, keyed by its {@link RecordType}.
 *
 * The mapping is: `A`/`AAAA`/`NS`/`CNAME`/`PTR` decode to a string; `TXT` to a string array (one
 * per character-string); `MX`/`SOA`/`SRV`/`CAA`/`NAPTR`/`SSHFP`/`DS`/`DNSKEY`/`TLSA`/`RRSIG` to
 * their typed shapes; `SVCB`/`HTTPS` to {@link SvcbRecord}; `OPT` to {@link OptData}; and any
 * other TYPE to the raw rdata bytes.
 *
 * @since 1.0.4
 */
export type RData =
	| string
	| string[]
	| MxRecord
	| SoaRecord
	| SrvRecord
	| CaaRecord
	| NaptrRecord
	| SshfpRecord
	| DsRecord
	| DnskeyRecord
	| TlsaRecord
	| RrsigRecord
	| SvcbRecord
	| OptData
	| Uint8Array;

/**
 * A decoded resource record: the owner name, TYPE, CLASS, TTL, the raw rdata, and (for the
 * understood types) its structured {@link RData}.
 *
 * @since 1.0.4
 */
export interface ResourceRecord {
	/** The owner domain name. */
	name: string;
	/** The record TYPE. */
	type: RecordType | number;
	/** The record CLASS (almost always {@link RecordClass.IN}). */
	class: RecordClass | number;
	/** Time-to-live in seconds. */
	ttl: number;
	/** The raw resource-data octets, always present. */
	rdata: Uint8Array;
	/** The parsed resource data; the raw `rdata` for an un-decoded TYPE. */
	data: RData;
}

/**
 * A complete DNS message: the header id/flags, the question section, and the three RR sections.
 *
 * The section counts are derived from the array lengths on encode, so they are not stored here.
 *
 * @since 1.0.4
 */
export interface DnsMessage {
	/** The 16-bit id. */
	id: number;
	/** The flags word. */
	flags: DnsFlags;
	/** The question section. */
	question: Question[];
	/** The answer section. */
	answer: ResourceRecord[];
	/** The authority section. */
	authority: ResourceRecord[];
	/** The additional section (where an OPT record rides). */
	additional: ResourceRecord[];
}

// packs a DnsFlags into its 16-bit wire word
function packFlags(f: DnsFlags): number {
	let w = 0;
	if (f.qr) w |= 0x8000;
	w |= ((f.opcode as number) & 0x0f) << 11;
	if (f.aa) w |= 0x0400;
	if (f.tc) w |= 0x0200;
	if (f.rd) w |= 0x0100;
	if (f.ra) w |= 0x0080;
	if (f.z) w |= 0x0040;
	if (f.ad) w |= 0x0020;
	if (f.cd) w |= 0x0010;
	w |= (f.rcode as number) & 0x0f;
	return w & 0xffff;
}

// unpacks a 16-bit wire word into DnsFlags
function unpackFlags(w: number): DnsFlags {
	return {
		qr: (w & 0x8000) !== 0,
		opcode: (w >> 11) & 0x0f,
		aa: (w & 0x0400) !== 0,
		tc: (w & 0x0200) !== 0,
		rd: (w & 0x0100) !== 0,
		ra: (w & 0x0080) !== 0,
		z: (w & 0x0040) !== 0,
		ad: (w & 0x0020) !== 0,
		cd: (w & 0x0010) !== 0,
		rcode: w & 0x0f
	};
}

/**
 * Packs a {@link DnsFlags} into its 16-bit wire representation.
 *
 * @param flags - The flags to pack.
 * @returns The 16-bit flags word.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { encodeFlags, Opcode, ResponseCode } from 'edgeport/dns';
 *
 * const w = encodeFlags({ qr: false, opcode: Opcode.QUERY, aa: false, tc: false, rd: true,
 * 	ra: false, z: false, ad: false, cd: false, rcode: ResponseCode.NOERROR });
 * // w === 0x0100 (RD set)
 * ```
 */
export function encodeFlags(flags: DnsFlags): number {
	return packFlags(flags);
}

/**
 * Unpacks a 16-bit wire flags word into a {@link DnsFlags}.
 *
 * @param word - The 16-bit flags word.
 * @returns The decoded flags.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { decodeFlags } from 'edgeport/dns';
 *
 * const f = decodeFlags(0x8180); // { qr: true, rd: true, ra: true, rcode: 0, ... }
 * ```
 */
export function decodeFlags(word: number): DnsFlags {
	return unpackFlags(word);
}

// resolves a type name or number to its numeric TYPE
function typeNumber(t: RecordTypeName | RecordType | number): number {
	return typeof t === 'number' ? t : RecordType[t];
}

/**
 * Encodes a domain name as a sequence of length-prefixed labels ending in the zero label.
 *
 * Names are encoded uncompressed (never using pointers), which is always valid on the wire. A
 * trailing dot is accepted and ignored; the root (`""` or `"."`) encodes to a single zero byte.
 *
 * @param name - The dot-separated domain name.
 * @returns The encoded name bytes.
 * @throws {ProtocolError} If a label exceeds 63 octets or the whole name exceeds 255 octets.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { encodeName } from 'edgeport/dns';
 *
 * encodeName('example.com'); // 07 'example' 03 'com' 00
 * ```
 */
export function encodeName(name: string): Uint8Array {
	// drop a single trailing dot; root becomes an empty label set
	const trimmed = name.endsWith('.') ? name.slice(0, -1) : name;
	const labels = trimmed.length === 0 ? [] : trimmed.split('.');
	const parts: Uint8Array[] = [];
	let total = 1; // the terminating zero label
	for (const label of labels) {
		const bytes = encoder.encode(label);
		if (bytes.length === 0) {
			throw new ProtocolError(`empty label in name "${name}"`, { protocol: PROTO });
		}
		if (bytes.length > MAX_LABEL_LENGTH) {
			throw new ProtocolError(`label exceeds ${MAX_LABEL_LENGTH} octets in "${name}"`, {
				protocol: PROTO
			});
		}
		const chunk = new Uint8Array(bytes.length + 1);
		chunk[0] = bytes.length;
		chunk.set(bytes, 1);
		parts.push(chunk);
		total += chunk.length;
	}
	if (total > MAX_NAME_LENGTH) {
		throw new ProtocolError(`name "${name}" exceeds ${MAX_NAME_LENGTH} octets`, {
			protocol: PROTO
		});
	}
	const out = new Uint8Array(total);
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	out[at] = 0; // root label
	return out;
}

// decodes one label's bytes to a string, escaping the special characters DNS uses in zone form
function decodeLabel(bytes: Uint8Array): string {
	let out = '';
	for (const b of bytes) {
		if (b === 0x2e)
			out += '\\.'; // dot inside a label
		else if (b === 0x5c)
			out += '\\\\'; // backslash
		else if (b < 0x20 || b > 0x7e) out += '\\' + b.toString().padStart(3, '0');
		else out += String.fromCharCode(b);
	}
	return out;
}

/**
 * Decodes a domain name from a message, following compression pointers.
 *
 * A length byte with its top two bits set (`0xC0`) is a pointer to an earlier offset; this
 * follows the chain with a loop guard (a pointer must be seen at most once). The returned `next`
 * is the offset immediately after the name in the linear stream - after the first pointer, if
 * one is present - which is what a caller uses to continue parsing.
 *
 * @param msg - The full message buffer (needed to resolve pointers).
 * @param offset - Where the name begins.
 * @returns The decoded name and the offset just past it in the linear stream.
 * @throws {ProtocolError} If the name runs past the buffer, uses a reserved label form, or a
 *   compression pointer loops.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { decodeName } from 'edgeport/dns';
 *
 * const { name, next } = decodeName(messageBytes, 12);
 * ```
 */
export function decodeName(msg: Uint8Array, offset: number): { name: string; next: number } {
	const labels: string[] = [];
	let at = offset;
	let next = -1;
	const seen = new Set<number>();
	for (;;) {
		if (at >= msg.length) {
			throw new ProtocolError('name runs past the end of the message', { protocol: PROTO });
		}
		const len = msg[at]!;
		const kind = len & 0xc0;
		if (kind === 0x00) {
			if (len === 0) {
				at += 1;
				if (next === -1) next = at;
				break;
			}
			const start = at + 1;
			const end = start + len;
			if (end > msg.length) {
				throw new ProtocolError('label runs past the end of the message', { protocol: PROTO });
			}
			labels.push(decodeLabel(msg.subarray(start, end)));
			at = end;
		} else if (kind === 0xc0) {
			if (at + 1 >= msg.length) {
				throw new ProtocolError('truncated compression pointer', { protocol: PROTO });
			}
			const ptr = ((len & 0x3f) << 8) | msg[at + 1]!;
			if (next === -1) next = at + 2;
			if (seen.has(at)) {
				throw new ProtocolError('compression pointer loop', { protocol: PROTO });
			}
			seen.add(at);
			at = ptr;
		} else {
			throw new ProtocolError(`reserved label length bits 0x${kind.toString(16)}`, {
				protocol: PROTO
			});
		}
	}
	return { name: labels.join('.'), next };
}

// cursor over the full message; name() follows pointers, everything else is bounds-checked
class MessageReader {
	readonly msg: Uint8Array;
	readonly #view: DataView;
	off: number;
	readonly end: number;

	constructor(msg: Uint8Array, off: number, end: number) {
		this.msg = msg;
		this.#view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
		this.off = off;
		this.end = end;
	}

	get remaining(): number {
		return this.end - this.off;
	}

	u8(): number {
		if (this.off + 1 > this.end) {
			throw new ProtocolError('message truncated reading a byte', { protocol: PROTO });
		}
		return this.#view.getUint8(this.off++);
	}

	u16(): number {
		if (this.off + 2 > this.end) {
			throw new ProtocolError('message truncated reading a uint16', { protocol: PROTO });
		}
		const v = this.#view.getUint16(this.off, false);
		this.off += 2;
		return v;
	}

	u32(): number {
		if (this.off + 4 > this.end) {
			throw new ProtocolError('message truncated reading a uint32', { protocol: PROTO });
		}
		const v = this.#view.getUint32(this.off, false);
		this.off += 4;
		return v;
	}

	bytes(n: number): Uint8Array {
		if (this.off + n > this.end) {
			throw new ProtocolError('message truncated reading octets', { protocol: PROTO });
		}
		const out = this.msg.slice(this.off, this.off + n);
		this.off += n;
		return out;
	}

	// a <character-string>: one length byte then that many bytes
	charString(): Uint8Array {
		const n = this.u8();
		return this.bytes(n);
	}

	// a domain name, following any compression pointers into the full message
	name(): string {
		const { name, next } = decodeName(this.msg, this.off);
		this.off = next;
		return name;
	}
}

// formats 4 octets as a dotted IPv4 string
function formatIpv4(bytes: Uint8Array): string {
	return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

/**
 * Formats 16 octets as a canonical compressed IPv6 string.
 *
 * The longest run of zero groups (of length two or more) is collapsed to `::`; each remaining
 * group is lowercase hex with no leading zeros.
 *
 * @param bytes - Exactly 16 octets.
 * @returns The compressed IPv6 text (e.g. `2001:db8::1`).
 * @throws {ProtocolError} If `bytes` is not 16 octets long.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { formatIpv6 } from 'edgeport/dns';
 *
 * formatIpv6(new Uint8Array(16)); // '::'
 * ```
 */
export function formatIpv6(bytes: Uint8Array): string {
	if (bytes.length !== 16) {
		throw new ProtocolError('ipv6 address must be 16 octets', { protocol: PROTO });
	}
	const groups: number[] = [];
	for (let i = 0; i < 16; i += 2) groups.push(((bytes[i]! << 8) | bytes[i + 1]!) >>> 0);
	// find the longest run of zero groups (only runs of length >= 2 are worth compressing)
	let bestStart = -1;
	let bestLen = 0;
	let curStart = -1;
	let curLen = 0;
	for (let i = 0; i < 8; i++) {
		if (groups[i] === 0) {
			if (curStart < 0) curStart = i;
			curLen++;
			if (curLen > bestLen) {
				bestLen = curLen;
				bestStart = curStart;
			}
		} else {
			curStart = -1;
			curLen = 0;
		}
	}
	if (bestLen < 2) return groups.map((g) => g.toString(16)).join(':');
	const head = groups
		.slice(0, bestStart)
		.map((g) => g.toString(16))
		.join(':');
	const tail = groups
		.slice(bestStart + bestLen)
		.map((g) => g.toString(16))
		.join(':');
	return `${head}::${tail}`;
}

/**
 * Parses a dotted IPv4 string into 4 octets.
 *
 * @param ip - The dotted-quad address.
 * @returns The 4 address octets.
 * @throws {ProtocolError} If the input is not four decimal octets in `0..255`.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { parseIpv4 } from 'edgeport/dns';
 *
 * parseIpv4('93.184.216.34'); // Uint8Array [93, 184, 216, 34]
 * ```
 */
export function parseIpv4(ip: string): Uint8Array {
	const parts = ip.split('.');
	if (parts.length !== 4) {
		throw new ProtocolError(`invalid ipv4 address "${ip}"`, { protocol: PROTO });
	}
	const out = new Uint8Array(4);
	for (let i = 0; i < 4; i++) {
		const n = Number(parts[i]);
		if (!Number.isInteger(n) || n < 0 || n > 255 || !/^\d+$/.test(parts[i]!)) {
			throw new ProtocolError(`invalid ipv4 octet in "${ip}"`, { protocol: PROTO });
		}
		out[i] = n;
	}
	return out;
}

/**
 * Parses an IPv6 string (compressed or full, optionally with an embedded IPv4 tail) into 16
 * octets.
 *
 * @param ip - The IPv6 text.
 * @returns The 16 address octets.
 * @throws {ProtocolError} If the input is not a valid IPv6 address.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { parseIpv6 } from 'edgeport/dns';
 *
 * parseIpv6('2001:db8::1'); // 16 octets
 * ```
 */
export function parseIpv6(ip: string): Uint8Array {
	const halves = ip.split('::');
	if (halves.length > 2) {
		throw new ProtocolError(`invalid ipv6 address "${ip}" (multiple "::")`, { protocol: PROTO });
	}
	// expand a group list, splitting a trailing embedded ipv4 into two 16-bit groups
	const expand = (part: string): number[] => {
		if (part === '') return [];
		const out: number[] = [];
		const tokens = part.split(':');
		for (let i = 0; i < tokens.length; i++) {
			const tok = tokens[i]!;
			if (tok.includes('.')) {
				const v4 = parseIpv4(tok);
				out.push((v4[0]! << 8) | v4[1]!, (v4[2]! << 8) | v4[3]!);
			} else {
				if (!/^[0-9a-fA-F]{1,4}$/.test(tok)) {
					throw new ProtocolError(`invalid ipv6 group "${tok}" in "${ip}"`, { protocol: PROTO });
				}
				out.push(Number.parseInt(tok, 16));
			}
		}
		return out;
	};
	const head = expand(halves[0]!);
	const tail = halves.length === 2 ? expand(halves[1]!) : null;
	let groups: number[];
	if (tail === null) {
		groups = head;
	} else {
		const gap = 8 - head.length - tail.length;
		if (gap < 1) {
			throw new ProtocolError(`invalid ipv6 address "${ip}"`, { protocol: PROTO });
		}
		groups = [...head, ...new Array<number>(gap).fill(0), ...tail];
	}
	if (groups.length !== 8) {
		throw new ProtocolError(`invalid ipv6 address "${ip}" (expected 8 groups)`, {
			protocol: PROTO
		});
	}
	const out = new Uint8Array(16);
	for (let i = 0; i < 8; i++) {
		out[i * 2] = (groups[i]! >> 8) & 0xff;
		out[i * 2 + 1] = groups[i]! & 0xff;
	}
	return out;
}

// decodes the structured rdata of the understood record types; raw bytes for the rest
function parseRdata(type: number, msg: Uint8Array, start: number, length: number): RData {
	const end = start + length;
	const r = new MessageReader(msg, start, end);
	switch (type) {
		case RecordType.A:
			return formatIpv4(r.bytes(4));
		case RecordType.AAAA:
			return formatIpv6(r.bytes(16));
		case RecordType.NS:
		case RecordType.CNAME:
		case RecordType.PTR:
			return r.name();
		case RecordType.MX: {
			const preference = r.u16();
			const exchange = r.name();
			return { preference, exchange } satisfies MxRecord;
		}
		case RecordType.TXT: {
			const strings: string[] = [];
			while (r.remaining > 0) strings.push(new TextDecoder().decode(r.charString()));
			return strings;
		}
		case RecordType.SOA:
			return {
				mname: r.name(),
				rname: r.name(),
				serial: r.u32(),
				refresh: r.u32(),
				retry: r.u32(),
				expire: r.u32(),
				minimum: r.u32()
			} satisfies SoaRecord;
		case RecordType.SRV: {
			const priority = r.u16();
			const weight = r.u16();
			const port = r.u16();
			const target = r.name();
			return { priority, weight, port, target } satisfies SrvRecord;
		}
		case RecordType.CAA: {
			const flags = r.u8();
			const tag = new TextDecoder().decode(r.charString());
			const value = new TextDecoder().decode(r.bytes(r.remaining));
			return { flags, tag, value } satisfies CaaRecord;
		}
		case RecordType.NAPTR: {
			const order = r.u16();
			const preference = r.u16();
			const flags = new TextDecoder().decode(r.charString());
			const service = new TextDecoder().decode(r.charString());
			const regexp = new TextDecoder().decode(r.charString());
			const replacement = r.name();
			return { order, preference, flags, service, regexp, replacement } satisfies NaptrRecord;
		}
		case RecordType.SSHFP: {
			const algorithm = r.u8();
			const fpType = r.u8();
			return { algorithm, fpType, fingerprint: toHex(r.bytes(r.remaining)) } satisfies SshfpRecord;
		}
		case RecordType.DS: {
			const keyTag = r.u16();
			const algorithm = r.u8();
			const digestType = r.u8();
			return {
				keyTag,
				algorithm,
				digestType,
				digest: toHex(r.bytes(r.remaining))
			} satisfies DsRecord;
		}
		case RecordType.DNSKEY: {
			const flags = r.u16();
			const protocol = r.u8();
			const algorithm = r.u8();
			return {
				flags,
				protocol,
				algorithm,
				publicKey: toBase64(r.bytes(r.remaining))
			} satisfies DnskeyRecord;
		}
		case RecordType.TLSA: {
			const usage = r.u8();
			const selector = r.u8();
			const matchingType = r.u8();
			return {
				usage,
				selector,
				matchingType,
				cert: toHex(r.bytes(r.remaining))
			} satisfies TlsaRecord;
		}
		case RecordType.RRSIG: {
			const typeCovered = r.u16();
			const algorithm = r.u8();
			const labels = r.u8();
			const originalTtl = r.u32();
			const expiration = r.u32();
			const inception = r.u32();
			const keyTag = r.u16();
			const signerName = r.name();
			return {
				typeCovered,
				algorithm,
				labels,
				originalTtl,
				expiration,
				inception,
				keyTag,
				signerName,
				signature: toBase64(r.bytes(r.remaining))
			} satisfies RrsigRecord;
		}
		case RecordType.SVCB:
		case RecordType.HTTPS: {
			const priority = r.u16();
			const target = r.name();
			const params: SvcbParam[] = [];
			while (r.remaining >= 4) {
				const key = r.u16();
				const len = r.u16();
				params.push({ key, value: r.bytes(len) });
			}
			return { priority, target, params } satisfies SvcbRecord;
		}
		case RecordType.OPT: {
			const options: EdnsOption[] = [];
			while (r.remaining >= 4) {
				const code = r.u16();
				const len = r.u16();
				options.push({ code, value: r.bytes(len) });
			}
			// udpPayloadSize/DO live in class/ttl, not rdata; decodeOpt reads the whole record
			return { udpPayloadSize: 0, dnssecOk: false, extendedRcode: 0, version: 0, options };
		}
		default:
			return msg.slice(start, end);
	}
}

// concatenates byte chunks into one buffer
function concat(chunks: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const c of chunks) total += c.length;
	const out = new Uint8Array(total);
	let at = 0;
	for (const c of chunks) {
		out.set(c, at);
		at += c.length;
	}
	return out;
}

// a <character-string>: one length byte then up to 255 value bytes
function charStringBytes(value: string | Uint8Array): Uint8Array {
	const bytes = typeof value === 'string' ? encoder.encode(value) : value;
	if (bytes.length > 255) {
		throw new ProtocolError('character-string exceeds 255 octets', { protocol: PROTO });
	}
	const out = new Uint8Array(bytes.length + 1);
	out[0] = bytes.length;
	out.set(bytes, 1);
	return out;
}

function u16(n: number): Uint8Array {
	const out = new Uint8Array(2);
	new DataView(out.buffer).setUint16(0, n & 0xffff, false);
	return out;
}

function u32(n: number): Uint8Array {
	const out = new Uint8Array(4);
	new DataView(out.buffer).setUint32(0, n >>> 0, false);
	return out;
}

/**
 * Encodes the structured resource data of a record TYPE into its wire rdata (uncompressed names).
 *
 * Supports the same TYPEs {@link parseRdata} decodes; for any other TYPE, pass the raw rdata as a
 * `Uint8Array` and it is returned unchanged. Used by {@link record} and by tests building
 * responses.
 *
 * @param type - The record TYPE.
 * @param data - The structured data for a known TYPE, or raw rdata bytes.
 * @returns The encoded rdata octets.
 * @throws {ProtocolError} If a known TYPE is given data of the wrong shape.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { encodeRdata, RecordType } from 'edgeport/dns';
 *
 * encodeRdata(RecordType.A, '93.184.216.34'); // Uint8Array [93, 184, 216, 34]
 * ```
 */
export function encodeRdata(type: RecordType | number, data: RData): Uint8Array {
	if (data instanceof Uint8Array) return data;
	switch (type) {
		case RecordType.A:
			return parseIpv4(data as string);
		case RecordType.AAAA:
			return parseIpv6(data as string);
		case RecordType.NS:
		case RecordType.CNAME:
		case RecordType.PTR:
			return encodeName(data as string);
		case RecordType.MX: {
			const mx = data as MxRecord;
			return concat([u16(mx.preference), encodeName(mx.exchange)]);
		}
		case RecordType.TXT: {
			const arr = Array.isArray(data) ? (data as string[]) : [String(data)];
			return concat(arr.map((s) => charStringBytes(s)));
		}
		case RecordType.SOA: {
			const s = data as SoaRecord;
			return concat([
				encodeName(s.mname),
				encodeName(s.rname),
				u32(s.serial),
				u32(s.refresh),
				u32(s.retry),
				u32(s.expire),
				u32(s.minimum)
			]);
		}
		case RecordType.SRV: {
			const s = data as SrvRecord;
			return concat([u16(s.priority), u16(s.weight), u16(s.port), encodeName(s.target)]);
		}
		case RecordType.CAA: {
			const c = data as CaaRecord;
			return concat([
				new Uint8Array([c.flags & 0xff]),
				charStringBytes(c.tag),
				encoder.encode(c.value)
			]);
		}
		case RecordType.NAPTR: {
			const n = data as NaptrRecord;
			return concat([
				u16(n.order),
				u16(n.preference),
				charStringBytes(n.flags),
				charStringBytes(n.service),
				charStringBytes(n.regexp),
				encodeName(n.replacement)
			]);
		}
		case RecordType.SSHFP: {
			const s = data as SshfpRecord;
			return concat([
				new Uint8Array([s.algorithm & 0xff, s.fpType & 0xff]),
				fromHex(s.fingerprint)
			]);
		}
		case RecordType.DS: {
			const d = data as DsRecord;
			return concat([
				u16(d.keyTag),
				new Uint8Array([d.algorithm & 0xff, d.digestType & 0xff]),
				fromHex(d.digest)
			]);
		}
		case RecordType.DNSKEY: {
			const k = data as DnskeyRecord;
			return concat([
				u16(k.flags),
				new Uint8Array([k.protocol & 0xff, k.algorithm & 0xff]),
				fromBase64(k.publicKey)
			]);
		}
		case RecordType.TLSA: {
			const t = data as TlsaRecord;
			return concat([
				new Uint8Array([t.usage & 0xff, t.selector & 0xff, t.matchingType & 0xff]),
				fromHex(t.cert)
			]);
		}
		case RecordType.RRSIG: {
			const s = data as RrsigRecord;
			// signer name is uncompressed per RFC 4034; the signature is the trailing bytes
			return concat([
				u16(s.typeCovered),
				new Uint8Array([s.algorithm & 0xff, s.labels & 0xff]),
				u32(s.originalTtl),
				u32(s.expiration),
				u32(s.inception),
				u16(s.keyTag),
				encodeName(s.signerName),
				fromBase64(s.signature)
			]);
		}
		case RecordType.SVCB:
		case RecordType.HTTPS: {
			const s = data as SvcbRecord;
			const chunks: Uint8Array[] = [u16(s.priority), encodeName(s.target)];
			for (const p of s.params) chunks.push(u16(p.key), u16(p.value.length), p.value);
			return concat(chunks);
		}
		default:
			throw new ProtocolError(`cannot encode structured rdata for type ${type}`, {
				protocol: PROTO
			});
	}
}

/**
 * Builds a {@link ResourceRecord}, encoding the rdata from structured `data` (or accepting raw
 * bytes).
 *
 * A convenience for constructing answers/authority/additional records to feed
 * {@link encodeMessage}; `data` may be the typed shape for the TYPE or a `Uint8Array` of raw rdata.
 *
 * @param name - The owner name.
 * @param type - The record TYPE.
 * @param ttl - The TTL in seconds.
 * @param data - The structured data or raw rdata bytes.
 * @param cls - The CLASS; defaults to {@link RecordClass.IN}.
 * @returns The assembled record.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { record, RecordType } from 'edgeport/dns';
 *
 * const rr = record('example.com', RecordType.A, 3600, '93.184.216.34');
 * ```
 */
export function record(
	name: string,
	type: RecordType | number,
	ttl: number,
	data: RData,
	cls: RecordClass | number = RecordClass.IN
): ResourceRecord {
	const rdata = encodeRdata(type, data);
	return { name, type, class: cls, ttl, rdata, data };
}

// encodes one resource record: name, type, class, ttl, rdlength, rdata
function encodeRecord(rr: ResourceRecord): Uint8Array {
	return concat([
		encodeName(rr.name),
		u16(rr.type as number),
		u16(rr.class as number),
		u32(rr.ttl),
		u16(rr.rdata.length),
		rr.rdata
	]);
}

/**
 * Encodes a question section entry (name, TYPE, CLASS).
 *
 * @param q - The question to encode.
 * @returns The encoded question bytes.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { encodeQuestion, RecordType, RecordClass } from 'edgeport/dns';
 *
 * const bytes = encodeQuestion({ name: 'example.com', type: RecordType.A, class: RecordClass.IN });
 * ```
 */
export function encodeQuestion(q: Question): Uint8Array {
	return concat([encodeName(q.name), u16(q.type as number), u16(q.class as number)]);
}

/**
 * Encodes a complete DNS message (header, question, and RR sections) to its wire bytes.
 *
 * Section counts are derived from the array lengths. Each resource record is written with its raw
 * `rdata`; names are always uncompressed. The result is the bare DNS message - the 2-byte TCP
 * length prefix is added by the transport, not here.
 *
 * @param msg - The message to encode.
 * @returns The encoded message octets.
 * @throws {ProtocolError} If a name or label is out of range.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { encodeMessage, RecordType, RecordClass, Opcode, ResponseCode } from 'edgeport/dns';
 *
 * const bytes = encodeMessage({
 * 	id: 0x1234,
 * 	flags: { qr: false, opcode: Opcode.QUERY, aa: false, tc: false, rd: true, ra: false,
 * 		z: false, ad: false, cd: false, rcode: ResponseCode.NOERROR },
 * 	question: [{ name: 'example.com', type: RecordType.A, class: RecordClass.IN }],
 * 	answer: [], authority: [], additional: []
 * });
 * ```
 */
export function encodeMessage(msg: DnsMessage): Uint8Array {
	const header = new Uint8Array(HEADER_LENGTH);
	const dv = new DataView(header.buffer);
	dv.setUint16(0, msg.id & 0xffff, false);
	dv.setUint16(2, packFlags(msg.flags), false);
	dv.setUint16(4, msg.question.length, false);
	dv.setUint16(6, msg.answer.length, false);
	dv.setUint16(8, msg.authority.length, false);
	dv.setUint16(10, msg.additional.length, false);
	const chunks: Uint8Array[] = [header];
	for (const q of msg.question) chunks.push(encodeQuestion(q));
	for (const rr of msg.answer) chunks.push(encodeRecord(rr));
	for (const rr of msg.authority) chunks.push(encodeRecord(rr));
	for (const rr of msg.additional) chunks.push(encodeRecord(rr));
	return concat(chunks);
}

// decodes one resource record at the reader's cursor
function decodeRecord(r: MessageReader): ResourceRecord {
	const name = r.name();
	const type = r.u16();
	const cls = r.u16();
	const ttl = r.u32();
	const rdlength = r.u16();
	const rdataStart = r.off;
	if (rdataStart + rdlength > r.end) {
		throw new ProtocolError('resource record rdata runs past the message', { protocol: PROTO });
	}
	const rdata = r.msg.slice(rdataStart, rdataStart + rdlength);
	const data = parseRdata(type, r.msg, rdataStart, rdlength);
	r.off = rdataStart + rdlength;
	return { name, type, class: cls, ttl, rdata, data };
}

/**
 * Decodes a complete, already-framed DNS message (without the TCP length prefix).
 *
 * Reads the header, the question section, then the answer / authority / additional records,
 * decoding the resource data of the understood TYPEs into structured fields while keeping the raw
 * `rdata` on every record. Compression pointers in names (including inside rdata) are followed.
 *
 * @param bytes - The bare DNS message bytes.
 * @returns The decoded message.
 * @throws {ProtocolError} If the header is short or any field runs past the buffer.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { decodeMessage } from 'edgeport/dns';
 *
 * const msg = decodeMessage(responseBytes);
 * console.log(msg.answer[0]?.data);
 * ```
 */
export function decodeMessage(bytes: Uint8Array): DnsMessage {
	if (bytes.length < HEADER_LENGTH) {
		throw new ProtocolError('dns message shorter than the 12-byte header', { protocol: PROTO });
	}
	const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const id = dv.getUint16(0, false);
	const flags = unpackFlags(dv.getUint16(2, false));
	const qdcount = dv.getUint16(4, false);
	const ancount = dv.getUint16(6, false);
	const nscount = dv.getUint16(8, false);
	const arcount = dv.getUint16(10, false);
	const r = new MessageReader(bytes, HEADER_LENGTH, bytes.length);

	const question: Question[] = [];
	for (let i = 0; i < qdcount; i++) {
		const name = r.name();
		const type = r.u16();
		const cls = r.u16();
		question.push({ name, type, class: cls });
	}
	const readN = (n: number): ResourceRecord[] => {
		const out: ResourceRecord[] = [];
		for (let i = 0; i < n; i++) out.push(decodeRecord(r));
		return out;
	};
	const answer = readN(ancount);
	const authority = readN(nscount);
	const additional = readN(arcount);
	return { id, flags, question, answer, authority, additional };
}

/**
 * Options for {@link encodeOptRecord}.
 *
 * @since 1.0.4
 */
export interface EdnsOptions {
	/** The advertised UDP payload size; defaults to {@link DEFAULT_UDP_PAYLOAD_SIZE}. */
	udpPayloadSize?: number;
	/** Set the DNSSEC OK (DO) bit to request DNSSEC records. */
	dnssecOk?: boolean;
	/** The upper 8 bits of the extended RCODE; defaults to 0. */
	extendedRcode?: number;
	/** The EDNS version; defaults to 0 (EDNS0). */
	version?: number;
	/** Extra EDNS options to carry in the rdata. */
	options?: EdnsOption[];
}

/**
 * Builds an EDNS0 OPT pseudo-record for the additional section (RFC 6891).
 *
 * The OPT record repurposes the header fields: CLASS carries the UDP payload size and TTL packs
 * the extended RCODE, version, and the DO (DNSSEC OK) bit. The owner name is always the root.
 *
 * @param opts - The OPT parameters.
 * @returns A {@link ResourceRecord} ready to append to a message's additional section.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { encodeOptRecord } from 'edgeport/dns';
 *
 * const opt = encodeOptRecord({ dnssecOk: true }); // 4096-byte UDP size, DO bit set
 * ```
 */
export function encodeOptRecord(opts: EdnsOptions = {}): ResourceRecord {
	const udpPayloadSize = opts.udpPayloadSize ?? DEFAULT_UDP_PAYLOAD_SIZE;
	// ttl = extended-rcode(8) | version(8) | DO(1) | z(15)
	const ttl =
		(((opts.extendedRcode ?? 0) & 0xff) << 24) |
		(((opts.version ?? 0) & 0xff) << 16) |
		(opts.dnssecOk ? 0x8000 : 0);
	const options = opts.options ?? [];
	const rdataChunks: Uint8Array[] = [];
	for (const o of options) rdataChunks.push(u16(o.code), u16(o.value.length), o.value);
	const rdata = concat(rdataChunks);
	const data: OptData = {
		udpPayloadSize,
		dnssecOk: opts.dnssecOk ?? false,
		extendedRcode: opts.extendedRcode ?? 0,
		version: opts.version ?? 0,
		options
	};
	return { name: '', type: RecordType.OPT, class: udpPayloadSize, ttl: ttl >>> 0, rdata, data };
}

/**
 * Decodes an OPT pseudo-record's full EDNS0 semantics from its header fields and rdata.
 *
 * The UDP payload size comes from the record's CLASS, the DO bit / version / extended RCODE from
 * its TTL, and the options from its rdata.
 *
 * @param rr - An OPT resource record (`type === RecordType.OPT`).
 * @returns The decoded EDNS0 fields.
 * @throws {ProtocolError} If the record is not an OPT record.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { decodeOpt, RecordType } from 'edgeport/dns';
 *
 * const opt = response.additional.find((rr) => rr.type === RecordType.OPT);
 * if (opt) console.log(decodeOpt(opt).dnssecOk);
 * ```
 */
export function decodeOpt(rr: ResourceRecord): OptData {
	if (rr.type !== RecordType.OPT) {
		throw new ProtocolError('record is not an OPT record', { protocol: PROTO });
	}
	const options = Array.isArray((rr.data as OptData).options) ? (rr.data as OptData).options : [];
	return {
		udpPayloadSize: rr.class as number,
		dnssecOk: (rr.ttl & 0x8000) !== 0,
		extendedRcode: (rr.ttl >>> 24) & 0xff,
		version: (rr.ttl >>> 16) & 0xff,
		options
	};
}

/**
 * Builds the reverse-DNS PTR query name for an IP address.
 *
 * IPv4 yields `<reversed octets>.in-addr.arpa`; IPv6 yields the 32 reversed nibbles followed by
 * `.ip6.arpa` (RFC 3596).
 *
 * @param ip - The IPv4 or IPv6 address.
 * @returns The `.arpa` name to query for a PTR record.
 * @throws {ProtocolError} If `ip` is not a valid address.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { reverseName } from 'edgeport/dns';
 *
 * reverseName('8.8.8.8'); // '8.8.8.8.in-addr.arpa'
 * ```
 */
export function reverseName(ip: string): string {
	if (ip.includes(':')) {
		const bytes = parseIpv6(ip);
		const nibbles: string[] = [];
		for (let i = bytes.length - 1; i >= 0; i--) {
			nibbles.push((bytes[i]! & 0x0f).toString(16), (bytes[i]! >> 4).toString(16));
		}
		return `${nibbles.join('.')}.ip6.arpa`;
	}
	const octets = parseIpv4(ip);
	return `${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa`;
}

/**
 * Returns the string name of a record TYPE (e.g. `1` -> `"A"`), or the number as text if unknown.
 *
 * @param type - The numeric TYPE.
 * @returns The type name or the decimal string for an unrecognized TYPE.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { recordTypeName } from 'edgeport/dns';
 *
 * recordTypeName(28); // 'AAAA'
 * ```
 */
export function recordTypeName(type: number): string {
	return RecordType[type] ?? String(type);
}

/**
 * Resolves a record TYPE name or number to its numeric TYPE value.
 *
 * @param type - A {@link RecordTypeName} (e.g. `"MX"`) or a numeric TYPE.
 * @returns The numeric TYPE.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { recordTypeNumber } from 'edgeport/dns';
 *
 * recordTypeNumber('AAAA'); // 28
 * ```
 */
export function recordTypeNumber(type: RecordTypeName | RecordType | number): number {
	return typeNumber(type);
}
