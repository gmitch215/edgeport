import { describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/errors';
import {
	_sessionOverSocket,
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
} from '../../src/ldap';
import {
	BerReader,
	BerWriter,
	TAG_OCTET_STRING,
	TAG_SEQUENCE,
	applicationTag,
	contextTag
} from '../../src/ldap/ber';
import { encodeFilter, parseFilter, type Filter } from '../../src/ldap/filter';
import { mockConnection } from '../mock-socket';

const w = new BerWriter();
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

// shallow structural view of an encoded filter: its outer tag + a reader over its content
function decode(f: Filter): { tag: number; reader: BerReader } {
	const el = new BerReader(encodeFilter(f)).readElement();
	return { tag: el.tag, reader: el.reader };
}

// reads attribute + value out of an AttributeValueAssertion-shaped filter
function ava(f: Filter): { attr: string; value: string } {
	const { reader } = decode(f);
	return { attr: dec(reader.octetString()), value: dec(reader.octetString()) };
}

// reads the substring pieces: { initial?, any[], final? } out of a substrings filter
function subPieces(f: Filter): { attr: string; initial?: string; any: string[]; final?: string } {
	const { reader } = decode(f);
	const attr = dec(reader.octetString());
	const seq = reader.sequence();
	const out: { attr: string; initial?: string; any: string[]; final?: string } = { attr, any: [] };
	while (seq.hasMore()) {
		const piece = seq.readElement();
		const tagNum = piece.tag & 0x1f;
		const text = dec(piece.content);
		if (tagNum === 0) out.initial = text;
		else if (tagNum === 1) out.any.push(text);
		else if (tagNum === 2) out.final = text;
	}
	return out;
}

// op tags used to script server responses
const OP_BIND_RESPONSE = 1;
const OP_SEARCH_RESULT_ENTRY = 4;
const OP_SEARCH_RESULT_DONE = 5;
const AUTH_SIMPLE = 0;

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

// builds an LDAPMessage with an LDAPResult-shaped protocolOp (BindResponse / SearchResultDone)
function ldapResult(id: number, op: number, code: number, diag = ''): Uint8Array {
	const body = concat([w.enumerated(code), w.octetString(''), w.octetString(diag)]);
	return w.sequence([w.integer(id), w.tagged(applicationTag(op, true), body)]);
}

// builds a SearchResultEntry message
function searchEntry(id: number, dn: string, attrs: Record<string, string[]>): Uint8Array {
	const attrSeqs = Object.entries(attrs).map(([type, vals]) =>
		w.sequence([w.octetString(type), w.set(vals.map((v) => w.octetString(v)))])
	);
	const body = concat([w.octetString(dn), w.sequence(attrSeqs)]);
	return w.sequence([w.integer(id), w.tagged(applicationTag(OP_SEARCH_RESULT_ENTRY, true), body)]);
}

// reads one full LDAPMessage off the server end (mirrors the client's framing)
async function readMessage(server: {
	readN: (n: number) => Promise<Uint8Array>;
}): Promise<Uint8Array> {
	const tag = await server.readN(1);
	const lenByte = (await server.readN(1))[0]!;
	let length = lenByte;
	let lenBytes: Uint8Array = new Uint8Array(0);
	if (lenByte >= 0x80) {
		const count = lenByte & 0x7f;
		lenBytes = await server.readN(count);
		length = 0;
		for (const b of lenBytes) length = length * 256 + b;
	}
	const content = await server.readN(length);
	return concat([tag, new Uint8Array([lenByte]), lenBytes, content]);
}

describe('BER round-trips', () => {
	it('encodes and decodes an integer', () => {
		const r = new BerReader(w.integer(12345));
		expect(r.integer()).toBe(12345);
	});

	it('encodes and decodes a negative integer', () => {
		const r = new BerReader(w.integer(-200));
		expect(r.integer()).toBe(-200);
	});

	it('encodes and decodes an octet string', () => {
		const el = w.octetString('cn=admin,dc=example,dc=com');
		expect(el[0]).toBe(TAG_OCTET_STRING);
		const r = new BerReader(el);
		expect(dec(r.octetString())).toBe('cn=admin,dc=example,dc=com');
	});

	it('encodes and decodes a nested sequence', () => {
		const seq = w.sequence([w.integer(1), w.octetString('x'), w.boolean(false)]);
		expect(seq[0]).toBe(TAG_SEQUENCE);
		const inner = new BerReader(seq).sequence();
		expect(inner.integer()).toBe(1);
		expect(dec(inner.octetString())).toBe('x');
	});

	it('round-trips long-form lengths (> 127 bytes)', () => {
		const big = 'a'.repeat(300);
		const r = new BerReader(w.octetString(big));
		expect(dec(r.octetString())).toBe(big);
	});

	it('encodes application and context tags', () => {
		const app = w.tagged(applicationTag(0, true), w.integer(3));
		expect(app[0]).toBe(0x60); // APPLICATION 0 constructed
		const inner = new BerReader(app).readElement();
		expect(inner.tag & 0x1f).toBe(0); // tag number 0
		expect(inner.reader.integer()).toBe(3);
		const ctx = w.tagged(contextTag(7, false), new TextEncoder().encode('mail'));
		expect(ctx[0]).toBe(0x87); // context 7 primitive
		expect(dec(new BerReader(ctx).readElement().content)).toBe('mail');
	});

	it('encodes a simple-auth context primitive tag (0x80)', () => {
		const el = w.tagged(contextTag(AUTH_SIMPLE, false), new TextEncoder().encode('pw'));
		expect(el[0]).toBe(0x80);
	});
});

describe('filter parse + encode round-trips', () => {
	// re-parse the BER back into a shallow structural view for assertions
	function decodeFilter(bytes: Uint8Array): { tag: number; reader: BerReader } {
		const el = new BerReader(bytes).readElement();
		return { tag: el.tag, reader: el.reader };
	}

	it('parses equality', () => {
		const f = parseFilter('(uid=jdoe)');
		expect(f).toEqual({ type: 'equalityMatch', attribute: 'uid', value: 'jdoe' });
		const { tag, reader } = decodeFilter(encodeFilter(f));
		expect(tag).toBe(contextTag(3, true));
		expect(dec(reader.octetString())).toBe('uid');
		expect(dec(reader.octetString())).toBe('jdoe');
	});

	it('parses present', () => {
		const f = parseFilter('(mail=*)');
		expect(f).toEqual({ type: 'present', attribute: 'mail' });
		const el = new BerReader(encodeFilter(f)).readElement();
		expect(el.tag).toBe(contextTag(7, false)); // 0x87, primitive
		expect(dec(el.content)).toBe('mail'); // bare attribute name
	});

	it('parses substrings (initial, any, final)', () => {
		const f = parseFilter('(cn=a*b*c)');
		expect(f).toEqual({
			type: 'substrings',
			attribute: 'cn',
			initial: 'a',
			any: ['b'],
			final: 'c'
		});
		const { tag } = decodeFilter(encodeFilter(f));
		expect(tag).toBe(contextTag(4, true)); // 0xA4
	});

	it('parses leading-wildcard substrings (final only)', () => {
		const f = parseFilter('(cn=*smith)') as Extract<Filter, { type: 'substrings' }>;
		expect(f.type).toBe('substrings');
		expect(f.initial).toBeUndefined();
		expect(f.final).toBe('smith');
	});

	it('parses and/or/not nesting', () => {
		const f = parseFilter('(&(objectClass=person)(|(uid=a)(uid=b))(!(disabled=TRUE)))');
		expect(f.type).toBe('and');
		const and = f as Extract<Filter, { filters: Filter[] }>;
		expect(and.filters).toHaveLength(3);
		expect(and.filters[1]!.type).toBe('or');
		expect(and.filters[2]!.type).toBe('not');
		// encodes to an `and` context-constructed tag (0xA0)
		expect(encodeFilter(f)[0]).toBe(contextTag(0, true));
	});

	it('parses comparison operators', () => {
		expect(parseFilter('(age>=18)')).toEqual({
			type: 'greaterOrEqual',
			attribute: 'age',
			value: '18'
		});
		expect(parseFilter('(age<=65)')).toEqual({
			type: 'lessOrEqual',
			attribute: 'age',
			value: '65'
		});
		expect(parseFilter('(cn~=jon)')).toEqual({
			type: 'approxMatch',
			attribute: 'cn',
			value: 'jon'
		});
	});

	it('rejects malformed filters', () => {
		expect(() => parseFilter('uid=jdoe')).toThrow();
		expect(() => parseFilter('(uid=jdoe')).toThrow();
	});
});

describe('bind', () => {
	it('binds successfully with simple auth', async () => {
		const { socket, server } = mockConnection();
		const client = _sessionOverSocket(socket, {
			hostname: 'ldap.test',
			bindDN: 'cn=admin,dc=example,dc=com',
			password: 'secret'
		});

		const script = (async () => {
			const reqBytes = await readMessage(server);
			// parse the client's BindRequest to verify it
			const seq = new BerReader(reqBytes).sequence();
			expect(seq.integer()).toBe(1); // messageID
			const op = seq.readElement();
			expect(op.tag).toBe(applicationTag(0, true)); // BindRequest
			expect(op.reader.integer()).toBe(3); // version
			expect(dec(op.reader.octetString())).toBe('cn=admin,dc=example,dc=com');
			const auth = op.reader.readElement();
			expect(auth.tag).toBe(contextTag(AUTH_SIMPLE, false));
			expect(dec(auth.content)).toBe('secret');
			await server.write(ldapResult(1, OP_BIND_RESPONSE, 0));
		})();

		const [session] = await Promise.all([client, script]);
		expect(session).toBeDefined();
	});

	it('throws AuthError on invalidCredentials (49)', async () => {
		const { socket, server } = mockConnection();
		const client = _sessionOverSocket(socket, {
			hostname: 'ldap.test',
			bindDN: 'cn=admin',
			password: 'wrong'
		});

		const script = (async () => {
			await readMessage(server);
			await server.write(ldapResult(1, OP_BIND_RESPONSE, 49, 'invalid credentials'));
		})();

		await expect(Promise.all([client, script])).rejects.toBeInstanceOf(AuthError);
	});
});

describe('search', () => {
	it('returns two entries then a done, parsing dn and attributes', async () => {
		const { socket, server } = mockConnection();
		const session = await _sessionOverSocket(socket, { hostname: 'ldap.test' });

		const script = (async () => {
			const reqBytes = await readMessage(server);
			const seq = new BerReader(reqBytes).sequence();
			expect(seq.integer()).toBe(1); // first messageID (no bind happened)
			const op = seq.readElement();
			expect(op.tag).toBe(applicationTag(3, true)); // SearchRequest
			expect(dec(op.reader.octetString())).toBe('dc=example,dc=com'); // base
			expect(op.reader.enumerated()).toBe(2); // scope sub

			await server.write(
				searchEntry(1, 'uid=alice,dc=example,dc=com', {
					uid: ['alice'],
					mail: ['alice@example.com', 'a@example.com']
				})
			);
			await server.write(searchEntry(1, 'uid=bob,dc=example,dc=com', { uid: ['bob'] }));
			await server.write(ldapResult(1, OP_SEARCH_RESULT_DONE, 0));
		})();

		const [entries] = await Promise.all([
			session.search({ base: 'dc=example,dc=com', filter: '(objectClass=*)' }),
			script
		]);

		expect(entries).toHaveLength(2);
		expect(entries[0]).toEqual({
			dn: 'uid=alice,dc=example,dc=com',
			attributes: { uid: ['alice'], mail: ['alice@example.com', 'a@example.com'] }
		});
		expect(entries[1]).toEqual({
			dn: 'uid=bob,dc=example,dc=com',
			attributes: { uid: ['bob'] }
		});
	});

	it('encodes an RFC 4515 filter string into the request', async () => {
		const { socket, server } = mockConnection();
		const session = await _sessionOverSocket(socket, { hostname: 'ldap.test' });

		const script = (async () => {
			const reqBytes = await readMessage(server);
			const seq = new BerReader(reqBytes).sequence();
			seq.integer(); // messageID
			const op = seq.readElement();
			op.reader.octetString(); // base
			op.reader.enumerated(); // scope
			op.reader.enumerated(); // deref
			op.reader.integer(); // sizeLimit
			op.reader.integer(); // timeLimit
			op.reader.readElement(); // typesOnly boolean
			const filter = op.reader.readElement();
			// (&(objectClass=person)(uid=jdoe)) -> top-level `and` (0xA0)
			expect(filter.tag).toBe(contextTag(0, true));
			await server.write(ldapResult(1, OP_SEARCH_RESULT_DONE, 0));
		})();

		const [entries] = await Promise.all([
			session.search({
				base: 'dc=example,dc=com',
				scope: 'one',
				filter: '(&(objectClass=person)(uid=jdoe))',
				attributes: ['cn', 'mail']
			}),
			script
		]);
		expect(entries).toEqual([]);
	});
});

describe('filter builders -> RFC 4511 BER', () => {
	it('eq produces an equalityMatch (tag 0xA3) with attr + value', () => {
		const f = eq('uid', 'jdoe');
		expect(f).toEqual({ type: 'equalityMatch', attribute: 'uid', value: 'jdoe' });
		const { tag } = decode(f);
		expect(tag).toBe(contextTag(3, true));
		expect(ava(f)).toEqual({ attr: 'uid', value: 'jdoe' });
	});

	it('present produces a primitive present (tag 0x87) carrying the bare attribute', () => {
		const f = present('mail');
		expect(f).toEqual({ type: 'present', attribute: 'mail' });
		const el = new BerReader(encodeFilter(f)).readElement();
		expect(el.tag).toBe(contextTag(7, false));
		expect(dec(el.content)).toBe('mail');
	});

	it('gte / lte / approx map to tags 0xA5 / 0xA6 / 0xA8', () => {
		expect(decode(gte('age', '18')).tag).toBe(contextTag(5, true));
		expect(decode(lte('age', '65')).tag).toBe(contextTag(6, true));
		expect(decode(approx('sn', 'jonsen')).tag).toBe(contextTag(8, true));
		expect(ava(gte('age', '18'))).toEqual({ attr: 'age', value: '18' });
	});

	it('substring renders initial/any/final pieces (tag 0xA4)', () => {
		const f = substring('cn', { initial: 'a', any: ['b', 'c'], final: 'd' });
		expect(decode(f).tag).toBe(contextTag(4, true));
		expect(subPieces(f)).toEqual({ attr: 'cn', initial: 'a', any: ['b', 'c'], final: 'd' });
	});

	it('substring with only a final anchor omits initial/any', () => {
		const f = substring('mail', { final: '@example.org' });
		expect(subPieces(f)).toEqual({ attr: 'mail', any: [], final: '@example.org' });
	});

	it('substring with no pieces throws RangeError', () => {
		expect(() => substring('cn', {})).toThrow(RangeError);
		expect(() => substring('cn', { any: [''] })).toThrow(RangeError);
	});

	it('contains renders (attr=*text*) as a single any piece', () => {
		const f = contains('cn', 'smith');
		expect(f).toEqual({ type: 'substrings', attribute: 'cn', any: ['smith'] });
		expect(subPieces(f)).toEqual({ attr: 'cn', any: ['smith'] });
	});
});

describe('builder nesting', () => {
	it('and nests members under a 0xA0 constructed tag', () => {
		const f = and(eq('objectClass', 'person'), present('uid'));
		expect(f.type).toBe('and');
		expect(encodeFilter(f)[0]).toBe(contextTag(0, true));
		const { reader } = decode(f);
		const first = reader.readElement();
		expect(first.tag).toBe(contextTag(3, true)); // equalityMatch
		const second = reader.readElement();
		expect(second.tag).toBe(contextTag(7, false)); // present
	});

	it('or nests members under a 0xA1 constructed tag', () => {
		const f = or(eq('uid', 'alice'), eq('uid', 'bob'));
		expect(encodeFilter(f)[0]).toBe(contextTag(1, true));
		expect(f.filters).toHaveLength(2);
	});

	it('not wraps a single member under a 0xA2 constructed tag', () => {
		const f = not(eq('disabled', 'TRUE'));
		expect(f).toEqual({
			type: 'not',
			filter: { type: 'equalityMatch', attribute: 'disabled', value: 'TRUE' }
		});
		expect(encodeFilter(f)[0]).toBe(contextTag(2, true));
		const { reader } = decode(f);
		expect(reader.readElement().tag).toBe(contextTag(3, true));
	});

	it('composes deep and/or/not trees', () => {
		const f = and(
			eq('objectClass', 'person'),
			or(eq('uid', 'a'), eq('uid', 'b')),
			not(present('disabled'))
		);
		const { reader } = decode(f);
		expect(reader.readElement().tag).toBe(contextTag(3, true)); // eq
		expect(reader.readElement().tag).toBe(contextTag(1, true)); // or
		expect(reader.readElement().tag).toBe(contextTag(2, true)); // not
	});
});

describe('injection safety (structured values carried literally)', () => {
	it('eq does not let filter metacharacters leak into the wire form', () => {
		// raw metachars are bytes in the value, not parsed as wildcards/grouping
		const f = eq('uid', 'a*b(c)');
		expect(ava(f)).toEqual({ attr: 'uid', value: 'a*b(c)' });
		// the encoded value octets are exactly the literal string, no \xx escaping applied
		const { reader } = decode(f);
		reader.octetString(); // attr
		expect(dec(reader.octetString())).toBe('a*b(c)');
	});

	it('contains carries a wildcard-looking substring literally', () => {
		const f = contains('cn', 'a*b');
		expect(subPieces(f)).toEqual({ attr: 'cn', any: ['a*b'] });
	});
});

describe('escapeFilterValue (RFC 4515 assertion value)', () => {
	it('escapes the metacharacter set to \\xx hex', () => {
		expect(escapeFilterValue('*')).toBe('\\2a');
		expect(escapeFilterValue('(')).toBe('\\28');
		expect(escapeFilterValue(')')).toBe('\\29');
		expect(escapeFilterValue('\\')).toBe('\\5c');
		expect(escapeFilterValue('\0')).toBe('\\00');
	});

	it('escapes a mixed value and leaves ordinary text alone', () => {
		expect(escapeFilterValue('a*b(c)')).toBe('a\\2ab\\28c\\29');
		expect(escapeFilterValue('John Doe')).toBe('John Doe');
	});

	it('produces a string with no raw metachars left', () => {
		const escaped = escapeFilterValue('x)(uid=*)');
		expect(escaped).not.toMatch(/[*()]/);
	});
});

describe('escapeDN (RFC 4514 attribute value)', () => {
	it('escapes the special set anywhere in the value', () => {
		expect(escapeDN('a,b')).toBe('a\\,b');
		expect(escapeDN('a+b')).toBe('a\\+b');
		expect(escapeDN('a"b')).toBe('a\\"b');
		expect(escapeDN('a\\b')).toBe('a\\\\b');
		expect(escapeDN('a<b')).toBe('a\\<b');
		expect(escapeDN('a>b')).toBe('a\\>b');
		expect(escapeDN('a;b')).toBe('a\\;b');
		expect(escapeDN('a=b')).toBe('a\\=b');
	});

	it('escapes a leading #, leading and trailing space', () => {
		expect(escapeDN('#abc')).toBe('\\#abc');
		expect(escapeDN(' abc')).toBe('\\ abc');
		expect(escapeDN('abc ')).toBe('abc\\ ');
		// inner spaces and inner # stay untouched
		expect(escapeDN('a # b')).toBe('a # b');
	});

	it('escapes a real comma-bearing CN component', () => {
		expect(escapeDN('Doe, John')).toBe('Doe\\, John');
	});
});

describe('filters namespace', () => {
	it('exposes the same builders as the named exports', () => {
		expect(filters.eq).toBe(eq);
		expect(filters.and).toBe(and);
		expect(filters.escapeFilterValue).toBe(escapeFilterValue);
		const f = filters.and(filters.eq('objectClass', 'person'), filters.present('uid'));
		expect(encodeFilter(f)[0]).toBe(contextTag(0, true));
	});
});
