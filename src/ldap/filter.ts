/**
 * @fileoverview RFC 4515 search filter parsing and BER encoding for LDAP.
 *
 * LDAP search filters arrive two ways in this library: as the familiar parenthesised string
 * form (`(&(objectClass=person)(uid=jdoe))`) and as a structured object. This module defines
 * the structured {@link Filter} union, parses the string form into it with {@link parseFilter},
 * and serialises either form to the context-tagged BER the wire protocol expects with
 * {@link encodeFilter}.
 *
 * The filter choices are context-class tags from RFC 4511 section 4.5.1: `and [0]`, `or [1]`,
 * `not [2]`, `equalityMatch [3]`, `substrings [4]`, `greaterOrEqual [5]`, `lessOrEqual [6]`,
 * `present [7]`, and `approxMatch [8]`. The `present` choice is primitive (the bare attribute
 * name); the rest are constructed.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { BerWriter, contextTag } from './ber';

const encoder = new TextEncoder();
const writer = new BerWriter();

/** Equality, ordering, and approximate-match filters: `attr OP value`. */
export interface AttributeValueFilter {
	/** The match kind. */
	type: 'equalityMatch' | 'greaterOrEqual' | 'lessOrEqual' | 'approxMatch';
	/** The attribute description (e.g. `cn`). */
	attribute: string;
	/** The assertion value. */
	value: string;
}

/** A substring filter: `attr=initial*any*...*final`, with at least one piece present. */
export interface SubstringsFilter {
	/** Discriminator. */
	type: 'substrings';
	/** The attribute description. */
	attribute: string;
	/** The leading anchor (the text before the first `*`), if any. */
	initial?: string;
	/** Ordered middle pieces (between `*`s). */
	any?: string[];
	/** The trailing anchor (the text after the last `*`), if any. */
	final?: string;
}

/** A presence filter: `attr=*`. */
export interface PresentFilter {
	/** Discriminator. */
	type: 'present';
	/** The attribute that must be present. */
	attribute: string;
}

/** Conjunction or disjunction of one or more sub-filters. */
export interface AndOrFilter {
	/** Discriminator. */
	type: 'and' | 'or';
	/** The member filters. */
	filters: Filter[];
}

/** Negation of a single sub-filter. */
export interface NotFilter {
	/** Discriminator. */
	type: 'not';
	/** The negated filter. */
	filter: Filter;
}

/**
 * A structured LDAP search filter: a discriminated union over every supported choice.
 *
 * @since 1.0.0
 */
export type Filter =
	AttributeValueFilter | SubstringsFilter | PresentFilter | AndOrFilter | NotFilter;

// context tag numbers from RFC 4511 4.5.1
const TAG_AND = 0;
const TAG_OR = 1;
const TAG_NOT = 2;
const TAG_EQUALITY = 3;
const TAG_SUBSTRINGS = 4;
const TAG_GREATER_OR_EQUAL = 5;
const TAG_LESS_OR_EQUAL = 6;
const TAG_PRESENT = 7;
const TAG_APPROX = 8;
// substring choice tags (within the substrings SEQUENCE)
const SUB_INITIAL = 0;
const SUB_ANY = 1;
const SUB_FINAL = 2;

/**
 * BER-encodes a structured {@link Filter} into the context-tagged bytes used inside a
 * SearchRequest.
 *
 * @param f - The structured filter.
 * @returns The encoded filter element.
 * @throws {RangeError} If a composite filter has no members.
 * @since 1.0.0
 * @example
 * ```typescript
 * encodeFilter({ type: 'present', attribute: 'mail' });
 * ```
 */
export function encodeFilter(f: Filter): Uint8Array {
	switch (f.type) {
		case 'and':
		case 'or': {
			if (f.filters.length === 0) throw new RangeError(`${f.type} filter needs >= 1 member`);
			const tag = contextTag(f.type === 'and' ? TAG_AND : TAG_OR, true);
			return writer.tagged(tag, concat(f.filters.map(encodeFilter)));
		}
		case 'not':
			return writer.tagged(contextTag(TAG_NOT, true), encodeFilter(f.filter));
		case 'present':
			// primitive choice: content is just the attribute name bytes
			return writer.tagged(contextTag(TAG_PRESENT, false), encoder.encode(f.attribute));
		case 'substrings':
			return encodeSubstrings(f);
		case 'equalityMatch':
			return encodeAva(TAG_EQUALITY, f);
		case 'greaterOrEqual':
			return encodeAva(TAG_GREATER_OR_EQUAL, f);
		case 'lessOrEqual':
			return encodeAva(TAG_LESS_OR_EQUAL, f);
		case 'approxMatch':
			return encodeAva(TAG_APPROX, f);
	}
}

// AttributeValueAssertion ::= SEQUENCE { attributeDesc, assertionValue }
function encodeAva(tagNum: number, f: AttributeValueFilter): Uint8Array {
	const content = concat([writer.octetString(f.attribute), writer.octetString(f.value)]);
	return writer.tagged(contextTag(tagNum, true), content);
}

// SubstringFilter ::= SEQUENCE { type, substrings SEQUENCE OF choice }
function encodeSubstrings(f: SubstringsFilter): Uint8Array {
	const pieces: Uint8Array[] = [];
	if (f.initial !== undefined) {
		pieces.push(writer.tagged(contextTag(SUB_INITIAL, false), encoder.encode(f.initial)));
	}
	for (const a of f.any ?? []) {
		pieces.push(writer.tagged(contextTag(SUB_ANY, false), encoder.encode(a)));
	}
	if (f.final !== undefined) {
		pieces.push(writer.tagged(contextTag(SUB_FINAL, false), encoder.encode(f.final)));
	}
	if (pieces.length === 0) throw new RangeError('substrings filter needs >= 1 piece');
	const content = concat([writer.octetString(f.attribute), writer.sequence(pieces)]);
	return writer.tagged(contextTag(TAG_SUBSTRINGS, true), content);
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

/**
 * Parses an RFC 4515 filter string into a structured {@link Filter}.
 *
 * Supports the composite operators `&`, `|`, `!`, the comparison operators `=`, `>=`, `<=`,
 * `~=`, the presence test `attr=*`, and substring patterns such as `cn=a*b*c`. The outermost
 * parentheses are required, matching the RFC grammar.
 *
 * @param input - The filter string (e.g. `(&(objectClass=person)(uid=jdoe))`).
 * @returns The structured filter.
 * @throws {SyntaxError} If the string is malformed (unbalanced parens, empty filter, etc.).
 * @since 1.0.0
 * @example
 * ```typescript
 * parseFilter('(mail=*)'); // { type: 'present', attribute: 'mail' }
 * parseFilter('(cn=a*b*c)'); // substrings: initial a, any [b], final c
 * ```
 */
export function parseFilter(input: string): Filter {
	const p = new FilterParser(input);
	const f = p.parseFilter();
	p.expectEnd();
	return f;
}

// recursive-descent parser over the RFC 4515 grammar
class FilterParser {
	readonly #s: string;
	#i = 0;

	constructor(s: string) {
		this.#s = s;
	}

	parseFilter(): Filter {
		this.#expect('(');
		const f = this.#parseFilterComp();
		this.#expect(')');
		return f;
	}

	#parseFilterComp(): Filter {
		const c = this.#peek();
		if (c === '&' || c === '|') {
			this.#i++;
			const filters = this.#parseFilterList();
			return { type: c === '&' ? 'and' : 'or', filters };
		}
		if (c === '!') {
			this.#i++;
			const filter = this.parseFilter();
			return { type: 'not', filter };
		}
		return this.#parseItem();
	}

	#parseFilterList(): Filter[] {
		const list: Filter[] = [];
		while (this.#peek() === '(') list.push(this.parseFilter());
		if (list.length === 0) throw new SyntaxError('filter: empty &/| list');
		return list;
	}

	// attr OP value, where OP is =, >=, <=, or ~=; = may be present or substrings
	#parseItem(): Filter {
		const attr = this.#readAttribute();
		const op = this.#readOp();
		const value = this.#readValue();
		if (op === '>=') return { type: 'greaterOrEqual', attribute: attr, value };
		if (op === '<=') return { type: 'lessOrEqual', attribute: attr, value };
		if (op === '~=') return { type: 'approxMatch', attribute: attr, value };
		// op is '='
		if (value === '*') return { type: 'present', attribute: attr };
		if (value.includes('*')) return this.#substrings(attr, value);
		return { type: 'equalityMatch', attribute: attr, value };
	}

	#substrings(attr: string, value: string): SubstringsFilter {
		const parts = value.split('*');
		const initial = parts[0] !== '' ? parts[0] : undefined;
		const final = parts[parts.length - 1] !== '' ? parts[parts.length - 1] : undefined;
		const any = parts.slice(1, -1).filter((s) => s !== '');
		const out: SubstringsFilter = { type: 'substrings', attribute: attr };
		if (initial !== undefined) out.initial = initial;
		if (any.length > 0) out.any = any;
		if (final !== undefined) out.final = final;
		return out;
	}

	#readAttribute(): string {
		const start = this.#i;
		while (this.#i < this.#s.length && !'=<>~()'.includes(this.#s[this.#i]!)) this.#i++;
		const attr = this.#s.slice(start, this.#i).trim();
		if (attr === '') throw new SyntaxError('filter: missing attribute');
		return attr;
	}

	#readOp(): '=' | '>=' | '<=' | '~=' {
		const c = this.#peek();
		if (c === '=') {
			this.#i++;
			return '=';
		}
		if (c === '>' || c === '<' || c === '~') {
			if (this.#s[this.#i + 1] !== '=') throw new SyntaxError(`filter: expected '=' after '${c}'`);
			this.#i += 2;
			return (c + '=') as '>=' | '<=' | '~=';
		}
		throw new SyntaxError(`filter: expected comparison operator, got '${c}'`);
	}

	#readValue(): string {
		const start = this.#i;
		while (this.#i < this.#s.length && this.#s[this.#i] !== ')') this.#i++;
		return this.#s.slice(start, this.#i);
	}

	#peek(): string {
		if (this.#i >= this.#s.length) throw new SyntaxError('filter: unexpected end of input');
		return this.#s[this.#i]!;
	}

	#expect(ch: string): void {
		if (this.#peek() !== ch) throw new SyntaxError(`filter: expected '${ch}' at ${this.#i}`);
		this.#i++;
	}

	expectEnd(): void {
		if (this.#i !== this.#s.length) throw new SyntaxError('filter: trailing characters');
	}
}
