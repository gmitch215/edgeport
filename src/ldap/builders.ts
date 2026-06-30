/**
 * @fileoverview Injection-safe builders for the structured {@link Filter} union, plus the
 * RFC 4515 / RFC 4514 escaping helpers.
 *
 * The structured {@link Filter} form is the safe way to build search filters from untrusted
 * input: {@link encodeFilter} writes assertion values as literal BER octet strings, so a `*`,
 * `(`, or `)` in a value becomes a literal byte on the wire -- never a wildcard or a grouping
 * token. The builders here ({@link eq}, {@link contains}, {@link substring}, ...) return those
 * structured nodes, so `eq('uid', userInput)` cannot be used to inject filter syntax.
 *
 * {@link escapeFilterValue} and {@link escapeDN} exist for the other direction: when a caller
 * assembles a filter *string* or a DN by hand and needs to neutralise metacharacters in an
 * interpolated value. They are not applied to the structured builders (that would
 * double-escape, since the BER encoder does not unescape).
 *
 * @author Gregory Mitchell
 * @since 1.0.2
 */
import type {
	AndOrFilter,
	AttributeValueFilter,
	Filter,
	NotFilter,
	PresentFilter,
	SubstringsFilter
} from './filter';

/**
 * Escapes a value for safe interpolation into an RFC 4515 filter *string*.
 *
 * Replaces the assertion-value metacharacters -- `\`, `*`, `(`, `)`, and the NUL byte -- with
 * their `\xx` hex escapes (`\5c`, `\2a`, `\28`, `\29`, `\00`). Use this only when building a
 * filter string by hand; the structured builders ({@link eq}, {@link contains}, ...) are
 * already injection-safe and must not be combined with this (it would double-escape).
 *
 * @param value - The raw assertion value.
 * @returns The escaped value, safe to splice between an operator and a `)`.
 * @since 1.0.2
 * @example
 * ```typescript
 * const f = `(cn=${escapeFilterValue('a*b(c)')})`; // (cn=a\2ab\28c\29)
 * ```
 */
export function escapeFilterValue(value: string): string {
	let out = '';
	for (const ch of value) {
		switch (ch) {
			case '\\':
				out += '\\5c';
				break;
			case '*':
				out += '\\2a';
				break;
			case '(':
				out += '\\28';
				break;
			case ')':
				out += '\\29';
				break;
			case '\0':
				out += '\\00';
				break;
			default:
				out += ch;
		}
	}
	return out;
}

/**
 * Escapes a single DN attribute value per RFC 4514 (section 2.4).
 *
 * Escapes a leading `#` or leading/trailing space, plus the special characters `,`, `+`, `"`,
 * `\`, `<`, `>`, `;`, and `=` anywhere in the value, by prefixing each with a backslash. Use
 * when composing a DN component from untrusted input, e.g. `` `uid=${escapeDN(uid)},${base}` ``.
 *
 * @param value - The raw attribute value (one RDN component value, not a whole DN).
 * @returns The escaped value.
 * @since 1.0.2
 * @example
 * ```typescript
 * const dn = `cn=${escapeDN('Doe, John')},dc=example,dc=org`; // cn=Doe\, John,...
 * ```
 */
export function escapeDN(value: string): string {
	let out = '';
	for (let i = 0; i < value.length; i++) {
		const ch = value[i]!;
		// leading/trailing space and a leading # must be escaped
		const edgeSpace = ch === ' ' && (i === 0 || i === value.length - 1);
		const leadingHash = ch === '#' && i === 0;
		if (edgeSpace || leadingHash || ',+"\\<>;='.includes(ch)) {
			out += '\\' + ch;
		} else {
			out += ch;
		}
	}
	return out;
}

/**
 * Conjunction (`&`) of one or more sub-filters.
 *
 * @param f - The member filters (at least one).
 * @returns An `and` {@link Filter} node.
 * @since 1.0.2
 * @example
 * ```typescript
 * and(eq('objectClass', 'person'), eq('uid', 'jdoe'));
 * ```
 */
export function and(...f: Filter[]): AndOrFilter {
	return { type: 'and', filters: f };
}

/**
 * Disjunction (`|`) of one or more sub-filters.
 *
 * @param f - The member filters (at least one).
 * @returns An `or` {@link Filter} node.
 * @since 1.0.2
 * @example
 * ```typescript
 * or(eq('uid', 'alice'), eq('uid', 'bob'));
 * ```
 */
export function or(...f: Filter[]): AndOrFilter {
	return { type: 'or', filters: f };
}

/**
 * Negation (`!`) of a single sub-filter.
 *
 * @param f - The filter to negate.
 * @returns A `not` {@link Filter} node.
 * @since 1.0.2
 * @example
 * ```typescript
 * not(eq('disabled', 'TRUE'));
 * ```
 */
export function not(f: Filter): NotFilter {
	return { type: 'not', filter: f };
}

/**
 * Equality match (`attr=value`).
 *
 * The value is carried literally in the structured node, so metacharacters in `value` are not
 * interpreted -- `eq('uid', untrusted)` is injection-safe.
 *
 * @param attr - The attribute description (e.g. `uid`).
 * @param value - The assertion value (used verbatim).
 * @returns An `equalityMatch` {@link Filter} node.
 * @since 1.0.2
 * @example
 * ```typescript
 * eq('uid', 'jdoe');
 * ```
 */
export function eq(attr: string, value: string): AttributeValueFilter {
	return { type: 'equalityMatch', attribute: attr, value };
}

/**
 * Presence test (`attr=*`): matches entries that have the attribute set.
 *
 * @param attr - The attribute that must be present.
 * @returns A `present` {@link Filter} node.
 * @since 1.0.2
 * @example
 * ```typescript
 * present('mail');
 * ```
 */
export function present(attr: string): PresentFilter {
	return { type: 'present', attribute: attr };
}

/**
 * Greater-or-equal ordering match (`attr>=value`).
 *
 * @param attr - The attribute description.
 * @param value - The assertion value (used verbatim).
 * @returns A `greaterOrEqual` {@link Filter} node.
 * @since 1.0.2
 * @example
 * ```typescript
 * gte('age', '18');
 * ```
 */
export function gte(attr: string, value: string): AttributeValueFilter {
	return { type: 'greaterOrEqual', attribute: attr, value };
}

/**
 * Less-or-equal ordering match (`attr<=value`).
 *
 * @param attr - The attribute description.
 * @param value - The assertion value (used verbatim).
 * @returns A `lessOrEqual` {@link Filter} node.
 * @since 1.0.2
 * @example
 * ```typescript
 * lte('age', '65');
 * ```
 */
export function lte(attr: string, value: string): AttributeValueFilter {
	return { type: 'lessOrEqual', attribute: attr, value };
}

/**
 * Approximate match (`attr~=value`); server-defined fuzzy comparison.
 *
 * @param attr - The attribute description.
 * @param value - The assertion value (used verbatim).
 * @returns An `approxMatch` {@link Filter} node.
 * @since 1.0.2
 * @example
 * ```typescript
 * approx('sn', 'jonsen');
 * ```
 */
export function approx(attr: string, value: string): AttributeValueFilter {
	return { type: 'approxMatch', attribute: attr, value };
}

/**
 * Substring match (`attr=initial*any*...*final`) from explicit anchor parts.
 *
 * Each part is carried literally, so wildcards are expressed only by which parts are present,
 * never by metacharacters inside them. At least one part must be supplied.
 *
 * @param attr - The attribute description.
 * @param parts - The substring anchors: optional `initial`, ordered `any[]`, optional `final`.
 * @returns A `substrings` {@link Filter} node.
 * @throws {RangeError} If no part is supplied.
 * @since 1.0.2
 * @example
 * ```typescript
 * substring('cn', { initial: 'a', any: ['b'], final: 'c' }); // (cn=a*b*c)
 * substring('mail', { final: '@example.org' });              // (mail=*@example.org)
 * ```
 */
export function substring(
	attr: string,
	parts: { initial?: string; any?: string[]; final?: string }
): SubstringsFilter {
	const any = (parts.any ?? []).filter((s) => s !== '');
	const hasInitial = parts.initial !== undefined && parts.initial !== '';
	const hasFinal = parts.final !== undefined && parts.final !== '';
	if (!hasInitial && !hasFinal && any.length === 0) {
		throw new RangeError('substring filter needs at least one of initial/any/final');
	}
	const out: SubstringsFilter = { type: 'substrings', attribute: attr };
	if (hasInitial) out.initial = parts.initial;
	if (any.length > 0) out.any = any;
	if (hasFinal) out.final = parts.final;
	return out;
}

/**
 * Substring "contains" match (`attr=*text*`): the value appears somewhere in the attribute.
 *
 * `text` is carried literally as a single `any` anchor, so it is injection-safe -- a `*` in
 * `text` matches a literal asterisk, not an extra wildcard.
 *
 * @param attr - The attribute description.
 * @param text - The substring to look for (used verbatim).
 * @returns A `substrings` {@link Filter} node with one `any` part.
 * @since 1.0.2
 * @example
 * ```typescript
 * contains('cn', 'smith'); // (cn=*smith*)
 * ```
 */
export function contains(attr: string, text: string): SubstringsFilter {
	return { type: 'substrings', attribute: attr, any: [text] };
}

/**
 * The filter builders grouped under one namespace, for callers who prefer `filters.eq(...)`
 * over importing each builder individually. Identical to the named exports.
 *
 * @since 1.0.2
 * @example
 * ```typescript
 * import { filters } from 'edgeport/ldap';
 * const f = filters.and(filters.eq('objectClass', 'person'), filters.present('uid'));
 * ```
 */
export const filters = {
	and,
	or,
	not,
	eq,
	present,
	gte,
	lte,
	approx,
	substring,
	contains,
	escapeFilterValue,
	escapeDN
} as const;
