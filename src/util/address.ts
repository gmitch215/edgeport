/**
 * @fileoverview Email-address parsing helpers shared across the mail protocol modules.
 *
 * The SMTP envelope, the MIME `From`/`To`/`Message-ID` headers, and any inbound-mail consumer
 * all need the same small chore: pull the bare `local@domain` out of a `Display Name <addr>`
 * string, and sometimes put one back together. Doing it inline breeds subtly different regexes
 * (some drop the display name, some forget the domain, some mishandle a quoted name), so this
 * centralizes the parse/format pair. Pure and transport-free, published under `edgeport/util`.
 *
 * @author Gregory Mitchell
 * @since 1.0.4
 */

/**
 * The pieces of a parsed email address.
 *
 * @since 1.0.4
 */
export interface ParsedAddress {
	/** The display name, when the input used the `Name <addr>` form; otherwise absent. */
	name?: string;
	/** The bare address with any display name and angle brackets removed. */
	address: string;
	/** The local part (everything before the last `@`), or the whole address if there is no `@`. */
	local: string;
	/** The domain part (everything after the last `@`), or absent if the address has no `@`. */
	domain?: string;
}

// strips a surrounding rfc 5322 quoted-string and unescapes its backslash escapes
function stripQuotes(name: string): string {
	if (name.length >= 2 && name.startsWith('"') && name.endsWith('"')) {
		return name.slice(1, -1).replace(/\\(.)/g, '$1');
	}
	return name;
}

/**
 * Parses an email address in either the bare (`local@domain`) or display-name
 * (`Display Name <local@domain>`) form.
 *
 * Whitespace around the whole input, the display name, and the bracketed address is trimmed;
 * a quoted display name (`"Doe, John" <j@x>`) is unquoted. When the input has no angle
 * brackets the entire trimmed string is treated as the address. The domain is split on the
 * last `@`, so it is absent for an address that contains no `@` at all.
 *
 * @param input - The raw address string.
 * @returns The parsed {@link ParsedAddress}. `address` is always present (possibly empty);
 *   `name` and `domain` are present only when the input supplied them.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { parseEmailAddress } from 'edgeport/util';
 *
 * parseEmailAddress('Ada Lovelace <ada@example.com>');
 * // { name: 'Ada Lovelace', address: 'ada@example.com', local: 'ada', domain: 'example.com' }
 *
 * parseEmailAddress('ops@example.com');
 * // { address: 'ops@example.com', local: 'ops', domain: 'example.com' }
 * ```
 */
export function parseEmailAddress(input: string): ParsedAddress {
	const trimmed = String(input ?? '').trim();

	let name: string | undefined;
	let address = trimmed;
	const angle = trimmed.match(/<([^>]*)>/);
	if (angle) {
		address = (angle[1] ?? '').trim();
		// the display name is whatever precedes the first '<'
		const namePart = trimmed.slice(0, trimmed.indexOf('<')).trim();
		const unquoted = stripQuotes(namePart).trim();
		if (unquoted) name = unquoted;
	}

	const at = address.lastIndexOf('@');
	const local = at >= 0 ? address.slice(0, at) : address;
	const result: ParsedAddress = { address, local };
	if (name !== undefined) result.name = name;
	if (at >= 0) result.domain = address.slice(at + 1);
	return result;
}

/**
 * Formats an address, wrapping it in a display name when one is given.
 *
 * The inverse of {@link parseEmailAddress}: a bare address is returned unchanged, and a named
 * address becomes `Name <address>`. A display name containing characters that would break the
 * header syntax (`",<>@()`) is emitted as a quoted string.
 *
 * @param addr - The address plus an optional display name.
 * @returns The formatted address string.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { formatEmailAddress } from 'edgeport/util';
 *
 * formatEmailAddress({ address: 'ada@example.com' }); // 'ada@example.com'
 * formatEmailAddress({ name: 'Doe, John', address: 'j@x.com' }); // '"Doe, John" <j@x.com>'
 * ```
 */
export function formatEmailAddress(addr: { name?: string; address: string }): string {
	const address = addr.address.trim();
	const name = addr.name?.trim();
	if (!name) return address;
	const needsQuote = /[",<>@()]/.test(name);
	const display = needsQuote ? `"${name.replace(/(["\\])/g, '\\$1')}"` : name;
	return `${display} <${address}>`;
}
