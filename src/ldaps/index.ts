/**
 * @fileoverview LDAP over implicit TLS (LDAPS, port 636).
 *
 * LDAPS is plain LDAP carried on a TLS socket from the first byte, the analogue of HTTPS to
 * HTTP. This module is a thin shim over `edgeport/ldap`: it defaults the transport to implicit
 * TLS and the port to 636, then delegates to the same {@link ldapConnect}/{@link ldapSearch}
 * implementations. All types and the structured filter API are re-exported so callers need
 * only import from one place.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import {
	connect as ldapConnect,
	search as ldapSearch,
	type LdapConnectOptions,
	type LdapEntry,
	type LdapSession,
	type SearchOptions
} from '../ldap';

export {
	encodeFilter,
	parseFilter,
	type Filter,
	type LdapConnectOptions,
	type LdapEntry,
	type LdapSession,
	type SearchOptions,
	type SearchScope
} from '../ldap';

const DEFAULT_LDAPS_PORT = 636;

/**
 * Applies the LDAPS defaults (implicit TLS, port 636) unless the caller overrode them.
 *
 * @param opts - The caller's options.
 * @returns The options with `tls` and `port` defaulted for LDAPS.
 * @internal
 */
export function _withDefaults<T extends LdapConnectOptions>(opts: T): T {
	return { ...opts, tls: opts.tls ?? 'implicit', port: opts.port ?? DEFAULT_LDAPS_PORT };
}

/**
 * Opens an LDAPS connection (implicit TLS, port 636) and optionally binds.
 *
 * Identical to {@link ldapConnect} except {@link LdapConnectOptions.tls} defaults to
 * `'implicit'` and {@link LdapConnectOptions.port} defaults to 636.
 *
 * @param opts - Connection options; `tls` and `port` are defaulted for LDAPS.
 * @returns A ready {@link LdapSession}.
 * @throws {AuthError} If a requested bind is rejected.
 * @throws {ConnectionError} If the connection or TLS handshake fails.
 * @since 1.0.0
 * @example
 * ```typescript
 * await using session = await connect({
 *   hostname: 'ldaps.example.com',
 *   bindDN: 'cn=admin,dc=example,dc=com',
 *   password: 'secret'
 * });
 * ```
 */
export function connect(opts: LdapConnectOptions): Promise<LdapSession> {
	return ldapConnect(_withDefaults(opts));
}

/**
 * One-shot LDAPS search: connect (optionally bind), search, and close.
 *
 * Identical to {@link ldapSearch} except the transport defaults to implicit TLS on port 636.
 *
 * @param opts - Combined connection and search options.
 * @returns The matched entries.
 * @throws {AuthError} If a requested bind is rejected.
 * @throws {ProtocolError} If the search fails.
 * @since 1.0.0
 * @example
 * ```typescript
 * const entries = await search({
 *   hostname: 'ldaps.example.com',
 *   base: 'dc=example,dc=com',
 *   filter: '(uid=jdoe)'
 * });
 * ```
 */
export function search(opts: LdapConnectOptions & SearchOptions): Promise<LdapEntry[]> {
	return ldapSearch(_withDefaults(opts));
}
