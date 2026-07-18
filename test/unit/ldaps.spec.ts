// the LDAPS shim defaults transport to implicit TLS on 636 and re-exports the filter API
import { describe, expect, it, vi } from 'vitest';
import { connect as ldapConnect, search as ldapSearch, type LdapSession } from '../../src/ldap';
import {
	_withDefaults,
	connect as ldapsConnect,
	search as ldapsSearch,
	parseFilter
} from '../../src/ldaps/index';

// stub only connect/search on the underlying ldap module so the shim can be exercised without a
// real socket; everything else (the filter API it re-exports) stays real
vi.mock('../../src/ldap', async (importOriginal) => {
	const actual = await importOriginal<typeof import('../../src/ldap')>();
	return { ...actual, connect: vi.fn(), search: vi.fn() };
});

describe('ldaps defaults', () => {
	it('defaults tls to implicit and port to 636', () => {
		expect(_withDefaults({ hostname: 'h' })).toMatchObject({
			hostname: 'h',
			tls: 'implicit',
			port: 636
		});
	});

	it('respects caller overrides of tls and port', () => {
		const o = _withDefaults({ hostname: 'h', tls: 'starttls', port: 3899 });
		expect(o.tls).toBe('starttls');
		expect(o.port).toBe(3899);
	});

	it('re-exports the filter API', () => {
		expect(parseFilter('(uid=jdoe)')).toBeTruthy();
	});
});

describe('ldaps connect / search delegation', () => {
	it('connect applies the LDAPS defaults and delegates to ldap.connect', async () => {
		const fakeSession = {} as LdapSession;
		vi.mocked(ldapConnect).mockResolvedValue(fakeSession);
		const session = await ldapsConnect({ hostname: 'ldaps.test' });
		expect(session).toBe(fakeSession);
		expect(ldapConnect).toHaveBeenCalledWith(
			expect.objectContaining({ hostname: 'ldaps.test', tls: 'implicit', port: 636 })
		);
	});

	it('search applies the LDAPS defaults and delegates to ldap.search', async () => {
		const entries = [{ dn: 'uid=jdoe,dc=example,dc=org', attributes: { uid: ['jdoe'] } }];
		vi.mocked(ldapSearch).mockResolvedValue(entries);
		const result = await ldapsSearch({ hostname: 'ldaps.test', base: 'dc=example,dc=org' });
		expect(result).toBe(entries);
		expect(ldapSearch).toHaveBeenCalledWith(
			expect.objectContaining({ tls: 'implicit', port: 636, base: 'dc=example,dc=org' })
		);
	});

	it('honors a caller override instead of the LDAPS default port', async () => {
		vi.mocked(ldapSearch).mockResolvedValue([]);
		await ldapsSearch({ hostname: 'ldaps.test', base: 'dc=x', port: 3899 });
		expect(ldapSearch).toHaveBeenCalledWith(expect.objectContaining({ port: 3899 }));
	});
});
