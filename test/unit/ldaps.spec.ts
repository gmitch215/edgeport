// the LDAPS shim defaults transport to implicit TLS on 636 and re-exports the filter API
import { expect, it } from 'vitest';
import { _withDefaults, parseFilter } from '../../src/ldaps/index';

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
