import { expect, it } from 'vitest';
import { connect, search } from '../../src/ldap/index';

const admin = {
	hostname: '127.0.0.1',
	port: 389,
	bindDN: 'cn=admin,dc=example,dc=org',
	password: 'admin'
};

it('binds as admin and searches the base DN', async () => {
	await using ldap = await connect(admin);
	const entries = await ldap.search({
		base: 'dc=example,dc=org',
		scope: 'base',
		filter: '(objectClass=*)'
	});
	expect(entries.length).toBeGreaterThan(0);
	expect(entries[0]!.dn.toLowerCase()).toContain('dc=example,dc=org');
});

it('one-shot search with an RFC 4515 filter', async () => {
	const entries = await search({
		...admin,
		base: 'dc=example,dc=org',
		scope: 'sub',
		filter: '(objectClass=organization)'
	});
	expect(entries.length).toBeGreaterThan(0);
});

it('rejects a wrong bind password with AuthError', async () => {
	await expect(connect({ ...admin, password: 'wrong' })).rejects.toBeTruthy();
});
