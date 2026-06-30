import { describe, expect, it } from 'vitest';
import { authenticate, connect, contains, eq, present, search } from '../../src/ldap/index';

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

describe('filter builders, findOne, and authenticate', () => {
	const peopleBase = 'ou=people,dc=example,dc=org';

	it('findOne returns the first matching entry built with eq()', async () => {
		await using ldap = await connect(admin);
		const entry = await ldap.findOne({ base: peopleBase, filter: eq('uid', 'alice') });
		expect(entry).not.toBeNull();
		expect(entry!.dn.toLowerCase()).toBe('uid=alice,ou=people,dc=example,dc=org');
		expect(entry!.attributes.uid).toEqual(['alice']);
	});

	it('findOne returns null when nothing matches', async () => {
		await using ldap = await connect(admin);
		const entry = await ldap.findOne({ base: peopleBase, filter: eq('uid', 'nobody') });
		expect(entry).toBeNull();
	});

	it('contains() builder matches a substring of cn', async () => {
		await using ldap = await connect(admin);
		const entries = await ldap.search({ base: peopleBase, filter: contains('cn', 'Admin') });
		expect(entries.map((e) => e.attributes.uid?.[0])).toContain('alice');
	});

	it('present() builder matches entries carrying the attribute', async () => {
		await using ldap = await connect(admin);
		const entries = await ldap.search({ base: peopleBase, filter: present('mail') });
		// alice, bob, carol all have mail
		expect(entries.length).toBeGreaterThanOrEqual(3);
	});

	it('a structured eq() value with filter metacharacters does not inject', async () => {
		await using ldap = await connect(admin);
		// the '*' is a literal here, so it must NOT behave like a presence/wildcard match
		const entries = await ldap.search({ base: peopleBase, filter: eq('uid', '*') });
		expect(entries).toHaveLength(0);
	});

	it('authenticate succeeds with the correct user password and returns the entry', async () => {
		const entry = await authenticate({
			...admin,
			bindPassword: 'admin',
			base: peopleBase,
			userFilter: eq('uid', 'bob'),
			password: 'bobpw'
		});
		expect(entry).not.toBeNull();
		expect(entry!.dn.toLowerCase()).toBe('uid=bob,ou=people,dc=example,dc=org');
	});

	it('authenticate returns null on a wrong user password', async () => {
		const entry = await authenticate({
			...admin,
			bindPassword: 'admin',
			base: peopleBase,
			userFilter: eq('uid', 'bob'),
			password: 'not-bobpw'
		});
		expect(entry).toBeNull();
	});

	it('authenticate returns null when the user is not found', async () => {
		const entry = await authenticate({
			...admin,
			bindPassword: 'admin',
			base: peopleBase,
			userFilter: eq('uid', 'ghost'),
			password: 'whatever'
		});
		expect(entry).toBeNull();
	});
});
