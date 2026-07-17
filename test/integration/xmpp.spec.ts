import { describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/errors';
import { connect, el, text, type XmppSession } from '../../src/xmpp/index';

const HOST = '127.0.0.1';
const PORT = 5222;
const DOMAIN = 'localhost';
const PASSWORD = 'testpass';
const PUBSUB = 'pubsub.localhost';

// SASL PLAIN over the plaintext c2s stream (workerd cannot trust a self-signed STARTTLS cert)
function login(
	user: string,
	opts: { password?: string; resource?: string } = {}
): Promise<XmppSession> {
	return connect({
		hostname: HOST,
		port: PORT,
		domain: DOMAIN,
		jid: `${user}@${DOMAIN}`,
		password: opts.password ?? PASSWORD,
		resource: opts.resource ?? `res-${Math.floor(Math.random() * 1e6)}`,
		mechanisms: 'PLAIN',
		tls: 'off',
		timeoutMs: 10_000
	});
}

// reads the next item from an async iterator with a deadline so a miss fails fast
async function nextWithin<T>(iter: AsyncIterator<T>, ms: number): Promise<T> {
	const timeout = new Promise<never>((_, reject) =>
		setTimeout(() => reject(new Error('timed out waiting for stanza')), ms)
	);
	const { value, done } = await Promise.race([iter.next(), timeout]);
	if (done) throw new Error('iterator ended');
	return value;
}

describe('xmpp against ejabberd (plaintext)', () => {
	it('connects, authenticates (SASL PLAIN), and binds a full jid', async () => {
		await using session = await login('tester', { resource: 'edge' });
		expect(session.jid).toBe('tester@localhost/edge');
	});

	it('rejects a bad password with AuthError', async () => {
		await expect(login('tester', { password: 'wrongpass' })).rejects.toBeInstanceOf(AuthError);
	});

	it('sets presence without error', async () => {
		await using session = await login('tester');
		await session.setPresence('online');
		await session.setPresence('away', { status: 'brb', priority: 1 });
	});

	it('reads and mutates the roster (add item then see it listed)', async () => {
		await using session = await login('tester');
		const contact = `tester2@${DOMAIN}`;
		await session.removeRosterItem(contact).catch(() => {});
		await session.addRosterItem(contact, { name: 'Tester Two', groups: ['Friends'] });

		const items = await session.roster();
		const found = items.find((i) => i.jid === contact);
		expect(found).toBeDefined();
		expect(found!.name).toBe('Tester Two');
		expect(found!.groups).toContain('Friends');

		// clean up so re-runs start from a known state
		await session.removeRosterItem(contact).catch(() => {});
	});

	it('routes a chat message between two accounts (send + receive)', async () => {
		await using sender = await login('tester');
		await using recipient = await login('tester2', { resource: 'inbox' });
		await sender.setPresence('online');
		await recipient.setPresence('online');

		const inbox = recipient.messages()[Symbol.asyncIterator]();
		const body = `hello tester2 ${Date.now()}`;
		await sender.send({ to: `tester2@${DOMAIN}`, body });

		const msg = await nextWithin(inbox, 8000);
		expect(msg.body).toBe(body);
		expect(msg.from).toContain('tester@localhost');
	});

	it('publishes to a pubsub node and receives the item via subscribe', async () => {
		await using session = await login('tester');
		await session.setPresence('online');
		const node = `edgeport-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

		await session.createNode(PUBSUB, node);
		await session.subscribeNode(PUBSUB, node);

		const events = session.pubsub()[Symbol.asyncIterator]();
		const itemId = await session.publish(
			node,
			el('entry', { xmlns: 'urn:edgeport:test' }, 'pubsub payload'),
			{
				service: PUBSUB,
				itemId: 'item-1'
			}
		);
		expect(itemId).toBe('item-1');

		const event = await nextWithin(events, 8000);
		expect(event.node).toBe(node);
		expect(event.itemId).toBe('item-1');
		expect(text(event.payload!)).toBe('pubsub payload');
	});

	it('runs a full SCRAM-SHA-256 handshake', async () => {
		await using session = await connect({
			hostname: HOST,
			port: PORT,
			domain: DOMAIN,
			jid: `tester@${DOMAIN}`,
			password: PASSWORD,
			mechanisms: 'SCRAM-SHA-256',
			tls: 'off',
			timeoutMs: 10_000
		});
		expect(session.jid).toContain('tester@localhost/');
	});
});
