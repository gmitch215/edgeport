import { expect, it } from 'vitest';
import { connect as coreConnect } from '../../src/core/socket';
import { _imapSessionFromSocket } from '../../src/imap/index';
import { _sessionFromSocket as smtpSession } from '../../src/smtp/index';

const auth = { username: 'tester', password: 'testpass' };

// drops a uniquely-marked message into tester's mailbox via SMTP
async function deliver(marker: string): Promise<void> {
	const s = await coreConnect({ hostname: '127.0.0.1', port: 3025, tls: 'off' });
	const session = await smtpSession(s, { hostname: '127.0.0.1', tls: 'implicit', auth });
	await session.send({
		from: 'tester@localhost',
		to: 'tester@localhost',
		subject: marker,
		text: marker
	});
	await session.close();
}

it('logs in, selects INBOX, searches and fetches a delivered message', async () => {
	const marker = 'edgeport-imap-' + Math.floor(Date.now()).toString(36);
	await deliver(marker);

	const socket = await coreConnect({ hostname: '127.0.0.1', port: 3143, tls: 'off' });
	const session = await _imapSessionFromSocket(socket, {
		hostname: '127.0.0.1',
		tls: 'implicit',
		auth
	});
	const status = await session.select('INBOX');
	expect(status.exists).toBeGreaterThan(0);

	const uids = await session.search({ all: true });
	expect(uids.length).toBeGreaterThan(0);

	const messages = await session.fetch(uids, { flags: true, body: true, size: true });
	const bodies = messages.map((m) => (m.body ? new TextDecoder().decode(m.body) : ''));
	expect(bodies.some((b) => b.includes(marker))).toBe(true);
	await session.close();
});
