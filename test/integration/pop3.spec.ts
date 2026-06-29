import { expect, it } from 'vitest';
import { connect as coreConnect } from '../../src/core/socket';
import { _pop3SessionFromSocket } from '../../src/pop3/index';
import { _sessionFromSocket as smtpSession } from '../../src/smtp/index';

const auth = { username: 'tester', password: 'testpass' };

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

it('logs in, stats, lists and retrieves a delivered message', async () => {
	const marker = 'edgeport-pop3-' + Math.floor(Date.now()).toString(36);
	await deliver(marker);

	const socket = await coreConnect({ hostname: '127.0.0.1', port: 3110, tls: 'off' });
	const session = await _pop3SessionFromSocket(socket, {
		hostname: '127.0.0.1',
		tls: 'implicit',
		auth
	});
	const stat = await session.stat();
	expect(stat.count).toBeGreaterThan(0);

	const list = await session.list();
	expect(list.length).toBe(stat.count);

	const last = list[list.length - 1]!;
	const raw = new TextDecoder().decode(await session.retrieve(last.id));
	expect(raw).toContain(marker);
	await session.close();
});
