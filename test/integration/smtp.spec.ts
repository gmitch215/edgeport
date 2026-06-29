import { expect, it } from 'vitest';
import { connect as coreConnect } from '../../src/core/socket';
import { _sessionFromSocket, send } from '../../src/smtp/index';

const auth = { username: 'tester', password: 'testpass' };

it('sends over the public API with tls:"off" (plaintext relay)', async () => {
	const res = await send({
		hostname: '127.0.0.1',
		port: 3025,
		tls: 'off',
		auth,
		from: 'tester@localhost',
		to: 'tester@localhost',
		subject: 'edgeport plaintext public-api',
		text: 'sent via public connect with tls off'
	});
	expect(res.accepted).toContain('tester@localhost');
});

it('authenticates and sends a message greenmail accepts', async () => {
	const socket = await coreConnect({ hostname: '127.0.0.1', port: 3025, tls: 'off' });
	// tls:'implicit' tells the session the socket is already usable (no STARTTLS upgrade)
	const session = await _sessionFromSocket(socket, {
		hostname: '127.0.0.1',
		tls: 'implicit',
		auth
	});
	const res = await session.send({
		from: 'tester@localhost',
		to: 'tester@localhost',
		subject: 'edgeport smtp integration',
		text: 'hello from edgeport'
	});
	expect(res.accepted).toContain('tester@localhost');
	await session.close();
});
