// resilience: mail protocols must surface spontaneous disconnects and bad greetings cleanly
import { describe, expect, it } from 'vitest';
import { ConnectionError, ProtocolError } from '../../src/core/errors';
import { _imapSessionFromSocket as imapSession } from '../../src/imap/index';
import { _pop3SessionFromSocket as pop3Session } from '../../src/pop3/index';
import { _sessionFromSocket as smtpSession } from '../../src/smtp/index';
import { mockConnection } from '../mock-socket';

const auth = { username: 'u', password: 'p' };

describe('spontaneous disconnect before greeting -> ConnectionError', () => {
	it('smtp', async () => {
		const { socket, server } = mockConnection();
		const p = smtpSession(socket, { hostname: 'h', tls: 'implicit', auth });
		await server.close();
		await expect(p).rejects.toBeInstanceOf(ConnectionError);
	});

	it('imap', async () => {
		const { socket, server } = mockConnection();
		const p = imapSession(socket, { hostname: 'h', tls: 'implicit', auth });
		await server.close();
		await expect(p).rejects.toBeInstanceOf(ConnectionError);
	});

	it('pop3', async () => {
		const { socket, server } = mockConnection();
		const p = pop3Session(socket, { hostname: 'h', tls: 'implicit', auth });
		await server.close();
		await expect(p).rejects.toBeInstanceOf(ConnectionError);
	});
});

describe('bad greeting -> ProtocolError', () => {
	it('smtp rejects a non-220 greeting', async () => {
		const { socket, server } = mockConnection();
		const p = smtpSession(socket, { hostname: 'h', tls: 'implicit', auth });
		await server.writeLine('554 service unavailable');
		await expect(p).rejects.toBeInstanceOf(ProtocolError);
	});

	it('pop3 rejects a non-+OK greeting', async () => {
		const { socket, server } = mockConnection();
		const p = pop3Session(socket, { hostname: 'h', tls: 'implicit', auth });
		await server.writeLine('-ERR locked');
		await expect(p).rejects.toBeTruthy();
	});
});
