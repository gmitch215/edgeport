import { describe, expect, it } from 'vitest';
import { ConnectionError, ProtocolError } from '../../src/core/errors';
import { _sessionOverSocket as ftpSession } from '../../src/ftp/index';
import { _imapSessionFromSocket as imapSession } from '../../src/imap/index';
import { _sessionOverSocket as ldapSession } from '../../src/ldap/index';
import { _connectOverSocket as mqttConnect } from '../../src/mqtt/index';
import { _connectOverSocket as natsConnect } from '../../src/nats/index';
import { _pop3SessionFromSocket as pop3Session } from '../../src/pop3/index';
import { _sessionFromSocket as smtpSession } from '../../src/smtp/index';
import { _connectOverSocket as stompConnect } from '../../src/stomp/index';
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

describe('spontaneous disconnect during handshake -> ConnectionError', () => {
	it('nats (drops before INFO)', async () => {
		const { socket, server } = mockConnection();
		const p = natsConnect(socket, { hostname: 'h' });
		await server.close();
		await expect(p).rejects.toBeInstanceOf(ConnectionError);
	});

	it('mqtt (drops before CONNACK)', async () => {
		const { socket, server } = mockConnection();
		const p = mqttConnect(socket, { hostname: 'h', clientId: 'c' });
		await server.close();
		await expect(p).rejects.toBeInstanceOf(ConnectionError);
	});

	it('stomp (drops before CONNECTED)', async () => {
		const { socket, server } = mockConnection();
		const p = stompConnect(socket, { hostname: 'h' });
		await server.close();
		await expect(p).rejects.toBeInstanceOf(ConnectionError);
	});

	it('ftp (drops before greeting)', async () => {
		const { socket, server } = mockConnection();
		const p = ftpSession(socket, { hostname: 'h', username: 'u', password: 'p' });
		await server.close();
		await expect(p).rejects.toBeInstanceOf(ConnectionError);
	});

	it('ldap (drops before bind response)', async () => {
		const { socket, server } = mockConnection();
		const p = ldapSession(socket, { hostname: 'h', bindDN: 'cn=x,dc=e,dc=org', password: 'p' });
		await server.close();
		await expect(p).rejects.toBeInstanceOf(ConnectionError);
	});
});
