import { describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/errors';
import { _pop3SessionFromSocket } from '../../src/pop3';
import { mockConnection } from '../mock-socket';

const AUTH = { username: 'me', password: 'secret' };

describe('pop3 implicit-tls login + stat + list + retrieve + delete', () => {
	it('drives the full read path including dot-unstuffing', async () => {
		const { socket, server } = mockConnection();

		const client = _pop3SessionFromSocket(socket, {
			hostname: 'pop.test',
			tls: 'implicit',
			auth: AUTH
		});

		const loginScript = (async () => {
			await server.writeLine('+OK POP3 ready');
			expect(await server.readLine()).toBe('USER me');
			await server.writeLine('+OK user accepted');
			expect(await server.readLine()).toBe('PASS secret');
			await server.writeLine('+OK mailbox locked and ready');
		})();
		const session = (await Promise.all([client, loginScript]))[0];

		// STAT
		const statScript = (async () => {
			expect(await server.readLine()).toBe('STAT');
			await server.writeLine('+OK 2 320');
		})();
		const stat = (await Promise.all([session.stat(), statScript]))[0];
		expect(stat).toEqual({ count: 2, size: 320 });

		// LIST (multiline)
		const listScript = (async () => {
			expect(await server.readLine()).toBe('LIST');
			await server.writeLine('+OK 2 messages');
			await server.writeLine('1 120');
			await server.writeLine('2 200');
			await server.writeLine('.');
		})();
		const list = (await Promise.all([session.list(), listScript]))[0];
		expect(list).toEqual([
			{ id: 1, size: 120 },
			{ id: 2, size: 200 }
		]);

		// RETR (multiline, with a dot-stuffed line)
		const retrScript = (async () => {
			expect(await server.readLine()).toBe('RETR 1');
			await server.writeLine('+OK 120 octets');
			await server.writeLine('Subject: Test');
			await server.writeLine('');
			await server.writeLine('Body line one.');
			// dot-stuffed: a body line beginning with '.' is doubled on the wire
			await server.writeLine('..hidden leading dot');
			await server.writeLine('.');
		})();
		const raw = (await Promise.all([session.retrieve(1), retrScript]))[0];
		expect(new TextDecoder().decode(raw)).toBe(
			'Subject: Test\r\n\r\nBody line one.\r\n.hidden leading dot'
		);

		// retrieveText re-runs RETR and returns the server text directly (no byte round-trip)
		const retrTextScript = (async () => {
			expect(await server.readLine()).toBe('RETR 1');
			await server.writeLine('+OK 120 octets');
			await server.writeLine('Subject: Test');
			await server.writeLine('');
			await server.writeLine('Body line one.');
			await server.writeLine('.');
		})();
		const text = (await Promise.all([session.retrieveText(1), retrTextScript]))[0];
		expect(text).toBe('Subject: Test\r\n\r\nBody line one.');

		// DELE
		const deleScript = (async () => {
			expect(await server.readLine()).toBe('DELE 2');
			await server.writeLine('+OK message 2 deleted');
		})();
		await Promise.all([session.delete(2), deleScript]);

		// QUIT on close
		const closeScript = (async () => {
			expect(await server.readLine()).toBe('QUIT');
			await server.writeLine('+OK bye');
		})();
		await Promise.all([session.close(), closeScript]);
	});
});

describe('pop3 stls', () => {
	it('upgrades the transport exactly once before auth', async () => {
		const { socket, server, startTlsCount } = mockConnection();

		const client = _pop3SessionFromSocket(socket, {
			hostname: 'pop.test',
			tls: 'starttls',
			auth: AUTH
		});

		const script = (async () => {
			await server.writeLine('+OK ready');
			expect(await server.readLine()).toBe('STLS');
			await server.writeLine('+OK begin TLS');
			expect(await server.readLine()).toBe('USER me');
			await server.writeLine('+OK');
			expect(await server.readLine()).toBe('PASS secret');
			await server.writeLine('+OK logged in');
		})();
		const session = (await Promise.all([client, script]))[0];
		expect(startTlsCount()).toBe(1);

		const closeScript = (async () => {
			await server.readLine();
			await server.writeLine('+OK bye');
		})();
		await Promise.all([session.close(), closeScript]);
	});
});

describe('pop3 auth failure', () => {
	it('maps -ERR on PASS to AuthError', async () => {
		const { socket, server } = mockConnection();

		const client = _pop3SessionFromSocket(socket, {
			hostname: 'pop.test',
			tls: 'implicit',
			auth: { username: 'me', password: 'wrong' }
		});

		const script = (async () => {
			await server.writeLine('+OK ready');
			expect(await server.readLine()).toBe('USER me');
			await server.writeLine('+OK');
			expect(await server.readLine()).toBe('PASS wrong');
			await server.writeLine('-ERR invalid password');
		})();

		await expect(Promise.all([client, script])).rejects.toBeInstanceOf(AuthError);
	});
});
