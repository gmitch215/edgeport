import { describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/errors';
import { _imapSessionFromSocket } from '../../src/imap';
import { mockConnection } from '../mock-socket';

const enc = (s: string) => new TextEncoder().encode(s);

const AUTH = { username: 'me', password: 'secret' };

describe('imap implicit-tls login + select + search + fetch', () => {
	it('drives the full read path including a literal body', async () => {
		const { socket, server } = mockConnection();

		const client = _imapSessionFromSocket(socket, {
			hostname: 'imap.test',
			tls: 'implicit',
			auth: AUTH
		});

		const script = (async () => {
			// greeting
			await server.writeLine('* OK [CAPABILITY IMAP4rev1] ready');

			// LOGIN
			const login = await server.readLine();
			expect(login).toMatch(/^a001 LOGIN "me" "secret"$/);
			await server.writeLine('a001 OK LOGIN completed');
		})();

		const session = (await Promise.all([client, script]))[0];

		// SELECT INBOX
		const selectScript = (async () => {
			const cmd = await server.readLine();
			expect(cmd).toBe('a002 SELECT "INBOX"');
			await server.writeLine('* 3 EXISTS');
			await server.writeLine('* OK [UIDVALIDITY 1234567] UIDs valid');
			await server.writeLine('a002 OK [READ-WRITE] SELECT completed');
		})();
		const sel = (await Promise.all([session.select('INBOX'), selectScript]))[0];
		expect(sel).toEqual({ exists: 3, uidValidity: 1234567 });

		// SEARCH unseen
		const searchScript = (async () => {
			const cmd = await server.readLine();
			expect(cmd).toBe('a003 UID SEARCH UNSEEN');
			await server.writeLine('* SEARCH 101 102');
			await server.writeLine('a003 OK SEARCH completed');
		})();
		const uids = (await Promise.all([session.search({ unseen: true }), searchScript]))[0];
		expect(uids).toEqual([101, 102]);

		// FETCH with a literal {N} body
		const bodyText = 'Subject: Hi there\r\nFrom: a@b.com\r\n\r\nHello body.';
		const fetchScript = (async () => {
			const cmd = await server.readLine();
			expect(cmd).toBe('a004 UID FETCH 101,102 (UID FLAGS RFC822.SIZE BODY.PEEK[])');
			// first message uses a literal
			await server.write(
				enc(`* 1 FETCH (UID 101 FLAGS (\\Seen) RFC822.SIZE 42 BODY[] {${bodyText.length}}\r\n`)
			);
			await server.write(enc(bodyText));
			await server.writeLine(')');
			// second message, no body
			await server.writeLine('* 2 FETCH (UID 102 FLAGS (\\Flagged) RFC822.SIZE 7 BODY[] {0}\r\n)');
			await server.writeLine('a004 OK FETCH completed');
		})();
		const msgs = (
			await Promise.all([
				session.fetch([101, 102], { flags: true, body: true, size: true }),
				fetchScript
			])
		)[0];

		expect(msgs.length).toBe(2);
		const first = msgs[0]!;
		expect(first.uid).toBe(101);
		expect(first.flags).toEqual(['\\Seen']);
		expect(first.size).toBe(42);
		expect(new TextDecoder().decode(first.body!)).toBe(bodyText);
		expect(first.text()).toBe(bodyText);
		expect(first.headers?.subject).toBe('Hi there');
		expect(first.headers?.from).toBe('a@b.com');

		const second = msgs[1]!;
		expect(second.uid).toBe(102);
		expect(second.flags).toEqual(['\\Flagged']);

		// LOGOUT on close
		const closeScript = (async () => {
			const cmd = await server.readLine();
			expect(cmd).toBe('a005 LOGOUT');
			await server.writeLine('* BYE logging out');
			await server.writeLine('a005 OK LOGOUT completed');
		})();
		await Promise.all([session.close(), closeScript]);
	});
});

describe('imap starttls', () => {
	it('upgrades the transport exactly once before login', async () => {
		const { socket, server, startTlsCount } = mockConnection();

		const client = _imapSessionFromSocket(socket, {
			hostname: 'imap.test',
			tls: 'starttls',
			auth: AUTH
		});

		const script = (async () => {
			await server.writeLine('* OK ready');
			const starttls = await server.readLine();
			expect(starttls).toBe('a001 STARTTLS');
			await server.writeLine('a001 OK begin TLS');
			const login = await server.readLine();
			expect(login).toBe('a002 LOGIN "me" "secret"');
			await server.writeLine('a002 OK LOGIN completed');
		})();

		const session = (await Promise.all([client, script]))[0];
		expect(startTlsCount()).toBe(1);

		const closeScript = (async () => {
			await server.readLine();
			await server.writeLine('a003 OK bye');
		})();
		await Promise.all([session.close(), closeScript]);
	});
});

describe('imap login failure', () => {
	it('maps a tagged NO to AuthError', async () => {
		const { socket, server } = mockConnection();

		const client = _imapSessionFromSocket(socket, {
			hostname: 'imap.test',
			tls: 'implicit',
			auth: { username: 'me', password: 'wrong' }
		});

		const script = (async () => {
			await server.writeLine('* OK ready');
			await server.readLine();
			await server.writeLine('a001 NO [AUTHENTICATIONFAILED] bad password');
		})();

		await expect(Promise.all([client, script])).rejects.toBeInstanceOf(AuthError);
	});
});
