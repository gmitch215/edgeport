import { describe, expect, it } from 'vitest';
import { AuthError, ProtocolError } from '../../src/core';
import {
	CarrierGateways,
	_sessionFromSocket,
	sendSms,
	smsAddress,
	type CarrierGateway,
	type SmtpConnectOptions
} from '../../src/smtp/index';
import { buildMime } from '../../src/smtp/mime';
import { mockConnection, type MockServerEnd } from '../mock-socket';

const decoder = new TextDecoder();

// collects every command line the server received during a scripted exchange
type Recorder = string[];

// reads exactly the DATA payload up to and including the CRLF.CRLF terminator, returning
// the decoded body (with the trailing terminator stripped)
async function readDataBody(server: MockServerEnd): Promise<string> {
	const chunks: number[] = [];
	const term = '\r\n.\r\n';
	for (;;) {
		const byte = await server.readN(1);
		chunks.push(byte[0]!);
		const tail = decoder.decode(new Uint8Array(chunks.slice(-term.length)));
		if (tail === term) break;
	}
	const full = decoder.decode(new Uint8Array(chunks));
	return full.slice(0, -term.length);
}

describe('SMTP STARTTLS + AUTH PLAIN happy path', () => {
	it('runs greeting, EHLO, STARTTLS, EHLO, AUTH PLAIN, then sends', async () => {
		const { socket, server, startTlsCount } = mockConnection();
		const received: Recorder = [];

		const opts: SmtpConnectOptions = {
			hostname: 'smtp.example.com',
			tls: 'starttls',
			auth: { username: 'user@example.com', password: 'secret', mechanism: 'PLAIN' }
		};

		const serverScript = async () => {
			await server.writeLine('220 smtp.example.com ESMTP ready');
			received.push(await server.readLine()); // EHLO edgeport
			await server.writeLine('250-smtp.example.com');
			await server.writeLine('250-STARTTLS');
			await server.writeLine('250 AUTH PLAIN LOGIN');
			received.push(await server.readLine()); // STARTTLS
			await server.writeLine('220 go ahead');
			received.push(await server.readLine()); // EHLO edgeport (post-TLS)
			await server.writeLine('250-smtp.example.com');
			await server.writeLine('250 AUTH PLAIN LOGIN');
			received.push(await server.readLine()); // AUTH PLAIN <token>
			await server.writeLine('235 2.7.0 Authentication successful');
			// send()
			received.push(await server.readLine()); // MAIL FROM
			await server.writeLine('250 OK');
			received.push(await server.readLine()); // RCPT TO
			await server.writeLine('250 OK');
			received.push(await server.readLine()); // DATA
			await server.writeLine('354 End data with <CR><LF>.<CR><LF>');
			await readDataBody(server);
			await server.writeLine('250 2.0.0 Queued');
		};

		const clientFlow = async () => {
			const session = await _sessionFromSocket(socket, opts);
			const result = await session.send({
				from: 'user@example.com',
				to: 'dest@example.com',
				subject: 'Hello',
				text: 'Body'
			});
			return result;
		};

		const [result] = await Promise.all([clientFlow(), serverScript()]);

		expect(startTlsCount()).toBe(1);
		expect(result.accepted).toEqual(['dest@example.com']);
		expect(result.response).toContain('Queued');

		expect(received).toEqual([
			'EHLO edgeport',
			'STARTTLS',
			'EHLO edgeport',
			`AUTH PLAIN ${btoa('\0user@example.com\0secret')}`,
			'MAIL FROM:<user@example.com>',
			'RCPT TO:<dest@example.com>',
			'DATA'
		]);
	});
});

describe('SMTP AUTH LOGIN path', () => {
	it('walks the 334 username/password challenge', async () => {
		const { socket, server } = mockConnection();
		const received: Recorder = [];

		const serverScript = async () => {
			await server.writeLine('220 ready');
			received.push(await server.readLine()); // EHLO
			await server.writeLine('250-ok');
			await server.writeLine('250 STARTTLS');
			received.push(await server.readLine()); // STARTTLS
			await server.writeLine('220 go');
			received.push(await server.readLine()); // EHLO
			await server.writeLine('250 AUTH LOGIN');
			received.push(await server.readLine()); // AUTH LOGIN
			await server.writeLine('334 VXNlcm5hbWU6');
			received.push(await server.readLine()); // base64 username
			await server.writeLine('334 UGFzc3dvcmQ6');
			received.push(await server.readLine()); // base64 password
			await server.writeLine('235 OK');
			// drain the QUIT from close()
			received.push(await server.readLine());
			await server.writeLine('221 bye');
		};

		const clientFlow = async () => {
			const session = await _sessionFromSocket(socket, {
				hostname: 'h',
				auth: { username: 'bob', password: 'pw', mechanism: 'LOGIN' }
			});
			await session.close();
		};

		await Promise.all([clientFlow(), serverScript()]);

		expect(received).toEqual([
			'EHLO edgeport',
			'STARTTLS',
			'EHLO edgeport',
			'AUTH LOGIN',
			btoa('bob'),
			btoa('pw'),
			'QUIT'
		]);
	});
});

describe('SMTP implicit TLS path', () => {
	it('skips STARTTLS and goes straight to EHLO over the encrypted channel', async () => {
		const { socket, server, startTlsCount } = mockConnection();
		const received: Recorder = [];

		const serverScript = async () => {
			await server.writeLine('220 secure ready');
			received.push(await server.readLine()); // EHLO
			await server.writeLine('250 ok');
			received.push(await server.readLine()); // MAIL FROM
			await server.writeLine('250 OK');
			received.push(await server.readLine()); // RCPT TO
			await server.writeLine('250 OK');
			received.push(await server.readLine()); // DATA
			await server.writeLine('354 go');
			await readDataBody(server);
			await server.writeLine('250 queued');
		};

		const clientFlow = async () => {
			const session = await _sessionFromSocket(socket, { hostname: 'h', tls: 'implicit' });
			return session.send({ from: 'a@h', to: 'b@h', subject: 's', text: 't' });
		};

		const [result] = await Promise.all([clientFlow(), serverScript()]);

		// implicit TLS never calls startTls; the socket is already encrypted
		expect(startTlsCount()).toBe(0);
		expect(received[0]).toBe('EHLO edgeport');
		expect(received).not.toContain('STARTTLS');
		expect(result.accepted).toEqual(['b@h']);
	});
});

describe('SMTP auth failure', () => {
	it('throws AuthError on a 535 reply', async () => {
		const { socket, server } = mockConnection();

		const serverScript = async () => {
			await server.writeLine('220 ready');
			await server.readLine(); // EHLO
			await server.writeLine('250 ok');
			await server.readLine(); // STARTTLS
			await server.writeLine('220 go');
			await server.readLine(); // EHLO
			await server.writeLine('250 AUTH PLAIN');
			await server.readLine(); // AUTH PLAIN <token>
			await server.writeLine('535 5.7.8 Authentication credentials invalid');
		};

		const clientFlow = _sessionFromSocket(socket, {
			hostname: 'h',
			auth: { username: 'u', password: 'bad' }
		});

		const [err] = await Promise.all([
			clientFlow.then(
				() => null,
				(e: unknown) => e
			),
			serverScript()
		]);

		expect(err).toBeInstanceOf(AuthError);
		expect((err as AuthError).message).toContain('535');
	});
});

describe('SMTP multiline EHLO capability parse', () => {
	it('parses a long multiline 250 EHLO into the conversation without error', async () => {
		const { socket, server } = mockConnection();
		const received: Recorder = [];

		const serverScript = async () => {
			await server.writeLine('220 ready');
			received.push(await server.readLine()); // EHLO
			// a realistic multiline capability block: 250- continues, 250 ends
			await server.writeLine('250-smtp.example.com at your service');
			await server.writeLine('250-SIZE 35882577');
			await server.writeLine('250-8BITMIME');
			await server.writeLine('250-STARTTLS');
			await server.writeLine('250-ENHANCEDSTATUSCODES');
			await server.writeLine('250-PIPELINING');
			await server.writeLine('250 SMTPUTF8');
			received.push(await server.readLine()); // STARTTLS
			await server.writeLine('220 go');
			received.push(await server.readLine()); // EHLO
			await server.writeLine('250 only-line');
			received.push(await server.readLine()); // QUIT
			await server.writeLine('221 bye');
		};

		const clientFlow = async () => {
			const session = await _sessionFromSocket(socket, { hostname: 'h' });
			await session.close();
		};

		await Promise.all([clientFlow(), serverScript()]);
		expect(received).toEqual(['EHLO edgeport', 'STARTTLS', 'EHLO edgeport', 'QUIT']);
	});
});

describe('SMTP DATA dot-stuffing', () => {
	it('doubles the leading dot on body lines that start with a period', async () => {
		const { socket, server } = mockConnection();
		let bodyOnWire = '';

		const serverScript = async () => {
			await server.writeLine('220 ready');
			await server.readLine(); // EHLO
			await server.writeLine('250 ok');
			await server.readLine(); // STARTTLS
			await server.writeLine('220 go');
			await server.readLine(); // EHLO
			await server.writeLine('250 ok');
			await server.readLine(); // MAIL FROM
			await server.writeLine('250 OK');
			await server.readLine(); // RCPT TO
			await server.writeLine('250 OK');
			await server.readLine(); // DATA
			await server.writeLine('354 go');
			bodyOnWire = await readDataBody(server);
			await server.writeLine('250 queued');
		};

		const clientFlow = async () => {
			const session = await _sessionFromSocket(socket, { hostname: 'h' });
			// a raw body whose lines start with '.' to exercise dot-stuffing directly
			const raw = new TextEncoder().encode('.first line\r\nnormal\r\n.last');
			return session.send({ from: 'a@h', to: 'b@h', subject: 's', raw });
		};

		await Promise.all([clientFlow(), serverScript()]);

		// every line that began with '.' must be sent doubled on the wire
		expect(bodyOnWire).toContain('..first line');
		expect(bodyOnWire).toContain('..last');
		expect(bodyOnWire).toContain('\r\nnormal\r\n');
		// a normal line is untouched
		expect(bodyOnWire).not.toContain('..normal');
	});
});

describe('SMTP multi-recipient accepted list', () => {
	it('collects to + cc + bcc recipients that the server accepts', async () => {
		const { socket, server } = mockConnection();
		const rcpts: string[] = [];

		const serverScript = async () => {
			await server.writeLine('220 ready');
			await server.readLine(); // EHLO
			await server.writeLine('250 ok');
			await server.readLine(); // STARTTLS
			await server.writeLine('220 go');
			await server.readLine(); // EHLO
			await server.writeLine('250 ok');
			await server.readLine(); // MAIL FROM
			await server.writeLine('250 OK');
			// four recipients: to, two cc, one bcc; reject the third with 550
			rcpts.push(await server.readLine());
			await server.writeLine('250 OK');
			rcpts.push(await server.readLine());
			await server.writeLine('251 User not local; will forward');
			rcpts.push(await server.readLine());
			await server.writeLine('550 No such user'); // rejected, not fatal
			rcpts.push(await server.readLine());
			await server.writeLine('250 OK');
			await server.readLine(); // DATA
			await server.writeLine('354 go');
			await readDataBody(server);
			await server.writeLine('250 queued');
		};

		const clientFlow = async () => {
			const session = await _sessionFromSocket(socket, { hostname: 'h' });
			return session.send({
				from: 'a@h',
				to: 'to@h',
				cc: ['cc1@h', 'cc2@h'],
				bcc: ['bcc@h'],
				subject: 's',
				text: 't'
			});
		};

		const [result] = await Promise.all([clientFlow(), serverScript()]);

		expect(rcpts).toEqual([
			'RCPT TO:<to@h>',
			'RCPT TO:<cc1@h>',
			'RCPT TO:<cc2@h>',
			'RCPT TO:<bcc@h>'
		]);
		// cc2 (550) is dropped; the other three (250/251) are accepted
		expect(result.accepted).toEqual(['to@h', 'cc1@h', 'bcc@h']);
	});
});

describe('MIME builder', () => {
	it('returns raw verbatim when provided', () => {
		const raw = new TextEncoder().encode('Subject: x\r\n\r\nbody');
		expect(buildMime({ from: 'a@h', to: 'b@h', subject: 'ignored', raw })).toBe(raw);
	});

	it('builds a text/plain message with the standard headers', () => {
		const out = decoder.decode(
			buildMime({ from: 'a@example.com', to: 'b@example.com', subject: 'Hi', text: 'Hello' })
		);
		expect(out).toContain('From: a@example.com');
		expect(out).toContain('To: b@example.com');
		expect(out).toContain('Subject: Hi');
		expect(out).toContain('MIME-Version: 1.0');
		expect(out).toMatch(/Message-ID: <[0-9a-f-]+@example\.com>/);
		expect(out).toContain('Content-Type: text/plain; charset=utf-8');
		expect(out.endsWith('Hello')).toBe(true);
		// CRLF line endings throughout
		expect(out).toContain('\r\n');
	});

	it('builds multipart/alternative when both text and html are present', () => {
		const out = decoder.decode(
			buildMime({
				from: 'a@h',
				to: 'b@h',
				subject: 's',
				text: 'plain version',
				html: '<b>rich</b>'
			})
		);
		const m = out.match(/boundary="([^"]+)"/);
		expect(m).not.toBeNull();
		const boundary = m![1]!;
		expect(out).toContain('Content-Type: multipart/alternative;');
		expect(out).toContain('Content-Type: text/plain; charset=utf-8');
		expect(out).toContain('Content-Type: text/html; charset=utf-8');
		expect(out).toContain('plain version');
		expect(out).toContain('<b>rich</b>');
		expect(out).toContain(`--${boundary}--`);
	});

	it('joins array To/Cc with commas and omits Cc when empty', () => {
		const out = decoder.decode(
			buildMime({ from: 'a@h', to: ['x@h', 'y@h'], subject: 's', text: 't' })
		);
		expect(out).toContain('To: x@h, y@h');
		expect(out).not.toContain('Cc:');
	});

	it('builds an html-only message', () => {
		const out = decoder.decode(
			buildMime({ from: 'a@h', to: 'b@h', subject: 'H', html: '<p>x</p>' })
		);
		expect(out.toLowerCase()).toContain('text/html');
		expect(out).toContain('<p>x</p>');
	});

	it('builds multipart/mixed with a base64 attachment', () => {
		const content = new Uint8Array([0, 1, 2, 250, 251, 252]);
		const out = decoder.decode(
			buildMime({
				from: 'a@h',
				to: 'b@h',
				subject: 'report',
				text: 'see attached',
				attachments: [{ filename: 'r.bin', content, contentType: 'application/octet-stream' }]
			})
		);
		expect(out.toLowerCase()).toContain('multipart/mixed');
		expect(out).toContain('Content-Transfer-Encoding: base64');
		expect(out).toContain('filename="r.bin"');
		expect(out).toContain('see attached'); // body survives as the first part
		expect(out).toContain(btoa(String.fromCharCode(...content))); // attachment bytes round-trip
	});
});

describe('SMS gateway addressing (smsAddress)', () => {
	it('computes the SMS address for known carriers', () => {
		expect(smsAddress('5551234567', 'att')).toBe('5551234567@txt.att.net');
		expect(smsAddress('5551234567', 'tmobile')).toBe('5551234567@tmomail.net');
		expect(smsAddress('5551234567', 'verizon')).toBe('5551234567@vtext.com');
		expect(smsAddress('5551234567', 'rogers')).toBe('5551234567@pcs.rogers.com');
	});

	it('computes the MMS address where the carrier uses a distinct domain', () => {
		expect(smsAddress('5551234567', 'att', { type: 'mms' })).toBe('5551234567@mms.att.net');
		expect(smsAddress('5551234567', 'verizon', { type: 'mms' })).toBe('5551234567@vzwpix.com');
		expect(smsAddress('5551234567', 'sprint', { type: 'mms' })).toBe('5551234567@pm.sprint.com');
	});

	it('falls back to the SMS domain for MMS when no distinct MMS domain exists', () => {
		// tmobile has no separate mms domain
		expect(smsAddress('5551234567', 'tmobile', { type: 'mms' })).toBe('5551234567@tmomail.net');
	});

	it('normalizes messy numbers to digits only', () => {
		expect(smsAddress('5551234567', 'att')).toBe('5551234567@txt.att.net');
		expect(smsAddress('555.123.4567', 'att')).toBe('5551234567@txt.att.net');
		expect(smsAddress('  555 123 4567  ', 'att')).toBe('5551234567@txt.att.net');
		expect(smsAddress('555-123-4567', 'att')).toBe('5551234567@txt.att.net');
		expect(smsAddress('555 1234567', 'att')).toBe('5551234567@txt.att.net');
		expect(smsAddress('555.  123.     4567', 'att')).toBe('5551234567@txt.att.net');

		expect(smsAddress('+1 (555) 123-4567', 'att')).toBe('15551234567@txt.att.net');
		expect(smsAddress('+15551234567', 'att')).toBe('15551234567@txt.att.net');
		expect(smsAddress('+1-555-123-4567', 'att')).toBe('15551234567@txt.att.net');
		expect(smsAddress('+1.555.123.4567', 'att')).toBe('15551234567@txt.att.net');
		expect(smsAddress('1 (555) 123-4567', 'att')).toBe('15551234567@txt.att.net');
		expect(smsAddress('+1 5551234567', 'att')).toBe('15551234567@txt.att.net');
		expect(smsAddress('+1 555 1234567', 'att')).toBe('15551234567@txt.att.net');
	});

	it('passes an unknown-but-plausible string through as a raw gateway domain', () => {
		expect(smsAddress('5551234567', 'sms.example.net')).toBe('5551234567@sms.example.net');
		// a raw domain ignores the type option (it is already a full gateway)
		expect(smsAddress('5551234567', 'sms.example.net', { type: 'mms' })).toBe(
			'5551234567@sms.example.net'
		);
	});

	it('throws ProtocolError on an unknown carrier that is not a plausible domain', () => {
		expect(() => smsAddress('5551234567', 'notacarrier')).toThrow(ProtocolError);
	});

	it('throws ProtocolError on an empty number', () => {
		expect(() => smsAddress('', 'att')).toThrow(ProtocolError);
		expect(() => smsAddress('()-  .', 'att')).toThrow(ProtocolError);
	});
});

describe('CarrierGateways table', () => {
	const domainRe = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

	it('gives every entry a non-empty sms domain that looks like a domain', () => {
		for (const [key, gw] of Object.entries(CarrierGateways) as [string, CarrierGateway][]) {
			expect(gw.sms, `${key}.sms`).toMatch(domainRe);
			if (gw.mms !== undefined) expect(gw.mms, `${key}.mms`).toMatch(domainRe);
		}
	});

	it('includes the required major carriers', () => {
		for (const key of [
			'att',
			'tmobile',
			'verizon',
			'sprint',
			'cricket',
			'uscellular',
			'metropcs',
			'boost',
			'virgin',
			'googlefi',
			'rogers',
			'bell',
			'telus',
			'fido',
			'koodo'
		]) {
			expect(CarrierGateways, key).toHaveProperty(key);
		}
	});
});

describe('SMS over email (sendSms addressing + envelope)', () => {
	it('routes the RCPT TO envelope to the computed carrier gateway address', async () => {
		const { socket, server } = mockConnection();
		const received: Recorder = [];

		// exactly what sendSms computes for this recipient
		const recipient = smsAddress('+1 (555) 123-4567', 'att');

		const serverScript = async () => {
			await server.writeLine('220 gw ready');
			received.push(await server.readLine()); // EHLO
			await server.writeLine('250 ok');
			received.push(await server.readLine()); // MAIL FROM
			await server.writeLine('250 OK');
			received.push(await server.readLine()); // RCPT TO
			await server.writeLine('250 OK');
			received.push(await server.readLine()); // DATA
			await server.writeLine('354 go');
			await readDataBody(server);
			await server.writeLine('250 queued');
		};

		// mirrors sendSms: text-only body, empty subject, addressed to the gateway
		const clientFlow = async () => {
			const session = await _sessionFromSocket(socket, { hostname: 'h', tls: 'implicit' });
			return session.send({
				from: 'me@example.com',
				to: recipient,
				subject: '',
				text: 'code 123456'
			});
		};

		const [result] = await Promise.all([clientFlow(), serverScript()]);

		expect(recipient).toBe('15551234567@txt.att.net');
		expect(received).toContain('RCPT TO:<15551234567@txt.att.net>');
		expect(result.accepted).toEqual(['15551234567@txt.att.net']);
	});

	it('rejects a bad carrier before opening a connection', async () => {
		// smsAddress runs first, so this fails without touching the network
		await expect(
			sendSms({
				hostname: 'smtp.example.com',
				from: 'me@example.com',
				to: { number: '5551234567', carrier: 'notacarrier' },
				text: 'hi'
			})
		).rejects.toBeInstanceOf(ProtocolError);
	});
});
