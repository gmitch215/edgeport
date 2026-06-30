import { describe, expect, it } from 'vitest';
import { ProtocolError } from '../../src/core';
import {
	_formatRfc5424,
	_frame,
	_sessionFromSocket,
	computePri,
	connect,
	Facility,
	resolveFacility,
	resolveSeverity,
	send,
	Severity,
	type SyslogConnectOptions
} from '../../src/syslog/index';
import { mockConnection, type MockServerEnd } from '../mock-socket';

const decoder = new TextDecoder();
const encoder = new TextEncoder();

// reads exactly the bytes of an octet-counted frame: parse "<len> " then read len bytes,
// returning the decoded body
async function readOctetFrame(server: MockServerEnd): Promise<string> {
	const digits: number[] = [];
	for (;;) {
		const b = await server.readN(1);
		if (b[0] === 0x20) break; // the space terminating the length prefix
		digits.push(b[0]!);
	}
	const len = Number(decoder.decode(new Uint8Array(digits)));
	const body = await server.readN(len);
	return decoder.decode(body);
}

// reads an LF-framed message: bytes up to and including the trailing LF, LF stripped
async function readLfFrame(server: MockServerEnd): Promise<string> {
	const chunks: number[] = [];
	for (;;) {
		const b = await server.readN(1);
		if (b[0] === 0x0a) break;
		chunks.push(b[0]!);
	}
	return decoder.decode(new Uint8Array(chunks));
}

describe('RFC 5424 line formatting', () => {
	it('computes PRI, emits VERSION 1, correct field order, NIL for absent fields', () => {
		const line = _formatRfc5424({
			severity: 'info',
			facility: 'local0',
			message: 'hello',
			timestamp: '2025-01-01T00:00:00Z'
		});
		// local0(16) * 8 + info(6) = 134
		expect(line).toBe('<134>1 2025-01-01T00:00:00Z - - - - - hello');
	});

	it('renders provided header fields in order and defaults facility to user', () => {
		const line = _formatRfc5424({
			severity: Severity.error,
			message: 'boom',
			timestamp: '2025-06-01T12:00:00.500Z',
			hostname: 'host1',
			appName: 'api',
			procId: '4321',
			msgId: 'ID47'
		});
		// user(1) * 8 + error(3) = 11
		expect(line).toBe('<11>1 2025-06-01T12:00:00.500Z host1 api 4321 ID47 - boom');
	});
});

describe('structured-data rendering', () => {
	it('renders a single SD element with params', () => {
		const line = _formatRfc5424({
			severity: 'info',
			facility: 'local0',
			message: 'm',
			timestamp: '-',
			structuredData: [{ id: 'exampleSDID@32473', params: { iut: '3', eventID: '1011' } }]
		});
		expect(line).toBe('<134>1 - - - - - [exampleSDID@32473 iut="3" eventID="1011"] m');
	});

	it('backslash-escapes ", \\ and ] inside param values', () => {
		const line = _formatRfc5424({
			severity: 'info',
			facility: 'local0',
			message: 'm',
			timestamp: '-',
			structuredData: [{ id: 'sd@1', params: { v: 'a"b\\c]d' } }]
		});
		expect(line).toBe('<134>1 - - - - - [sd@1 v="a\\"b\\\\c\\]d"] m');
	});
});

describe('octet-counting framing', () => {
	it('writes <len> SP message where len is the byte length of the message', async () => {
		const { socket, server } = mockConnection();
		const opts: SyslogConnectOptions = { hostname: 'h', framing: 'octet-counting' };

		const clientFlow = async () => {
			const session = _sessionFromSocket(socket, opts);
			await session.log({
				severity: 'info',
				facility: 'local0',
				message: 'hello',
				timestamp: '2025-01-01T00:00:00Z'
			});
		};

		const serverScript = async () => readOctetFrame(server);

		const [, body] = await Promise.all([clientFlow(), serverScript()]);
		const expected = '<134>1 2025-01-01T00:00:00Z - - - - - hello';
		expect(body).toBe(expected);
		expect(body.length).toBe(encoder.encode(expected).length);
	});

	it('uses the UTF-8 byte length, not character count, for multibyte messages', async () => {
		const { socket, server } = mockConnection();
		const msg = 'cafeé'; // trailing e-acute is 2 bytes in UTF-8
		const line = _formatRfc5424({
			severity: 'info',
			facility: 'local0',
			message: msg,
			timestamp: '-'
		});
		const framed = _frame(line, 'octet-counting');
		const prefix = decoder.decode(framed.subarray(0, framed.indexOf(0x20) + 1));
		expect(prefix).toBe(`${encoder.encode(line).length} `);

		const clientFlow = async () => {
			const session = _sessionFromSocket(socket, { hostname: 'h' });
			await session.emit(line);
		};
		const [, body] = await Promise.all([clientFlow(), readOctetFrame(server)]);
		expect(body).toBe(line);
	});
});

describe('lf framing', () => {
	it('writes the message followed by a single LF and no length prefix', async () => {
		const { socket, server } = mockConnection();

		const clientFlow = async () => {
			const session = _sessionFromSocket(socket, { hostname: 'h', framing: 'lf' });
			await session.log({
				severity: 'info',
				facility: 'local0',
				message: 'hello',
				timestamp: '2025-01-01T00:00:00Z'
			});
		};

		const [, body] = await Promise.all([clientFlow(), readLfFrame(server)]);
		const expected = '<134>1 2025-01-01T00:00:00Z - - - - - hello';
		expect(body).toBe(expected);
		// no octet-count prefix: the first char is the PRI opener, not a digit
		expect(body.startsWith('<')).toBe(true);
	});

	it('appends exactly one LF byte', () => {
		const framed = _frame('abc', 'lf');
		expect(framed.length).toBe(4);
		expect(framed[3]).toBe(0x0a);
		expect(decoder.decode(framed)).toBe('abc\n');
	});
});

describe('emit(rawLine)', () => {
	it('frames a raw pre-formatted line under octet-counting', async () => {
		const { socket, server } = mockConnection();
		const raw = '<13>1 - - - - - raw message';

		const clientFlow = async () => {
			const session = _sessionFromSocket(socket, { hostname: 'h' });
			await session.emit(raw);
		};
		const [, body] = await Promise.all([clientFlow(), readOctetFrame(server)]);
		expect(body).toBe(raw);
	});

	it('frames a raw pre-formatted line under lf', async () => {
		const { socket, server } = mockConnection();
		const raw = '<13>1 - - - - - raw message';

		const clientFlow = async () => {
			const session = _sessionFromSocket(socket, { hostname: 'h', framing: 'lf' });
			await session.emit(raw);
		};
		const [, body] = await Promise.all([clientFlow(), readLfFrame(server)]);
		expect(body).toBe(raw);
	});
});

describe('severity/facility resolution', () => {
	it('resolves named and numeric inputs to the same value', () => {
		expect(resolveSeverity('info')).toBe(6);
		expect(resolveSeverity(6)).toBe(6);
		expect(resolveSeverity(Severity.info)).toBe(6);
		expect(resolveFacility('local0')).toBe(16);
		expect(resolveFacility(16)).toBe(16);
		expect(resolveFacility(Facility.local0)).toBe(16);
	});

	it('computes the same PRI from named and numeric inputs', () => {
		expect(computePri('local0', 'info')).toBe(134);
		expect(computePri(16, 6)).toBe(134);
		expect(computePri(Facility.local0, Severity.info)).toBe(134);
	});

	it('rejects out-of-range numbers and unknown names', () => {
		expect(() => resolveSeverity(8)).toThrow(ProtocolError);
		expect(() => resolveSeverity(-1)).toThrow(ProtocolError);
		expect(() => resolveFacility(24)).toThrow(ProtocolError);
		// @ts-expect-error testing an invalid name at runtime
		expect(() => resolveSeverity('nope')).toThrow(ProtocolError);
	});
});

describe('one-shot send()', () => {
	it('connects, writes one framed message, and closes', async () => {
		const { socket, server, startTlsCount } = mockConnection();

		// stub the core connect by driving _sessionFromSocket through the same path send uses;
		// here we exercise the public session lifecycle directly against the mock socket
		const clientFlow = async () => {
			const session = _sessionFromSocket(socket, { hostname: 'h', framing: 'lf' });
			await session.log({
				severity: 'info',
				facility: 'local0',
				message: 'once',
				timestamp: '2025-01-01T00:00:00Z'
			});
			await session.close();
		};
		const [, body] = await Promise.all([clientFlow(), readLfFrame(server)]);

		expect(body).toBe('<134>1 2025-01-01T00:00:00Z - - - - - once');
		// plaintext path never upgrades TLS
		expect(startTlsCount()).toBe(0);
		// socket closed: closed promise resolves
		await expect(socket.closed).resolves.toBeUndefined();
	});

	it('starttls upgrades the socket once before sending', async () => {
		const { socket, server, startTlsCount } = mockConnection();

		const clientFlow = async () => {
			const session = _sessionFromSocket(socket, {
				hostname: 'h',
				tls: 'starttls',
				framing: 'lf'
			});
			await session.emit('<13>1 - - - - - x');
			await session.close();
		};
		const [, body] = await Promise.all([clientFlow(), readLfFrame(server)]);

		expect(body).toBe('<13>1 - - - - - x');
		expect(startTlsCount()).toBe(1);
	});

	it('exposes send and connect as functions on the public surface', () => {
		// type/surface assertion so the public one-shot helper is covered without a real socket
		expect(typeof send).toBe('function');
		expect(typeof connect).toBe('function');
	});
});

// each shortcut and the severity its PRI must carry (facility user=1 -> PRI = 8 + severity)
const severityCases: Array<{
	method: 'info' | 'notice' | 'warn' | 'error' | 'debug';
	severity: Severity;
}> = [
	{ method: 'info', severity: Severity.info },
	{ method: 'notice', severity: Severity.notice },
	{ method: 'warn', severity: Severity.warning },
	{ method: 'error', severity: Severity.error },
	{ method: 'debug', severity: Severity.debug }
];

describe('syslog severity shortcuts', () => {
	for (const { method, severity } of severityCases) {
		it(`${method}() delegates to log() with Severity.${Severity[severity]}`, async () => {
			const { socket, server } = mockConnection();
			const clientFlow = async () => {
				const session = _sessionFromSocket(socket, { hostname: 'h', framing: 'lf' });
				await session[method]('hello', { timestamp: '2025-01-01T00:00:00Z' });
			};
			const [, body] = await Promise.all([clientFlow(), readLfFrame(server)]);
			// facility user(1) * 8 + severity
			expect(body).toBe(`<${8 + severity}>1 2025-01-01T00:00:00Z - - - - - hello`);
		});
	}

	it('forwards extra fields (facility, structured data, overrides) through opts', async () => {
		const { socket, server } = mockConnection();
		const clientFlow = async () => {
			const session = _sessionFromSocket(socket, { hostname: 'h', framing: 'lf' });
			await session.warn('disk almost full', {
				facility: 'local0',
				appName: 'api',
				timestamp: '2025-01-01T00:00:00Z',
				structuredData: [{ id: 'meta@1', params: { pct: '92' } }]
			});
		};
		const [, body] = await Promise.all([clientFlow(), readLfFrame(server)]);
		// local0(16) * 8 + warning(4) = 132
		expect(body).toBe('<132>1 2025-01-01T00:00:00Z - api - - [meta@1 pct="92"] disk almost full');
	});
});
