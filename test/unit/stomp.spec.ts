import { describe, expect, it } from 'vitest';
import { AuthError, ProtocolError } from '../../src/core/errors';
import { StreamFramedReader } from '../../src/core/framing';
import {
	_connectOverSocket,
	decodeFrame,
	encodeFrame,
	escapeHeader,
	unescapeHeader,
	type StompSession
} from '../../src/stomp';
import { mockConnection, type MockServerEnd } from '../mock-socket';

const enc = new TextEncoder();
const dec = new TextDecoder();

// wraps bytes in a one-chunk stream so decodeFrame can read them via a real FramedReader
function readerOf(bytes: Uint8Array): StreamFramedReader {
	const stream = new ReadableStream<Uint8Array>({
		start(controller) {
			controller.enqueue(bytes);
			controller.close();
		}
	});
	return new StreamFramedReader(stream);
}

// reads one full STOMP frame the way a broker would, off the wire the client wrote
async function readFrame(server: MockServerEnd): Promise<{
	command: string;
	headers: Record<string, string>;
	body: Uint8Array;
}> {
	let command = await server.readLine();
	while (command === '') command = await server.readLine();
	const headers: Record<string, string> = {};
	for (;;) {
		const line = await server.readLine();
		if (line === '') break;
		const idx = line.indexOf(':');
		const key = unescapeHeader(line.slice(0, idx));
		const value = unescapeHeader(line.slice(idx + 1));
		if (headers[key] === undefined) headers[key] = value;
	}
	let body: Uint8Array;
	const len = headers['content-length'];
	if (len !== undefined) {
		body = await server.readN(Number(len));
		await server.readN(1); // NUL
	} else {
		// read byte-at-a-time until NUL (test bodies here always carry content-length, so unused)
		const chunks: number[] = [];
		for (;;) {
			const b = await server.readN(1);
			if (b[0] === 0x00) break;
			chunks.push(b[0]!);
		}
		body = new Uint8Array(chunks);
	}
	return { command, headers, body };
}

// runs the CONNECT -> CONNECTED handshake and returns the parsed CONNECT frame
async function handshake(server: MockServerEnd): Promise<Record<string, string>> {
	const connect = await readFrame(server);
	expect(connect.command).toBe('CONNECT');
	await server.write(encodeFrame('CONNECTED', { version: '1.2', 'heart-beat': '0,0' }));
	return connect.headers;
}

// reads the client's DISCONNECT and answers its receipt so close() resolves
async function disconnect(server: MockServerEnd): Promise<void> {
	const frame = await readFrame(server);
	expect(frame.command).toBe('DISCONNECT');
	const receipt = frame.headers['receipt'];
	if (receipt !== undefined) {
		await server.write(encodeFrame('RECEIPT', { 'receipt-id': receipt }));
	}
}

describe('stomp frame codec', () => {
	it('round-trips a SEND frame with headers and body', async () => {
		const body = enc.encode('hello world');
		const bytes = encodeFrame('SEND', { destination: '/queue/a', persistent: 'true' }, body);
		const frame = await decodeFrame(readerOf(bytes));
		expect(frame.command).toBe('SEND');
		expect(frame.headers['destination']).toBe('/queue/a');
		expect(frame.headers['persistent']).toBe('true');
		expect(frame.headers['content-length']).toBe(String(body.length));
		expect(dec.decode(frame.body)).toBe('hello world');
	});

	it('escapes and unescapes reserved header characters', () => {
		const raw = 'a:b\nc\rd\\e';
		const escaped = escapeHeader(raw);
		expect(escaped).toBe('a\\cb\\nc\\rd\\\\e');
		expect(unescapeHeader(escaped)).toBe(raw);
	});

	it('round-trips a header value containing : \\n \\r and backslash', async () => {
		const value = 'x:y\nz\rw\\v';
		const bytes = encodeFrame('SEND', { destination: '/q', note: value }, enc.encode('b'));
		// the wire form must not contain a literal newline inside the header value
		const wire = dec.decode(bytes);
		const headerSection = wire.slice(0, wire.indexOf('\n\n'));
		expect(headerSection.includes('note:x\\cy\\nz\\rw\\\\v')).toBe(true);
		const frame = await decodeFrame(readerOf(bytes));
		expect(frame.headers['note']).toBe(value);
	});

	it('reads exactly content-length bytes including an embedded NUL', async () => {
		const body = new Uint8Array([0x41, 0x00, 0x42, 0x00, 0x43]); // A NUL B NUL C
		const bytes = encodeFrame('MESSAGE', { destination: '/q', 'message-id': '7' }, body);
		expect(dec.decode(bytes).includes('content-length:5')).toBe(true);
		const frame = await decodeFrame(readerOf(bytes));
		expect(frame.body.length).toBe(5);
		expect(Array.from(frame.body)).toEqual([0x41, 0x00, 0x42, 0x00, 0x43]);
	});

	it('reads a body up to the first NUL when no content-length is present', async () => {
		// hand-build a frame with no content-length header
		const wire = enc.encode('MESSAGE\ndestination:/q\n\nplain body\x00');
		const frame = await decodeFrame(readerOf(wire));
		expect(frame.headers['content-length']).toBeUndefined();
		expect(dec.decode(frame.body)).toBe('plain body');
	});
});

describe('stomp handshake', () => {
	it('sends CONNECT with login/passcode/host/accept-version then is ready', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			const headers = await handshake(server);
			expect(headers['accept-version']).toBe('1.2');
			expect(headers['host']).toBe('vhost.test');
			expect(headers['login']).toBe('alice');
			expect(headers['passcode']).toBe('hunter2');
			expect(headers['heart-beat']).toBe('0,0');
		})();
		const session = (
			await Promise.all([
				_connectOverSocket(socket, {
					hostname: 'broker.test',
					host: 'vhost.test',
					login: 'alice',
					passcode: 'hunter2'
				}),
				script
			])
		)[0];
		await Promise.all([session.close(), disconnect(server)]);
	});

	it('sends the negotiated heart-beat header', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			const headers = await handshake(server);
			expect(headers['heart-beat']).toBe('5000,10000');
		})();
		const session = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'broker.test', heartBeat: [5000, 10000] }),
				script
			])
		)[0];
		await Promise.all([session.close(), disconnect(server)]);
	});
});

describe('stomp send', () => {
	it('frames SEND with destination, content-length, body and trailing NUL', async () => {
		const { socket, server } = mockConnection();
		const session = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'broker.test' }),
				handshake(server)
			])
		)[0];

		const sendScript = (async () => {
			const frame = await readFrame(server);
			expect(frame.command).toBe('SEND');
			expect(frame.headers['destination']).toBe('/queue/work');
			expect(frame.headers['content-length']).toBe('5');
			expect(frame.headers['content-type']).toBe('text/plain');
			expect(dec.decode(frame.body)).toBe('howdy');
		})();
		await Promise.all([
			session.send('/queue/work', 'howdy', { contentType: 'text/plain' }),
			sendScript
		]);

		await Promise.all([session.close(), disconnect(server)]);
	});
});

describe('stomp subscribe / message delivery', () => {
	it('subscribes then delivers a MESSAGE through the async iterator', async () => {
		const { socket, server } = mockConnection();
		const session = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'broker.test' }),
				handshake(server)
			])
		)[0];

		const sub = session.subscribe('/topic/news', { ack: 'client' });
		expect(sub.destination).toBe('/topic/news');

		const subScript = (async () => {
			const frame = await readFrame(server);
			expect(frame.command).toBe('SUBSCRIBE');
			expect(frame.headers['id']).toBe(sub.id);
			expect(frame.headers['destination']).toBe('/topic/news');
			expect(frame.headers['ack']).toBe('client');
			// now push a MESSAGE on that subscription
			await server.write(
				encodeFrame(
					'MESSAGE',
					{
						subscription: sub.id,
						'message-id': 'm-42',
						destination: '/topic/news',
						ack: 'ack-1'
					},
					enc.encode('breaking')
				)
			);
		})();

		const iter = sub[Symbol.asyncIterator]();
		const [result] = await Promise.all([iter.next(), subScript]);
		expect(result.done).toBe(false);
		expect(result.value.destination).toBe('/topic/news');
		expect(result.value.messageId).toBe('m-42');
		expect(dec.decode(result.value.body)).toBe('breaking');
		expect(result.value.headers['subscription']).toBe(sub.id);
		expect(typeof result.value.ack).toBe('function');

		// ack the message and assert the ACK frame on the wire
		const ackScript = (async () => {
			const frame = await readFrame(server);
			expect(frame.command).toBe('ACK');
			expect(frame.headers['id']).toBe('ack-1');
		})();
		await Promise.all([result.value.ack!(), ackScript]);

		await Promise.all([session.close(), disconnect(server)]);
	});
});

describe('stomp error frames', () => {
	it('throws AuthError for an auth-related ERROR during connect', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			const frame = await readFrame(server);
			expect(frame.command).toBe('CONNECT');
			await server.write(
				encodeFrame('ERROR', { message: 'Bad CONNECT: authentication failed for login alice' })
			);
		})();
		await expect(
			Promise.all([
				_connectOverSocket(socket, {
					hostname: 'broker.test',
					login: 'alice',
					passcode: 'wrong'
				}),
				script
			])
		).rejects.toBeInstanceOf(AuthError);
	});

	it('throws ProtocolError for a generic ERROR during connect', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			await readFrame(server);
			await server.write(encodeFrame('ERROR', { message: 'destination /queue/x does not exist' }));
		})();
		const result = Promise.all([_connectOverSocket(socket, { hostname: 'broker.test' }), script]);
		await expect(result).rejects.toBeInstanceOf(ProtocolError);
		await expect(result).rejects.not.toBeInstanceOf(AuthError);
	});
});

describe('stomp session type', () => {
	it('exposes the expected public surface', async () => {
		const { socket, server } = mockConnection();
		const session: StompSession = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'broker.test' }),
				handshake(server)
			])
		)[0];
		expect(typeof session.send).toBe('function');
		expect(typeof session.subscribe).toBe('function');
		expect(typeof session.unsubscribe).toBe('function');
		expect(typeof session.begin).toBe('function');
		expect(typeof session.close).toBe('function');
		await Promise.all([session.close(), disconnect(server)]);
	});
});

describe('stomp transactions', () => {
	it('emits BEGIN, a transaction-tagged SEND, and COMMIT', async () => {
		const { socket, server } = mockConnection();
		const [session] = await Promise.all([
			_connectOverSocket(socket, { hostname: 'broker.test' }),
			handshake(server)
		]);

		const tx = await session.begin();
		const begin = await readFrame(server);
		expect(begin.command).toBe('BEGIN');
		expect(begin.headers['transaction']).toBe(tx.id);

		await tx.send('/queue/x', 'hi');
		const send = await readFrame(server);
		expect(send.command).toBe('SEND');
		expect(send.headers['transaction']).toBe(tx.id);
		expect(send.headers['destination']).toBe('/queue/x');
		expect(dec.decode(send.body)).toBe('hi');

		await tx.commit();
		const commit = await readFrame(server);
		expect(commit.command).toBe('COMMIT');
		expect(commit.headers['transaction']).toBe(tx.id);

		await Promise.all([session.close(), disconnect(server)]);
	});

	it('emits ABORT to roll back a transaction', async () => {
		const { socket, server } = mockConnection();
		const [session] = await Promise.all([
			_connectOverSocket(socket, { hostname: 'broker.test' }),
			handshake(server)
		]);

		const tx = await session.begin();
		expect((await readFrame(server)).command).toBe('BEGIN');
		await tx.send('/queue/x', 'staged');
		expect((await readFrame(server)).command).toBe('SEND');
		await tx.abort();
		const abort = await readFrame(server);
		expect(abort.command).toBe('ABORT');
		expect(abort.headers['transaction']).toBe(tx.id);

		await Promise.all([session.close(), disconnect(server)]);
	});
});

describe('stomp unsubscribe idempotency', () => {
	it('writes UNSUBSCRIBE only once even if unsubscribed twice', async () => {
		const { socket, server } = mockConnection();
		const [session] = await Promise.all([
			_connectOverSocket(socket, { hostname: 'broker.test' }),
			handshake(server)
		]);

		const sub = session.subscribe('/queue/q');
		const subFrame = await readFrame(server);
		expect(subFrame.command).toBe('SUBSCRIBE');
		const id = subFrame.headers['id']!;

		await session.unsubscribe(id);
		const unsub = await readFrame(server);
		expect(unsub.command).toBe('UNSUBSCRIBE');

		// a second unsubscribe for the same id must NOT hit the wire (would ERROR on brokers
		// like ActiveMQ and kill the pump); the next frame the server sees is the SEND below
		await session.unsubscribe(id);
		await sub.unsubscribe(); // disposal-style second call - also a no-op on the wire
		await session.send('/queue/q', 'still-alive');
		const next = await readFrame(server);
		expect(next.command).toBe('SEND');
		expect(dec.decode(next.body)).toBe('still-alive');

		await Promise.all([session.close(), disconnect(server)]);
	});
});
