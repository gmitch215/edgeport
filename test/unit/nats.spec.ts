import { describe, expect, it } from 'vitest';
import { AuthError, ProtocolError } from '../../src/core/errors';
import { _connectOverSocket, type NatsConnection } from '../../src/nats';
import { isDeliveredMessage, parseApiResponse, parsePubAck } from '../../src/nats/jetstream';
import { parseCreds, signNonce } from '../../src/nats/nkey';
import { mockConnection, type MockServerEnd } from '../mock-socket';

const dec = new TextDecoder();
const enc = new TextEncoder();

// reads CONNECT json + the following PING, then sends PONG; returns the parsed CONNECT
async function handshake(server: MockServerEnd): Promise<Record<string, unknown>> {
	await server.writeLine('INFO {"server_id":"test","tls_required":false}');
	const connectLine = await server.readLine();
	expect(connectLine.startsWith('CONNECT ')).toBe(true);
	const json = JSON.parse(connectLine.slice('CONNECT '.length)) as Record<string, unknown>;
	expect(await server.readLine()).toBe('PING');
	await server.writeLine('PONG');
	return json;
}

// writes a MSG frame the way a NATS server would: header line, payload, CRLF
async function sendMsg(
	server: MockServerEnd,
	subject: string,
	sid: string,
	payload: string,
	reply?: string
): Promise<void> {
	const body = enc.encode(payload);
	const head =
		reply !== undefined
			? `MSG ${subject} ${sid} ${reply} ${body.length}`
			: `MSG ${subject} ${sid} ${body.length}`;
	await server.writeLine(head);
	const frame = new Uint8Array(body.length + 2);
	frame.set(body, 0);
	frame.set(enc.encode('\r\n'), body.length);
	await server.write(frame);
}

describe('nats handshake', () => {
	it('sends CONNECT with token auth then PINGs', async () => {
		const { socket, server } = mockConnection();
		let conn: NatsConnection;
		const script = (async () => {
			const json = await handshake(server);
			expect(json.auth_token).toBe('s3cr3t');
			expect(json.user).toBeUndefined();
			expect(json.lang).toBe('edgeport');
			expect(json.verbose).toBe(false);
			expect(json.protocol).toBe(1);
		})();
		conn = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'nats.test', tls: 'off', token: 's3cr3t' }),
				script
			])
		)[0];
		await conn.close();
	});

	it('sends CONNECT with user/pass auth', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			const json = await handshake(server);
			expect(json.user).toBe('alice');
			expect(json.pass).toBe('hunter2');
			expect(json.auth_token).toBeUndefined();
		})();
		const conn = (
			await Promise.all([
				_connectOverSocket(socket, {
					hostname: 'nats.test',
					tls: 'off',
					username: 'alice',
					password: 'hunter2'
				}),
				script
			])
		)[0];
		await conn.close();
	});

	it('upgrades to TLS when tls: starttls is requested', async () => {
		const { socket, server, startTlsCount } = mockConnection();
		const script = (async () => {
			await server.writeLine('INFO {"tls_required":true}');
			const connectLine = await server.readLine();
			expect(connectLine.startsWith('CONNECT ')).toBe(true);
			const json = JSON.parse(connectLine.slice(8)) as Record<string, unknown>;
			expect(json.tls_required).toBe(true);
			expect(await server.readLine()).toBe('PING');
			await server.writeLine('PONG');
		})();
		const conn = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'nats.test', tls: 'starttls' }),
				script
			])
		)[0];
		expect(startTlsCount()).toBe(1);
		await conn.close();
	});

	it("surfaces -ERR 'Authorization Violation' as AuthError", async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			await server.writeLine('INFO {"tls_required":false}');
			expect((await server.readLine()).startsWith('CONNECT ')).toBe(true);
			expect(await server.readLine()).toBe('PING');
			await server.writeLine("-ERR 'Authorization Violation'");
		})();
		await expect(
			Promise.all([
				_connectOverSocket(socket, { hostname: 'nats.test', tls: 'off', token: 'bad' }),
				script
			])
		).rejects.toBeInstanceOf(AuthError);
	});
});

describe('nats publish / subscribe / request', () => {
	it('formats PUB correctly', async () => {
		const { socket, server } = mockConnection();
		const conn = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'nats.test', tls: 'off' }),
				handshake(server)
			])
		)[0];

		const pubScript = (async () => {
			expect(await server.readLine()).toBe('PUB greet 5');
			const payload = await server.readN(5);
			expect(dec.decode(payload)).toBe('hello');
			expect(await server.readN(2)).toEqual(enc.encode('\r\n'));
		})();
		await Promise.all([conn.publish('greet', 'hello'), pubScript]);

		// PUB with a reply subject
		const replyScript = (async () => {
			expect(await server.readLine()).toBe('PUB greet reply.box 2');
			expect(dec.decode(await server.readN(2))).toBe('hi');
			await server.readN(2);
		})();
		await Promise.all([conn.publish('greet', 'hi', { reply: 'reply.box' }), replyScript]);

		await conn.close();
	});

	it('delivers server MSG frames through the async iterator', async () => {
		const { socket, server } = mockConnection();
		const conn = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'nats.test', tls: 'off' }),
				handshake(server)
			])
		)[0];

		const sub = conn.subscribe('events.>');
		expect(sub.subject).toBe('events.>');
		expect(await server.readLine()).toBe('SUB events.> 1');

		await sendMsg(server, 'events.temp', '1', 'first');
		await sendMsg(server, 'events.req', '1', 'second', 'reply.inbox');

		const iter = sub[Symbol.asyncIterator]();
		const a = await iter.next();
		expect(a.done).toBe(false);
		expect(a.value.subject).toBe('events.temp');
		expect(dec.decode(a.value.data)).toBe('first');
		expect(a.value.reply).toBeUndefined();

		const b = await iter.next();
		expect(b.value.subject).toBe('events.req');
		expect(dec.decode(b.value.data)).toBe('second');
		expect(b.value.reply).toBe('reply.inbox');

		const unsubScript = (async () => {
			expect(await server.readLine()).toBe('UNSUB 1');
		})();
		await Promise.all([sub.unsubscribe(), unsubScript]);
		await conn.close();
	});

	it('includes the queue group in SUB', async () => {
		const { socket, server } = mockConnection();
		const conn = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'nats.test', tls: 'off' }),
				handshake(server)
			])
		)[0];

		conn.subscribe('work.jobs', { queue: 'workers' });
		expect(await server.readLine()).toBe('SUB work.jobs workers 1');
		await conn.close();
	});

	it('completes request-reply against a server that answers the inbox', async () => {
		const { socket, server } = mockConnection();
		const conn = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'nats.test', tls: 'off' }),
				handshake(server)
			])
		)[0];

		const serverScript = (async () => {
			const subLine = await server.readLine();
			const subParts = subLine.split(/\s+/);
			expect(subParts[0]).toBe('SUB');
			const inbox = subParts[1]!;
			expect(inbox.startsWith('_INBOX.')).toBe(true);
			const sid = subParts[2]!;

			const pubLine = await server.readLine();
			const pubParts = pubLine.split(/\s+/);
			expect(pubParts[0]).toBe('PUB');
			expect(pubParts[1]).toBe('time.now');
			expect(pubParts[2]).toBe(inbox); // reply subject is the inbox
			const reqLen = Number(pubParts[3]);
			expect(dec.decode(await server.readN(reqLen))).toBe('q');
			await server.readN(2); // CRLF

			// reply on the inbox using the assigned sid
			await sendMsg(server, inbox, sid, 'pong-reply');
			expect(await server.readLine()).toBe(`UNSUB ${sid}`);
		})();

		const [reply] = await Promise.all([conn.request('time.now', 'q'), serverScript]);
		expect(dec.decode(reply.data)).toBe('pong-reply');
		await conn.close();
	});

	it('answers a server PING with PONG', async () => {
		const { socket, server } = mockConnection();
		const conn = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'nats.test', tls: 'off' }),
				handshake(server)
			])
		)[0];

		const pingScript = (async () => {
			await server.writeLine('PING');
			expect(await server.readLine()).toBe('PONG');
		})();
		await pingScript;
		await conn.close();
	});
});

describe('nats nkey signing', () => {
	// a valid NATS user seed (verified to round-trip below); the matching public user nkey
	const SEED = 'SUAEL6GG2L2HIF7DUGZJGMRUFKXELGGYFMHF76UO2AYBG3K4YLWR3FKC2Q';
	const EXPECTED_PUB = 'UD6OU4D3CIOGIDZVL4ANXU3NWXOW5DCDE2YPZDBHPBXCVKHSODUA4FKI';

	it('derives the user public nkey and a verifiable signature', async () => {
		const nonce = enc.encode('PXoWU7zWAMt75FY');
		const { nkey, sig } = await signNonce(SEED, nonce);

		expect(nkey.startsWith('U')).toBe(true);
		expect(nkey).toBe(EXPECTED_PUB);

		// rebuild the raw public key from the nkey string and verify the signature
		const { fromBase32 } = await import('../../src/nats/nkey');
		const decoded = fromBase32(nkey);
		const pub32 = decoded.subarray(1, 33); // [roleByte][pub32][crc16]
		const pubKey = await crypto.subtle.importKey(
			'raw',
			pub32 as BufferSource,
			{ name: 'Ed25519' },
			false,
			['verify']
		);
		const sigBytes = b64urlDecode(sig);
		const ok = await crypto.subtle.verify(
			{ name: 'Ed25519' },
			pubKey,
			sigBytes as BufferSource,
			nonce as BufferSource
		);
		expect(ok).toBe(true);
	});
});

describe('nats jwt creds parsing', () => {
	const SEED = 'SUAEL6GG2L2HIF7DUGZJGMRUFKXELGGYFMHF76UO2AYBG3K4YLWR3FKC2Q';
	const CREDS = `-----BEGIN NATS USER JWT-----
eyJhbGciOiJlZDI1NTE5LXNpZyJ9.eyJzdWIiOiJVRURHRVBPUlQifQ.sig
------END NATS USER JWT------

-----BEGIN USER NKEY SEED-----
${SEED}
------END USER NKEY SEED------
`;

	it('parseCreds extracts the JWT and seed', () => {
		const { jwt, seed } = parseCreds(CREDS);
		expect(seed).toBe(SEED);
		expect(jwt.startsWith('eyJ')).toBe(true);
	});

	it('parseCreds rejects a malformed creds file', () => {
		expect(() => parseCreds('not a creds file')).toThrow(AuthError);
	});

	it('sends a CONNECT with jwt + sig from a creds file', async () => {
		const { socket, server } = mockConnection();
		const client = _connectOverSocket(socket, { hostname: 'h', creds: CREDS });
		await server.writeLine(`INFO {"tls_required":false,"nonce":"abcdef"}`);
		const connectLine = await server.readLine();
		const pingLine = await server.readLine();
		await server.writeLine('PONG');
		await client;
		expect(connectLine.startsWith('CONNECT ')).toBe(true);
		const json = JSON.parse(connectLine.slice('CONNECT '.length));
		expect(typeof json.jwt).toBe('string');
		expect(typeof json.sig).toBe('string');
		expect(json.nkey).toBeUndefined();
		expect(pingLine).toBe('PING');
	});
});

describe('jetstream parsing helpers', () => {
	const bytes = (s: string) => enc.encode(s);

	it('parsePubAck reads stream + seq', () => {
		const ack = parsePubAck(bytes('{"stream":"ORDERS","seq":7}'));
		expect(ack.stream).toBe('ORDERS');
		expect(ack.seq).toBe(7);
		expect(ack.duplicate).toBeUndefined();
	});

	it('parsePubAck carries the duplicate flag', () => {
		const ack = parsePubAck(bytes('{"stream":"S","seq":3,"duplicate":true}'));
		expect(ack.duplicate).toBe(true);
	});

	it('parsePubAck throws ProtocolError on an API error body', () => {
		expect(() =>
			parsePubAck(bytes('{"error":{"err_code":10060,"description":"no stream matches"}}'))
		).toThrow(ProtocolError);
	});

	it('parsePubAck throws ProtocolError when stream/seq are missing', () => {
		expect(() => parsePubAck(bytes('{"foo":1}'))).toThrow(ProtocolError);
		expect(() => parsePubAck(bytes('not json'))).toThrow(ProtocolError);
	});

	it('parseApiResponse swallows ignored err_codes (idempotent create)', () => {
		const body = bytes('{"error":{"err_code":10058,"description":"stream name already in use"}}');
		// 10058 ignored -> returns the parsed object instead of throwing
		const res = parseApiResponse<{ error?: { err_code?: number } }>(body, [10058]);
		expect(res.error?.err_code).toBe(10058);
		// not ignored -> throws
		expect(() => parseApiResponse(body, [])).toThrow(ProtocolError);
	});

	it('isDeliveredMessage tells a real msg from a status frame', () => {
		// a real pulled message carries an ack inbox in reply
		expect(isDeliveredMessage({ data: bytes('payload'), reply: '$JS.ACK.S.D.1.2.3' })).toBe(true);
		// a 404/408 status frame has no reply subject (and usually no body)
		expect(isDeliveredMessage({ data: new Uint8Array(0) })).toBe(false);
		expect(isDeliveredMessage({ data: bytes('x'), reply: '' })).toBe(false);
	});
});

function b64urlDecode(s: string): Uint8Array {
	const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}
