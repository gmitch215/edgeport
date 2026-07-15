import { describe, expect, it } from 'vitest';
import { AuthError, ProtocolError } from '../../src/core/errors';
import {
	_sessionFromSocket,
	buildMsrpOffer,
	computeDigestResponse,
	decodeMsrp,
	encodeMsrp,
	getParam,
	parseChallenge,
	parseMessage,
	parseSdp,
	parseUri,
	serializeMessage,
	SipHeaders,
	type SipMessage,
	type SipScheduler,
	type SipSession
} from '../../src/sip';
import { mockConnection, type MockServerEnd } from '../mock-socket';

const enc = new TextEncoder();
const dec = new TextDecoder();

// timers are irrelevant to these flows; a no-op scheduler keeps real setTimeout out of the tests
const noScheduler: SipScheduler = { set: () => 0, clear: () => {} };

// reads one complete SIP message the client wrote to the server (headers by line + body by length)
async function readSip(server: MockServerEnd): Promise<SipMessage> {
	const lines: string[] = [];
	for (;;) {
		const line = await server.readLine();
		if (line === '') break;
		lines.push(line);
	}
	const msg = parseMessage(enc.encode(lines.join('\r\n') + '\r\n\r\n'));
	const len = Number(msg.headers.get('Content-Length') ?? '0');
	if (len > 0) msg.body = await server.readN(len);
	return msg;
}

// builds a response echoing the request's dialog headers (adds a server To-tag)
function response(
	req: SipMessage,
	status: number,
	reason: string,
	extra: Record<string, string> = {},
	body: Uint8Array = new Uint8Array(0)
): Uint8Array {
	const h = new SipHeaders();
	for (const v of req.headers.getAll('Via')) h.add('Via', v);
	h.add('From', req.headers.get('From') ?? '');
	let to = req.headers.get('To') ?? '';
	if (!getParam(to, 'tag')) to += ';tag=srvtag';
	h.add('To', to);
	h.add('Call-ID', req.headers.get('Call-ID') ?? '');
	h.add('CSeq', req.headers.get('CSeq') ?? '');
	for (const [k, v] of Object.entries(extra)) h.add(k, v);
	return serializeMessage({ kind: 'response', status, reason, headers: h, body });
}

// a server->client MESSAGE request
function inboundMessage(text: string): Uint8Array {
	const h = new SipHeaders();
	h.add('Via', 'SIP/2.0/TCP proxy;branch=z9hG4bKinbound');
	h.add('Max-Forwards', '70');
	h.add('From', '<sip:bob@edgeport.test>;tag=bobtag');
	h.add('To', '<sip:tester@edgeport.test>');
	h.add('Call-ID', 'inbound-1');
	h.add('CSeq', '1 MESSAGE');
	h.add('Content-Type', 'text/plain');
	return serializeMessage({
		kind: 'request',
		method: 'MESSAGE',
		uri: 'sip:tester@edgeport.test',
		headers: h,
		body: enc.encode(text)
	});
}

function connected(opts: Record<string, unknown> = {}): {
	session: SipSession;
	server: MockServerEnd;
} {
	const { socket, server } = mockConnection();
	const session = _sessionFromSocket(socket, {
		hostname: 'sip.test',
		username: 'tester',
		password: 'testpass',
		domain: 'edgeport.test',
		scheduler: noScheduler,
		...opts
	});
	return { session, server };
}

describe('sip message codec', () => {
	it('round-trips a request through parse/serialize and forces Content-Length', () => {
		const h = new SipHeaders()
			.add('Via', 'SIP/2.0/TCP host;branch=z9hG4bKx')
			.add('Max-Forwards', '70')
			.add('From', '<sip:a@b>;tag=1')
			.add('To', '<sip:c@d>')
			.add('Call-ID', 'abc')
			.add('CSeq', '1 MESSAGE')
			.add('Content-Type', 'text/plain');
		const bytes = serializeMessage({
			kind: 'request',
			method: 'MESSAGE',
			uri: 'sip:c@d',
			headers: h,
			body: enc.encode('hi')
		});
		const msg = parseMessage(bytes);
		if (msg.kind !== 'request') throw new Error('expected request');
		expect(msg.method).toBe('MESSAGE');
		expect(msg.uri).toBe('sip:c@d');
		expect(msg.headers.get('Content-Length')).toBe('2');
		expect(dec.decode(msg.body)).toBe('hi');
	});

	it('expands the RFC 3261 compact header forms on parse', () => {
		const raw =
			'SIP/2.0 200 OK\r\nv: SIP/2.0/TCP h;branch=zz\r\nf: <sip:a@b>;tag=1\r\nt: <sip:c@d>\r\ni: cid\r\nl: 0\r\n\r\n';
		const msg = parseMessage(enc.encode(raw));
		if (msg.kind !== 'response') throw new Error('expected response');
		expect(msg.status).toBe(200);
		expect(msg.headers.get('Via')).toContain('branch=zz');
		expect(msg.headers.get('From')).toContain('tag=1');
		expect(msg.headers.get('Call-ID')).toBe('cid');
	});

	it('parses and formats SIP URIs', () => {
		const u = parseUri('"A" <sip:alice@example.com:5061;transport=tls>');
		expect(u.user).toBe('alice');
		expect(u.host).toBe('example.com');
		expect(u.port).toBe(5061);
		expect(u.params.transport).toBe('tls');
		expect(parseUri('sip:bob@x').host).toBe('x');
		expect(() => parseUri('http://x')).toThrow(ProtocolError);
	});
});

describe('sip digest auth KAT', () => {
	it('matches the RFC 2617 MD5 worked example', async () => {
		const header = await computeDigestResponse({
			username: 'Mufasa',
			password: 'Circle Of Life',
			method: 'GET',
			uri: '/dir/index.html',
			challenge: {
				realm: 'testrealm@host.com',
				nonce: 'dcd98b7102dd2f0e8b11d0f600bfb0c093',
				qop: 'auth',
				opaque: '5ccc069c403ebaf9f0171e9517f40e41'
			},
			cnonce: '0a4f113b',
			nc: '00000001'
		});
		expect(header).toContain('response="6629fae49393a05397450978507c4ef1"');
		expect(header).toContain('qop=auth');
		expect(header).toContain('opaque="5ccc069c403ebaf9f0171e9517f40e41"');
	});

	it('matches the RFC 7616 SHA-256 worked example', async () => {
		const header = await computeDigestResponse({
			username: 'Mufasa',
			password: 'Circle of Life',
			method: 'GET',
			uri: '/dir/index.html',
			challenge: {
				realm: 'http-auth@example.org',
				nonce: '7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v',
				qop: 'auth',
				algorithm: 'SHA-256'
			},
			cnonce: 'f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ',
			nc: '00000001'
		});
		expect(header).toContain(
			'response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"'
		);
	});

	it('parses a Digest challenge header', () => {
		const c = parseChallenge('Digest realm="r", nonce="n", qop="auth,auth-int", algorithm=MD5');
		expect(c.realm).toBe('r');
		expect(c.nonce).toBe('n');
		expect(c.qop).toBe('auth,auth-int');
		expect(c.algorithm).toBe('MD5');
	});
});

describe('sip REGISTER', () => {
	it('registers with digest auth on a 401 challenge', async () => {
		const { session, server } = connected();
		const script = (async () => {
			const req1 = await readSip(server);
			if (req1.kind !== 'request') throw new Error('expected request');
			expect(req1.method).toBe('REGISTER');
			expect(req1.headers.get('Authorization')).toBeUndefined();
			// the Contact carries the RFC 5626 outbound instance + reg-id
			expect(req1.headers.get('Contact')).toContain('+sip.instance');
			expect(req1.headers.get('Supported')).toContain('outbound');
			await server.write(
				response(req1, 401, 'Unauthorized', {
					'WWW-Authenticate':
						'Digest realm="edgeport.test", nonce="abc123", qop="auth", algorithm=MD5'
				})
			);
			const req2 = await readSip(server);
			const auth = req2.headers.get('Authorization');
			expect(auth).toBeDefined();
			expect(auth).toContain('username="tester"');
			expect(auth).toContain('realm="edgeport.test"');
			expect(auth).toContain('response="');
			expect(auth).toContain('nc=00000001');
			expect(auth).toContain('cnonce="');
			await server.write(response(req2, 200, 'OK', { Contact: '<sip:tester@x>;expires=3600' }));
		})();
		await Promise.all([session.register(), script]);
		await session.close();
	});

	it('rejects a bad password with AuthError', async () => {
		const { session, server } = connected();
		const script = (async () => {
			const req1 = await readSip(server);
			await server.write(
				response(req1, 401, 'Unauthorized', {
					'WWW-Authenticate': 'Digest realm="edgeport.test", nonce="n", qop="auth"'
				})
			);
			const req2 = await readSip(server);
			await server.write(
				response(req2, 401, 'Unauthorized', {
					'WWW-Authenticate': 'Digest realm="edgeport.test", nonce="n", qop="auth"'
				})
			);
		})();
		await expect(Promise.all([session.register(), script])).rejects.toBeInstanceOf(AuthError);
		await session.close();
	});
});

describe('sip MESSAGE', () => {
	it('sends a MESSAGE, authenticating on a 407 proxy challenge', async () => {
		const { session, server } = connected();
		const script = (async () => {
			const req1 = await readSip(server);
			if (req1.kind !== 'request') throw new Error('expected request');
			expect(req1.method).toBe('MESSAGE');
			expect(req1.uri).toBe('sip:bob@edgeport.test');
			expect(req1.headers.get('Proxy-Authorization')).toBeUndefined();
			await server.write(
				response(req1, 407, 'Proxy Authentication Required', {
					'Proxy-Authenticate': 'Digest realm="edgeport.test", nonce="xyz", qop="auth"'
				})
			);
			const req2 = await readSip(server);
			expect(req2.headers.get('Proxy-Authorization')).toContain('response="');
			expect(dec.decode(req2.body)).toBe('hi there');
			await server.write(response(req2, 202, 'Accepted'));
		})();
		const [resp] = await Promise.all([session.message('bob', 'hi there'), script]);
		expect(resp.status).toBe(202);
		await session.close();
	});

	it('receives an inbound MESSAGE and auto-answers 200', async () => {
		const { session, server } = connected();
		const iter = session.messages()[Symbol.asyncIterator]();
		await server.write(inboundMessage('hello inbound'));
		const first = await iter.next();
		expect(first.done).toBe(false);
		expect(first.value.text()).toBe('hello inbound');
		expect(first.value.from).toContain('bob@edgeport.test');
		// the client must have answered 200 on the same flow
		const resp = await readSip(server);
		if (resp.kind !== 'response') throw new Error('expected response');
		expect(resp.status).toBe(200);
		expect(resp.headers.get('CSeq')).toBe('1 MESSAGE');
		await session.close();
	});
});

describe('sip OPTIONS', () => {
	it('probes capabilities and parses Allow/Accept', async () => {
		const { session, server } = connected();
		const script = (async () => {
			const req = await readSip(server);
			if (req.kind !== 'request') throw new Error('expected request');
			expect(req.method).toBe('OPTIONS');
			await server.write(
				response(req, 200, 'OK', { Allow: 'INVITE, ACK, BYE, MESSAGE', Accept: 'application/sdp' })
			);
		})();
		const [res] = await Promise.all([session.options('bob'), script]);
		expect(res.status).toBe(200);
		expect(res.allow).toContain('MESSAGE');
		expect(res.accept).toContain('application/sdp');
		await session.close();
	});
});

describe('msrp codec', () => {
	it('round-trips a SEND request', () => {
		const bytes = encodeMsrp({
			kind: 'request',
			transactionId: 'abc123',
			method: 'SEND',
			headers: {
				'To-Path': 'msrp://relay:2855/to;tcp',
				'From-Path': 'msrp://client:2855/from;tcp',
				'Message-ID': 'm1',
				'Content-Type': 'text/plain'
			},
			body: enc.encode('hello msrp'),
			continuation: '$'
		});
		const d = decodeMsrp(bytes);
		if (d.kind !== 'request') throw new Error('expected request');
		expect(d.transactionId).toBe('abc123');
		expect(d.method).toBe('SEND');
		expect(d.headers['Message-ID']).toBe('m1');
		expect(dec.decode(d.body)).toBe('hello msrp');
		expect(d.continuation).toBe('$');
	});

	it('round-trips a response frame', () => {
		const bytes = encodeMsrp({
			kind: 'response',
			transactionId: 'abc123',
			code: 200,
			reason: 'OK',
			headers: { 'To-Path': 'msrp://x', 'From-Path': 'msrp://y' },
			continuation: '$'
		});
		const d = decodeMsrp(bytes);
		if (d.kind !== 'response') throw new Error('expected response');
		expect(d.code).toBe(200);
		expect(d.reason).toBe('OK');
	});
});

describe('sdp', () => {
	it('builds an MSRP offer with active setup', () => {
		const offer = buildMsrpOffer({ path: 'msrp://client:2855/xyz;tcp', sessionId: '1' });
		expect(offer).toContain('m=message');
		expect(offer).toContain('TCP/MSRP');
		expect(offer).toContain('a=setup:active');
		expect(offer).toContain('a=path:msrp://client:2855/xyz;tcp');
	});

	it('parses an MSRP answer for the peer path', () => {
		const sdp = parseSdp(
			'v=0\r\no=- 1 1 IN IP4 relay\r\ns=-\r\nc=IN IP4 relay\r\nt=0 0\r\nm=message 2855 TCP/MSRP *\r\na=accept-types:text/plain\r\na=path:msrp://relay:2855/xyz;tcp\r\n'
		);
		const media = sdp.media.find((m) => m.type === 'message');
		expect(media?.port).toBe(2855);
		expect(media?.attributes.path).toBe('msrp://relay:2855/xyz;tcp');
	});
});
