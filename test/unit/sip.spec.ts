import { describe, expect, it } from 'vitest';
import { AuthError, ProtocolError } from '../../src/core/errors';
import {
	_msrpSessionFromSocket,
	_sessionFromSocket,
	buildMsrpOffer,
	computeDigestResponse,
	connectMsrp,
	decodeMsrp,
	encodeMsrp,
	getParam,
	parseChallenge,
	parseMessage,
	parseSdp,
	parseUri,
	serializeMessage,
	SipHeaders,
	writePing,
	writePong,
	type MsrpMessage,
	type MsrpSession,
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

// builds a server->client SIP request with the dialog headers the pump/#respond need
function inboundRequest(
	method: string,
	extra: Record<string, string> = {},
	body: Uint8Array = new Uint8Array(0)
): Uint8Array {
	const h = new SipHeaders();
	h.add('Via', `SIP/2.0/TCP proxy;branch=z9hG4bK${method}`);
	h.add('Max-Forwards', '70');
	h.add('From', '<sip:bob@edgeport.test>;tag=bobtag');
	h.add('To', '<sip:tester@edgeport.test>');
	h.add('Call-ID', `in-${method}`);
	h.add('CSeq', `1 ${method}`);
	for (const [k, v] of Object.entries(extra)) h.add(k, v);
	return serializeMessage({
		kind: 'request',
		method,
		uri: 'sip:tester@edgeport.test',
		headers: h,
		body
	});
}

// builds a NOTIFY carrying a subscription state and a PIDF body, keyed to a subscription Call-ID
function notify(callId: string, state: string, pidf: string): Uint8Array {
	const h = new SipHeaders();
	h.add('Via', 'SIP/2.0/TCP proxy;branch=z9hG4bKnotify');
	h.add('Max-Forwards', '70');
	h.add('From', '<sip:bob@edgeport.test>;tag=bobtag');
	h.add('To', '<sip:tester@edgeport.test>;tag=mytag');
	h.add('Call-ID', callId);
	h.add('CSeq', '1 NOTIFY');
	h.add('Event', 'presence');
	h.add('Subscription-State', state);
	h.add('Content-Type', 'application/pidf+xml');
	return serializeMessage({
		kind: 'request',
		method: 'NOTIFY',
		uri: 'sip:tester@edgeport.test',
		headers: h,
		body: enc.encode(pidf)
	});
}

describe('sip keep-alive framing', () => {
	it('writePing writes the RFC 5626 double-CRLF', async () => {
		const { socket, server } = mockConnection();
		await writePing(socket.writer);
		expect([...(await server.readN(4))]).toEqual([0x0d, 0x0a, 0x0d, 0x0a]);
	});

	it('writePong writes a single CRLF', async () => {
		const { socket, server } = mockConnection();
		await writePong(socket.writer);
		expect([...(await server.readN(2))]).toEqual([0x0d, 0x0a]);
	});
});

describe('sip inbound request handling', () => {
	async function roundtrip(method: string, extra?: Record<string, string>): Promise<SipMessage> {
		const { session, server } = connected();
		await server.write(inboundRequest(method, extra));
		const resp = await readSip(server);
		await session.close();
		return resp;
	}

	it('auto-answers an inbound OPTIONS with 200 and an Allow list', async () => {
		const resp = await roundtrip('OPTIONS');
		if (resp.kind !== 'response') throw new Error('expected response');
		expect(resp.status).toBe(200);
		expect(resp.headers.get('Allow')).toContain('MESSAGE');
	});

	it('answers an inbound BYE with 200', async () => {
		const resp = await roundtrip('BYE');
		if (resp.kind !== 'response') throw new Error('expected response');
		expect(resp.status).toBe(200);
	});

	it('declines an inbound INVITE with 488', async () => {
		const resp = await roundtrip('INVITE', { 'Content-Type': 'application/sdp' });
		if (resp.kind !== 'response') throw new Error('expected response');
		expect(resp.status).toBe(488);
	});

	it('rejects an unknown method with 405', async () => {
		const resp = await roundtrip('INFO');
		if (resp.kind !== 'response') throw new Error('expected response');
		expect(resp.status).toBe(405);
	});
});

describe('sip OPTIONS (server target)', () => {
	it('probes the server itself when no target is given', async () => {
		const { session, server } = connected();
		const script = (async () => {
			const req = await readSip(server);
			if (req.kind !== 'request') throw new Error('expected request');
			expect(req.method).toBe('OPTIONS');
			expect(req.uri).toBe('sip:edgeport.test');
			await server.write(response(req, 200, 'OK', { Allow: 'INVITE, MESSAGE' }));
		})();
		const [res] = await Promise.all([session.options(), script]);
		expect(res.status).toBe(200);
		expect(res.allow).toContain('INVITE');
		await session.close();
	});
});

describe('sip presence subscription', () => {
	it('subscribes, receives NOTIFYs, and ends on a terminated state', async () => {
		const { session, server } = connected();
		let subCallId = '';
		const subScript = (async () => {
			const req = await readSip(server);
			if (req.kind !== 'request') throw new Error('expected request');
			expect(req.method).toBe('SUBSCRIBE');
			expect(req.headers.get('Event')).toBe('presence');
			subCallId = req.headers.get('Call-ID') ?? '';
			await server.write(response(req, 200, 'OK'));
		})();
		const sub = (await Promise.all([session.subscribePresence('bob'), subScript]))[0];
		const iter = sub[Symbol.asyncIterator]();

		await server.write(notify(subCallId, 'active;expires=3600', '<presence>online</presence>'));
		const active = await iter.next();
		expect(active.done).toBe(false);
		expect(active.value.state).toContain('active');
		expect(active.value.text()).toContain('online');
		// the pump auto-answers each NOTIFY with 200
		const notifyResp = await readSip(server);
		if (notifyResp.kind !== 'response') throw new Error('expected response');
		expect(notifyResp.status).toBe(200);

		await server.write(notify(subCallId, 'terminated', '<presence>offline</presence>'));
		const terminated = await iter.next();
		expect(terminated.done).toBe(false);
		expect(terminated.value.state).toContain('terminated');
		// after a terminated NOTIFY the subscription iterator completes
		const done = await iter.next();
		expect(done.done).toBe(true);
		await session.close();
	});

	it('unsubscribes with an Expires: 0 SUBSCRIBE', async () => {
		const { session, server } = connected();
		let subCallId = '';
		const subScript = (async () => {
			const req = await readSip(server);
			subCallId = req.headers.get('Call-ID') ?? '';
			await server.write(response(req, 200, 'OK'));
		})();
		const sub = (await Promise.all([session.subscribePresence('bob'), subScript]))[0];
		const unsubScript = (async () => {
			const req = await readSip(server);
			if (req.kind !== 'request') throw new Error('expected request');
			expect(req.method).toBe('SUBSCRIBE');
			expect(req.headers.get('Expires')).toBe('0');
			expect(req.headers.get('Call-ID')).toBe(subCallId);
			// the unsubscribe awaits its SUBSCRIBE response, so answer it
			await server.write(response(req, 200, 'OK'));
		})();
		await Promise.all([sub.unsubscribe(), unsubScript]);
		await session.close();
	});

	it('rejects a failed SUBSCRIBE with ProtocolError', async () => {
		const { session, server } = connected();
		const script = (async () => {
			const req = await readSip(server);
			await server.write(response(req, 403, 'Forbidden'));
		})();
		await expect(Promise.all([session.subscribePresence('bob'), script])).rejects.toBeInstanceOf(
			ProtocolError
		);
		await session.close();
	});
});

describe('sip INVITE (chat setup)', () => {
	it('rejects a declined INVITE with ProtocolError', async () => {
		const { session, server } = connected();
		const script = (async () => {
			const req = await readSip(server);
			if (req.kind !== 'request') throw new Error('expected request');
			expect(req.method).toBe('INVITE');
			expect(req.headers.get('Content-Type')).toBe('application/sdp');
			await server.write(response(req, 488, 'Not Acceptable Here'));
		})();
		await expect(Promise.all([session.invite('bob'), script])).rejects.toBeInstanceOf(
			ProtocolError
		);
		await session.close();
	});

	it('ACKs, then BYEs and throws when the answer carries no MSRP path', async () => {
		const { session, server } = connected();
		const answer =
			'v=0\r\no=- 1 1 IN IP4 relay\r\ns=-\r\nc=IN IP4 relay\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\n';
		const script = (async () => {
			const invite = await readSip(server);
			await server.write(
				response(invite, 200, 'OK', { 'Content-Type': 'application/sdp' }, enc.encode(answer))
			);
			const ack = await readSip(server);
			if (ack.kind !== 'request') throw new Error('expected request');
			expect(ack.method).toBe('ACK');
			const bye = await readSip(server);
			if (bye.kind !== 'request') throw new Error('expected request');
			expect(bye.method).toBe('BYE');
			await server.write(response(bye, 200, 'OK'));
		})();
		await expect(Promise.all([session.invite('bob'), script])).rejects.toBeInstanceOf(
			ProtocolError
		);
		await session.close();
	});
});

describe('sip registration timers', () => {
	// a scheduler that captures the refresh + keep-alive callbacks so the test can fire them
	function capturing(): { timers: Array<{ fn: () => void; ms: number }>; scheduler: SipScheduler } {
		const timers: Array<{ fn: () => void; ms: number }> = [];
		return {
			timers,
			scheduler: {
				set: (fn, ms) => {
					timers.push({ fn, ms });
					return timers.length;
				},
				clear: () => {}
			}
		};
	}

	it('schedules a refresh from the Expires header and keeps the flow alive', async () => {
		const { timers, scheduler } = capturing();
		const { session, server } = connected({ scheduler });
		const regScript = (async () => {
			const req = await readSip(server);
			if (req.kind !== 'request') throw new Error('expected request');
			expect(req.method).toBe('REGISTER');
			// no Contact ;expires -> the Expires header supplies the granted lifetime
			await server.write(response(req, 200, 'OK', { Expires: '1800' }));
		})();
		await Promise.all([session.register(), regScript]);

		// two timers: [0] refresh at 90% of 1800s, [1] keep-alive at 25s
		expect(timers).toHaveLength(2);
		expect(timers[0]!.ms).toBe(Math.floor(1800 * 0.9) * 1000);

		// firing the keep-alive writes the RFC 5626 double-CRLF ping
		timers[1]!.fn();
		expect([...(await server.readN(4))]).toEqual([0x0d, 0x0a, 0x0d, 0x0a]);

		// firing the refresh sends a fresh REGISTER on the wire
		timers[0]!.fn();
		const refresh = await readSip(server);
		if (refresh.kind !== 'request') throw new Error('expected request');
		expect(refresh.method).toBe('REGISTER');
		await session.close();
	});
});

describe('sip unregister / close', () => {
	it('unregister sends REGISTER Expires: 0 carrying the cached digest', async () => {
		const { session, server } = connected();
		// a challenged register so an auth state is cached for the unregister
		const regScript = (async () => {
			const req1 = await readSip(server);
			await server.write(
				response(req1, 401, 'Unauthorized', {
					'WWW-Authenticate': 'Digest realm="edgeport.test", nonce="n1", qop="auth"'
				})
			);
			const req2 = await readSip(server);
			await server.write(response(req2, 200, 'OK', { Contact: '<sip:tester@x>;expires=3600' }));
		})();
		await Promise.all([session.register(), regScript]);

		const unregScript = (async () => {
			const req = await readSip(server);
			if (req.kind !== 'request') throw new Error('expected request');
			expect(req.method).toBe('REGISTER');
			expect(req.headers.get('Expires')).toBe('0');
			expect(req.headers.get('Authorization')).toContain('response="');
		})();
		await Promise.all([session.unregister(), unregScript]);
		await session.close();
	});

	it('close best-effort un-REGISTERs when still registered', async () => {
		const { session, server } = connected();
		const regScript = (async () => {
			const req = await readSip(server);
			await server.write(response(req, 200, 'OK', { Contact: '<sip:tester@x>;expires=3600' }));
		})();
		await Promise.all([session.register(), regScript]);

		const closeScript = (async () => {
			const req = await readSip(server);
			if (req.kind !== 'request') throw new Error('expected request');
			expect(req.method).toBe('REGISTER');
			expect(req.headers.get('Expires')).toBe('0');
		})();
		await Promise.all([session.close(), closeScript]);
	});
});

// reads one complete MSRP frame the client wrote (first line, headers, optional single-line body)
async function readMsrp(
	server: MockServerEnd
): Promise<{ first: string; headers: Record<string, string>; body: string; endLine: string }> {
	const first = await server.readLine();
	const headers: Record<string, string> = {};
	let body = '';
	let endLine = '';
	for (;;) {
		const line = await server.readLine();
		if (line.startsWith(END_DASHES)) {
			endLine = line;
			break;
		}
		if (line === '') {
			// blank line separates headers from the body; the body is one line in these tests
			body = await server.readLine();
			endLine = await server.readLine();
			break;
		}
		const colon = line.indexOf(':');
		if (colon >= 0) headers[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
	}
	return { first, headers, body, endLine };
}

const END_DASHES = '-------';
const REMOTE_PATH = 'msrp://relay:2855/to;tcp';
const LOCAL_PATH = 'msrp://client:2855/from;tcp';

function connectedMsrp(opts: { chunkSize?: number } = {}): {
	session: MsrpSession;
	server: MockServerEnd;
} {
	const { socket, server } = mockConnection();
	const session = _msrpSessionFromSocket(socket, {
		remotePath: REMOTE_PATH,
		localPath: LOCAL_PATH,
		...opts
	});
	return { session, server };
}

// replies 200 OK to a SEND the client wrote, echoing its transaction id
function msrpOk(tid: string): Uint8Array {
	return encodeMsrp({
		kind: 'response',
		transactionId: tid,
		code: 200,
		reason: 'OK',
		headers: { 'To-Path': LOCAL_PATH, 'From-Path': REMOTE_PATH },
		continuation: '$'
	});
}

describe('msrp session send', () => {
	it('sends a single SEND and resolves on the 200', async () => {
		const { session, server } = connectedMsrp();
		const script = (async () => {
			const frame = await readMsrp(server);
			const tid = frame.first.match(/^MSRP (\S+) SEND$/)![1]!;
			expect(frame.headers['To-Path']).toBe(REMOTE_PATH);
			expect(frame.headers['From-Path']).toBe(LOCAL_PATH);
			expect(frame.headers['Byte-Range']).toBe('1-2/2');
			expect(frame.headers['Content-Type']).toBe('text/plain');
			expect(frame.body).toBe('hi');
			expect(frame.endLine).toBe(`${END_DASHES}${tid}$`);
			await server.write(msrpOk(tid));
		})();
		await Promise.all([session.send('hi'), script]);
		await session.close();
	});

	it('chunks a body larger than the chunk size and confirms every chunk', async () => {
		const { session, server } = connectedMsrp({ chunkSize: 4 });
		const payload = 'abcdefghij'; // 10 bytes -> chunks of 4, 4, 2
		const script = (async () => {
			const continuations: string[] = [];
			const ranges: string[] = [];
			for (let i = 0; i < 3; i++) {
				const frame = await readMsrp(server);
				const tid = frame.first.match(/^MSRP (\S+) SEND$/)![1]!;
				continuations.push(frame.endLine.slice(`${END_DASHES}${tid}`.length));
				ranges.push(frame.headers['Byte-Range']!);
				await server.write(msrpOk(tid));
			}
			expect(continuations).toEqual(['+', '+', '$']);
			expect(ranges).toEqual(['1-4/10', '5-8/10', '9-10/10']);
		})();
		await Promise.all([session.send(payload), script]);
		await session.close();
	});

	it('throws ProtocolError when a chunk is rejected', async () => {
		const { session, server } = connectedMsrp();
		const script = (async () => {
			const frame = await readMsrp(server);
			const tid = frame.first.match(/^MSRP (\S+) SEND$/)![1]!;
			await server.write(
				encodeMsrp({
					kind: 'response',
					transactionId: tid,
					code: 413,
					reason: 'Request Entity Too Large',
					headers: { 'To-Path': LOCAL_PATH, 'From-Path': REMOTE_PATH },
					continuation: '$'
				})
			);
		})();
		await expect(Promise.all([session.send('hi'), script])).rejects.toBeInstanceOf(ProtocolError);
		await session.close();
	});

	it('rejects a send on a closed session', async () => {
		const { session } = connectedMsrp();
		await session.close();
		await expect(session.send('hi')).rejects.toBeTruthy();
	});
});

describe('msrp session receive', () => {
	it('delivers an inbound SEND and auto-acknowledges it', async () => {
		const { session, server } = connectedMsrp();
		const inbound = encodeMsrp({
			kind: 'request',
			transactionId: 'srv001',
			method: 'SEND',
			headers: {
				'To-Path': LOCAL_PATH,
				'From-Path': REMOTE_PATH,
				'Message-ID': 'm-99',
				'Content-Type': 'text/plain'
			},
			body: enc.encode('hello from peer'),
			continuation: '$'
		});
		await server.write(inbound);

		const iter = session.messages()[Symbol.asyncIterator]();
		const first = await iter.next();
		expect(first.done).toBe(false);
		const msg = first.value as MsrpMessage;
		expect(msg.text()).toBe('hello from peer');
		expect(msg.contentType).toBe('text/plain');
		expect(msg.messageId).toBe('m-99');

		// the session must have written a 200 OK for the inbound transaction
		const ack = await readMsrp(server);
		expect(ack.first).toBe('MSRP srv001 200 OK');
		expect(ack.headers['To-Path']).toBe(REMOTE_PATH);
		expect(ack.headers['From-Path']).toBe(LOCAL_PATH);
		await session.close();
	});
});

describe('connectMsrp uri parsing', () => {
	it('throws ProtocolError on a malformed MSRP uri (before dialing)', async () => {
		await expect(
			connectMsrp({ remotePath: 'not-a-uri', localPath: LOCAL_PATH })
		).rejects.toBeInstanceOf(ProtocolError);
	});
});
