import { describe, expect, it } from 'vitest';
import { AuthError, ProtocolError, TimeoutError } from '../../src/core/errors';
import { StreamFramedReader } from '../../src/core/framing';
import {
	_connectOverSocket,
	el,
	findChild,
	parseFragment,
	saslPlain,
	scramClient,
	serialize,
	text,
	XmlStreamReader,
	type XmlElement,
	type XmppSession
} from '../../src/xmpp/index';
import { mockConnection, type MockServerEnd } from '../mock-socket';

const encoder = new TextEncoder();
const enc = (s: string) => encoder.encode(s);
const dec = new TextDecoder();

// ---- xml stream reader test harness --------------------------------------------------------

// builds an XmlStreamReader over a stream fed the given chunks (to exercise chunk boundaries)
function xmlReaderOf(...chunks: string[]): XmlStreamReader {
	const stream = new ReadableStream<Uint8Array>({
		start(c) {
			for (const ch of chunks) c.enqueue(enc(ch));
			c.close();
		}
	});
	return new XmlStreamReader(new StreamFramedReader(stream));
}

// ---- server-side handshake scripting -------------------------------------------------------

const SASL_NS = 'urn:ietf:params:xml:ns:xmpp-sasl';
const BIND_NS = 'urn:ietf:params:xml:ns:xmpp-bind';
const SESSION_NS = 'urn:ietf:params:xml:ns:xmpp-session';

// reads raw bytes until the client's <stream:stream ...> open tag is complete
async function readStreamOpen(server: MockServerEnd): Promise<void> {
	let buf = '';
	for (;;) {
		const b = await server.readN(1);
		buf += String.fromCharCode(b[0]!);
		if (buf.endsWith('>') && buf.includes('<stream:stream')) return;
	}
}

// true once `buf` holds one complete balanced top-level element (test client emits no '>' in attrs)
function stanzaComplete(buf: string): boolean {
	let depth = 0;
	const re = /<[^>]*>/g;
	let m: RegExpExecArray | null;
	while ((m = re.exec(buf)) !== null) {
		const t = m[0];
		if (t.startsWith('<?') || t.startsWith('<!')) continue;
		if (t.endsWith('/>')) {
			if (depth === 0) return true;
		} else if (t.startsWith('</')) {
			depth--;
			if (depth === 0) return true;
		} else {
			depth++;
		}
	}
	return false;
}

// reads one complete stanza the client wrote and parses it
async function readStanza(server: MockServerEnd): Promise<XmlElement> {
	let buf = '';
	for (;;) {
		const b = await server.readN(1);
		const ch = String.fromCharCode(b[0]!);
		buf += ch;
		if (ch === '>' && stanzaComplete(buf)) return parseFragment(buf);
	}
}

function streamHeader(): string {
	return (
		`<?xml version='1.0'?><stream:stream xmlns='jabber:client' ` +
		`xmlns:stream='http://etherx.jabber.org/streams' id='sh1' from='localhost' version='1.0'>`
	);
}

function saslFeatures(mechanisms: string[]): string {
	const mechs = mechanisms.map((m) => `<mechanism>${m}</mechanism>`).join('');
	return `<stream:features><mechanisms xmlns='${SASL_NS}'>${mechs}</mechanisms></stream:features>`;
}

function bindFeatures(offerSession: boolean): string {
	const session = offerSession ? `<session xmlns='${SESSION_NS}'/>` : '';
	return `<stream:features><bind xmlns='${BIND_NS}'/>${session}</stream:features>`;
}

interface HandshakeOpts {
	mechanisms?: string[];
	offerSession?: boolean;
	jid?: string;
}

// drives the server side of a full successful PLAIN handshake; returns the client's <auth> stanza
async function serverHandshake(
	server: MockServerEnd,
	opts: HandshakeOpts = {}
): Promise<XmlElement> {
	const mechanisms = opts.mechanisms ?? ['PLAIN'];
	const jid = opts.jid ?? 'juliet@localhost/res';

	await readStreamOpen(server);
	await server.write(enc(streamHeader() + saslFeatures(mechanisms)));

	const auth = await readStanza(server);
	await server.write(enc(`<success xmlns='${SASL_NS}'/>`));

	await readStreamOpen(server);
	await server.write(enc(streamHeader() + bindFeatures(!!opts.offerSession)));

	const bindIq = await readStanza(server);
	await server.write(
		enc(
			`<iq type='result' id='${bindIq.attrs['id']}'><bind xmlns='${BIND_NS}'><jid>${jid}</jid></bind></iq>`
		)
	);

	if (opts.offerSession) {
		const sess = await readStanza(server);
		await server.write(enc(`<iq type='result' id='${sess.attrs['id']}'/>`));
	}
	return auth;
}

// opens a session through the full PLAIN handshake and returns it + the server end
async function connectMock(
	client: Partial<Parameters<typeof _connectOverSocket>[1]> = {},
	handshake: HandshakeOpts = {}
): Promise<{ session: XmppSession; server: MockServerEnd; auth: XmlElement }> {
	const { socket, server } = mockConnection();
	let auth!: XmlElement;
	const [session] = await Promise.all([
		_connectOverSocket(socket, {
			jid: 'juliet@localhost',
			password: 'r0m30',
			tls: 'off',
			resource: 'res',
			...client
		}),
		(async () => {
			auth = await serverHandshake(server, handshake);
		})()
	]);
	return { session, server, auth };
}

// ---- xml.ts ---------------------------------------------------------------------------------

describe('xml element model + serializer', () => {
	it('el() drops nullish children and flattens arrays', () => {
		const e = el('a', { x: '1' }, null, el('b'), [el('c'), undefined], 'text');
		expect(e.children.map((c) => (typeof c === 'string' ? c : c.name))).toEqual(['b', 'c', 'text']);
	});

	it('serializes empty elements self-closing and escapes text/attrs', () => {
		expect(serialize(el('presence'))).toBe('<presence/>');
		expect(serialize(el('body', {}, 'a < b & "c">'))).toBe('<body>a &lt; b &amp; "c"&gt;</body>');
		expect(serialize(el('x', { q: 'a"<>&' }))).toBe('<x q="a&quot;&lt;&gt;&amp;"/>');
	});

	it('parseFragment round-trips through serialize', () => {
		const src =
			'<iq type="set" id="1"><query xmlns="jabber:iq:roster"><item jid="a@b"/></query></iq>';
		expect(serialize(parseFragment(src))).toBe(src);
	});

	it('unescapes named and numeric entities on parse', () => {
		const e = parseFragment('<body>a &lt;b&gt; &amp; &#65;&#x42;</body>');
		expect(text(e)).toBe('a <b> & AB');
	});

	it('findChild matches by local name and optional namespace', () => {
		const e = parseFragment("<x><q xmlns='ns1'/><q xmlns='ns2'/></x>");
		expect(findChild(e, 'q', 'ns2')!.attrs['xmlns']).toBe('ns2');
		expect(findChild(e, 'q')!.attrs['xmlns']).toBe('ns1');
		expect(findChild(e, 'nope')).toBeUndefined();
	});
});

describe('xml streaming reader', () => {
	it('emits stream open then each top-level stanza in a single chunk', async () => {
		const r = xmlReaderOf(
			"<?xml version='1.0'?><stream:stream xmlns='jabber:client' version='1.0'>" +
				'<message from="a" to="b"><body>hi</body></message><presence/>'
		);
		const open = await r.readEvent();
		expect(open!.type).toBe('open');
		const m = await r.readEvent();
		expect(m!.type).toBe('element');
		expect((m as { element: XmlElement }).element.name).toBe('message');
		expect(text(findChild((m as { element: XmlElement }).element, 'body')!)).toBe('hi');
		const p = await r.readEvent();
		expect((p as { element: XmlElement }).element.name).toBe('presence');
	});

	it('reassembles a stanza split across chunk boundaries', async () => {
		const r = xmlReaderOf(
			'<stream:stream xmlns="jabber:client">',
			'<message><bo',
			'dy>sp',
			'lit</body></mess',
			'age>'
		);
		expect((await r.readEvent())!.type).toBe('open');
		const m = await r.readEvent();
		expect(text(findChild((m as { element: XmlElement }).element, 'body')!)).toBe('split');
	});

	it('handles self-closing top-level stanzas', async () => {
		const r = xmlReaderOf('<stream:stream>', "<presence type='unavailable'/>");
		await r.readEvent();
		const p = await r.readEvent();
		expect((p as { element: XmlElement }).element.attrs['type']).toBe('unavailable');
	});

	it('treats CDATA contents as literal text', async () => {
		const r = xmlReaderOf(
			'<stream:stream>',
			'<message><body><![CDATA[a<b>c & d]]></body></message>'
		);
		await r.readEvent();
		const m = await r.readEvent();
		expect(text(findChild((m as { element: XmlElement }).element, 'body')!)).toBe('a<b>c & d');
	});

	it('skips comments and the xml declaration', async () => {
		const r = xmlReaderOf('<!-- hi --><stream:stream>', '<!-- x --><presence/>');
		expect((await r.readEvent())!.type).toBe('open');
		expect(((await r.readEvent()) as { element: XmlElement }).element.name).toBe('presence');
	});

	it('reports the stream close and then end of stream', async () => {
		const r = xmlReaderOf('<stream:stream>', '<presence/>', '</stream:stream>');
		await r.readEvent(); // open
		await r.readEvent(); // presence
		expect((await r.readEvent())!.type).toBe('close');
		expect(await r.readEvent()).toBeNull();
	});
});

// ---- sasl.ts --------------------------------------------------------------------------------

describe('sasl PLAIN', () => {
	it('encodes authzid \\0 authcid \\0 password', () => {
		const payload = saslPlain('juliet', 'r0m30');
		const decoded = dec.decode(Uint8Array.from(atob(payload), (c) => c.charCodeAt(0)));
		expect(decoded).toBe('\0juliet\0r0m30');
	});
});

describe('sasl SCRAM state machine', () => {
	it('builds a client-first with gs2 header and nonce', () => {
		const c = scramClient('SCRAM-SHA-256', 'user', 'pw', { nonce: 'abc' });
		expect(c.clientFirst).toBe('n,,n=user,r=abc');
		expect(c.mechanism).toBe('SCRAM-SHA-256');
	});

	it('produces a client-final that carries the proof, then round-trips verification', async () => {
		// act as our own SCRAM-SHA-256 server to close the loop end-to-end
		const c = scramClient('SCRAM-SHA-256', 'user', 'pencil', { nonce: 'clientnonce' });
		const cnonce = c.clientNonce;
		const combined = cnonce + 'servernonce';
		const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
		const iterations = 2048;
		const serverFirst = `r=${combined},s=${btoa('\x01\x02\x03\x04\x05\x06\x07\x08')},i=${iterations}`;
		const clientFinal = await c.handleServerFirst(serverFirst);
		expect(clientFinal.startsWith(`c=biws,r=${combined},p=`)).toBe(true);

		// recompute the server signature the way a server would and feed it back
		const saltedPassword = await deriveSalted('pencil', salt, iterations);
		const serverKey = await hmacKey(saltedPassword, 'Server Key');
		const clientFirstBare = `n=user,r=${cnonce}`;
		const clientFinalNoProof = `c=biws,r=${combined}`;
		const authMessage = `${clientFirstBare},${serverFirst},${clientFinalNoProof}`;
		const serverSig = await hmac(serverKey, authMessage);
		await expect(
			c.verifyServerFinal(`v=${btoa(String.fromCharCode(...serverSig))}`)
		).resolves.toBeUndefined();
	});

	it('rejects when the server nonce does not extend the client nonce', async () => {
		const c = scramClient('SCRAM-SHA-1', 'user', 'pw', { nonce: 'abc' });
		await expect(c.handleServerFirst('r=xyz,s=AAAA,i=1')).rejects.toBeInstanceOf(ProtocolError);
	});
});

// helpers reproducing the SCRAM server math for the round-trip test
async function deriveSalted(
	password: string,
	salt: Uint8Array,
	iterations: number
): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey('raw', enc(password), { name: 'PBKDF2' }, false, [
		'deriveBits'
	]);
	const bits = await crypto.subtle.deriveBits(
		{ name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' },
		key,
		256
	);
	return new Uint8Array(bits);
}
async function hmacKey(key: Uint8Array, label: string): Promise<Uint8Array> {
	return hmac(key, label);
}
async function hmac(key: Uint8Array, data: string): Promise<Uint8Array> {
	const k = await crypto.subtle.importKey(
		'raw',
		key as BufferSource,
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign']
	);
	return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc(data)));
}

// ---- index.ts handshake + concept API ------------------------------------------------------

describe('xmpp handshake', () => {
	it('completes SASL PLAIN + resource binding and reports the bound jid', async () => {
		const { session, auth } = await connectMock();
		expect(auth.name).toBe('auth');
		expect(auth.attrs['mechanism']).toBe('PLAIN');
		expect(dec.decode(Uint8Array.from(atob(text(auth)), (c) => c.charCodeAt(0)))).toBe(
			'\0juliet\0r0m30'
		);
		expect(session.jid).toBe('juliet@localhost/res');
		await session.close();
	});

	it('establishes a legacy session when offered', async () => {
		const { session } = await connectMock({}, { offerSession: true });
		expect(session.jid).toBe('juliet@localhost/res');
		await session.close();
	});

	it('selects the strongest offered mechanism', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			await readStreamOpen(server);
			await server.write(
				enc(streamHeader() + saslFeatures(['PLAIN', 'SCRAM-SHA-1', 'SCRAM-SHA-256']))
			);
			const auth = await readStanza(server);
			expect(auth.attrs['mechanism']).toBe('SCRAM-SHA-256');
			// abort with a failure so connect settles without a full SCRAM exchange
			await server.write(enc(`<failure xmlns='${SASL_NS}'><temporary-auth-failure/></failure>`));
		})();
		await expect(
			Promise.all([
				_connectOverSocket(socket, { jid: 'juliet@localhost', password: 'pw', tls: 'off' }),
				script
			])
		).rejects.toBeInstanceOf(AuthError);
	});

	it('maps a SASL <failure> to AuthError', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			await readStreamOpen(server);
			await server.write(enc(streamHeader() + saslFeatures(['PLAIN'])));
			await readStanza(server);
			await server.write(enc(`<failure xmlns='${SASL_NS}'><not-authorized/></failure>`));
		})();
		await expect(
			Promise.all([
				_connectOverSocket(socket, { jid: 'juliet@localhost', password: 'bad', tls: 'off' }),
				script
			])
		).rejects.toBeInstanceOf(AuthError);
	});

	it('upgrades via STARTTLS then continues the handshake', async () => {
		const { socket, server, startTlsCount } = mockConnection();
		const TLS_NS = 'urn:ietf:params:xml:ns:xmpp-tls';
		const script = (async () => {
			await readStreamOpen(server);
			await server.write(
				enc(streamHeader() + `<stream:features><starttls xmlns='${TLS_NS}'/></stream:features>`)
			);
			const st = await readStanza(server);
			expect(st.name).toBe('starttls');
			await server.write(enc(`<proceed xmlns='${TLS_NS}'/>`));
			// after the (mock) upgrade the client re-opens; run the normal handshake
			await serverHandshake(server);
		})();
		const [session] = await Promise.all([
			_connectOverSocket(socket, {
				jid: 'juliet@localhost',
				password: 'r0m30',
				tls: 'starttls',
				resource: 'res'
			}),
			script
		]);
		expect(startTlsCount()).toBe(1);
		expect(session.jid).toBe('juliet@localhost/res');
		await session.close();
	});
});

describe('xmpp send / presence / receive', () => {
	it('serializes send() with subject, body, thread and returns the id', async () => {
		const { session, server } = await connectMock();
		const [id, stanza] = await Promise.all([
			session.send({
				to: 'romeo@localhost',
				body: 'hi <there>',
				subject: 's',
				thread: 't',
				type: 'chat'
			}),
			readStanza(server)
		]);
		expect(stanza.name).toBe('message');
		expect(stanza.attrs['to']).toBe('romeo@localhost');
		expect(stanza.attrs['type']).toBe('chat');
		expect(stanza.attrs['id']).toBe(id);
		expect(text(findChild(stanza, 'body')!)).toBe('hi <there>');
		expect(text(findChild(stanza, 'subject')!)).toBe('s');
		expect(text(findChild(stanza, 'thread')!)).toBe('t');
		await session.close();
	});

	it('maps friendly presence states onto show/type', async () => {
		const { session, server } = await connectMock();
		const [, away] = await Promise.all([
			session.setPresence('away', { status: 'brb' }),
			readStanza(server)
		]);
		expect(text(findChild(away, 'show')!)).toBe('away');
		expect(text(findChild(away, 'status')!)).toBe('brb');
		const [, busy] = await Promise.all([session.setPresence('busy'), readStanza(server)]);
		expect(text(findChild(busy, 'show')!)).toBe('dnd');
		const [, off] = await Promise.all([session.setPresence('offline'), readStanza(server)]);
		expect(off.attrs['type']).toBe('unavailable');
		await session.close();
	});

	it('parses inbound messages through messages()', async () => {
		const { session, server } = await connectMock();
		const iter = session.messages()[Symbol.asyncIterator]();
		await server.write(
			enc(
				"<message from='romeo@localhost/r' to='juliet@localhost/res' type='chat' id='m1'><body>o romeo</body></message>"
			)
		);
		const { value } = await iter.next();
		expect(value!.from).toBe('romeo@localhost/r');
		expect(value!.body).toBe('o romeo');
		expect(value!.type).toBe('chat');
		expect(value!.id).toBe('m1');
		await session.close();
	});

	it('parses inbound presence through presence()', async () => {
		const { session, server } = await connectMock();
		const iter = session.presence()[Symbol.asyncIterator]();
		await server.write(
			enc(
				"<presence from='romeo@localhost/r'><show>xa</show><status>away</status><priority>3</priority></presence>"
			)
		);
		const { value } = await iter.next();
		expect(value!.from).toBe('romeo@localhost/r');
		expect(value!.show).toBe('xa');
		expect(value!.status).toBe('away');
		expect(value!.priority).toBe(3);
		await session.close();
	});
});

describe('xmpp iq: roster / publish / correlation', () => {
	it('roster() sends iq-get and parses items', async () => {
		const { session, server } = await connectMock();
		const answer = (async () => {
			const iq = await readStanza(server);
			expect(iq.attrs['type']).toBe('get');
			expect(findChild(iq, 'query', 'jabber:iq:roster')).toBeDefined();
			await server.write(
				enc(
					`<iq type='result' id='${iq.attrs['id']}'><query xmlns='jabber:iq:roster'>` +
						`<item jid='romeo@localhost' name='Romeo' subscription='both'><group>Montague</group></item>` +
						`<item jid='tybalt@localhost' subscription='to'/>` +
						`</query></iq>`
				)
			);
		})();
		const [items] = await Promise.all([session.roster(), answer]);
		expect(items).toEqual([
			{ jid: 'romeo@localhost', name: 'Romeo', subscription: 'both', groups: ['Montague'] },
			{ jid: 'tybalt@localhost', name: undefined, subscription: 'to', groups: [] }
		]);
		await session.close();
	});

	it('addRosterItem sends an iq-set with the item + groups', async () => {
		const { session, server } = await connectMock();
		const answer = (async () => {
			const iq = await readStanza(server);
			const item = findChild(findChild(iq, 'query', 'jabber:iq:roster')!, 'item')!;
			expect(item.attrs['jid']).toBe('romeo@localhost');
			expect(item.attrs['name']).toBe('Romeo');
			expect(text(findChild(item, 'group')!)).toBe('Friends');
			await server.write(enc(`<iq type='result' id='${iq.attrs['id']}'/>`));
		})();
		await Promise.all([
			session.addRosterItem('romeo@localhost', { name: 'Romeo', groups: ['Friends'] }),
			answer
		]);
		await session.close();
	});

	it('publish() builds a PEP pubsub iq and returns the item id', async () => {
		const { session, server } = await connectMock();
		const answer = (async () => {
			const iq = await readStanza(server);
			const pubsub = findChild(iq, 'pubsub', 'http://jabber.org/protocol/pubsub')!;
			const publish = findChild(pubsub, 'publish')!;
			expect(publish.attrs['node']).toBe('urn:xmpp:test');
			const item = findChild(publish, 'item')!;
			expect(item.attrs['id']).toBe('it1');
			expect(findChild(item, 'entry')).toBeDefined();
			await server.write(enc(`<iq type='result' id='${iq.attrs['id']}'/>`));
		})();
		const [rid] = await Promise.all([
			session.publish('urn:xmpp:test', el('entry', {}, 'hello'), { itemId: 'it1' }),
			answer
		]);
		expect(rid).toBe('it1');
		await session.close();
	});

	it('publish() wraps a plain-text payload in a carrier element', async () => {
		const { session, server } = await connectMock();
		const answer = (async () => {
			const iq = await readStanza(server);
			const item = findChild(findChild(findChild(iq, 'pubsub')!, 'publish')!, 'item')!;
			const payload = findChild(item, 'payload')!;
			expect(payload.attrs['xmlns']).toBe('urn:xmpp:edgeport:payload:0');
			expect(text(payload)).toBe('just text');
			await server.write(enc(`<iq type='result' id='${iq.attrs['id']}'/>`));
		})();
		await Promise.all([session.publish('n', 'just text'), answer]);
		await session.close();
	});

	it('routes pubsub event messages to pubsub() not messages()', async () => {
		const { session, server } = await connectMock();
		const iter = session.pubsub()[Symbol.asyncIterator]();
		await server.write(
			enc(
				"<message from='pubsub.localhost'><event xmlns='http://jabber.org/protocol/pubsub#event'>" +
					"<items node='urn:xmpp:test'><item id='i9'><entry>payload</entry></item></items>" +
					'</event></message>'
			)
		);
		const { value } = await iter.next();
		expect(value!.node).toBe('urn:xmpp:test');
		expect(value!.itemId).toBe('i9');
		expect(text(value!.payload!)).toBe('payload');
		await session.close();
	});

	it('iq() correlates the response by id', async () => {
		const { session, server } = await connectMock();
		const answer = (async () => {
			const iq = await readStanza(server);
			await server.write(
				enc(
					`<iq type='result' id='${iq.attrs['id']}'><query xmlns='jabber:iq:version'><name>x</name></query></iq>`
				)
			);
		})();
		const [res] = await Promise.all([
			session.iq('get', el('query', { xmlns: 'jabber:iq:version' })),
			answer
		]);
		expect(text(findChild(findChild(res, 'query')!, 'name')!)).toBe('x');
		await session.close();
	});

	it('iq() rejects with TimeoutError when no response arrives', async () => {
		const { session } = await connectMock();
		await expect(
			session.iq('get', el('query', { xmlns: 'jabber:iq:version' }), { timeoutMs: 40 })
		).rejects.toBeInstanceOf(TimeoutError);
		await session.close();
	});

	it('iq() rejects error responses with ProtocolError', async () => {
		const { session, server } = await connectMock();
		const answer = (async () => {
			const iq = await readStanza(server);
			await server.write(
				enc(
					`<iq type='error' id='${iq.attrs['id']}'><error type='cancel'><item-not-found/></error></iq>`
				)
			);
		})();
		await expect(
			Promise.all([session.iq('get', el('query', { xmlns: 'jabber:iq:version' })), answer])
		).rejects.toBeInstanceOf(ProtocolError);
		await session.close();
	});
});

describe('xmpp escape hatches', () => {
	it('sendXML writes the raw string verbatim', async () => {
		const { session, server } = await connectMock();
		const [, stanza] = await Promise.all([
			session.sendXML('<presence type="unavailable"/>'),
			readStanza(server)
		]);
		expect(stanza.name).toBe('presence');
		expect(stanza.attrs['type']).toBe('unavailable');
		await session.close();
	});

	it('sendStanza serializes an element', async () => {
		const { session, server } = await connectMock();
		const [, stanza] = await Promise.all([
			session.sendStanza(
				el('iq', { type: 'get', id: 'z1' }, el('ping', { xmlns: 'urn:xmpp:ping' }))
			),
			readStanza(server)
		]);
		expect(stanza.attrs['id']).toBe('z1');
		expect(findChild(stanza, 'ping', 'urn:xmpp:ping')).toBeDefined();
		await session.close();
	});
});
