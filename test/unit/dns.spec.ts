import { describe, expect, it } from 'vitest';
import { ProtocolError } from '../../src/core/errors';
import {
	_connectOverSocket,
	decodeMessage,
	decodeName,
	decodeOpt,
	encodeMessage,
	encodeName,
	encodeOptRecord,
	formatIpv6,
	parseIpv4,
	parseIpv6,
	record,
	RecordClass,
	RecordType,
	ResponseCode,
	reverseName,
	type CaaRecord,
	type DnsMessage,
	type MxRecord,
	type ResourceRecord,
	type SoaRecord,
	type SrvRecord
} from '../../src/dns';
import { fromHex } from '../../src/util';
import { mockConnection, type MockServerEnd } from '../mock-socket';

// reads one length-prefixed message the client wrote to the server end
async function readFramed(server: MockServerEnd): Promise<Uint8Array> {
	const lenBytes = await server.readN(2);
	const len = (lenBytes[0]! << 8) | lenBytes[1]!;
	return server.readN(len);
}

// writes one length-prefixed message from the server end to the client
async function writeFramed(server: MockServerEnd, msg: Uint8Array): Promise<void> {
	const out = new Uint8Array(msg.length + 2);
	out[0] = (msg.length >> 8) & 0xff;
	out[1] = msg.length & 0xff;
	out.set(msg, 2);
	await server.write(out);
}

// a NOERROR response echoing the query's id and question, carrying the given sections
function makeResponse(
	query: DnsMessage,
	answer: ResourceRecord[],
	opts: { authority?: ResourceRecord[]; additional?: ResourceRecord[]; rcode?: number } = {}
): DnsMessage {
	return {
		id: query.id,
		flags: {
			qr: true,
			opcode: 0,
			aa: false,
			tc: false,
			rd: true,
			ra: true,
			z: false,
			ad: false,
			cd: false,
			rcode: opts.rcode ?? ResponseCode.NOERROR
		},
		question: query.question,
		answer,
		authority: opts.authority ?? [],
		additional: opts.additional ?? []
	};
}

// reads one query and replies with the response `make` builds from it
async function serveOnce(
	server: MockServerEnd,
	make: (query: DnsMessage) => DnsMessage
): Promise<DnsMessage> {
	const query = decodeMessage(await readFramed(server));
	await writeFramed(server, encodeMessage(make(query)));
	return query;
}

describe('dns name codec', () => {
	it('encodes a name as length-prefixed labels ending in the root label', () => {
		expect([...encodeName('example.com')]).toEqual([
			7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0
		]);
	});

	it('encodes the root as a single zero byte and tolerates a trailing dot', () => {
		expect([...encodeName('')]).toEqual([0]);
		expect([...encodeName('.')]).toEqual([0]);
		expect(encodeName('example.com.')).toEqual(encodeName('example.com'));
	});

	it('rejects a label over 63 octets', () => {
		expect(() => encodeName('a'.repeat(64) + '.com')).toThrow(ProtocolError);
	});

	it('decodes a name and follows a compression pointer', () => {
		// "example.com" at offset 0, then a pointer (0xC0 0x00) back to it at offset 13
		const buf = new Uint8Array([...encodeName('example.com'), 0xc0, 0x00]);
		expect(decodeName(buf, 0).name).toBe('example.com');
		const followed = decodeName(buf, 13);
		expect(followed.name).toBe('example.com');
		expect(followed.next).toBe(15); // just past the 2-byte pointer
	});

	it('throws on a compression pointer loop', () => {
		// a pointer at offset 0 that points to itself
		expect(() => decodeName(new Uint8Array([0xc0, 0x00]), 0)).toThrow(ProtocolError);
	});
});

describe('dns message compression (real captured layout)', () => {
	it('decodes an example.com A response whose answer name is a pointer to the question', () => {
		// id 0x1234, flags 0x8180 (QR|RD|RA), qd 1 an 1, question example.com A IN,
		// answer name 0xC00C -> offset 12 (the question name), A 93.184.216.34, ttl 300
		const hex =
			'123481800001000100000000' + // header: id 0x1234, flags 0x8180, qd 1, an 1
			'076578616d706c6503636f6d0000010001' + // question: example.com A IN
			'c00c000100010000012c00045db8d822'; // answer: ptr->0x0c, A IN, ttl 300, 93.184.216.34
		const msg = decodeMessage(fromHex(hex));
		expect(msg.answer).toHaveLength(1);
		expect(msg.answer[0]!.name).toBe('example.com');
		expect(msg.answer[0]!.type).toBe(RecordType.A);
		expect(msg.answer[0]!.data).toBe('93.184.216.34');
		expect(msg.answer[0]!.ttl).toBe(300);
	});
});

describe('dns rdata codec roundtrips', () => {
	const roundtrip = (rr: ResourceRecord): ResourceRecord => {
		const msg: DnsMessage = {
			id: 1,
			flags: {
				qr: true,
				opcode: 0,
				aa: false,
				tc: false,
				rd: false,
				ra: false,
				z: false,
				ad: false,
				cd: false,
				rcode: 0
			},
			question: [],
			answer: [rr],
			authority: [],
			additional: []
		};
		return decodeMessage(encodeMessage(msg)).answer[0]!;
	};

	it('A / AAAA', () => {
		expect(roundtrip(record('h.test', RecordType.A, 60, '93.184.216.34')).data).toBe(
			'93.184.216.34'
		);
		expect(roundtrip(record('h.test', RecordType.AAAA, 60, '2001:db8::1')).data).toBe(
			'2001:db8::1'
		);
	});

	it('NS / CNAME / PTR', () => {
		expect(roundtrip(record('z.test', RecordType.NS, 60, 'ns1.z.test')).data).toBe('ns1.z.test');
		expect(roundtrip(record('www.z.test', RecordType.CNAME, 60, 'z.test')).data).toBe('z.test');
		expect(roundtrip(record('4.3.2.1.in-addr.arpa', RecordType.PTR, 60, 'host.z.test')).data).toBe(
			'host.z.test'
		);
	});

	it('MX', () => {
		const mx = roundtrip(
			record('z.test', RecordType.MX, 60, { preference: 10, exchange: 'mail.z.test' })
		).data as MxRecord;
		expect(mx).toEqual({ preference: 10, exchange: 'mail.z.test' });
	});

	it('TXT (multiple character-strings)', () => {
		expect(roundtrip(record('z.test', RecordType.TXT, 60, ['v=spf1 -all', 'k=v'])).data).toEqual([
			'v=spf1 -all',
			'k=v'
		]);
	});

	it('SOA', () => {
		const soa: SoaRecord = {
			mname: 'ns1.z.test',
			rname: 'hostmaster.z.test',
			serial: 2026071700,
			refresh: 7200,
			retry: 3600,
			expire: 1209600,
			minimum: 300
		};
		expect(roundtrip(record('z.test', RecordType.SOA, 60, soa)).data).toEqual(soa);
	});

	it('SRV', () => {
		const srv: SrvRecord = { priority: 10, weight: 20, port: 5060, target: 'sip.z.test' };
		expect(roundtrip(record('_sip._tcp.z.test', RecordType.SRV, 60, srv)).data).toEqual(srv);
	});

	it('CAA', () => {
		const caa: CaaRecord = { flags: 0, tag: 'issue', value: 'letsencrypt.org' };
		expect(roundtrip(record('z.test', RecordType.CAA, 60, caa)).data).toEqual(caa);
	});

	it('keeps the raw rdata available alongside the parsed value', () => {
		const rr = roundtrip(record('h.test', RecordType.A, 60, '1.2.3.4'));
		expect([...rr.rdata]).toEqual([1, 2, 3, 4]);
	});
});

describe('dns ipv6 formatting', () => {
	it('compresses the longest zero run to ::', () => {
		expect(formatIpv6(new Uint8Array(16))).toBe('::');
		expect(formatIpv6(parseIpv6('::1'))).toBe('::1');
		expect(formatIpv6(parseIpv6('2001:db8:0:0:0:0:0:1'))).toBe('2001:db8::1');
		expect(formatIpv6(parseIpv6('fe80::'))).toBe('fe80::');
		// two zero runs: the longest (leading, length 3) is compressed, not the shorter one
		expect(formatIpv6(parseIpv6('1:0:0:0:1:0:0:1'))).toBe('1::1:0:0:1');
		// no run of length >= 2 stays fully expanded
		expect(formatIpv6(parseIpv6('2001:db8:1:2:3:4:5:6'))).toBe('2001:db8:1:2:3:4:5:6');
	});

	it('round-trips through parseIpv6', () => {
		expect(formatIpv6(parseIpv6('2606:4700:4700::1111'))).toBe('2606:4700:4700::1111');
	});

	it('rejects a bad ipv4', () => {
		expect(() => parseIpv4('1.2.3')).toThrow(ProtocolError);
		expect(() => parseIpv4('1.2.3.999')).toThrow(ProtocolError);
	});
});

describe('dns reverse name construction', () => {
	it('builds an in-addr.arpa name for IPv4', () => {
		expect(reverseName('8.8.8.8')).toBe('8.8.8.8.in-addr.arpa');
		expect(reverseName('1.2.3.4')).toBe('4.3.2.1.in-addr.arpa');
	});

	it('builds a nibble-reversed ip6.arpa name for IPv6', () => {
		const expected = ['1', ...new Array<string>(31).fill('0')].join('.') + '.ip6.arpa';
		expect(reverseName('::1')).toBe(expected);
	});
});

describe('dns edns0 OPT record', () => {
	it('sets the DO bit and default UDP payload size, and decodes back', () => {
		const opt = encodeOptRecord({ dnssecOk: true });
		expect(opt.type).toBe(RecordType.OPT);
		const decoded = decodeOpt(opt);
		expect(decoded.dnssecOk).toBe(true);
		expect(decoded.udpPayloadSize).toBe(4096);
	});

	it('round-trips OPT options and the payload size through a full message', () => {
		const opt = encodeOptRecord({
			udpPayloadSize: 1232,
			options: [{ code: 10, value: fromHex('abcd') }]
		});
		const msg: DnsMessage = {
			id: 1,
			flags: {
				qr: false,
				opcode: 0,
				aa: false,
				tc: false,
				rd: true,
				ra: false,
				z: false,
				ad: false,
				cd: false,
				rcode: 0
			},
			question: [],
			answer: [],
			authority: [],
			additional: [opt]
		};
		const back = decodeMessage(encodeMessage(msg)).additional[0]!;
		const decoded = decodeOpt(back);
		expect(decoded.udpPayloadSize).toBe(1232);
		expect(decoded.options[0]!.code).toBe(10);
		expect([...decoded.options[0]!.value]).toEqual([0xab, 0xcd]);
	});
});

describe('dns session query', () => {
	it('resolves A records and echoes the question', async () => {
		const { socket, server } = mockConnection();
		const session = _connectOverSocket(socket, {});
		const [ips, query] = await Promise.all([
			session.query('example.com', 'A'),
			serveOnce(server, (q) =>
				makeResponse(q, [
					record('example.com', RecordType.A, 300, '93.184.216.34'),
					record('example.com', RecordType.A, 300, '93.184.216.35')
				])
			)
		]);
		expect(query.question[0]!.name).toBe('example.com');
		expect(query.question[0]!.type).toBe(RecordType.A);
		expect(query.question[0]!.class).toBe(RecordClass.IN);
		expect(query.flags.rd).toBe(true);
		expect(ips).toEqual(['93.184.216.34', '93.184.216.35']);
		await session.close();
	});

	it('resolves AAAA to compressed strings', async () => {
		const { socket, server } = mockConnection();
		const session = _connectOverSocket(socket, {});
		const [ips] = await Promise.all([
			session.query('example.com', 'AAAA'),
			serveOnce(server, (q) =>
				makeResponse(q, [record('example.com', RecordType.AAAA, 300, '2606:4700::1')])
			)
		]);
		expect(ips).toEqual(['2606:4700::1']);
		await session.close();
	});

	it('resolves MX / TXT / SOA / SRV / CAA / NS / CNAME / PTR', async () => {
		const { socket, server } = mockConnection();
		const session = _connectOverSocket(socket, {});

		const runQuery = session.query.bind(session) as (n: string, t: string) => Promise<unknown>;
		const check = async (
			type: string,
			answer: ResourceRecord[],
			expected: unknown
		): Promise<void> => {
			const [got] = await Promise.all([
				runQuery('z.test', type),
				serveOnce(server, (q) => makeResponse(q, answer))
			]);
			expect(got).toEqual(expected);
		};

		await check(
			'MX',
			[record('z.test', RecordType.MX, 60, { preference: 5, exchange: 'mail.z.test' })],
			[{ preference: 5, exchange: 'mail.z.test' }]
		);
		await check(
			'TXT',
			[record('z.test', RecordType.TXT, 60, ['hello', 'world'])],
			[['hello', 'world']]
		);
		await check(
			'SOA',
			[
				record('z.test', RecordType.SOA, 60, {
					mname: 'ns1.z.test',
					rname: 'hostmaster.z.test',
					serial: 1,
					refresh: 2,
					retry: 3,
					expire: 4,
					minimum: 5
				})
			],
			{
				mname: 'ns1.z.test',
				rname: 'hostmaster.z.test',
				serial: 1,
				refresh: 2,
				retry: 3,
				expire: 4,
				minimum: 5
			}
		);
		await check(
			'SRV',
			[
				record('_sip._tcp.z.test', RecordType.SRV, 60, {
					priority: 10,
					weight: 20,
					port: 5060,
					target: 'sip.z.test'
				})
			],
			[{ priority: 10, weight: 20, port: 5060, target: 'sip.z.test' }]
		);
		await check(
			'CAA',
			[record('z.test', RecordType.CAA, 60, { flags: 0, tag: 'issue', value: 'letsencrypt.org' })],
			[{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }]
		);
		await check('NS', [record('z.test', RecordType.NS, 60, 'ns1.z.test')], ['ns1.z.test']);
		await check('CNAME', [record('www.z.test', RecordType.CNAME, 60, 'z.test')], ['z.test']);
		await check(
			'PTR',
			[record('4.3.2.1.in-addr.arpa', RecordType.PTR, 60, 'host.z.test')],
			['host.z.test']
		);

		await session.close();
	});

	it('filters answers to the queried type (drops a leading CNAME)', async () => {
		const { socket, server } = mockConnection();
		const session = _connectOverSocket(socket, {});
		const [ips] = await Promise.all([
			session.query('www.z.test', 'A'),
			serveOnce(server, (q) =>
				makeResponse(q, [
					record('www.z.test', RecordType.CNAME, 60, 'z.test'),
					record('z.test', RecordType.A, 60, '10.0.0.1')
				])
			)
		]);
		expect(ips).toEqual(['10.0.0.1']);
		await session.close();
	});

	it('correlates out-of-order responses by id (RFC 7766 pipelining)', async () => {
		const { socket, server } = mockConnection();
		const session = _connectOverSocket(socket, {});
		const p1 = session.query('a.test', 'A');
		const p2 = session.query('b.test', 'A');
		const q1 = decodeMessage(await readFramed(server));
		const q2 = decodeMessage(await readFramed(server));
		expect(q1.id).not.toBe(q2.id);
		// answer the second query first, then the first
		await writeFramed(
			server,
			encodeMessage(makeResponse(q2, [record('b.test', RecordType.A, 60, '2.2.2.2')]))
		);
		await writeFramed(
			server,
			encodeMessage(makeResponse(q1, [record('a.test', RecordType.A, 60, '1.1.1.1')]))
		);
		const [r1, r2] = await Promise.all([p1, p2]);
		expect(r1).toEqual(['1.1.1.1']);
		expect(r2).toEqual(['2.2.2.2']);
		await session.close();
	});

	it('ignores a response for an unknown id and still answers the real query', async () => {
		const { socket, server } = mockConnection();
		const session = _connectOverSocket(socket, {});
		const p = session.query('a.test', 'A');
		const q = decodeMessage(await readFramed(server));
		// a response whose id does not match any pending query is dropped by the pump
		const bogus = makeResponse({ ...q, id: (q.id ^ 0x1) & 0xffff }, [
			record('a.test', RecordType.A, 60, '9.9.9.9')
		]);
		await writeFramed(server, encodeMessage(bogus));
		await writeFramed(
			server,
			encodeMessage(makeResponse(q, [record('a.test', RecordType.A, 60, '1.1.1.1')]))
		);
		expect(await p).toEqual(['1.1.1.1']);
		await session.close();
	});

	it('returns an empty array on NXDOMAIN (does not throw)', async () => {
		const { socket, server } = mockConnection();
		const session = _connectOverSocket(socket, {});
		const [ips] = await Promise.all([
			session.query('nope.test', 'A'),
			serveOnce(server, (q) => makeResponse(q, [], { rcode: ResponseCode.NXDOMAIN }))
		]);
		expect(ips).toEqual([]);
		await session.close();
	});

	it('throws ProtocolError on SERVFAIL', async () => {
		const { socket, server } = mockConnection();
		const session = _connectOverSocket(socket, {});
		const [result] = await Promise.allSettled([
			session.query('broken.test', 'A'),
			serveOnce(server, (q) => makeResponse(q, [], { rcode: ResponseCode.SERVFAIL }))
		]);
		expect(result.status).toBe('rejected');
		if (result.status === 'rejected') expect(result.reason).toBeInstanceOf(ProtocolError);
		await session.close();
	});

	it('rejects the specific query with ProtocolError on a malformed response', async () => {
		const { socket, server } = mockConnection();
		const session = _connectOverSocket(socket, {});
		const p = session.query('a.test', 'A');
		const q = decodeMessage(await readFramed(server));
		// claim one answer record that is not actually present -> decode overruns the buffer
		const bytes = encodeMessage(makeResponse(q, []));
		bytes[6] = 0x00;
		bytes[7] = 0x01;
		await writeFramed(server, bytes);
		await expect(p).rejects.toBeInstanceOf(ProtocolError);
		await session.close();
	});

	it('sets the EDNS0 DO bit when dnssec is requested', async () => {
		const { socket, server } = mockConnection();
		const session = _connectOverSocket(socket, {});
		const [ips, query] = await Promise.all([
			session.query('example.com', { type: 'A', dnssec: true }),
			serveOnce(server, (q) =>
				makeResponse(q, [record('example.com', RecordType.A, 60, '1.2.3.4')])
			)
		]);
		const opt = query.additional.find((rr) => rr.type === RecordType.OPT);
		expect(opt).toBeDefined();
		expect(decodeOpt(opt!).dnssecOk).toBe(true);
		expect(ips).toEqual(['1.2.3.4']);
		await session.close();
	});
});

describe('dns raw (level 3) query', () => {
	it('returns the full message with authority and additional sections', async () => {
		const { socket, server } = mockConnection();
		const session = _connectOverSocket(socket, {});
		const soa = record('z.test', RecordType.SOA, 300, {
			mname: 'ns1.z.test',
			rname: 'hostmaster.z.test',
			serial: 1,
			refresh: 2,
			retry: 3,
			expire: 4,
			minimum: 5
		});
		const glue = record('ns1.z.test', RecordType.A, 300, '10.0.0.53');
		const [res] = await Promise.all([
			session.query({ questions: [{ name: 'host.z.test', type: 'A' }], recursionDesired: true }),
			serveOnce(server, (q) =>
				makeResponse(q, [record('host.z.test', RecordType.A, 300, '10.0.0.9')], {
					authority: [soa],
					additional: [glue]
				})
			)
		]);
		expect(res.rcode).toBe(ResponseCode.NOERROR);
		expect(res.answers[0]!.data).toBe('10.0.0.9');
		expect((res.authority[0]!.data as SoaRecord).mname).toBe('ns1.z.test');
		expect(res.additional[0]!.data).toBe('10.0.0.53');
		await session.close();
	});

	it('exposes an error rcode on the raw path without throwing', async () => {
		const { socket, server } = mockConnection();
		const session = _connectOverSocket(socket, {});
		const [res] = await Promise.all([
			session.query({ questions: [{ name: 'nope.test', type: 'A' }] }),
			serveOnce(server, (q) => makeResponse(q, [], { rcode: ResponseCode.NXDOMAIN }))
		]);
		expect(res.rcode).toBe(ResponseCode.NXDOMAIN);
		expect(res.answers).toEqual([]);
		await session.close();
	});
});
