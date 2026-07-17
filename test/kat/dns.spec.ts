import { describe, expect, it } from 'vitest';
import {
	decodeMessage,
	encodeMessage,
	encodeName,
	encodeOptRecord,
	formatIpv6,
	parseIpv6,
	RecordType,
	ResponseCode,
	type DnsFlags,
	type DnsMessage
} from '../../src/dns';
import { fromHex, toHex } from '../../src/util';

// a standard-query flags word: RD set, everything else clear
const QUERY_FLAGS: DnsFlags = {
	qr: false,
	opcode: 0,
	aa: false,
	tc: false,
	rd: true,
	ra: false,
	z: false,
	ad: false,
	cd: false,
	rcode: ResponseCode.NOERROR
};

describe('dns query KAT (RFC 1035 wire format)', () => {
	it('encodes a standard A query for example.com byte-for-byte', () => {
		const msg: DnsMessage = {
			id: 0x1234,
			flags: QUERY_FLAGS,
			question: [{ name: 'example.com', type: RecordType.A, class: 1 }],
			answer: [],
			authority: [],
			additional: []
		};
		// 12-byte header (id 0x1234, flags 0x0100 RD, qd 1) + QNAME + QTYPE A + QCLASS IN
		const expected = '123401000001000000000000' + '076578616d706c6503636f6d' + '0000010001';
		expect(toHex(encodeMessage(msg))).toBe(expected);
	});

	it('encodes domain names as length-prefixed labels', () => {
		expect(toHex(encodeName('example.com'))).toBe('076578616d706c6503636f6d00');
		expect(toHex(encodeName('www.example.com'))).toBe('03777777076578616d706c6503636f6d00');
		expect(toHex(encodeName('.'))).toBe('00');
	});

	it('re-encodes a decoded (uncompressed) query to the identical bytes', () => {
		const bytes = fromHex('123401000001000000000000076578616d706c6503636f6d0000010001');
		expect(toHex(encodeMessage(decodeMessage(bytes)))).toBe(toHex(bytes));
	});
});

describe('dns response KAT (compression + known answer)', () => {
	// a real-shape example.com A response: QR|RD|RA, answer name is a pointer to the question,
	// A 93.184.216.34, TTL 300
	const hex =
		'123481800001000100000000' +
		'076578616d706c6503636f6d0000010001' +
		'c00c000100010000012c00045db8d822';

	it('decodes the header, rcode, and the compressed answer name', () => {
		const msg = decodeMessage(fromHex(hex));
		expect(msg.id).toBe(0x1234);
		expect(msg.flags.qr).toBe(true);
		expect(msg.flags.ra).toBe(true);
		expect(msg.flags.rcode).toBe(ResponseCode.NOERROR);
		expect(msg.question[0]!.name).toBe('example.com');
		expect(msg.answer).toHaveLength(1);
		expect(msg.answer[0]!.name).toBe('example.com');
		expect(msg.answer[0]!.type).toBe(RecordType.A);
		expect(msg.answer[0]!.ttl).toBe(300);
		expect(msg.answer[0]!.data).toBe('93.184.216.34');
		expect([...msg.answer[0]!.rdata]).toEqual([0x5d, 0xb8, 0xd8, 0x22]);
	});
});

describe('dns EDNS0 OPT KAT (RFC 6891)', () => {
	it('encodes a DO-bit OPT record with the default 4096 payload size byte-for-byte', () => {
		const msg: DnsMessage = {
			id: 0x1234,
			flags: QUERY_FLAGS,
			question: [{ name: 'example.com', type: RecordType.A, class: 1 }],
			answer: [],
			authority: [],
			additional: [encodeOptRecord({ dnssecOk: true })]
		};
		// header ar=1, question, then OPT: root, type 41 (0x0029), class 4096 (0x1000),
		// ttl 0x00008000 (DO bit), rdlength 0
		const expected =
			'123401000001000000000001' + '076578616d706c6503636f6d0000010001' + '0000291000000080000000';
		expect(toHex(encodeMessage(msg))).toBe(expected);
	});
});

describe('dns IPv6 canonical formatting KAT (RFC 5952)', () => {
	it('produces the canonical text form for the RFC 5952 examples', () => {
		const cases: Array<[string, string]> = [
			['00000000000000000000000000000000', '::'],
			['00000000000000000000000000000001', '::1'],
			['20010db8000000000000000000000001', '2001:db8::1'],
			// two equal-length zero runs: the first is compressed (RFC 5952 4.2.3)
			['20010db8000000000001000000000001', '2001:db8::1:0:0:1'],
			['fe800000000000000000000000000000', 'fe80::'],
			['20010db8000100020003000400050006', '2001:db8:1:2:3:4:5:6'],
			['26064700470000000000000000001111', '2606:4700:4700::1111']
		];
		for (const [hex, text] of cases) {
			expect(formatIpv6(fromHex(hex))).toBe(text);
			// and the text round-trips back to the same bytes
			expect(toHex(parseIpv6(text))).toBe(hex);
		}
	});
});
