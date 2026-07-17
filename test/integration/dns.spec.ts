import { beforeAll, describe, expect, it } from 'vitest';
import {
	connect,
	lookup,
	query,
	RecordType,
	resolve,
	resolve4,
	resolve6,
	resolveCaa,
	resolveCname,
	resolveMx,
	resolveNs,
	resolveSoa,
	resolveSrv,
	resolveTxt,
	ResponseCode,
	reverse
} from '../../src/dns/index';

const HOST = '127.0.0.1';
const PORT = 5354;
// resolve() options use `server`; connect()/query() use `hostname`
const opts = { server: HOST, port: PORT } as const;
const conn = { hostname: HOST, port: PORT } as const;

beforeAll(async () => {
	// the container may be "running" a beat before CoreDNS binds its listeners; poll until it answers
	const deadline = Date.now() + 15000;
	for (;;) {
		try {
			const dns = await connect({ ...conn, timeoutMs: 2000 });
			try {
				if (await dns.query('edgeport.test', 'SOA')) return;
			} finally {
				await dns.close();
			}
		} catch (err) {
			if (Date.now() > deadline) throw err;
			await new Promise((r) => setTimeout(r, 300));
		}
	}
}, 30000);

describe('dns against CoreDNS (edgeport.test zone)', () => {
	it('resolves A records', async () => {
		expect(await resolve4('host.edgeport.test', opts)).toEqual(['93.184.216.34']);
	});

	it('resolves AAAA records in canonical compressed form', async () => {
		expect(await resolve6('host.edgeport.test', opts)).toEqual(['2001:db8::53']);
	});

	it('resolves MX records', async () => {
		const mx = await resolveMx('edgeport.test', opts);
		expect(mx).toEqual([{ preference: 10, exchange: 'mail.edgeport.test' }]);
	});

	it('resolves TXT records (each an array of character-strings)', async () => {
		const txt = await resolveTxt('edgeport.test', opts);
		const flat = txt.flat();
		expect(flat).toContain('v=spf1 -all');
		expect(flat).toContain('edgeport=dns');
	});

	it('resolves SRV records', async () => {
		const srv = await resolveSrv('_sip._tcp.edgeport.test', opts);
		expect(srv).toEqual([{ priority: 10, weight: 20, port: 5060, target: 'sip.edgeport.test' }]);
	});

	it('resolves CNAME records', async () => {
		expect(await resolveCname('www.edgeport.test', opts)).toEqual(['host.edgeport.test']);
	});

	it('resolves CAA records', async () => {
		expect(await resolveCaa('edgeport.test', opts)).toEqual([
			{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }
		]);
	});

	it('resolves NS records', async () => {
		expect(await resolveNs('edgeport.test', opts)).toEqual(['ns1.edgeport.test']);
	});

	it('resolves the SOA record', async () => {
		const soa = await resolveSoa('edgeport.test', opts);
		expect(soa?.mname).toBe('ns1.edgeport.test');
		expect(soa?.rname).toBe('hostmaster.edgeport.test');
		expect(soa?.serial).toBe(2026071700);
		expect(soa?.minimum).toBe(300);
	});

	it('reverse-resolves an IPv4 address to its PTR name', async () => {
		expect(await reverse('10.0.1.25', opts)).toEqual(['mail.edgeport.test']);
	});

	it('looks up the first address Node-style', async () => {
		expect(await lookup('host.edgeport.test', opts)).toBe('93.184.216.34');
	});

	it('follows a CNAME and returns the A address for the overloaded resolve()', async () => {
		expect(await resolve('www.edgeport.test', { type: 'A', ...opts })).toEqual(['93.184.216.34']);
	});

	it('returns an empty array for a non-existent name (NXDOMAIN does not throw)', async () => {
		expect(await resolve4('nope.edgeport.test', opts)).toEqual([]);
	});

	it('accepts a DNSSEC-OK (EDNS0) query', async () => {
		expect(await resolve('host.edgeport.test', { type: 'A', dnssec: true, ...opts })).toEqual([
			'93.184.216.34'
		]);
	});

	it('reuses one connection to pipeline several queries', async () => {
		await using dns = await connect(conn);
		const [a, mx, srv] = await Promise.all([
			dns.query('host.edgeport.test', 'A'),
			dns.query('edgeport.test', 'MX'),
			dns.query('_sip._tcp.edgeport.test', 'SRV')
		]);
		expect(a).toContain('93.184.216.34');
		expect(mx[0]!.exchange).toBe('mail.edgeport.test');
		expect(srv[0]!.port).toBe(5060);
	});

	describe('raw (level 3) query', () => {
		it('returns the full structured message', async () => {
			const res = await query({ questions: [{ name: 'edgeport.test', type: 'SOA' }] }, conn);
			expect(res.rcode).toBe(ResponseCode.NOERROR);
			expect(res.answers[0]!.type).toBe(RecordType.SOA);
			expect(res.flags.qr).toBe(true);
		});

		it('exposes NXDOMAIN with the SOA in the authority section', async () => {
			const res = await query({ questions: [{ name: 'nope.edgeport.test', type: 'A' }] }, conn);
			expect(res.rcode).toBe(ResponseCode.NXDOMAIN);
			expect(res.authority.some((rr) => rr.type === RecordType.SOA)).toBe(true);
		});
	});
});
