// recipe: mainframe/ERP nightly batch - insecure-inside, secure-outside.
// a legacy system pushes fixed-width records over PLAIN ftp into a landing zone; a transfer
// agent re-sends them downstream SECURELY over sftp; every leg emits a syslog event; the run
// ends with a job-summary email over smtp. exercises four protocols end to end against the
// dockerized servers.
//
// notes vs the classic recipe:
// - the legacy leg uses PLAIN ftp in BINARY mode. transfers are PASSIVE-only by design - the
//   Workers runtime cannot accept inbound connections, so active/PORT mode is impossible;
//   passive is the only mode edgeport ftp offers. the CRLF-terminated fixed-width records must
//   survive byte-exact end to end (ftp put -> ftp get -> sftp put -> sftp read), which is a
//   binary-transfer property: a spec-compliant FTP server normalizes CRLF<->LF in ascii/TYPE A
//   mode, so binary is the correct mode for preserving fixed-width records verbatim.
// - greenmail smtp is plaintext on 3025; the public connect() only offers starttls|implicit,
//   so (matching mail.spec.ts / ci.spec.ts) we open a plaintext core socket and hand it to
//   _sessionFromSocket with tls:'implicit' (meaning "no upgrade, socket already usable").
import { describe, expect, it } from 'vitest';
import { connect as coreConnect } from '../../../src/core/socket';
import { connect as ftpConnect } from '../../../src/ftp/index';
import { connect as sftpConnect } from '../../../src/sftp/index';
import { _sessionFromSocket as smtpSessionFromSocket } from '../../../src/smtp/index';
import { Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const HOST = '127.0.0.1';
const FTP_PORT = 21;
const SFTP_PORT = 2222;
const SYSLOG_PORT = 5514;
const SMTP_PORT = 3025;
const MAILBOX = 'tester@localhost';
const ftpCreds = { hostname: HOST, port: FTP_PORT, username: 'tester', password: 'testpass' };
const sftpCreds = { hostname: HOST, port: SFTP_PORT, username: 'tester', password: 'testpass' };
const smtpAuth = { username: 'tester', password: 'testpass' };

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

// greenmail plaintext smtp (see header note)
async function openSmtp() {
	const socket = await coreConnect({ hostname: HOST, port: SMTP_PORT, tls: 'off' });
	return smtpSessionFromSocket(socket, { hostname: HOST, tls: 'implicit', auth: smtpAuth });
}

// plaintext syslog sink on 5514 (real deployments use 6514/implicit-tls)
async function openSyslog() {
	return syslogConnect({ hostname: HOST, port: SYSLOG_PORT, tls: 'off', appName: 'erp-batch' });
}

// fixed column layout for a legacy ERP record (COBOL-style fixed-width, total 40 cols)
const COLS = { acct: 8, name: 20, amount: 12 } as const;
const RECORD_WIDTH = COLS.acct + COLS.name + COLS.amount; // 40

// left-pad a numeric field, right-pad (space) a text field, to an exact column width
function padNum(value: string, width: number): string {
	if (value.length > width) throw new Error(`field overflow: ${value}`);
	return value.padStart(width, '0');
}
function padText(value: string, width: number): string {
	if (value.length > width) throw new Error(`field overflow: ${value}`);
	return value.padEnd(width, ' ');
}

interface ErpRecord {
	acct: string;
	name: string;
	amount: string;
}

// renders one fixed-width record (no terminator); each field padded to its column width
function renderRecord(r: ErpRecord): string {
	return padNum(r.acct, COLS.acct) + padText(r.name, COLS.name) + padNum(r.amount, COLS.amount);
}

// splits a fixed-width record back into its columns by byte offset
function parseRecord(line: string): ErpRecord {
	expect(line.length).toBe(RECORD_WIDTH);
	let o = 0;
	const acct = line.slice(o, (o += COLS.acct));
	const name = line.slice(o, (o += COLS.name));
	const amount = line.slice(o, (o += COLS.amount));
	return { acct, name, amount };
}

// builds the full fixed-width file: every record CRLF-terminated (mainframe line discipline)
function buildFixedWidthFile(records: ErpRecord[]): Uint8Array {
	const body = records.map((r) => renderRecord(r) + '\r\n').join('');
	return enc(body);
}

const SAMPLE: ErpRecord[] = [
	{ acct: '10000001', name: 'ACME WIDGETS LLC', amount: '000001234.56' },
	{ acct: '10000002', name: 'GLOBEX CORP', amount: '000099999.00' },
	{ acct: '10000003', name: 'INITECH', amount: '000000042.00' },
	{ acct: '10000004', name: 'UMBRELLA HOLDINGS', amount: '012345678.90' }
];

// counts occurrences of `needle` in the readback (octet-counting framing has no separators)
function occurrences(haystack: string, needle: string): number {
	return haystack.split(needle).length - 1;
}

describe('recipe: mainframe nightly batch (ftp -> sftp, syslog + smtp)', () => {
	it('lands fixed-width records over plain ftp, forwards securely over sftp, logs + emails', async () => {
		const job = uniqueId('erp');
		const landedName = `${job}.dat`; // relative path -> ftp user home (landing zone)
		const securePath = `/config/${job}.dat`; // sftp destination (downstream secure store)
		const original = buildFixedWidthFile(SAMPLE);

		// open one syslog session for the whole run so every leg shares the connection.
		// transfers are kept strictly sequential (ftp has only 10 passive ports).
		await using log = await openSyslog();
		await log.log({ severity: Severity.notice, message: `job-start ${job}` });

		// 1. legacy push: store the fixed-width file over PLAIN ftp into the landing zone.
		{
			await using ftp = await ftpConnect(ftpCreds);
			await ftp.put(landedName, original); // binary: preserve the CRLF fixed-width records verbatim
			// confirm it landed and is the exact byte length we pushed
			expect(await ftp.size(landedName)).toBe(original.length);
		}
		await log.log({ severity: Severity.info, message: `landed ${landedName} (job ${job})` });

		// 2. transfer agent: pull the landed file back over ftp (ascii), then push it downstream
		// over sftp. assert byte-exact equality at every hop (ASCII-correctness proof: the
		// CRLF-terminated fixed-width records survive verbatim across both transports).
		let forwarded: Uint8Array;
		{
			await using ftp = await ftpConnect(ftpCreds);
			const delivered = await ftp.get(landedName);
			expect(delivered).toEqual(original); // ftp round-trip is byte-exact

			await using sftp = await sftpConnect(sftpCreds);
			await sftp.writeFile(securePath, delivered);
			const stored = await sftp.readFile(securePath);
			expect(stored).toEqual(delivered); // sftp store is byte-exact
			expect(stored).toEqual(original); // end-to-end byte-exact (ftp -> sftp)
			forwarded = stored;
		}
		await log.log({ severity: Severity.info, message: `forwarded ${securePath} (job ${job})` });

		// 3. resume-on-interruption for the sftp leg: write the first half, stat the partial,
		// then write the remainder at { offset } and assert the final file is byte-exact.
		{
			await using sftp = await sftpConnect(sftpCreds);
			const resumePath = `/config/${job}-resume.dat`;
			const half = Math.floor(forwarded.length / 2);
			await sftp.writeFile(resumePath, forwarded.subarray(0, half));
			const partial = await sftp.stat(resumePath);
			expect(partial.size).toBe(half);
			await sftp.writeFile(resumePath, forwarded.subarray(partial.size!), {
				offset: partial.size!
			});
			const finished = await sftp.stat(resumePath);
			expect(finished.size).toBe(forwarded.length);
			const readBack = await sftp.readFile(resumePath);
			expect(readBack).toEqual(forwarded); // resumed file is byte-exact
			await sftp.remove(resumePath).catch(() => {});
		}

		await log.log({ severity: Severity.notice, message: `job-complete ${job}` });

		// 5. job-summary email: send a summary over smtp, assert the recipient was accepted.
		{
			await using smtp = await openSmtp();
			const subject = `${job} nightly batch`;
			const body =
				`Nightly ERP batch ${job} complete.\r\n` +
				`Records transferred: ${SAMPLE.length}\r\n` +
				`Landed: ${landedName}\r\n` +
				`Forwarded: ${securePath}\r\n`;
			const res = await smtp.send({ from: MAILBOX, to: MAILBOX, subject, text: body });
			expect(res.accepted).toContain(MAILBOX);
		}

		// close the syslog socket so the sink flushes the captured file before we read it back.
		await log.close();

		// 4. assert syslog captured every leg, for this job id, IN ORDER.
		// each event embeds `job` once; job-start/landed/forwarded/job-complete => 4 occurrences.
		const text = await waitFor(
			async () => {
				const t = await readSyslog();
				return occurrences(t, job) >= 4 ? t : null;
			},
			15000,
			250
		);
		expect(text, 'syslog readback did not contain all four leg events for the job').not.toBeNull();
		const captured = text!;

		const iStart = captured.indexOf(`job-start ${job}`);
		const iLanded = captured.indexOf(`landed ${landedName}`);
		const iForwarded = captured.indexOf(`forwarded ${securePath}`);
		const iComplete = captured.indexOf(`job-complete ${job}`);
		expect(iStart).toBeGreaterThanOrEqual(0);
		expect(iLanded).toBeGreaterThan(iStart);
		expect(iForwarded).toBeGreaterThan(iLanded);
		expect(iComplete).toBeGreaterThan(iForwarded);
		// app-name from the session default is present, and a framed PRI precedes a record
		expect(captured).toContain('erp-batch');
		expect(
			new RegExp(`\\d+ <\\d+>1 \\S+ - erp-batch - - .* landed ${landedName}`).test(captured)
		).toBe(true);

		// cleanup the secure copy (best effort)
		{
			await using sftp = await sftpConnect(sftpCreds);
			await sftp.remove(securePath).catch(() => {});
		}
		// cleanup the landing-zone file (best effort)
		{
			await using ftp = await ftpConnect(ftpCreds);
			await ftp.delete(landedName).catch(() => {});
		}
	});

	it('parses a landed fixed-width record back into its exact columns', async () => {
		const job = uniqueId('erp-parse');
		const name = `${job}.dat`;
		const file = buildFixedWidthFile(SAMPLE);

		await using ftp = await ftpConnect(ftpCreds);
		await ftp.put(name, file);
		const got = await ftp.get(name);
		expect(got).toEqual(file); // byte-exact round-trip

		// split on CRLF, drop the trailing empty field, and parse each record by column offset
		const lines = dec(got)
			.split('\r\n')
			.filter((l) => l.length > 0);
		expect(lines.length).toBe(SAMPLE.length);
		const first = parseRecord(lines[0]!);
		expect(first.acct).toBe('10000001');
		expect(first.name).toBe('ACME WIDGETS LLC    '); // right-padded to 20 cols
		expect(first.amount).toBe('000001234.56'); // left-padded to 12 cols
		// trimmed fields recover the logical values
		expect(first.name.trimEnd()).toBe('ACME WIDGETS LLC');
		expect(Number(first.amount)).toBeCloseTo(1234.56);
		// last record too, to prove offsets hold across the whole file
		const last = parseRecord(lines[lines.length - 1]!);
		expect(last.acct).toBe('10000004');
		expect(last.name.trimEnd()).toBe('UMBRELLA HOLDINGS');

		await ftp.delete(name).catch(() => {});
	});

	it('round-trips an empty file over ftp then sftp byte-exact', async () => {
		const job = uniqueId('erp-empty');
		const landedName = `${job}.dat`;
		const securePath = `/config/${job}.dat`;
		const empty = new Uint8Array(0);

		await using ftp = await ftpConnect(ftpCreds);
		await ftp.put(landedName, empty);
		expect(await ftp.size(landedName)).toBe(0);
		const delivered = await ftp.get(landedName);
		expect(delivered.length).toBe(0);

		await using sftp = await sftpConnect(sftpCreds);
		await sftp.writeFile(securePath, delivered);
		const st = await sftp.stat(securePath);
		expect(st.size).toBe(0);
		const stored = await sftp.readFile(securePath);
		expect(stored.length).toBe(0);

		await sftp.remove(securePath).catch(() => {});
		await ftp.delete(landedName).catch(() => {});
	});

	it('preserves CRLF line discipline verbatim (ascii-correctness proof)', async () => {
		const job = uniqueId('erp-crlf');
		const name = `${job}.dat`;
		// a record file whose terminators are CRLF; binary transfers must not rewrite them to LF
		const file = buildFixedWidthFile(SAMPLE.slice(0, 2));

		await using ftp = await ftpConnect(ftpCreds);
		await ftp.put(name, file);
		const got = await ftp.get(name);
		expect(got).toEqual(file);

		// every record is followed by exactly CR(0x0d) LF(0x0a), never a bare LF
		const crlf = occurrences(dec(got), '\r\n');
		expect(crlf).toBe(2); // two records, two CRLF terminators
		// no lone LF: count of LF equals count of CRLF (every LF is preceded by a CR)
		const lf = occurrences(dec(got), '\n');
		expect(lf).toBe(crlf);

		await ftp.delete(name).catch(() => {});
	});
});
