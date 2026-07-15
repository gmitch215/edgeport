// recipe: carrier SMS delivery with an email-to-SMS fallback
import { describe, expect, it } from 'vitest';
import { connect as smppConnect } from '../../../src/smpp/index';
import { sendSms, smsAddress } from '../../../src/smtp/index';
import { connect as syslogConnect } from '../../../src/syslog/index';
import { retry } from '../../../src/util/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const HOST = '127.0.0.1';
const SMPP_PORT = 2775;
const SMTP_PORT = 3025;
const SYSLOG_PORT = 5514;

// opens the plaintext syslog audit channel for this run
async function openSyslog(runId: string) {
	return syslogConnect({
		hostname: HOST,
		port: SYSLOG_PORT,
		appName: 'sms-gateway',
		procId: runId
	});
}

// polls the syslog readback until every marker for this run appears, in order
async function waitForAudit(runId: string, markers: string[]): Promise<string | null> {
	return waitFor(
		async () => {
			const mine = (await readSyslog())
				.split('\n')
				.filter((line) => line.includes(runId))
				.join('\n');
			let from = 0;
			for (const m of markers) {
				const at = mine.indexOf(m, from);
				if (at < 0) return null;
				from = at + m.length;
			}
			return mine;
		},
		15_000,
		300
	);
}

describe('recipe: carrier SMS delivery with email fallback (SMPP + SMS-over-email + util + Syslog)', () => {
	// 1. primary path: submit over SMPP and confirm delivery with the SMSC receipt, retry-wrapped.
	it('delivers over SMPP and confirms the delivery receipt, audited', async () => {
		const runId = uniqueId('sms-smpp');
		await using log = await openSyslog(runId);

		// util.retry retries only transient ConnectionError/TimeoutError, not auth/protocol errors
		await using smpp = await retry(
			() =>
				smppConnect({
					hostname: HOST,
					port: SMPP_PORT,
					systemId: `edgeport-${runId}`,
					password: 'pw',
					bindMode: 'transceiver',
					enquireLinkSeconds: 0
				}),
			{ attempts: 3, baseMs: 100 }
		);

		const id = await smpp.submit({
			source: 'EDGEPORT',
			destination: '12065550111',
			message: `carrier send ${runId}`,
			registeredDelivery: true
		});
		expect(id).toBeTruthy();
		await log.info(`smpp-submitted ${runId} id=${id}`);

		// wait for the SMSC delivery receipt on the same session and confirm it correlates
		const iter = smpp.messages()[Symbol.asyncIterator]();
		let stat: string | undefined;
		let receiptId: string | undefined;
		for (let i = 0; i < 5; i++) {
			const { value, done } = await iter.next();
			if (done || !value) break;
			const r = value.receipt();
			if (r.stat) {
				stat = r.stat;
				receiptId = r.id;
				break;
			}
		}
		expect(stat).toBe('DELIVRD');
		expect(receiptId).toBe(id);
		await log.info(`smpp-delivered ${runId} id=${id} stat=${stat}`);

		const audit = await waitForAudit(runId, [`smpp-submitted ${runId}`, `smpp-delivered ${runId}`]);
		expect(audit, 'the SMPP submit + receipt should be audited in order').not.toBeNull();
	});

	// 2. fallback path: address a carrier email-to-SMS gateway and send it over SMTP.
	it('falls back to an email-to-SMS gateway over SMTP, audited', async () => {
		const runId = uniqueId('sms-email');
		await using log = await openSyslog(runId);

		// the gateway address is derived deterministically from number + carrier
		const number = '12065550100';
		const gateway = smsAddress(number, 'att'); // 12065550100@txt.att.net
		expect(gateway).toBe('12065550100@txt.att.net');

		// send it as a short text over the real SMTP path (greenmail accepts any recipient)
		const result = await sendSms({
			hostname: HOST,
			port: SMTP_PORT,
			tls: 'off',
			from: 'alerts@edgeport.test',
			to: { number, carrier: 'att' },
			text: `fallback send ${runId}`
		});
		expect(result.accepted).toContain(gateway);
		await log.info(`email-sms-sent ${runId} to=${gateway}`);

		const audit = await waitForAudit(runId, [`email-sms-sent ${runId}`]);
		expect(audit, 'the email-to-SMS fallback should be audited').not.toBeNull();
	});

	// 3. end-to-end: try SMPP first, fall through to the email gateway, with an ordered audit.
	it('records an ordered primary-then-fallback audit trail', async () => {
		const runId = uniqueId('sms-both');
		await using log = await openSyslog(runId);

		// primary: SMPP one-off submit (no receipt wait needed for the ordering check)
		await using smpp = await retry(() =>
			smppConnect({
				hostname: HOST,
				port: SMPP_PORT,
				systemId: `edgeport-both-${runId}`,
				password: 'pw',
				bindMode: 'transmitter',
				enquireLinkSeconds: 0
			})
		);
		const id = await smpp.submit({ source: 'EDGE', destination: '12065550111', message: runId });
		await log.info(`primary-smpp ${runId} id=${id}`);

		// fallback: the same message to the carrier's email gateway
		const result = await sendSms({
			hostname: HOST,
			port: SMTP_PORT,
			tls: 'off',
			from: 'alerts@edgeport.test',
			to: { number: '12065550100', carrier: 'verizon' },
			text: runId
		});
		expect(result.accepted).toContain('12065550100@vtext.com');
		await log.info(`fallback-email ${runId} to=12065550100@vtext.com`);

		const audit = await waitForAudit(runId, [`primary-smpp ${runId}`, `fallback-email ${runId}`]);
		expect(audit, 'primary then fallback should appear in order').not.toBeNull();
	});
});
