import { describe, expect, it } from 'vitest';
import { connect, sendMessage } from '../../src/smpp/index';

const HOST = '127.0.0.1';
const PORT = 2775;
const HTTP = 'http://127.0.0.1:12775/';

describe('smpp against ukarim/smscsim', () => {
	it('binds as a transceiver and submits a message', async () => {
		await using smpp = await connect({
			hostname: HOST,
			port: PORT,
			systemId: 'edgeport',
			password: 'pw',
			bindMode: 'transceiver',
			enquireLinkSeconds: 0
		});
		const id = await smpp.submit({
			source: '12065550100',
			destination: '12065550111',
			message: 'hello smpp'
		});
		expect(id).toBeTruthy();
	});

	it('receives an SMSC delivery receipt for a registered submission', async () => {
		await using smpp = await connect({
			hostname: HOST,
			port: PORT,
			systemId: 'edgeport-dlr',
			password: 'pw',
			bindMode: 'transceiver',
			enquireLinkSeconds: 0
		});
		const id = await smpp.submit({
			source: 'EDGE',
			destination: '12065550111',
			message: 'please confirm delivery',
			registeredDelivery: true
		});

		// the sim sends a delivery-receipt deliver_sm ~2s later on the same session
		const iter = smpp.messages()[Symbol.asyncIterator]();
		let stat: string | undefined;
		let receiptId: string | undefined;
		let flagged = false;
		for (let i = 0; i < 5; i++) {
			const { value, done } = await iter.next();
			if (done || !value) break;
			const r = value.receipt();
			// a receipt parses to a stat field; skip anything that isn't one
			if (r.stat) {
				stat = r.stat;
				receiptId = r.id;
				flagged = value.isDeliveryReceipt;
				break;
			}
		}
		expect(stat).toBe('DELIVRD');
		// the receipt correlates to the message id the submit returned
		expect(receiptId).toBe(id);
		// and the esm_class flags it as a delivery receipt
		expect(flagged).toBe(true);
	});

	it('sends a one-shot message via sendMessage', async () => {
		const id = await sendMessage({
			hostname: HOST,
			port: PORT,
			systemId: 'edgeport-oneshot',
			password: 'pw',
			source: 'EDGE',
			destination: '12065550111',
			message: 'one-shot from the edge'
		});
		expect(id).toBeTruthy();
	});

	it('receives an injected mobile-originated message', async () => {
		const systemId = 'edgeport-mo';
		await using smpp = await connect({
			hostname: HOST,
			port: PORT,
			systemId,
			password: 'pw',
			bindMode: 'transceiver',
			enquireLinkSeconds: 0
		});
		const iter = smpp.messages()[Symbol.asyncIterator]();

		// inject an MO message routed to our bound system_id via the sim's http form
		const res = await fetch(HTTP, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				sender: '12065550111',
				recipient: '12065550100',
				message: 'hi from a handset',
				system_id: systemId
			})
		});
		expect(res.ok).toBe(true);

		const { value } = await iter.next();
		expect(value).toBeDefined();
		expect(value!.source).toBe('12065550111');
		expect(value!.text()).toContain('hi from a handset');
		expect(value!.isDeliveryReceipt).toBe(false);
	});
});
