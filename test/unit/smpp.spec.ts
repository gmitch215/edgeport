import { describe, expect, it } from 'vitest';
import { AuthError, ProtocolError } from '../../src/core/errors';
import {
	_connectOverSocket,
	Command,
	CommandStatus,
	DataCoding,
	decodeHeader,
	decodePdu,
	encodeEmpty,
	encodeGenericNack,
	encodePdu,
	encodeSubmitSm,
	ESM_DELIVERY_RECEIPT,
	HEADER_LENGTH,
	parseDeliveryReceipt,
	Tag,
	type SmppScheduler,
	type SmppSession
} from '../../src/smpp';
import { mockConnection, type MockServerEnd } from '../mock-socket';

const enc = new TextEncoder();
const dec = new TextDecoder();

// a NUL-terminated C-Octet String body, for building server-side PDUs
function cstr(s: string): Uint8Array {
	const body = enc.encode(s);
	const out = new Uint8Array(body.length + 1);
	out.set(body, 0);
	return out;
}

// reads one full PDU (command_length prefix + body) the client wrote to the server
async function readRaw(server: MockServerEnd): Promise<Uint8Array> {
	const lenBytes = await server.readN(4);
	const len = new DataView(lenBytes.buffer, lenBytes.byteOffset, 4).getUint32(0, false);
	const rest = len > 4 ? await server.readN(len - 4) : new Uint8Array(0);
	const full = new Uint8Array(len);
	full.set(lenBytes, 0);
	full.set(rest, 4);
	return full;
}

// the SMSC's bind response for a given bind request (resp id = request id | high bit)
function bindResp(reqCommand: number, sequence: number, systemId: string, status = 0): Uint8Array {
	const body = status === 0 ? cstr(systemId) : new Uint8Array(0);
	return encodePdu(reqCommand | 0x80000000, status, sequence, body);
}

// wraps a submit_sm-shaped body as a deliver_sm the SMSC pushes to the client
function deliverSm(sequence: number, params: Parameters<typeof encodeSubmitSm>[1]): Uint8Array {
	const body = encodeSubmitSm(sequence, params).subarray(HEADER_LENGTH);
	return encodePdu(Command.DeliverSm, 0, sequence, body);
}

// connects through a successful bind and returns the ready session + server end
async function bound(
	opts: Partial<Parameters<typeof _connectOverSocket>[1]> = {}
): Promise<{ session: SmppSession; server: MockServerEnd }> {
	const { socket, server } = mockConnection();
	const session = (
		await Promise.all([
			_connectOverSocket(socket, {
				hostname: 'smsc.test',
				systemId: 'esme',
				password: 'pw',
				enquireLinkSeconds: 0,
				...opts
			}),
			(async () => {
				const header = decodeHeader(await readRaw(server));
				await server.write(bindResp(header.command, header.sequence, 'SMSC-01'));
			})()
		])
	)[0];
	return { session, server };
}

describe('smpp pdu header', () => {
	it('encodes the 16-byte header with command_length, id, status, and sequence', () => {
		const pdu = encodeEmpty(Command.EnquireLink, 7);
		expect(pdu.length).toBe(HEADER_LENGTH);
		const header = decodeHeader(pdu);
		expect(header.commandLength).toBe(16);
		expect(header.command).toBe(Command.EnquireLink);
		expect(header.status).toBe(0);
		expect(header.sequence).toBe(7);
	});

	it('round-trips a response command id with the high bit set', () => {
		const resp = encodePdu(Command.SubmitSmResp, 0, 3, cstr('id-1'));
		const pdu = decodePdu(resp);
		expect(pdu.command).toBe(Command.SubmitSmResp);
		if (pdu.command !== Command.SubmitSmResp) throw new Error('wrong command');
		expect(pdu.messageId).toBe('id-1');
	});
});

describe('smpp submit_sm codec', () => {
	it('round-trips all mandatory fields including a length-prefixed short_message', () => {
		const bytes = encodeSubmitSm(9, {
			sourceAddr: '12065550100',
			destinationAddr: '12065550111',
			registeredDelivery: 1,
			dataCoding: DataCoding.Default,
			shortMessage: enc.encode('hello world')
		});
		const pdu = decodePdu(bytes);
		if (pdu.command !== Command.SubmitSm) throw new Error('wrong command');
		expect(pdu.sourceAddr).toBe('12065550100');
		expect(pdu.destinationAddr).toBe('12065550111');
		expect(pdu.registeredDelivery).toBe(1);
		expect(dec.decode(pdu.shortMessage)).toBe('hello world');
		expect(pdu.sequence).toBe(9);
	});

	it('encodes empty optional C-Octet strings as a lone NUL', () => {
		const bytes = encodeSubmitSm(1, { destinationAddr: '', shortMessage: new Uint8Array(0) });
		const pdu = decodePdu(bytes);
		if (pdu.command !== Command.SubmitSm) throw new Error('wrong command');
		expect(pdu.serviceType).toBe('');
		expect(pdu.sourceAddr).toBe('');
		expect(pdu.destinationAddr).toBe('');
		expect(pdu.shortMessage.length).toBe(0);
	});

	it('round-trips a trailing message_payload TLV', () => {
		const payload = enc.encode('x'.repeat(400));
		const bytes = encodeSubmitSm(2, {
			destinationAddr: '123',
			shortMessage: new Uint8Array(0),
			tlvs: [{ tag: Tag.MessagePayload, value: payload }]
		});
		const pdu = decodePdu(bytes);
		if (pdu.command !== Command.SubmitSm) throw new Error('wrong command');
		expect(pdu.tlvs).toHaveLength(1);
		expect(pdu.tlvs[0]!.tag).toBe(Tag.MessagePayload);
		expect(dec.decode(pdu.tlvs[0]!.value)).toBe('x'.repeat(400));
	});

	it('rejects a short_message over the 254-octet limit', () => {
		expect(() =>
			encodeSubmitSm(1, { destinationAddr: '1', shortMessage: new Uint8Array(255) })
		).toThrow(ProtocolError);
	});
});

describe('smpp deliver_sm codec', () => {
	it('decodes a deliver_sm that mirrors the submit_sm layout', () => {
		const pdu = decodePdu(
			deliverSm(5, {
				sourceAddr: '12065550111',
				destinationAddr: 'EDGE',
				shortMessage: enc.encode('inbound')
			})
		);
		if (pdu.command !== Command.DeliverSm) throw new Error('wrong command');
		expect(pdu.sourceAddr).toBe('12065550111');
		expect(pdu.destinationAddr).toBe('EDGE');
		expect(dec.decode(pdu.shortMessage)).toBe('inbound');
	});

	it('rejects an unsupported command id', () => {
		// 0x000000ff is not a command edgeport parses
		expect(() => decodePdu(encodePdu(0x000000ff, 0, 1, new Uint8Array(0)))).toThrow(ProtocolError);
	});
});

describe('smpp delivery receipt parser', () => {
	it('extracts the standard receipt fields case-insensitively', () => {
		const r = parseDeliveryReceipt(
			'id:msg-1 sub:001 dlvrd:001 submit date:2401010000 done date:2401010001 stat:DELIVRD err:000 Text:hello'
		);
		expect(r.id).toBe('msg-1');
		expect(r.sub).toBe('001');
		expect(r.dlvrd).toBe('001');
		expect(r.submitDate).toBe('2401010000');
		expect(r.doneDate).toBe('2401010001');
		expect(r.stat).toBe('DELIVRD');
		expect(r.err).toBe('000');
		expect(r.text).toBe('hello');
	});
});

describe('smpp bind handshake', () => {
	it('binds as a transceiver and exposes the smsc system id', async () => {
		const { session, server } = await bound();
		expect(session.bindMode).toBe('transceiver');
		expect(session.systemId).toBe('SMSC-01');
		await Promise.all([session.close(), readRaw(server)]);
	});

	it('sends the requested bind command for each mode', async () => {
		const { socket, server } = mockConnection();
		let seen = -1;
		const session = (
			await Promise.all([
				_connectOverSocket(socket, {
					hostname: 'smsc.test',
					systemId: 'esme',
					bindMode: 'transmitter',
					enquireLinkSeconds: 0
				}),
				(async () => {
					const header = decodeHeader(await readRaw(server));
					seen = header.command;
					await server.write(bindResp(header.command, header.sequence, 'SMSC'));
				})()
			])
		)[0];
		expect(seen).toBe(Command.BindTransmitter);
		await Promise.all([session.close(), readRaw(server)]);
	});

	it('maps an invalid-password bind status to AuthError', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			const header = decodeHeader(await readRaw(server));
			await server.write(
				bindResp(header.command, header.sequence, '', CommandStatus.ESME_RINVPASWD)
			);
		})();
		await expect(
			Promise.all([
				_connectOverSocket(socket, {
					hostname: 'smsc.test',
					systemId: 'esme',
					password: 'bad',
					enquireLinkSeconds: 0
				}),
				script
			])
		).rejects.toBeInstanceOf(AuthError);
	});

	it('maps a generic_nack bind response to ProtocolError', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			const header = decodeHeader(await readRaw(server));
			await server.write(encodeGenericNack(header.sequence, CommandStatus.ESME_RINVCMDID));
		})();
		await expect(
			Promise.all([
				_connectOverSocket(socket, {
					hostname: 'smsc.test',
					systemId: 'esme',
					enquireLinkSeconds: 0
				}),
				script
			])
		).rejects.toBeInstanceOf(ProtocolError);
	});
});

describe('smpp submit', () => {
	it('submits a message and resolves with the smsc message id', async () => {
		const { session, server } = await bound();
		const script = (async () => {
			const pdu = decodePdu(await readRaw(server));
			if (pdu.command !== Command.SubmitSm) throw new Error('expected submit_sm');
			expect(pdu.destinationAddr).toBe('12065550111');
			expect(dec.decode(pdu.shortMessage)).toBe('hello');
			expect(pdu.registeredDelivery).toBe(1); // registeredDelivery: true -> 1
			await server.write(encodePdu(Command.SubmitSmResp, 0, pdu.sequence, cstr('msg-1')));
		})();
		const [id] = await Promise.all([
			session.submit({ destination: '12065550111', message: 'hello', registeredDelivery: true }),
			script
		]);
		expect(id).toBe('msg-1');
		await Promise.all([session.close(), readRaw(server)]);
	});

	it('carries an oversized body in a message_payload TLV', async () => {
		const { session, server } = await bound();
		const big = 'x'.repeat(300);
		const script = (async () => {
			const pdu = decodePdu(await readRaw(server));
			if (pdu.command !== Command.SubmitSm) throw new Error('expected submit_sm');
			expect(pdu.shortMessage.length).toBe(0);
			const mp = pdu.tlvs.find((t) => t.tag === Tag.MessagePayload);
			expect(mp).toBeDefined();
			expect(dec.decode(mp!.value)).toBe(big);
			await server.write(encodePdu(Command.SubmitSmResp, 0, pdu.sequence, cstr('m2')));
		})();
		const [id] = await Promise.all([session.submit({ destination: '1', message: big }), script]);
		expect(id).toBe('m2');
		await Promise.all([session.close(), readRaw(server)]);
	});

	it('rejects a submission the smsc nacks', async () => {
		const { session, server } = await bound();
		const script = (async () => {
			const header = decodeHeader(await readRaw(server));
			await server.write(encodeGenericNack(header.sequence, CommandStatus.ESME_RSUBMITFAIL));
		})();
		await expect(
			Promise.all([session.submit({ destination: '1', message: 'x' }), script])
		).rejects.toBeInstanceOf(ProtocolError);
		await Promise.all([session.close(), readRaw(server)]);
	});

	it('refuses to submit on a receiver-only bind', async () => {
		const { session } = await bound({ bindMode: 'receiver' });
		await expect(session.submit({ destination: '1', message: 'x' })).rejects.toBeInstanceOf(
			ProtocolError
		);
		await session.close();
	});
});

describe('smpp inbound delivery', () => {
	it('yields an MO message and auto-sends deliver_sm_resp', async () => {
		const { session, server } = await bound();
		const iter = session.messages()[Symbol.asyncIterator]();
		await server.write(
			deliverSm(77, {
				sourceAddr: '12065550111',
				destinationAddr: 'EDGE',
				shortMessage: enc.encode('inbound!')
			})
		);
		const { value } = await iter.next();
		expect(value!.source).toBe('12065550111');
		expect(value!.text()).toBe('inbound!');
		expect(value!.isDeliveryReceipt).toBe(false);
		// the client must acknowledge every deliver_sm
		const resp = decodePdu(await readRaw(server));
		expect(resp.command).toBe(Command.DeliverSmResp);
		expect(resp.sequence).toBe(77);
		await Promise.all([session.close(), readRaw(server)]);
	});

	it('flags a delivery receipt and parses its fields', async () => {
		const { session, server } = await bound();
		const iter = session.messages()[Symbol.asyncIterator]();
		const receipt =
			'id:msg-1 sub:001 dlvrd:001 submit date:2401010000 done date:2401010001 stat:DELIVRD err:000 text:hi';
		await server.write(
			deliverSm(5, {
				sourceAddr: 'x',
				destinationAddr: 'y',
				esmClass: ESM_DELIVERY_RECEIPT,
				shortMessage: enc.encode(receipt)
			})
		);
		const { value } = await iter.next();
		expect(value!.isDeliveryReceipt).toBe(true);
		const parsed = value!.receipt();
		expect(parsed.id).toBe('msg-1');
		expect(parsed.stat).toBe('DELIVRD');
		await readRaw(server); // consume the deliver_sm_resp
		await Promise.all([session.close(), readRaw(server)]);
	});
});

describe('smpp keep-alive and enquire_link', () => {
	it('emits an enquire_link when the injected keep-alive timer fires', async () => {
		let fired: (() => void) | null = null;
		const scheduler: SmppScheduler = {
			set: (fn) => {
				fired = fn;
				return 1;
			},
			clear: () => {
				fired = null;
			}
		};
		const { session, server } = await bound({ enquireLinkSeconds: 30, scheduler });
		expect(fired).not.toBeNull();
		const script = (async () => {
			expect(decodeHeader(await readRaw(server)).command).toBe(Command.EnquireLink);
		})();
		fired!();
		await script;
		await Promise.all([session.close(), readRaw(server)]);
	});

	it('answers a server-initiated enquire_link with a matching resp', async () => {
		const { session, server } = await bound();
		await server.write(encodeEmpty(Command.EnquireLink, 42));
		const pdu = decodePdu(await readRaw(server));
		expect(pdu.command).toBe(Command.EnquireLinkResp);
		expect(pdu.sequence).toBe(42);
		await Promise.all([session.close(), readRaw(server)]);
	});

	it('enquireLink() resolves when the resp arrives', async () => {
		const { session, server } = await bound();
		const script = (async () => {
			const header = decodeHeader(await readRaw(server));
			expect(header.command).toBe(Command.EnquireLink);
			await server.write(encodeEmpty(Command.EnquireLinkResp, header.sequence));
		})();
		await Promise.all([session.enquireLink(), script]);
		await Promise.all([session.close(), readRaw(server)]);
	});
});

describe('smpp unbind and close', () => {
	it('close sends unbind before closing the socket', async () => {
		const { session, server } = await bound();
		const [, raw] = await Promise.all([session.close(), readRaw(server)]);
		expect(decodeHeader(raw).command).toBe(Command.Unbind);
	});

	it('unbind() awaits the unbind_resp', async () => {
		const { session, server } = await bound();
		const script = (async () => {
			const header = decodeHeader(await readRaw(server));
			expect(header.command).toBe(Command.Unbind);
			await server.write(encodeEmpty(Command.UnbindResp, header.sequence));
		})();
		await Promise.all([session.unbind(), script]);
		await session.close();
	});

	it('ends the delivery stream when the smsc unbinds', async () => {
		const { session, server } = await bound();
		const iter = session.messages()[Symbol.asyncIterator]();
		await server.write(encodeEmpty(Command.Unbind, 100));
		// the client answers unbind_resp and ends deliveries
		const resp = decodePdu(await readRaw(server));
		expect(resp.command).toBe(Command.UnbindResp);
		const done = await iter.next();
		expect(done.done).toBe(true);
		await session.close();
	});
});
