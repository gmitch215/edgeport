import { describe, expect, it } from 'vitest';
import { AuthError, ProtocolError } from '../../src/core/errors';
import {
	_connectOverSocket,
	_connectOverTransport,
	_wsTransport,
	type MqttMessage,
	type MqttScheduler,
	type MqttSession
} from '../../src/mqtt';
import {
	decodePacket,
	decodeRemainingLength,
	encodeConnect,
	encodeDisconnect,
	encodePingReq,
	encodePublish,
	encodeRemainingLength,
	encodeSubscribe,
	encodeUnsubscribe,
	PacketType,
	type DecodedPacket
} from '../../src/mqtt/packet';
import type { WsConnection, WsMessage } from '../../src/ws';
import { mockConnection, type MockServerEnd } from '../mock-socket';

const enc = new TextEncoder();
const dec = new TextDecoder();

// reads one complete control packet off the mock server: fixed byte + length varint + body
async function readPacketFromServer(server: MockServerEnd): Promise<DecodedPacket> {
	const first = (await server.readN(1))[0]!;
	const lenBytes: number[] = [];
	for (let i = 0; i < 4; i++) {
		const b = (await server.readN(1))[0]!;
		lenBytes.push(b);
		if ((b & 0x80) === 0) break;
	}
	const rl = decodeRemainingLength(new Uint8Array(lenBytes), 0);
	const body = rl.value > 0 ? await server.readN(rl.value) : new Uint8Array(0);
	const packet = new Uint8Array(1 + lenBytes.length + body.length);
	packet[0] = first;
	packet.set(lenBytes, 1);
	packet.set(body, 1 + lenBytes.length);
	return decodePacket(packet);
}

// encodes a CONNACK the way a broker would (fixed header 0x20, 2-byte body)
function connack(returnCode: number, sessionPresent = false): Uint8Array {
	return new Uint8Array([0x20, 0x02, sessionPresent ? 0x01 : 0x00, returnCode]);
}

// encodes a SUBACK with the given granted qos codes
function suback(packetId: number, codes: number[]): Uint8Array {
	const body = [(packetId >> 8) & 0xff, packetId & 0xff, ...codes];
	return new Uint8Array([0x90, body.length, ...body]);
}

// encodes an UNSUBACK
function unsuback(packetId: number): Uint8Array {
	return new Uint8Array([0xb0, 0x02, (packetId >> 8) & 0xff, packetId & 0xff]);
}

// encodes a PUBACK
function puback(packetId: number): Uint8Array {
	return new Uint8Array([0x40, 0x02, (packetId >> 8) & 0xff, packetId & 0xff]);
}

// drives the broker side of a successful CONNECT/CONNACK and returns the decoded CONNECT
async function brokerHandshake(server: MockServerEnd): Promise<DecodedPacket> {
	const connect = await readPacketFromServer(server);
	await server.write(connack(0));
	return connect;
}

// connects through a successful handshake and returns the ready session + server end
async function connected(): Promise<{ session: MqttSession; server: MockServerEnd }> {
	const { socket, server } = mockConnection();
	const session = (
		await Promise.all([
			_connectOverSocket(socket, { hostname: 'broker.test', tls: 'off', keepAliveSeconds: 0 }),
			brokerHandshake(server)
		])
	)[0];
	return { session, server };
}

describe('mqtt remaining-length varint', () => {
	it('round-trips the documented boundary values', () => {
		for (const v of [0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455]) {
			const bytes = encodeRemainingLength(v);
			const decoded = decodeRemainingLength(bytes, 0);
			expect(decoded.value).toBe(v);
			expect(decoded.bytesUsed).toBe(bytes.length);
		}
	});

	it('uses the expected byte width at the multi-byte boundaries', () => {
		expect(encodeRemainingLength(127).length).toBe(1);
		expect(Array.from(encodeRemainingLength(128))).toEqual([0x80, 0x01]);
		expect(Array.from(encodeRemainingLength(16383))).toEqual([0xff, 0x7f]);
		expect(Array.from(encodeRemainingLength(16384))).toEqual([0x80, 0x80, 0x01]);
		expect(encodeRemainingLength(268435455).length).toBe(4);
	});

	it('rejects out-of-range and over-long varints', () => {
		expect(() => encodeRemainingLength(268435456)).toThrow(ProtocolError);
		expect(() => encodeRemainingLength(-1)).toThrow(ProtocolError);
		expect(() => decodeRemainingLength(new Uint8Array([0x80, 0x80, 0x80, 0x80]), 0)).toThrow(
			ProtocolError
		);
	});
});

describe('mqtt packet codec', () => {
	it('encodes CONNECT with protocol name, level, flags, keepalive, and credentials', () => {
		const bytes = encodeConnect({
			clientId: 'edge-1',
			keepAliveSeconds: 30,
			cleanSession: true,
			username: 'alice',
			password: 'hunter2'
		});
		expect(bytes[0]).toBe(0x10); // CONNECT type nibble, zero flags
		const rl = decodeRemainingLength(bytes, 1);
		const body = bytes.subarray(1 + rl.bytesUsed);
		// protocol name 'MQTT'
		expect(body[0]).toBe(0x00);
		expect(body[1]).toBe(0x04);
		expect(dec.decode(body.subarray(2, 6))).toBe('MQTT');
		// protocol level 4
		expect(body[6]).toBe(0x04);
		// connect flags: clean(0x02) + username(0x80) + password(0x40)
		expect(body[7]).toBe(0x02 | 0x80 | 0x40);
		// keepalive 30
		expect((body[8]! << 8) | body[9]!).toBe(30);
		// payload: clientId then username then password
		const clientLen = (body[10]! << 8) | body[11]!;
		expect(dec.decode(body.subarray(12, 12 + clientLen))).toBe('edge-1');
	});

	it('round-trips a qos0 PUBLISH with no packet id', () => {
		const bytes = encodePublish({ topic: 'a/b', payload: enc.encode('hi'), qos: 0 });
		const pkt = decodePacket(bytes);
		expect(pkt.type).toBe(PacketType.PUBLISH);
		if (pkt.type !== PacketType.PUBLISH) throw new Error('wrong type');
		expect(pkt.topic).toBe('a/b');
		expect(dec.decode(pkt.payload)).toBe('hi');
		expect(pkt.qos).toBe(0);
		expect(pkt.packetId).toBeUndefined();
	});

	it('round-trips a qos1 PUBLISH carrying a packet id', () => {
		const bytes = encodePublish({
			topic: 'a/b',
			payload: enc.encode('data'),
			qos: 1,
			packetId: 42,
			retain: true
		});
		const pkt = decodePacket(bytes);
		if (pkt.type !== PacketType.PUBLISH) throw new Error('wrong type');
		expect(pkt.qos).toBe(1);
		expect(pkt.packetId).toBe(42);
		expect(pkt.retain).toBe(true);
		expect(dec.decode(pkt.payload)).toBe('data');
	});

	it('round-trips SUBSCRIBE and decodes SUBACK', () => {
		const bytes = encodeSubscribe(7, [{ topicFilter: 'x/+/y', qos: 2 }]);
		expect(bytes[0]).toBe(0x82); // SUBSCRIBE type + reserved flags 0x2
		const ack = decodePacket(suback(7, [2]));
		if (ack.type !== PacketType.SUBACK) throw new Error('wrong type');
		expect(ack.packetId).toBe(7);
		expect(ack.returnCodes).toEqual([2]);
	});

	it('round-trips UNSUBSCRIBE and decodes UNSUBACK', () => {
		const bytes = encodeUnsubscribe(9, ['x/+/y']);
		expect(bytes[0]).toBe(0xa2); // UNSUBSCRIBE type + reserved flags 0x2
		const ack = decodePacket(unsuback(9));
		if (ack.type !== PacketType.UNSUBACK) throw new Error('wrong type');
		expect(ack.packetId).toBe(9);
	});

	it('encodes the fixed-header-only packets', () => {
		expect(Array.from(encodePingReq())).toEqual([0xc0, 0x00]);
		expect(Array.from(encodeDisconnect())).toEqual([0xe0, 0x00]);
		expect(decodePacket(new Uint8Array([0xd0, 0x00])).type).toBe(PacketType.PINGRESP);
		expect(decodePacket(new Uint8Array([0xc0, 0x00])).type).toBe(PacketType.PINGREQ);
	});

	it('decodes a v5-style CONNACK with trailing property bytes gracefully', () => {
		// v5 brokers append a property length + properties; we read only the first two body bytes
		const v5 = new Uint8Array([0x20, 0x03, 0x00, 0x00, 0x00]);
		const pkt = decodePacket(v5);
		if (pkt.type !== PacketType.CONNACK) throw new Error('wrong type');
		expect(pkt.returnCode).toBe(0);
	});
});

describe('mqtt connect handshake', () => {
	it('sends CONNECT then becomes ready on CONNACK rc0', async () => {
		const { socket, server } = mockConnection();
		let session!: MqttSession;
		const script = (async () => {
			const connect = await brokerHandshake(server);
			expect(connect.type).toBe(PacketType.CONNECT);
		})();
		session = (
			await Promise.all([
				_connectOverSocket(socket, {
					hostname: 'broker.test',
					tls: 'off',
					clientId: 'edge-1',
					keepAliveSeconds: 0
				}),
				script
			])
		)[0];
		await Promise.all([session.close(), readPacketFromServer(server)]);
	});

	it('maps CONNACK rc4 to AuthError', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			await readPacketFromServer(server);
			await server.write(connack(4));
		})();
		await expect(
			Promise.all([
				_connectOverSocket(socket, { hostname: 'broker.test', tls: 'off', keepAliveSeconds: 0 }),
				script
			])
		).rejects.toBeInstanceOf(AuthError);
	});

	it('maps CONNACK rc5 to AuthError', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			await readPacketFromServer(server);
			await server.write(connack(5));
		})();
		await expect(
			Promise.all([
				_connectOverSocket(socket, { hostname: 'broker.test', tls: 'off', keepAliveSeconds: 0 }),
				script
			])
		).rejects.toBeInstanceOf(AuthError);
	});

	it('maps another non-zero CONNACK to ProtocolError', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			await readPacketFromServer(server);
			await server.write(connack(2)); // identifier rejected
		})();
		await expect(
			Promise.all([
				_connectOverSocket(socket, { hostname: 'broker.test', tls: 'off', keepAliveSeconds: 0 }),
				script
			])
		).rejects.toBeInstanceOf(ProtocolError);
	});
});

describe('mqtt publish', () => {
	it('sends a qos0 PUBLISH with no ack expected', async () => {
		const { socket, server } = mockConnection();
		const session = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'broker.test', tls: 'off', keepAliveSeconds: 0 }),
				brokerHandshake(server)
			])
		)[0];

		const pubScript = (async () => {
			const pkt = await readPacketFromServer(server);
			if (pkt.type !== PacketType.PUBLISH) throw new Error('wrong type');
			expect(pkt.topic).toBe('a/b');
			expect(dec.decode(pkt.payload)).toBe('hello');
			expect(pkt.qos).toBe(0);
			expect(pkt.packetId).toBeUndefined();
		})();
		await Promise.all([session.publish('a/b', 'hello'), pubScript]);
		await Promise.all([session.close(), readPacketFromServer(server)]);
	});

	it('resolves a qos1 PUBLISH only after the PUBACK arrives', async () => {
		const { socket, server } = mockConnection();
		const session = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'broker.test', tls: 'off', keepAliveSeconds: 0 }),
				brokerHandshake(server)
			])
		)[0];

		const pubScript = (async () => {
			const pkt = await readPacketFromServer(server);
			if (pkt.type !== PacketType.PUBLISH) throw new Error('wrong type');
			expect(pkt.qos).toBe(1);
			expect(pkt.packetId).toBeDefined();
			await server.write(puback(pkt.packetId!));
		})();
		await Promise.all([session.publish('a/b', 'data', { qos: 1 }), pubScript]);
		await Promise.all([session.close(), readPacketFromServer(server)]);
	});
});

describe('mqtt subscribe and delivery', () => {
	it('subscribes, receives SUBACK, then delivers a PUBLISH via the iterator', async () => {
		const { socket, server } = mockConnection();
		const session = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'broker.test', tls: 'off', keepAliveSeconds: 0 }),
				brokerHandshake(server)
			])
		)[0];

		const sub = session.subscribe('sensors/+/temp', { qos: 1 });
		expect(sub.topicFilter).toBe('sensors/+/temp');

		// read the SUBSCRIBE, ack it, then push a matching PUBLISH
		const subPkt = await readPacketFromServer(server);
		if (subPkt.type !== PacketType.SUBSCRIBE) throw new Error('wrong type');
		expect(subPkt.subscriptions[0]!.topicFilter).toBe('sensors/+/temp');
		expect(subPkt.subscriptions[0]!.qos).toBe(1);
		// echo the SUBACK with the id the client allocated
		await server.write(suback(subPkt.packetId, [1]));

		// server publishes a qos1 message on the topic
		await server.write(
			encodePublish({ topic: 'sensors/9/temp', payload: enc.encode('21.5'), qos: 1, packetId: 100 })
		);

		const iter = sub[Symbol.asyncIterator]();
		const first = await iter.next();
		expect(first.done).toBe(false);
		expect(first.value.topic).toBe('sensors/9/temp');
		expect(dec.decode(first.value.payload)).toBe('21.5');
		expect(first.value.qos).toBe(1);

		// the client must PUBACK the inbound qos1 publish
		const ackBack = await readPacketFromServer(server);
		expect(ackBack.type).toBe(PacketType.PUBACK);

		await Promise.all([session.close(), readPacketFromServer(server)]);
	});
});

describe('mqtt keep-alive', () => {
	it('emits a PINGREQ on the wire when the injected interval fires', async () => {
		const { socket, server } = mockConnection();
		// a controllable scheduler: capture the callback so the test can fire it
		let fired: (() => void) | null = null;
		const scheduler: MqttScheduler = {
			set: (fn) => {
				fired = fn;
				return 1;
			},
			clear: () => {
				fired = null;
			}
		};

		const session = (
			await Promise.all([
				_connectOverSocket(socket, {
					hostname: 'broker.test',
					tls: 'off',
					keepAliveSeconds: 1,
					scheduler
				}),
				brokerHandshake(server)
			])
		)[0];

		expect(fired).not.toBeNull();
		const pingScript = (async () => {
			const pkt = await readPacketFromServer(server);
			expect(pkt.type).toBe(PacketType.PINGREQ);
		})();
		fired!(); // drive the keep-alive tick
		await pingScript;

		await Promise.all([session.close(), readPacketFromServer(server)]);
	});
});

describe('mqtt publishJson', () => {
	it('serializes the value to JSON and PUBLISHes it as UTF-8 (qos0)', async () => {
		const { session, server } = await connected();
		const value = { temp: 21.5 };
		const json = JSON.stringify(value);

		const pubScript = (async () => {
			const pkt = await readPacketFromServer(server);
			if (pkt.type !== PacketType.PUBLISH) throw new Error('wrong type');
			expect(pkt.topic).toBe('sensors/1');
			expect(dec.decode(pkt.payload)).toBe(json);
			expect(pkt.qos).toBe(0);
		})();
		await Promise.all([session.publishJson('sensors/1', value), pubScript]);
		await Promise.all([session.close(), readPacketFromServer(server)]);
	});
});

describe('mqtt message json() / text()', () => {
	it('decodes a delivered payload as text and as JSON', async () => {
		const { session, server } = await connected();
		const sub = session.subscribe('sensors/+', { qos: 0 });

		const subPkt = await readPacketFromServer(server);
		if (subPkt.type !== PacketType.SUBSCRIBE) throw new Error('wrong type');
		await server.write(suback(subPkt.packetId, [0]));
		await server.write(
			encodePublish({ topic: 'sensors/9', payload: enc.encode('{"v":42}'), qos: 0 })
		);

		const iter = sub[Symbol.asyncIterator]();
		const msg: MqttMessage = (await iter.next()).value;
		expect(msg.text()).toBe('{"v":42}');
		expect(msg.json<{ v: number }>()).toEqual({ v: 42 });

		await Promise.all([session.close(), readPacketFromServer(server)]);
	});

	it('json() throws ProtocolError on a non-JSON payload', async () => {
		const { session, server } = await connected();
		const sub = session.subscribe('raw', { qos: 0 });

		const subPkt = await readPacketFromServer(server);
		if (subPkt.type !== PacketType.SUBSCRIBE) throw new Error('wrong type');
		await server.write(suback(subPkt.packetId, [0]));
		await server.write(encodePublish({ topic: 'raw', payload: enc.encode('<<bad>>'), qos: 0 }));

		const iter = sub[Symbol.asyncIterator]();
		const msg: MqttMessage = (await iter.next()).value;
		expect(msg.text()).toBe('<<bad>>');
		expect(() => msg.json()).toThrow(ProtocolError);

		await Promise.all([session.close(), readPacketFromServer(server)]);
	});
});

describe('mqtt subscribeJson', () => {
	it('yields { topic, value } with the payload parsed', async () => {
		const { session, server } = await connected();
		const sub = session.subscribeJson<{ id: number }>('sensors/+', { qos: 0 });

		const subPkt = await readPacketFromServer(server);
		if (subPkt.type !== PacketType.SUBSCRIBE) throw new Error('wrong type');
		expect(subPkt.subscriptions[0]!.topicFilter).toBe('sensors/+');
		await server.write(suback(subPkt.packetId, [0]));
		await server.write(
			encodePublish({ topic: 'sensors/3', payload: enc.encode('{"id":3}'), qos: 0 })
		);

		const iter = sub[Symbol.asyncIterator]();
		const { value } = await iter.next();
		expect(value).toEqual({ topic: 'sensors/3', value: { id: 3 } });

		await Promise.all([session.close(), readPacketFromServer(server)]);
	});
});

// broker-side encoders for the id-only ack packets
function pubrec(id: number): Uint8Array {
	return new Uint8Array([0x50, 0x02, (id >> 8) & 0xff, id & 0xff]);
}
function pubrel(id: number): Uint8Array {
	return new Uint8Array([0x62, 0x02, (id >> 8) & 0xff, id & 0xff]);
}
function pubcomp(id: number): Uint8Array {
	return new Uint8Array([0x70, 0x02, (id >> 8) & 0xff, id & 0xff]);
}

describe('mqtt qos2 publish (sender handshake)', () => {
	it('sends PUBLISH, releases on PUBREC, and resolves on PUBCOMP', async () => {
		const { session, server } = await connected();
		const pubScript = (async () => {
			const pub = await readPacketFromServer(server);
			if (pub.type !== PacketType.PUBLISH) throw new Error('wrong type');
			expect(pub.qos).toBe(2);
			const id = pub.packetId!;
			await server.write(pubrec(id));
			const rel = await readPacketFromServer(server);
			expect(rel.type).toBe(PacketType.PUBREL);
			await server.write(pubcomp(id));
		})();
		await Promise.all([session.publish('a/b', 'data', { qos: 2 }), pubScript]);
		await Promise.all([session.close(), readPacketFromServer(server)]);
	});
});

describe('mqtt qos2 delivery (receiver handshake)', () => {
	it('answers an inbound qos2 PUBLISH with PUBREC then PUBCOMP', async () => {
		const { session, server } = await connected();
		const sub = session.subscribe('s/#', { qos: 2 });
		const subPkt = await readPacketFromServer(server);
		if (subPkt.type !== PacketType.SUBSCRIBE) throw new Error('wrong type');
		await server.write(suback(subPkt.packetId, [2]));

		await server.write(
			encodePublish({ topic: 's/x', payload: enc.encode('q2'), qos: 2, packetId: 77 })
		);
		const rec = await readPacketFromServer(server);
		expect(rec.type).toBe(PacketType.PUBREC);
		await server.write(pubrel(77));
		const comp = await readPacketFromServer(server);
		expect(comp.type).toBe(PacketType.PUBCOMP);

		const first = await sub[Symbol.asyncIterator]().next();
		expect(first.value.topic).toBe('s/x');
		expect(first.value.qos).toBe(2);
		expect(first.value.text()).toBe('q2');

		await Promise.all([session.close(), readPacketFromServer(server)]);
	});
});

describe('mqtt broker-initiated frames', () => {
	it('ignores a PINGRESP and keeps working', async () => {
		const { session, server } = await connected();
		await server.write(new Uint8Array([0xd0, 0x00])); // PINGRESP
		const pubScript = (async () => {
			const pkt = await readPacketFromServer(server);
			expect(pkt.type).toBe(PacketType.PUBLISH);
		})();
		await Promise.all([session.publish('a/b', 'x'), pubScript]);
		await Promise.all([session.close(), readPacketFromServer(server)]);
	});

	it('ends subscriptions on a broker DISCONNECT', async () => {
		const { session, server } = await connected();
		const sub = session.subscribe('t/#', { qos: 0 });
		const subPkt = await readPacketFromServer(server);
		if (subPkt.type !== PacketType.SUBSCRIBE) throw new Error('wrong type');
		await server.write(suback(subPkt.packetId, [0]));

		await server.write(new Uint8Array([0xe0, 0x00])); // broker DISCONNECT
		const done = await sub[Symbol.asyncIterator]().next();
		expect(done.done).toBe(true);
		await Promise.all([session.close(), readPacketFromServer(server)]);
	});

	it('errors the pump on an unexpected packet type from the broker', async () => {
		const { session, server } = await connected();
		const sub = session.subscribe('t', { qos: 0 });
		const subPkt = await readPacketFromServer(server);
		if (subPkt.type !== PacketType.SUBSCRIBE) throw new Error('wrong type');
		await server.write(suback(subPkt.packetId, [0]));

		// a PINGREQ is only ever client->broker; receiving one is a protocol violation
		await server.write(new Uint8Array([0xc0, 0x00]));
		const done = await sub[Symbol.asyncIterator]().next();
		expect(done.done).toBe(true);
		await expect(session.publish('a/b', 'x')).rejects.toBeInstanceOf(ProtocolError);
	});
});

// builds a WsMessage of either kind (the transport only reads `type` / `data`)
function binFrame(data: Uint8Array): WsMessage {
	return {
		type: 'binary',
		data,
		text: () => dec.decode(data),
		json: () => JSON.parse(dec.decode(data))
	};
}
function textFrame(s: string): WsMessage {
	return { type: 'text', data: s, text: () => s, json: () => JSON.parse(s) };
}

describe('mqtt over websocket transport', () => {
	// a controllable fake WsConnection that yields queued frames and captures sent bytes
	function fakeWs(): {
		ws: WsConnection;
		sent: Uint8Array[];
		push: (m: WsMessage) => void;
		closedFlag: () => boolean;
	} {
		const queue: WsMessage[] = [];
		const sent: Uint8Array[] = [];
		let closed = false;
		let waiter: ((r: IteratorResult<WsMessage>) => void) | null = null;
		const push = (m: WsMessage): void => {
			if (waiter) {
				waiter({ value: m, done: false });
				waiter = null;
			} else queue.push(m);
		};
		const ws = {
			send: (d: string | Uint8Array) => sent.push(typeof d === 'string' ? enc.encode(d) : d),
			sendJson: () => {},
			close: () => {
				closed = true;
				if (waiter) {
					waiter({ value: undefined, done: true });
					waiter = null;
				}
			},
			closed: Promise.resolve({ code: 1000, reason: '' }),
			[Symbol.asyncIterator](): AsyncIterator<WsMessage> {
				return {
					next: () => {
						const m = queue.shift();
						if (m) return Promise.resolve({ value: m, done: false });
						if (closed) return Promise.resolve({ value: undefined, done: true });
						return new Promise((resolve) => (waiter = resolve));
					}
				};
			},
			[Symbol.asyncDispose]: () => Promise.resolve()
		} as unknown as WsConnection;
		return { ws, sent, push, closedFlag: () => closed };
	}

	it('runs the CONNECT/CONNACK handshake over binary frames (ignoring text frames)', async () => {
		const { ws, sent, push } = fakeWs();
		const transport = _wsTransport(ws);
		const sessionP = _connectOverTransport(transport, { hostname: '', keepAliveSeconds: 0 });
		// let the CONNECT get written before feeding the reply
		await Promise.resolve();
		push(textFrame('ignored')); // non-binary frames are skipped
		push(binFrame(connack(0)));
		const session = await sessionP;

		// the client wrote a CONNECT as the first binary frame
		expect(sent.length).toBeGreaterThan(0);
		expect(decodePacket(sent[0]!).type).toBe(PacketType.CONNECT);

		await session.close();
	});

	it('reassembles a packet split across two binary frames', async () => {
		const { ws, push } = fakeWs();
		const transport = _wsTransport(ws);
		const sessionP = _connectOverTransport(transport, { hostname: '', keepAliveSeconds: 0 });
		await Promise.resolve();
		const ca = connack(0);
		push(binFrame(ca.subarray(0, 1))); // fixed header only
		push(binFrame(ca.subarray(1))); // remaining bytes
		const session = await sessionP;
		await session.close();
	});
});
