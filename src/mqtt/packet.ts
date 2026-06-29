/**
 * @fileoverview The MQTT v3.1.1 control-packet codec.
 *
 * MQTT frames every control packet the same way: a fixed header (a one-byte type nibble plus a
 * flags nibble, then a remaining-length varint of up to four bytes), followed by a variable header
 * and an optional payload. This module is pure (no I/O): it encodes CONNECT, PUBLISH, SUBSCRIBE,
 * and friends into `Uint8Array`s and decodes a buffered packet back into a tagged union, leaving
 * all transport and session concerns to {@link module:mqtt}. It accepts a v5-style CONNACK
 * gracefully so a v5 broker that answers a v3.1.1 CONNECT does not break the handshake.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { ProtocolError } from '../core';

const PROTO = 'mqtt';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** The largest value a four-byte MQTT remaining-length varint can hold (`0xFF,0xFF,0xFF,0x7F`). */
export const MAX_REMAINING_LENGTH = 268435455;

/**
 * The MQTT control packet type, as carried in the high nibble of the fixed header.
 *
 * Each member's numeric value is the on-the-wire packet-type code. The codec switches on these
 * to choose an encoder or decoder, so they double as a stable, readable tag for callers.
 *
 * @since 1.0.0
 */
export enum PacketType {
	/** Client request to connect to a broker. */
	CONNECT = 1,
	/** Broker acknowledgement of a connect request. */
	CONNACK = 2,
	/** Publish message (either direction). */
	PUBLISH = 3,
	/** QoS 1 publish acknowledgement. */
	PUBACK = 4,
	/** QoS 2 publish received (part 1 of the QoS 2 handshake). */
	PUBREC = 5,
	/** QoS 2 publish release (part 2 of the QoS 2 handshake). */
	PUBREL = 6,
	/** QoS 2 publish complete (part 3 of the QoS 2 handshake). */
	PUBCOMP = 7,
	/** Client subscribe request. */
	SUBSCRIBE = 8,
	/** Broker subscribe acknowledgement. */
	SUBACK = 9,
	/** Client unsubscribe request. */
	UNSUBSCRIBE = 10,
	/** Broker unsubscribe acknowledgement. */
	UNSUBACK = 11,
	/** Keep-alive ping request. */
	PINGREQ = 12,
	/** Keep-alive ping response. */
	PINGRESP = 13,
	/** Graceful disconnect notification. */
	DISCONNECT = 14
}

/** Fields needed to build a CONNECT packet. */
export interface ConnectOptions {
	/** Client identifier; may be empty when the broker assigns one (requires `cleanSession`). */
	clientId: string;
	/** Keep-alive interval in seconds advertised to the broker (0 disables it). */
	keepAliveSeconds: number;
	/** Whether the broker should discard any prior session state for this client. */
	cleanSession: boolean;
	/** Optional username for credential auth. */
	username?: string;
	/** Optional password; encoded as bytes (a string is treated as UTF-8). */
	password?: string | Uint8Array;
}

/** Fields needed to build a PUBLISH packet. */
export interface PublishOptions {
	/** The topic the message is published to. */
	topic: string;
	/** The message body. */
	payload: Uint8Array;
	/** Quality-of-service level (0, 1, or 2). */
	qos: 0 | 1 | 2;
	/** Whether the broker should retain the message as the topic's last-known value. */
	retain?: boolean;
	/** Whether this is a redelivery of an earlier PUBLISH (the DUP flag). */
	dup?: boolean;
	/** Packet identifier; required for QoS 1 and 2, ignored for QoS 0. */
	packetId?: number;
}

/** One topic filter plus its requested maximum QoS, as carried in a SUBSCRIBE. */
export interface Subscription {
	/** The topic filter (may contain `+` / `#` wildcards). */
	topicFilter: string;
	/** The maximum QoS the client wants the broker to deliver at. */
	qos: 0 | 1 | 2;
}

/**
 * A decoded MQTT control packet, as a tag-on-`type` discriminated union.
 *
 * {@link decodePacket} returns one of these; branch on `type` (a {@link PacketType}) to read the
 * packet-specific fields. Packets with no body beyond the fixed header (PINGREQ, PINGRESP,
 * DISCONNECT) carry only their `type`.
 *
 * @since 1.0.0
 */
export type DecodedPacket =
	| {
			type: PacketType.CONNECT;
			protocolName: string;
			protocolLevel: number;
			cleanSession: boolean;
			keepAliveSeconds: number;
			clientId: string;
			username?: string;
			password?: Uint8Array;
	  }
	| { type: PacketType.CONNACK; sessionPresent: boolean; returnCode: number }
	| {
			type: PacketType.PUBLISH;
			topic: string;
			payload: Uint8Array;
			qos: 0 | 1 | 2;
			retain: boolean;
			dup: boolean;
			packetId?: number;
	  }
	| { type: PacketType.PUBACK; packetId: number }
	| { type: PacketType.PUBREC; packetId: number }
	| { type: PacketType.PUBREL; packetId: number }
	| { type: PacketType.PUBCOMP; packetId: number }
	| { type: PacketType.SUBSCRIBE; packetId: number; subscriptions: Subscription[] }
	| { type: PacketType.SUBACK; packetId: number; returnCodes: number[] }
	| { type: PacketType.UNSUBSCRIBE; packetId: number; topicFilters: string[] }
	| { type: PacketType.UNSUBACK; packetId: number }
	| { type: PacketType.PINGREQ }
	| { type: PacketType.PINGRESP }
	| { type: PacketType.DISCONNECT };

/**
 * Encodes an MQTT remaining-length value as a 1-4 byte varint.
 *
 * MQTT uses a base-128 varint with the high bit of each byte signalling continuation, capping the
 * value at {@link MAX_REMAINING_LENGTH}. This is the length prefix on every fixed header and is
 * the most error-prone part of the wire format, so it lives in its own well-tested function.
 *
 * @param value - A non-negative integer no larger than {@link MAX_REMAINING_LENGTH}.
 * @returns The encoded bytes (1-4 of them).
 * @throws {ProtocolError} If `value` is negative or exceeds the maximum.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { encodeRemainingLength } from 'edgeport/mqtt';
 *
 * encodeRemainingLength(0); // Uint8Array [0x00]
 * encodeRemainingLength(127); // Uint8Array [0x7f]
 * encodeRemainingLength(128); // Uint8Array [0x80, 0x01]
 * ```
 */
export function encodeRemainingLength(value: number): Uint8Array {
	if (!Number.isInteger(value) || value < 0 || value > MAX_REMAINING_LENGTH) {
		throw new ProtocolError(`remaining length out of range: ${value}`, { protocol: PROTO });
	}
	const out: number[] = [];
	let x = value;
	do {
		let byte = x % 128;
		x = Math.floor(x / 128);
		// set continuation bit while more digits remain
		if (x > 0) byte |= 0x80;
		out.push(byte);
	} while (x > 0);
	return new Uint8Array(out);
}

/** The result of decoding a remaining-length varint: its value and how many bytes it spanned. */
export interface RemainingLength {
	/** The decoded length value. */
	value: number;
	/** Number of bytes the varint occupied (1-4). */
	bytesUsed: number;
}

/**
 * Decodes an MQTT remaining-length varint starting at `offset`.
 *
 * Reads up to four continuation-flagged bytes and reconstructs the base-128 value, returning both
 * the value and how many bytes it consumed so the caller can advance its cursor. Rejects a varint
 * longer than four bytes, which would exceed {@link MAX_REMAINING_LENGTH}.
 *
 * @param bytes - The buffer to read from.
 * @param offset - Index of the first varint byte; defaults to 0.
 * @returns The decoded value and its byte length.
 * @throws {ProtocolError} If the varint runs past the buffer or exceeds four bytes.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { decodeRemainingLength } from 'edgeport/mqtt';
 *
 * decodeRemainingLength(new Uint8Array([0x80, 0x01])); // { value: 128, bytesUsed: 2 }
 * ```
 */
export function decodeRemainingLength(bytes: Uint8Array, offset = 0): RemainingLength {
	let value = 0;
	let multiplier = 1;
	let i = offset;
	for (let count = 0; count < 4; count++) {
		const byte = bytes[i];
		if (byte === undefined) {
			throw new ProtocolError('remaining length ran past end of buffer', { protocol: PROTO });
		}
		i++;
		value += (byte & 0x7f) * multiplier;
		if ((byte & 0x80) === 0) {
			return { value, bytesUsed: i - offset };
		}
		multiplier *= 128;
	}
	throw new ProtocolError('remaining length exceeded four bytes', { protocol: PROTO });
}

// length-prefixed UTF-8 string: two big-endian length bytes then the bytes
function encodeString(s: string): Uint8Array {
	const body = encoder.encode(s);
	if (body.length > 0xffff) {
		throw new ProtocolError(`mqtt string too long: ${body.length} bytes`, { protocol: PROTO });
	}
	const out = new Uint8Array(2 + body.length);
	out[0] = (body.length >> 8) & 0xff;
	out[1] = body.length & 0xff;
	out.set(body, 2);
	return out;
}

// two-byte big-endian length prefix over arbitrary bytes (password payload)
function encodeBinary(bytes: Uint8Array): Uint8Array {
	if (bytes.length > 0xffff) {
		throw new ProtocolError(`mqtt binary field too long: ${bytes.length} bytes`, {
			protocol: PROTO
		});
	}
	const out = new Uint8Array(2 + bytes.length);
	out[0] = (bytes.length >> 8) & 0xff;
	out[1] = bytes.length & 0xff;
	out.set(bytes, 2);
	return out;
}

// reads a two-byte length-prefixed UTF-8 string; returns it and the new cursor
function readString(bytes: Uint8Array, offset: number): { value: string; next: number } {
	const hi = bytes[offset];
	const lo = bytes[offset + 1];
	if (hi === undefined || lo === undefined) {
		throw new ProtocolError('string length ran past end of buffer', { protocol: PROTO });
	}
	const len = (hi << 8) | lo;
	const start = offset + 2;
	const end = start + len;
	if (end > bytes.length) {
		throw new ProtocolError('string body ran past end of buffer', { protocol: PROTO });
	}
	return { value: decoder.decode(bytes.subarray(start, end)), next: end };
}

// reads a two-byte big-endian packet identifier; returns it and the new cursor
function readUint16(bytes: Uint8Array, offset: number): { value: number; next: number } {
	const hi = bytes[offset];
	const lo = bytes[offset + 1];
	if (hi === undefined || lo === undefined) {
		throw new ProtocolError('uint16 ran past end of buffer', { protocol: PROTO });
	}
	return { value: (hi << 8) | lo, next: offset + 2 };
}

// wraps a variable-header+payload body in its fixed header (type nibble, flags, length varint)
function frame(type: PacketType, flags: number, body: Uint8Array): Uint8Array {
	const length = encodeRemainingLength(body.length);
	const out = new Uint8Array(1 + length.length + body.length);
	out[0] = ((type & 0x0f) << 4) | (flags & 0x0f);
	out.set(length, 1);
	out.set(body, 1 + length.length);
	return out;
}

// concatenates byte chunks into one buffer
function concat(chunks: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const c of chunks) total += c.length;
	const out = new Uint8Array(total);
	let at = 0;
	for (const c of chunks) {
		out.set(c, at);
		at += c.length;
	}
	return out;
}

/**
 * Encodes a CONNECT packet for MQTT v3.1.1.
 *
 * Writes the fixed protocol name `MQTT`, protocol level 4, the connect-flags byte (clean session,
 * and the username/password presence bits), the keep-alive, and the payload (client id, then any
 * username and password). Lean on TLS for confidentiality; the credentials travel in cleartext
 * inside this packet.
 *
 * @param opts - The client id, keep-alive, clean-session flag, and optional credentials.
 * @returns The complete CONNECT packet bytes.
 * @throws {ProtocolError} If a field exceeds the wire size limits.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { encodeConnect } from 'edgeport/mqtt';
 *
 * const bytes = encodeConnect({ clientId: 'edge-1', keepAliveSeconds: 60, cleanSession: true });
 * ```
 */
export function encodeConnect(opts: ConnectOptions): Uint8Array {
	let flags = 0;
	if (opts.cleanSession) flags |= 0x02;
	if (opts.username !== undefined) flags |= 0x80;
	if (opts.password !== undefined) flags |= 0x40;

	const keepAlive = opts.keepAliveSeconds & 0xffff;
	const header = new Uint8Array([(keepAlive >> 8) & 0xff, keepAlive & 0xff]);

	const chunks: Uint8Array[] = [
		encodeString('MQTT'),
		new Uint8Array([0x04]), // protocol level 4 (v3.1.1)
		new Uint8Array([flags]),
		header,
		encodeString(opts.clientId)
	];
	if (opts.username !== undefined) chunks.push(encodeString(opts.username));
	if (opts.password !== undefined) {
		const pw = typeof opts.password === 'string' ? encoder.encode(opts.password) : opts.password;
		chunks.push(encodeBinary(pw));
	}
	return frame(PacketType.CONNECT, 0, concat(chunks));
}

/**
 * Encodes a PUBLISH packet.
 *
 * Places the topic in the variable header, then a packet identifier when `qos >= 1`, then the raw
 * payload. The QoS, retain, and DUP bits go into the fixed-header flags nibble. A QoS 1 or 2
 * publish must supply `packetId`; QoS 0 must not include one.
 *
 * @param opts - Topic, payload, QoS, and optional retain/dup/packetId.
 * @returns The complete PUBLISH packet bytes.
 * @throws {ProtocolError} If `qos >= 1` without a `packetId`.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { encodePublish } from 'edgeport/mqtt';
 *
 * const enc = new TextEncoder();
 * const qos0 = encodePublish({ topic: 'a/b', payload: enc.encode('hi'), qos: 0 });
 * const qos1 = encodePublish({ topic: 'a/b', payload: enc.encode('hi'), qos: 1, packetId: 7 });
 * ```
 */
export function encodePublish(opts: PublishOptions): Uint8Array {
	let flags = 0;
	if (opts.dup) flags |= 0x08;
	flags |= (opts.qos & 0x03) << 1;
	if (opts.retain) flags |= 0x01;

	const chunks: Uint8Array[] = [encodeString(opts.topic)];
	if (opts.qos > 0) {
		if (opts.packetId === undefined) {
			throw new ProtocolError('qos >= 1 publish requires a packet id', { protocol: PROTO });
		}
		chunks.push(new Uint8Array([(opts.packetId >> 8) & 0xff, opts.packetId & 0xff]));
	}
	chunks.push(opts.payload);
	return frame(PacketType.PUBLISH, flags, concat(chunks));
}

// shared encoder for the four two-byte-id ack packets (PUBACK/PUBREC/PUBREL/PUBCOMP)
function encodeIdAck(type: PacketType, packetId: number, flags: number): Uint8Array {
	return frame(type, flags, new Uint8Array([(packetId >> 8) & 0xff, packetId & 0xff]));
}

/**
 * Encodes a PUBACK packet (the QoS 1 acknowledgement).
 *
 * @param packetId - The packet identifier of the PUBLISH being acknowledged.
 * @returns The PUBACK bytes.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { encodePubAck } from 'edgeport/mqtt';
 *
 * const bytes = encodePubAck(7);
 * ```
 */
export function encodePubAck(packetId: number): Uint8Array {
	return encodeIdAck(PacketType.PUBACK, packetId, 0);
}

/**
 * Encodes a PUBREC packet (QoS 2, part 1: publish received).
 *
 * @param packetId - The packet identifier of the PUBLISH being received.
 * @returns The PUBREC bytes.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { encodePubRec } from 'edgeport/mqtt';
 *
 * const bytes = encodePubRec(7);
 * ```
 */
export function encodePubRec(packetId: number): Uint8Array {
	return encodeIdAck(PacketType.PUBREC, packetId, 0);
}

/**
 * Encodes a PUBREL packet (QoS 2, part 2: publish release).
 *
 * PUBREL carries a reserved flags nibble of `0x2` per the spec, unlike the other id-only acks.
 *
 * @param packetId - The packet identifier being released.
 * @returns The PUBREL bytes.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { encodePubRel } from 'edgeport/mqtt';
 *
 * const bytes = encodePubRel(7);
 * ```
 */
export function encodePubRel(packetId: number): Uint8Array {
	return encodeIdAck(PacketType.PUBREL, packetId, 0x02);
}

/**
 * Encodes a PUBCOMP packet (QoS 2, part 3: publish complete).
 *
 * @param packetId - The packet identifier being completed.
 * @returns The PUBCOMP bytes.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { encodePubComp } from 'edgeport/mqtt';
 *
 * const bytes = encodePubComp(7);
 * ```
 */
export function encodePubComp(packetId: number): Uint8Array {
	return encodeIdAck(PacketType.PUBCOMP, packetId, 0);
}

/**
 * Encodes a SUBSCRIBE packet.
 *
 * Begins with the packet identifier, then a list of (topic filter, requested-QoS) pairs. The
 * fixed-header flags nibble is the spec-mandated `0x2`.
 *
 * @param packetId - A non-zero packet identifier the matching SUBACK will echo.
 * @param subscriptions - One or more topic filters with their requested maximum QoS.
 * @returns The SUBSCRIBE bytes.
 * @throws {ProtocolError} If no subscriptions are supplied.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { encodeSubscribe } from 'edgeport/mqtt';
 *
 * const bytes = encodeSubscribe(1, [{ topicFilter: 'sensors/+/temp', qos: 1 }]);
 * ```
 */
export function encodeSubscribe(packetId: number, subscriptions: Subscription[]): Uint8Array {
	if (subscriptions.length === 0) {
		throw new ProtocolError('subscribe requires at least one topic filter', { protocol: PROTO });
	}
	const chunks: Uint8Array[] = [new Uint8Array([(packetId >> 8) & 0xff, packetId & 0xff])];
	for (const sub of subscriptions) {
		chunks.push(encodeString(sub.topicFilter));
		chunks.push(new Uint8Array([sub.qos & 0x03]));
	}
	return frame(PacketType.SUBSCRIBE, 0x02, concat(chunks));
}

/**
 * Encodes an UNSUBSCRIBE packet.
 *
 * Begins with the packet identifier, then a list of topic filters to remove. The fixed-header
 * flags nibble is the spec-mandated `0x2`.
 *
 * @param packetId - A non-zero packet identifier the matching UNSUBACK will echo.
 * @param topicFilters - One or more topic filters to unsubscribe from.
 * @returns The UNSUBSCRIBE bytes.
 * @throws {ProtocolError} If no topic filters are supplied.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { encodeUnsubscribe } from 'edgeport/mqtt';
 *
 * const bytes = encodeUnsubscribe(2, ['sensors/+/temp']);
 * ```
 */
export function encodeUnsubscribe(packetId: number, topicFilters: string[]): Uint8Array {
	if (topicFilters.length === 0) {
		throw new ProtocolError('unsubscribe requires at least one topic filter', { protocol: PROTO });
	}
	const chunks: Uint8Array[] = [new Uint8Array([(packetId >> 8) & 0xff, packetId & 0xff])];
	for (const filter of topicFilters) chunks.push(encodeString(filter));
	return frame(PacketType.UNSUBSCRIBE, 0x02, concat(chunks));
}

/**
 * Encodes a PINGREQ packet (keep-alive request).
 *
 * @returns The two-byte PINGREQ packet.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { encodePingReq } from 'edgeport/mqtt';
 *
 * const bytes = encodePingReq(); // Uint8Array [0xc0, 0x00]
 * ```
 */
export function encodePingReq(): Uint8Array {
	return frame(PacketType.PINGREQ, 0, new Uint8Array(0));
}

/**
 * Encodes a DISCONNECT packet (graceful close notification).
 *
 * @returns The two-byte DISCONNECT packet.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { encodeDisconnect } from 'edgeport/mqtt';
 *
 * const bytes = encodeDisconnect(); // Uint8Array [0xe0, 0x00]
 * ```
 */
export function encodeDisconnect(): Uint8Array {
	return frame(PacketType.DISCONNECT, 0, new Uint8Array(0));
}

/**
 * Decodes one complete MQTT control packet from a buffer.
 *
 * Reads the fixed header, then dispatches on the packet type to parse the variable header and
 * payload, returning a {@link DecodedPacket} discriminated on `type`. The buffer must hold exactly
 * one full packet starting at offset 0; callers framing a stream should use
 * {@link decodeRemainingLength} to size each packet before slicing it out. A CONNACK is decoded
 * loosely so a v5 broker's extra trailing bytes (properties) are ignored rather than rejected.
 *
 * @param bytes - A buffer beginning with a single complete packet.
 * @returns The decoded packet.
 * @throws {ProtocolError} If the header is malformed or the type is unsupported.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { decodePacket, PacketType } from 'edgeport/mqtt';
 *
 * const pkt = decodePacket(new Uint8Array([0x20, 0x02, 0x00, 0x00]));
 * if (pkt.type === PacketType.CONNACK) console.log(pkt.returnCode); // 0
 * ```
 */
export function decodePacket(bytes: Uint8Array): DecodedPacket {
	const first = bytes[0];
	if (first === undefined) {
		throw new ProtocolError('cannot decode an empty packet', { protocol: PROTO });
	}
	const type = (first >> 4) as PacketType;
	const flags = first & 0x0f;
	const rl = decodeRemainingLength(bytes, 1);
	const start = 1 + rl.bytesUsed;
	const body = bytes.subarray(start, start + rl.value);

	switch (type) {
		case PacketType.CONNECT: {
			const name = readString(body, 0);
			const level = body[name.next];
			const flagsByte = body[name.next + 1];
			if (level === undefined || flagsByte === undefined) {
				throw new ProtocolError('truncated CONNECT', { protocol: PROTO });
			}
			const ka = readUint16(body, name.next + 2);
			const client = readString(body, ka.next);
			let cursor = client.next;
			let username: string | undefined;
			let password: Uint8Array | undefined;
			if ((flagsByte & 0x80) !== 0) {
				const u = readString(body, cursor);
				username = u.value;
				cursor = u.next;
			}
			if ((flagsByte & 0x40) !== 0) {
				const len = readUint16(body, cursor);
				password = body.slice(len.next, len.next + len.value);
			}
			return {
				type,
				protocolName: name.value,
				protocolLevel: level,
				cleanSession: (flagsByte & 0x02) !== 0,
				keepAliveSeconds: ka.value,
				clientId: client.value,
				username,
				password
			};
		}
		case PacketType.CONNACK: {
			const ackFlags = body[0];
			const returnCode = body[1];
			if (ackFlags === undefined || returnCode === undefined) {
				throw new ProtocolError('truncated CONNACK', { protocol: PROTO });
			}
			return { type, sessionPresent: (ackFlags & 0x01) === 1, returnCode };
		}
		case PacketType.PUBLISH: {
			const qos = ((flags >> 1) & 0x03) as 0 | 1 | 2;
			const retain = (flags & 0x01) === 1;
			const dup = (flags & 0x08) === 0x08;
			const t = readString(body, 0);
			let cursor = t.next;
			let packetId: number | undefined;
			if (qos > 0) {
				const id = readUint16(body, cursor);
				packetId = id.value;
				cursor = id.next;
			}
			const payload = body.slice(cursor);
			return { type, topic: t.value, payload, qos, retain, dup, packetId };
		}
		case PacketType.PUBACK:
		case PacketType.PUBREC:
		case PacketType.PUBREL:
		case PacketType.PUBCOMP: {
			const id = readUint16(body, 0);
			return { type, packetId: id.value };
		}
		case PacketType.SUBSCRIBE: {
			const id = readUint16(body, 0);
			const subscriptions: Subscription[] = [];
			let cursor = id.next;
			while (cursor < body.length) {
				const filter = readString(body, cursor);
				const qos = (body[filter.next] ?? 0) as 0 | 1 | 2;
				subscriptions.push({ topicFilter: filter.value, qos });
				cursor = filter.next + 1;
			}
			return { type, packetId: id.value, subscriptions };
		}
		case PacketType.SUBACK: {
			const id = readUint16(body, 0);
			const returnCodes = Array.from(body.subarray(id.next));
			return { type, packetId: id.value, returnCodes };
		}
		case PacketType.UNSUBSCRIBE: {
			const id = readUint16(body, 0);
			const topicFilters: string[] = [];
			let cursor = id.next;
			while (cursor < body.length) {
				const filter = readString(body, cursor);
				topicFilters.push(filter.value);
				cursor = filter.next;
			}
			return { type, packetId: id.value, topicFilters };
		}
		case PacketType.UNSUBACK: {
			const id = readUint16(body, 0);
			return { type, packetId: id.value };
		}
		case PacketType.PINGREQ:
			return { type };
		case PacketType.PINGRESP:
			return { type };
		case PacketType.DISCONNECT:
			return { type };
		default:
			throw new ProtocolError(`unsupported or unexpected packet type: ${type}`, {
				protocol: PROTO
			});
	}
}
