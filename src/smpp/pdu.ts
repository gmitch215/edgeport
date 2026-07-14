/**
 * @fileoverview The SMPP v3.4 PDU codec.
 *
 * SMPP frames every PDU the same way: a 16-byte header of four big-endian `uint32`s
 * (`command_length`, `command_id`, `command_status`, `sequence_number`) followed by a
 * command-specific body. This module is pure (no I/O): it encodes the PDUs an ESME sends
 * (bind, submit_sm, enquire_link, unbind, deliver_sm_resp, generic_nack) into `Uint8Array`s
 * and decodes an already-framed PDU back into a tagged union discriminated on `command`.
 * All transport and session concerns live in {@link module:smpp}.
 *
 * String fields come in two flavours the codec keeps straight: a **C-Octet String** is
 * NUL-terminated (`system_id`, `source_addr`, `message_id`, ...) while an **Octet String**
 * (`short_message`) carries a preceding length byte and no terminator. Optional parameters
 * are TLVs (tag/length/value), all big-endian.
 *
 * @author Gregory Mitchell
 * @since 1.0.3
 */
import { ProtocolError } from '../core';

const PROTO = 'smpp';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Length of the fixed SMPP PDU header in octets. */
export const HEADER_LENGTH = 16;

/** The `interface_version` byte advertised for SMPP v3.4. */
export const INTERFACE_VERSION_34 = 0x34;

/** Largest PDU this codec will accept, guarding against a bogus `command_length`. */
export const MAX_PDU_LENGTH = 131072;

/** `short_message` is a single length-prefixed octet string, so it caps at 254 usable octets. */
export const MAX_SHORT_MESSAGE = 254;

/**
 * SMPP `command_id` values (v3.4), as carried in bytes 4-7 of the header.
 *
 * Response ids are the request id with the high bit set (`0x80000000 | request`). The codec
 * switches on these to choose an encoder or decoder, so they double as a stable tag for
 * decoded PDUs.
 *
 * @since 1.0.3
 */
export enum Command {
	/** Negative acknowledgement to an unparseable or unsupported PDU. */
	GenericNack = 0x80000000,
	/** Bind as a receiver (inbound only). */
	BindReceiver = 0x00000001,
	/** Response to {@link Command.BindReceiver}. */
	BindReceiverResp = 0x80000001,
	/** Bind as a transmitter (outbound only). */
	BindTransmitter = 0x00000002,
	/** Response to {@link Command.BindTransmitter}. */
	BindTransmitterResp = 0x80000002,
	/** Query the state of a previously submitted message. */
	QuerySm = 0x00000003,
	/** Response to {@link Command.QuerySm}. */
	QuerySmResp = 0x80000003,
	/** Submit a short message for delivery. */
	SubmitSm = 0x00000004,
	/** Response to {@link Command.SubmitSm}, carrying the assigned `message_id`. */
	SubmitSmResp = 0x80000004,
	/** An inbound message or delivery receipt from the SMSC. */
	DeliverSm = 0x00000005,
	/** Response the ESME must send for each {@link Command.DeliverSm}. */
	DeliverSmResp = 0x80000005,
	/** Request to unbind and close the session. */
	Unbind = 0x00000006,
	/** Response to {@link Command.Unbind}. */
	UnbindResp = 0x80000006,
	/** Bind as a transceiver (inbound and outbound over one session). */
	BindTransceiver = 0x00000009,
	/** Response to {@link Command.BindTransceiver}. */
	BindTransceiverResp = 0x80000009,
	/** Keep-alive request; either peer may send it. */
	EnquireLink = 0x00000015,
	/** Response to {@link Command.EnquireLink}. */
	EnquireLinkResp = 0x80000015
}

/**
 * SMPP `command_status` values (v3.4), the subset edgeport surfaces.
 *
 * `ESME_ROK` (0) is success; any other value in a response indicates the SMSC rejected the
 * request. The bind-related password / system-id / bind-failed codes map to an `AuthError`
 * in the session layer; the rest map to a `ProtocolError`.
 *
 * @since 1.0.3
 */
export enum CommandStatus {
	/** No error. */
	ESME_ROK = 0x00000000,
	/** Message length is invalid. */
	ESME_RINVMSGLEN = 0x00000001,
	/** Command length is invalid. */
	ESME_RINVCMDLEN = 0x00000002,
	/** Invalid command id. */
	ESME_RINVCMDID = 0x00000003,
	/** Incorrect bind status for the given command. */
	ESME_RINVBNDSTS = 0x00000004,
	/** ESME is already bound. */
	ESME_RALYBND = 0x00000005,
	/** System error. */
	ESME_RSYSERR = 0x00000008,
	/** Invalid source address. */
	ESME_RINVSRCADR = 0x0000000a,
	/** Invalid destination address. */
	ESME_RINVDSTADR = 0x0000000b,
	/** Bind failed. */
	ESME_RBINDFAIL = 0x0000000d,
	/** Invalid password. */
	ESME_RINVPASWD = 0x0000000e,
	/** Invalid system id. */
	ESME_RINVSYSID = 0x0000000f,
	/** submit_sm or submit_multi failed. */
	ESME_RSUBMITFAIL = 0x00000045,
	/** Throttling error (ESME exceeded its allowed message rate). */
	ESME_RTHROTTLED = 0x00000058,
	/** Unknown error. */
	ESME_RUNKNOWNERR = 0x000000ff
}

/**
 * Type-of-Number (`ton`) values for SMPP addresses.
 *
 * @since 1.0.3
 */
export enum Ton {
	/** Unknown. */
	Unknown = 0x00,
	/** International (e.g. a full `+CC...` MSISDN). */
	International = 0x01,
	/** National. */
	National = 0x02,
	/** Network-specific. */
	NetworkSpecific = 0x03,
	/** Subscriber number. */
	Subscriber = 0x04,
	/** Alphanumeric (an 11-char sender id; requires NPI unknown). */
	Alphanumeric = 0x05,
	/** Abbreviated. */
	Abbreviated = 0x06
}

/**
 * Numbering-Plan-Indicator (`npi`) values for SMPP addresses.
 *
 * @since 1.0.3
 */
export enum Npi {
	/** Unknown. */
	Unknown = 0x00,
	/** ISDN (E.163/E.164), the usual choice for phone numbers. */
	Isdn = 0x01,
	/** Data (X.121). */
	Data = 0x03,
	/** Telex (F.69). */
	Telex = 0x04,
	/** Land mobile (E.212). */
	LandMobile = 0x06,
	/** National. */
	National = 0x08,
	/** Private. */
	Private = 0x09
}

/**
 * `data_coding` values for the message body.
 *
 * @since 1.0.3
 */
export enum DataCoding {
	/** SMSC default alphabet (usually GSM 03.38 7-bit); ASCII text is safe here. */
	Default = 0x00,
	/** IA5 (CCITT T.50) / ASCII. */
	Ia5 = 0x01,
	/** Latin-1 (ISO-8859-1). */
	Latin1 = 0x03,
	/** JIS. */
	Jis = 0x05,
	/** Cyrillic (ISO-8859-5). */
	Cyrillic = 0x06,
	/** Latin/Hebrew (ISO-8859-8). */
	LatinHebrew = 0x07,
	/** UCS2 (UTF-16 big-endian), for arbitrary Unicode text. */
	Ucs2 = 0x08
}

/** `esm_class` bit indicating the `short_message` carries an SMSC delivery receipt. */
export const ESM_DELIVERY_RECEIPT = 0x04;

/**
 * Common optional-parameter (TLV) tags used by the session layer.
 *
 * @since 1.0.3
 */
export enum Tag {
	/** Full message body, used when it does not fit in `short_message`. */
	MessagePayload = 0x0424,
	/** The `message_id` a delivery receipt refers to. */
	ReceiptedMessageId = 0x001e,
	/** The final state of a message referenced by a delivery receipt. */
	MessageState = 0x0427,
	/** The SMSC's supported interface version, returned in a bind response. */
	ScInterfaceVersion = 0x0210
}

/** One SMPP optional parameter (TLV): a 16-bit tag and its raw value bytes. */
export interface Tlv {
	/** The parameter tag (see {@link Tag}). */
	tag: number;
	/** The raw value bytes. */
	value: Uint8Array;
}

/** The decoded 16-byte PDU header. */
export interface PduHeader {
	/** Total PDU length in octets, including the header. */
	commandLength: number;
	/** The `command_id`. */
	command: number;
	/** The `command_status` (0 = success). */
	status: number;
	/** The `sequence_number` correlating a request with its response. */
	sequence: number;
}

/** Shared body shape for `submit_sm` and `deliver_sm` (identical layouts). */
export interface SmBody {
	/** The `service_type` (usually empty). */
	serviceType: string;
	/** Source address Type-of-Number. */
	sourceAddrTon: number;
	/** Source address Numbering-Plan-Indicator. */
	sourceAddrNpi: number;
	/** Source address. */
	sourceAddr: string;
	/** Destination address Type-of-Number. */
	destAddrTon: number;
	/** Destination address Numbering-Plan-Indicator. */
	destAddrNpi: number;
	/** Destination address. */
	destinationAddr: string;
	/** The `esm_class` flags byte. */
	esmClass: number;
	/** The `protocol_id`. */
	protocolId: number;
	/** The `priority_flag`. */
	priorityFlag: number;
	/** The `schedule_delivery_time` (empty for immediate). */
	scheduleDeliveryTime: string;
	/** The `validity_period` (empty for the SMSC default). */
	validityPeriod: string;
	/** The `registered_delivery` flags byte. */
	registeredDelivery: number;
	/** The `replace_if_present_flag`. */
	replaceIfPresentFlag: number;
	/** The `data_coding` byte. */
	dataCoding: number;
	/** The `sm_default_msg_id`. */
	smDefaultMsgId: number;
	/** The message body octets (may be empty when carried in a `message_payload` TLV). */
	shortMessage: Uint8Array;
	/** Any optional parameters that followed the mandatory body. */
	tlvs: Tlv[];
}

/**
 * A decoded SMPP PDU as a tag-on-`command` discriminated union.
 *
 * {@link decodePdu} returns one of these; branch on `command` (a {@link Command}) to read the
 * command-specific fields. The header fields (`commandLength`, `status`, `sequence`) are
 * spread onto every member.
 *
 * @since 1.0.3
 */
export type DecodedPdu =
	| (PduHeader & {
			command: Command.BindTransmitterResp | Command.BindReceiverResp | Command.BindTransceiverResp;
			/** The SMSC's system id echoed back in the bind response. */
			systemId: string;
			/** Optional parameters (e.g. `sc_interface_version`). */
			tlvs: Tlv[];
	  })
	| (PduHeader & {
			command: Command.SubmitSmResp;
			/** The SMSC-assigned message id (empty on a non-zero status). */
			messageId: string;
	  })
	| (PduHeader & { command: Command.SubmitSm } & SmBody)
	| (PduHeader & { command: Command.DeliverSm } & SmBody)
	| (PduHeader & {
			command: Command.DeliverSmResp;
			/** The message id echoed back (usually empty). */
			messageId: string;
	  })
	| (PduHeader & { command: Command.EnquireLink })
	| (PduHeader & { command: Command.EnquireLinkResp })
	| (PduHeader & { command: Command.Unbind })
	| (PduHeader & { command: Command.UnbindResp })
	| (PduHeader & { command: Command.GenericNack });

/** A decoded `submit_sm` or `deliver_sm` PDU: the header plus the shared message body. */
export type SmPdu = PduHeader & { command: Command.SubmitSm | Command.DeliverSm } & SmBody;

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

// a NUL-terminated C-Octet String: the ascii/utf-8 bytes followed by a single 0x00
function cOctetString(s: string): Uint8Array {
	const body = encoder.encode(s);
	const out = new Uint8Array(body.length + 1);
	out.set(body, 0);
	return out; // trailing byte is already 0
}

// a single unsigned byte
function u8(n: number): Uint8Array {
	return new Uint8Array([n & 0xff]);
}

// a big-endian uint32
function u32(n: number): Uint8Array {
	const out = new Uint8Array(4);
	new DataView(out.buffer).setUint32(0, n >>> 0, false);
	return out;
}

/**
 * Encodes one optional parameter (TLV): a big-endian tag, a big-endian length, then the value.
 *
 * @param tlv - The tag and value to encode.
 * @returns The encoded TLV bytes.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { encodeTlv, Tag } from 'edgeport/smpp';
 *
 * const bytes = encodeTlv({ tag: Tag.MessagePayload, value: new TextEncoder().encode('hi') });
 * ```
 */
export function encodeTlv(tlv: Tlv): Uint8Array {
	if (tlv.value.length > 0xffff) {
		throw new ProtocolError(`tlv value too long: ${tlv.value.length} bytes`, { protocol: PROTO });
	}
	const out = new Uint8Array(4 + tlv.value.length);
	const dv = new DataView(out.buffer);
	dv.setUint16(0, tlv.tag & 0xffff, false);
	dv.setUint16(2, tlv.value.length, false);
	out.set(tlv.value, 4);
	return out;
}

/**
 * Wraps a command body in the 16-byte SMPP header.
 *
 * Computes `command_length` from the body, then writes the four big-endian header words
 * followed by the body.
 *
 * @param command - The `command_id`.
 * @param status - The `command_status` (0 for a request).
 * @param sequence - The `sequence_number`.
 * @param body - The already-encoded command body (empty for header-only PDUs).
 * @returns The complete PDU bytes.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { encodePdu, Command } from 'edgeport/smpp';
 *
 * const enquireLink = encodePdu(Command.EnquireLink, 0, 1, new Uint8Array(0));
 * ```
 */
export function encodePdu(
	command: number,
	status: number,
	sequence: number,
	body: Uint8Array
): Uint8Array {
	const length = HEADER_LENGTH + body.length;
	const out = new Uint8Array(length);
	const dv = new DataView(out.buffer);
	dv.setUint32(0, length, false);
	dv.setUint32(4, command >>> 0, false);
	dv.setUint32(8, status >>> 0, false);
	dv.setUint32(12, sequence >>> 0, false);
	out.set(body, HEADER_LENGTH);
	return out;
}

/** Parameters for a bind PDU. */
export interface BindParams {
	/** The ESME system id (max 15 chars + NUL). */
	systemId: string;
	/** The bind password (max 8 chars + NUL). */
	password?: string;
	/** The ESME system type (max 12 chars + NUL). */
	systemType?: string;
	/** The advertised interface version; defaults to 0x34 (v3.4). */
	interfaceVersion?: number;
	/** The ESME address Type-of-Number. */
	addrTon?: number;
	/** The ESME address Numbering-Plan-Indicator. */
	addrNpi?: number;
	/** The address range the ESME serves (usually empty). */
	addressRange?: string;
}

/**
 * Encodes a bind PDU (`bind_transmitter`, `bind_receiver`, or `bind_transceiver`).
 *
 * The three bind commands share one body layout, so `command` selects which one is written.
 *
 * @param command - One of {@link Command.BindTransmitter}, {@link Command.BindReceiver}, or
 *   {@link Command.BindTransceiver}.
 * @param sequence - The `sequence_number`.
 * @param params - The system id, password, and address fields.
 * @returns The complete bind PDU bytes.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { encodeBind, Command } from 'edgeport/smpp';
 *
 * const bytes = encodeBind(Command.BindTransceiver, 1, { systemId: 'esme', password: 'secret' });
 * ```
 */
export function encodeBind(command: number, sequence: number, params: BindParams): Uint8Array {
	const body = concat([
		cOctetString(params.systemId),
		cOctetString(params.password ?? ''),
		cOctetString(params.systemType ?? ''),
		u8(params.interfaceVersion ?? INTERFACE_VERSION_34),
		u8(params.addrTon ?? 0),
		u8(params.addrNpi ?? 0),
		cOctetString(params.addressRange ?? '')
	]);
	return encodePdu(command, 0, sequence, body);
}

/** Parameters for a `submit_sm` PDU. */
export interface SubmitSmParams {
	/** The `service_type` (usually empty). */
	serviceType?: string;
	/** Source address Type-of-Number. */
	sourceAddrTon?: number;
	/** Source address Numbering-Plan-Indicator. */
	sourceAddrNpi?: number;
	/** Source address (the sender). */
	sourceAddr?: string;
	/** Destination address Type-of-Number. */
	destAddrTon?: number;
	/** Destination address Numbering-Plan-Indicator. */
	destAddrNpi?: number;
	/** Destination address (the recipient MSISDN). */
	destinationAddr: string;
	/** The `esm_class` flags byte. */
	esmClass?: number;
	/** The `protocol_id`. */
	protocolId?: number;
	/** The `priority_flag`. */
	priorityFlag?: number;
	/** The `schedule_delivery_time` (empty for immediate). */
	scheduleDeliveryTime?: string;
	/** The `validity_period` (empty for the SMSC default). */
	validityPeriod?: string;
	/** The `registered_delivery` flags byte (1 requests a delivery receipt). */
	registeredDelivery?: number;
	/** The `replace_if_present_flag`. */
	replaceIfPresentFlag?: number;
	/** The `data_coding` byte. */
	dataCoding?: number;
	/** The `sm_default_msg_id`. */
	smDefaultMsgId?: number;
	/** The message body octets (max 254; use a `message_payload` TLV for more). */
	shortMessage?: Uint8Array;
	/** Optional parameters appended after the mandatory body. */
	tlvs?: Tlv[];
}

/**
 * Encodes a `submit_sm` PDU.
 *
 * Writes the full mandatory body in spec order, prefixing `short_message` with its length
 * byte, then appends any TLVs. A body longer than {@link MAX_SHORT_MESSAGE} is rejected; the
 * session layer moves oversized messages into a `message_payload` TLV instead.
 *
 * @param sequence - The `sequence_number`.
 * @param params - The addresses, flags, and message body.
 * @returns The complete `submit_sm` PDU bytes.
 * @throws {ProtocolError} If `shortMessage` exceeds {@link MAX_SHORT_MESSAGE} octets.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { encodeSubmitSm } from 'edgeport/smpp';
 *
 * const bytes = encodeSubmitSm(2, {
 * 	sourceAddr: '12065550100',
 * 	destinationAddr: '12065550111',
 * 	shortMessage: new TextEncoder().encode('hello')
 * });
 * ```
 */
export function encodeSubmitSm(sequence: number, params: SubmitSmParams): Uint8Array {
	const sm = params.shortMessage ?? new Uint8Array(0);
	if (sm.length > MAX_SHORT_MESSAGE) {
		throw new ProtocolError(`short_message is ${sm.length} octets, max ${MAX_SHORT_MESSAGE}`, {
			protocol: PROTO
		});
	}
	const chunks: Uint8Array[] = [
		cOctetString(params.serviceType ?? ''),
		u8(params.sourceAddrTon ?? 0),
		u8(params.sourceAddrNpi ?? 0),
		cOctetString(params.sourceAddr ?? ''),
		u8(params.destAddrTon ?? 0),
		u8(params.destAddrNpi ?? 0),
		cOctetString(params.destinationAddr),
		u8(params.esmClass ?? 0),
		u8(params.protocolId ?? 0),
		u8(params.priorityFlag ?? 0),
		cOctetString(params.scheduleDeliveryTime ?? ''),
		cOctetString(params.validityPeriod ?? ''),
		u8(params.registeredDelivery ?? 0),
		u8(params.replaceIfPresentFlag ?? 0),
		u8(params.dataCoding ?? 0),
		u8(params.smDefaultMsgId ?? 0),
		u8(sm.length),
		sm
	];
	for (const tlv of params.tlvs ?? []) chunks.push(encodeTlv(tlv));
	return encodePdu(Command.SubmitSm, 0, sequence, concat(chunks));
}

/**
 * Encodes a `deliver_sm_resp` PDU (the ESME's acknowledgement of an inbound `deliver_sm`).
 *
 * @param sequence - The `sequence_number` of the `deliver_sm` being acknowledged.
 * @param status - The `command_status`; defaults to `ESME_ROK`.
 * @returns The complete `deliver_sm_resp` PDU bytes.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { encodeDeliverSmResp } from 'edgeport/smpp';
 *
 * const bytes = encodeDeliverSmResp(7);
 * ```
 */
export function encodeDeliverSmResp(sequence: number, status = CommandStatus.ESME_ROK): Uint8Array {
	// message_id is unused in deliver_sm_resp; a single NUL is the standard value
	return encodePdu(Command.DeliverSmResp, status, sequence, cOctetString(''));
}

/**
 * Encodes a header-only PDU (`enquire_link`, `enquire_link_resp`, `unbind`, `unbind_resp`).
 *
 * @param command - The `command_id` of the empty-body PDU.
 * @param sequence - The `sequence_number`.
 * @param status - The `command_status`; defaults to `ESME_ROK`.
 * @returns The complete PDU bytes.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { encodeEmpty, Command } from 'edgeport/smpp';
 *
 * const enquire = encodeEmpty(Command.EnquireLink, 5);
 * ```
 */
export function encodeEmpty(
	command: number,
	sequence: number,
	status = CommandStatus.ESME_ROK
): Uint8Array {
	return encodePdu(command, status, sequence, new Uint8Array(0));
}

/**
 * Encodes a `generic_nack` PDU.
 *
 * @param sequence - The `sequence_number` of the offending PDU (or 0 if unknown).
 * @param status - The `command_status` explaining the rejection.
 * @returns The complete `generic_nack` PDU bytes.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { encodeGenericNack, CommandStatus } from 'edgeport/smpp';
 *
 * const bytes = encodeGenericNack(9, CommandStatus.ESME_RINVCMDID);
 * ```
 */
export function encodeGenericNack(sequence: number, status: number): Uint8Array {
	return encodePdu(Command.GenericNack, status, sequence, new Uint8Array(0));
}

// cursor-based reader over a PDU's bytes with bounds checks
class Reader {
	readonly #bytes: Uint8Array;
	readonly #view: DataView;
	#off: number;
	readonly #end: number;

	constructor(bytes: Uint8Array, off: number, end: number) {
		this.#bytes = bytes;
		this.#view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
		this.#off = off;
		this.#end = end;
	}

	get remaining(): number {
		return this.#end - this.#off;
	}

	u8(): number {
		if (this.#off + 1 > this.#end) {
			throw new ProtocolError('smpp pdu truncated reading a byte', { protocol: PROTO });
		}
		return this.#view.getUint8(this.#off++);
	}

	u16(): number {
		if (this.#off + 2 > this.#end) {
			throw new ProtocolError('smpp pdu truncated reading a uint16', { protocol: PROTO });
		}
		const v = this.#view.getUint16(this.#off, false);
		this.#off += 2;
		return v;
	}

	octets(n: number): Uint8Array {
		if (this.#off + n > this.#end) {
			throw new ProtocolError('smpp pdu truncated reading octets', { protocol: PROTO });
		}
		const out = this.#bytes.slice(this.#off, this.#off + n);
		this.#off += n;
		return out;
	}

	// reads a NUL-terminated C-Octet String and consumes the terminator
	cString(): string {
		let i = this.#off;
		while (i < this.#end && this.#bytes[i] !== 0x00) i++;
		if (i >= this.#end) {
			throw new ProtocolError('smpp c-octet string missing NUL terminator', { protocol: PROTO });
		}
		const value = decoder.decode(this.#bytes.subarray(this.#off, i));
		this.#off = i + 1; // skip the NUL
		return value;
	}
}

/**
 * Reads the four header words of a framed PDU without decoding its body.
 *
 * Useful when the body will be discarded (an unsupported command) but the `sequence_number`
 * is still needed to answer with a `generic_nack`.
 *
 * @param bytes - A buffer beginning with a complete PDU at offset 0.
 * @returns The decoded header.
 * @throws {ProtocolError} If the buffer is shorter than the 16-byte header.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { decodeHeader } from 'edgeport/smpp';
 *
 * const header = decodeHeader(pduBytes);
 * console.log(header.command, header.sequence);
 * ```
 */
export function decodeHeader(bytes: Uint8Array): PduHeader {
	if (bytes.length < HEADER_LENGTH) {
		throw new ProtocolError('smpp pdu shorter than the 16-byte header', { protocol: PROTO });
	}
	const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	return {
		commandLength: dv.getUint32(0, false),
		command: dv.getUint32(4, false),
		status: dv.getUint32(8, false),
		sequence: dv.getUint32(12, false)
	};
}

// reads any trailing TLVs until fewer than 4 bytes remain
function decodeTlvs(r: Reader): Tlv[] {
	const tlvs: Tlv[] = [];
	while (r.remaining >= 4) {
		const tag = r.u16();
		const length = r.u16();
		const value = r.octets(length);
		tlvs.push({ tag, value });
	}
	return tlvs;
}

// reads the shared submit_sm / deliver_sm mandatory body then any TLVs
function decodeSmBody(r: Reader): SmBody {
	const serviceType = r.cString();
	const sourceAddrTon = r.u8();
	const sourceAddrNpi = r.u8();
	const sourceAddr = r.cString();
	const destAddrTon = r.u8();
	const destAddrNpi = r.u8();
	const destinationAddr = r.cString();
	const esmClass = r.u8();
	const protocolId = r.u8();
	const priorityFlag = r.u8();
	const scheduleDeliveryTime = r.cString();
	const validityPeriod = r.cString();
	const registeredDelivery = r.u8();
	const replaceIfPresentFlag = r.u8();
	const dataCoding = r.u8();
	const smDefaultMsgId = r.u8();
	const smLength = r.u8();
	const shortMessage = r.octets(smLength);
	const tlvs = decodeTlvs(r);
	return {
		serviceType,
		sourceAddrTon,
		sourceAddrNpi,
		sourceAddr,
		destAddrTon,
		destAddrNpi,
		destinationAddr,
		esmClass,
		protocolId,
		priorityFlag,
		scheduleDeliveryTime,
		validityPeriod,
		registeredDelivery,
		replaceIfPresentFlag,
		dataCoding,
		smDefaultMsgId,
		shortMessage,
		tlvs
	};
}

/**
 * Decodes one complete, already-framed SMPP PDU.
 *
 * Reads the header, then dispatches on `command_id` to parse the body, returning a
 * {@link DecodedPdu} discriminated on `command`. The buffer must hold exactly one PDU whose
 * `command_length` matches its size. Commands an ESME never has to parse the body of are
 * rejected with a {@link ProtocolError} so the session can answer them with a `generic_nack`.
 *
 * @param bytes - A buffer beginning with a single complete PDU.
 * @returns The decoded PDU.
 * @throws {ProtocolError} If the header is malformed or the command is unsupported.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { decodePdu, Command } from 'edgeport/smpp';
 *
 * const pdu = decodePdu(respBytes);
 * if (pdu.command === Command.SubmitSmResp) console.log(pdu.messageId);
 * ```
 */
export function decodePdu(bytes: Uint8Array): DecodedPdu {
	const header = decodeHeader(bytes);
	const bodyEnd = Math.min(header.commandLength, bytes.length);
	const r = new Reader(bytes, HEADER_LENGTH, bodyEnd);

	switch (header.command) {
		case Command.BindTransmitterResp:
		case Command.BindReceiverResp:
		case Command.BindTransceiverResp: {
			// a non-zero status bind response may carry no body at all
			const systemId = r.remaining > 0 ? r.cString() : '';
			const tlvs = decodeTlvs(r);
			// header.command is one of the three bind-resp ids here (the switch guarantees it)
			const command = header.command as
				Command.BindTransmitterResp | Command.BindReceiverResp | Command.BindTransceiverResp;
			return { ...header, command, systemId, tlvs };
		}
		case Command.SubmitSmResp: {
			const messageId = r.remaining > 0 ? r.cString() : '';
			return { ...header, command: Command.SubmitSmResp, messageId };
		}
		case Command.SubmitSm:
			return { ...header, command: Command.SubmitSm, ...decodeSmBody(r) };
		case Command.DeliverSm:
			return { ...header, command: Command.DeliverSm, ...decodeSmBody(r) };
		case Command.DeliverSmResp: {
			const messageId = r.remaining > 0 ? r.cString() : '';
			return { ...header, command: Command.DeliverSmResp, messageId };
		}
		case Command.EnquireLink:
			return { ...header, command: Command.EnquireLink };
		case Command.EnquireLinkResp:
			return { ...header, command: Command.EnquireLinkResp };
		case Command.Unbind:
			return { ...header, command: Command.Unbind };
		case Command.UnbindResp:
			return { ...header, command: Command.UnbindResp };
		case Command.GenericNack:
			return { ...header, command: Command.GenericNack };
		default:
			throw new ProtocolError(
				`unsupported or unexpected smpp command: 0x${header.command.toString(16)}`,
				{ protocol: PROTO }
			);
	}
}

/**
 * A parsed SMSC delivery receipt, extracted from a `deliver_sm` `short_message`.
 *
 * Delivery receipts use a loosely standardized `key:value` text format; every field is
 * optional here because SMSCs vary. See {@link parseDeliveryReceipt}.
 *
 * @since 1.0.3
 */
export interface DeliveryReceipt {
	/** The `message_id` of the original `submit_sm` this receipt is for. */
	id?: string;
	/** Number of messages submitted (`sub`). */
	sub?: string;
	/** Number of messages delivered (`dlvrd`). */
	dlvrd?: string;
	/** The submit date (`submit date`), in the SMSC's `YYMMDDhhmm` format. */
	submitDate?: string;
	/** The done date (`done date`), in the SMSC's `YYMMDDhhmm` format. */
	doneDate?: string;
	/** The final message state (`stat`), e.g. `DELIVRD`, `EXPIRED`, `UNDELIV`. */
	stat?: string;
	/** The network error code (`err`). */
	err?: string;
	/** The leading bytes of the original message (`text` / `Text`). */
	text?: string;
}

/**
 * Parses an SMSC delivery-receipt `short_message` into its fields.
 *
 * Delivery receipts follow the de-facto format
 * `id:IIII sub:SSS dlvrd:DDD submit date:YYMMDDhhmm done date:YYMMDDhhmm stat:DDDDDDD err:E text:....`.
 * Parsing is tolerant: keys are matched case-insensitively, spacing is flexible, and any
 * missing field is simply left undefined. Only meaningful when the `deliver_sm`'s `esm_class`
 * has the {@link ESM_DELIVERY_RECEIPT} bit set.
 *
 * @param text - The decoded `short_message` text of a delivery receipt.
 * @returns The parsed fields.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { parseDeliveryReceipt } from 'edgeport/smpp';
 *
 * const r = parseDeliveryReceipt('id:abc123 sub:001 dlvrd:001 stat:DELIVRD err:000 text:hello');
 * console.log(r.id, r.stat); // "abc123" "DELIVRD"
 * ```
 */
export function parseDeliveryReceipt(text: string): DeliveryReceipt {
	const receipt: DeliveryReceipt = {};
	const grab = (re: RegExp): string | undefined => text.match(re)?.[1];
	receipt.id = grab(/\bid:(\S+)/i);
	receipt.sub = grab(/\bsub:(\S+)/i);
	receipt.dlvrd = grab(/\bdlvrd:(\S+)/i);
	receipt.submitDate = grab(/\bsubmit date:(\S+)/i);
	receipt.doneDate = grab(/\bdone date:(\S+)/i);
	receipt.stat = grab(/\bstat:(\S+)/i);
	receipt.err = grab(/\berr:(\S+)/i);
	// text/Text runs to the end of the receipt and may contain spaces
	receipt.text = text.match(/\btext:(.*)$/i)?.[1];
	return receipt;
}
