/**
 * @fileoverview SIP-over-TCP framing: read and write whole SIP messages on a core socket.
 *
 * SIP over a stream transport delimits a message by the blank line after its headers, then
 * reads exactly `Content-Length` body octets (RFC 3261 §7.5). This module frames that off the
 * buffered {@link import('../core').FramedReader}: it reads the header block up to `CRLFCRLF`,
 * parses it, then pulls the body. It also tolerates the RFC 5626 keep-alive whitespace
 * (a lone `CRLF` "pong" or a `CRLFCRLF` "ping") that can appear between messages.
 *
 * @author Gregory Mitchell
 * @since 1.0.3
 */
import { ConnectionError, type FramedReader, type FramedWriter } from '../core';
import { parseMessage, serializeMessage, type SipMessage } from './message';

// end-of-headers delimiter
const CRLFCRLF = new Uint8Array([0x0d, 0x0a, 0x0d, 0x0a]);
// guard against a peer that never terminates the header block
const MAX_HEADER_BYTES = 65536;
// the RFC 5626 double-CRLF keep-alive ping
const PING = new Uint8Array([0x0d, 0x0a, 0x0d, 0x0a]);
// the RFC 5626 single-CRLF keep-alive pong
const PONG = new Uint8Array([0x0d, 0x0a]);

/**
 * Reads one complete SIP message off a framed reader, or `null` at end of stream.
 *
 * Reads the header block up to the blank-line separator, parses it to learn `Content-Length`,
 * then reads the body. Leading keep-alive `CRLF`s between messages are skipped.
 *
 * @param reader - The buffered socket reader.
 * @param timeoutMs - Optional per-read deadline.
 * @returns The parsed message, or `null` if the peer closed the connection.
 * @throws {ProtocolError} If a header block is malformed.
 * @throws {TimeoutError} If `timeoutMs` elapses.
 * @since 1.0.3
 */
export async function readMessage(
	reader: FramedReader,
	timeoutMs?: number
): Promise<SipMessage | null> {
	for (;;) {
		let block: Uint8Array;
		try {
			block = await reader.readUntil(CRLFCRLF, MAX_HEADER_BYTES, timeoutMs);
		} catch (err) {
			// a clean stream end surfaces as ConnectionError from the reader; treat it as EOF
			if (err instanceof ConnectionError) return null;
			throw err;
		}
		// trim any leading CR/LF (inter-message whitespace / a keep-alive ping)
		let start = 0;
		while (start < block.length && (block[start] === 0x0d || block[start] === 0x0a)) start++;
		if (start >= block.length) continue; // pure keep-alive; read the next block
		const headerBlock = block.subarray(start);
		const msg = parseMessage(headerBlock);
		const len = Number(msg.headers.get('Content-Length') ?? '0');
		if (Number.isFinite(len) && len > 0) {
			msg.body = await reader.readN(len, timeoutMs);
		}
		return msg;
	}
}

/**
 * Serializes and writes one SIP message.
 *
 * @param writer - The socket writer.
 * @param msg - The message to send.
 * @returns Resolves once the bytes are written.
 * @since 1.0.3
 */
export function writeMessage(writer: FramedWriter, msg: SipMessage): Promise<void> {
	return writer.write(serializeMessage(msg));
}

/**
 * Writes an RFC 5626 keep-alive ping (`CRLFCRLF`) to the flow.
 *
 * @param writer - The socket writer.
 * @returns Resolves once the ping is written.
 * @since 1.0.3
 */
export function writePing(writer: FramedWriter): Promise<void> {
	return writer.write(PING);
}

/**
 * Writes an RFC 5626 keep-alive pong (`CRLF`) in response to a ping.
 *
 * @param writer - The socket writer.
 * @returns Resolves once the pong is written.
 * @since 1.0.3
 */
export function writePong(writer: FramedWriter): Promise<void> {
	return writer.write(PONG);
}
