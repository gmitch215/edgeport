/**
 * @fileoverview SSH protocol version exchange (RFC 4253 section 4.2).
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { CLIENT_IDENTIFICATION } from '../../constants';
import { ProtocolError } from '../../core/errors';
import type { FramedReader, FramedWriter } from '../../core/framing';

const encoder = new TextEncoder();

/** Sends our identification line and returns its bytes (V_C, without CRLF). */
export async function sendIdentification(writer: FramedWriter): Promise<Uint8Array> {
	await writer.writeLine(CLIENT_IDENTIFICATION);
	return encoder.encode(CLIENT_IDENTIFICATION);
}

/**
 * Reads the server identification line (V_S), skipping any preamble lines the server may
 * send before the `SSH-` line.
 *
 * @param reader - The transport reader.
 * @returns The server identification bytes (no CRLF).
 * @throws {ProtocolError} If no valid `SSH-2.0`/`SSH-1.99` line arrives.
 * @since 1.0.0
 */
export async function readIdentification(reader: FramedReader): Promise<Uint8Array> {
	for (let i = 0; i < 50; i++) {
		const line = await reader.readLine(15_000);
		if (line.startsWith('SSH-')) {
			if (!line.startsWith('SSH-2.0') && !line.startsWith('SSH-1.99')) {
				throw new ProtocolError(`unsupported SSH protocol version: ${line}`);
			}
			return encoder.encode(line);
		}
	}
	throw new ProtocolError('no SSH identification string received');
}
