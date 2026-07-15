/**
 * @fileoverview Minimal SDP (RFC 4566) build/parse for the MSRP and call use cases.
 *
 * edgeport only needs enough SDP to offer/answer an MSRP message session (RFC 4975 §8) and to
 * carry a bare audio `m=` line for call signaling. A Worker cannot accept inbound TCP, so an
 * MSRP offer always advertises `a=setup:active` (RFC 6135): the Worker dials the peer's MSRP
 * path from the answer. This module does not attempt full SDP coverage; it is a focused line
 * codec for those two shapes.
 *
 * @author Gregory Mitchell
 * @since 1.0.3
 */

/** One parsed SDP media description (`m=` line plus its attributes). */
export interface SdpMedia {
	/** Media type (`message`, `audio`, ...). */
	type: string;
	/** Transport port. */
	port: number;
	/** Transport protocol (`TCP/MSRP`, `RTP/AVP`, ...). */
	protocol: string;
	/** The format list after the protocol. */
	formats: string[];
	/** Media-level attributes: `a=name:value` (value `''` for a flag). */
	attributes: Record<string, string>;
}

/** A parsed SDP body: the session connection address plus its media descriptions. */
export interface Sdp {
	/** The session-level `c=` connection address, if present. */
	connectionAddress?: string;
	/** The media descriptions. */
	media: SdpMedia[];
}

/**
 * Parses an SDP body into its connection address and media descriptions.
 *
 * @param text - The SDP body text.
 * @returns The parsed SDP.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { parseSdp } from 'edgeport/sip';
 *
 * const sdp = parseSdp(answerBody);
 * const path = sdp.media[0]?.attributes.path; // the peer's msrp:// path
 * ```
 */
export function parseSdp(text: string): Sdp {
	const sdp: Sdp = { media: [] };
	let current: SdpMedia | undefined;
	for (const raw of text.split(/\r\n|\n/)) {
		if (!raw) continue;
		const type = raw[0];
		const value = raw.slice(2); // skip "x="
		if (type === 'c' && !current) {
			// c=IN IP4 <addr>
			sdp.connectionAddress = value.split(/\s+/)[2];
		} else if (type === 'm') {
			// m=<media> <port> <proto> <fmt ...>
			const parts = value.split(/\s+/);
			current = {
				type: parts[0] ?? '',
				port: Number(parts[1] ?? 0),
				protocol: parts[2] ?? '',
				formats: parts.slice(3),
				attributes: {}
			};
			sdp.media.push(current);
		} else if (type === 'a' && current) {
			const colon = value.indexOf(':');
			if (colon >= 0) current.attributes[value.slice(0, colon)] = value.slice(colon + 1);
			else current.attributes[value] = '';
		} else if (type === 'c' && current) {
			current.attributes['connection'] = value;
		}
	}
	return sdp;
}

/** Options for {@link buildMsrpOffer}. */
export interface MsrpOfferOptions {
	/** Advertised connection address (often a placeholder for an active, listen-less client). */
	address?: string;
	/** The advertised MSRP port (nominal for an active client). */
	port?: number;
	/** Our MSRP URI (`msrp://host:port/session-id;tcp`), echoed as `a=path`. */
	path: string;
	/** Accepted content types; defaults to `message/cpim text/plain`. */
	acceptTypes?: string;
	/** SDP session id/version stamp (pass a stable value; the caller supplies it, no clock here). */
	sessionId?: string;
}

/**
 * Builds an SDP offer for an MSRP message session (active setup).
 *
 * The offer advertises `TCP/MSRP` with `a=setup:active`, so the Worker dials the peer's MSRP
 * path from the answer rather than listening (Workers cannot accept inbound TCP).
 *
 * @param opts - The local MSRP path, accept-types, and address/port placeholders.
 * @returns The SDP body text (CRLF-delimited).
 * @since 1.0.3
 * @example
 * ```typescript
 * import { buildMsrpOffer } from 'edgeport/sip';
 *
 * const offer = buildMsrpOffer({ path: 'msrp://client.invalid:2855/abcd;tcp', sessionId: '1' });
 * ```
 */
export function buildMsrpOffer(opts: MsrpOfferOptions): string {
	const address = opts.address ?? 'client.invalid';
	const port = opts.port ?? 2855;
	const sessId = opts.sessionId ?? '0';
	const accept = opts.acceptTypes ?? 'message/cpim text/plain';
	return [
		'v=0',
		`o=- ${sessId} ${sessId} IN IP4 ${address}`,
		's=-',
		`c=IN IP4 ${address}`,
		't=0 0',
		`m=message ${port} TCP/MSRP *`,
		`a=accept-types:${accept}`,
		`a=path:${opts.path}`,
		'a=setup:active',
		''
	].join('\r\n');
}
