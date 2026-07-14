/**
 * @fileoverview Email-to-SMS gateway addressing for the SMTP client.
 *
 * Many mobile carriers run an email-to-SMS gateway: mail sent to
 * `<number>@<gateway-domain>` is delivered to the handset as a text (or picture) message.
 * This module maps a phone number plus a carrier - either a known provider key from
 * {@link CarrierGateways} or a raw gateway domain - to that address ({@link smsAddress}),
 * and sends a short plaintext message to it over the existing SMTP {@link send} path
 * ({@link sendSms}).
 *
 * @author Gregory Mitchell
 * @since 1.0.3
 */
import { ProtocolError } from '../core';
import { send, type SendResult, type SmtpConnectOptions } from './index';

const PROTOCOL = 'smtp';

/**
 * The gateway domain(s) a carrier uses for email-to-SMS / MMS delivery.
 *
 * @since 1.0.3
 */
export interface CarrierGateway {
	/** Domain for text (SMS) messages, e.g. `txt.att.net`. */
	sms: string;
	/** Domain for picture / multimedia (MMS) messages, when the carrier uses a distinct one. */
	mms?: string;
}

/**
 * A known carrier provider key in {@link CarrierGateways}.
 *
 * Lowercase provider identifiers covering US + Canadian carriers. Pass one to
 * {@link smsAddress} / {@link sendSms}, or pass a raw gateway domain for any carrier not
 * listed here.
 *
 * @since 1.0.3
 */
export type Carrier =
	// united states
	| 'att'
	| 'tmobile'
	| 'verizon'
	| 'sprint'
	| 'cricket'
	| 'uscellular'
	| 'metropcs'
	| 'boost'
	| 'virgin'
	| 'googlefi'
	| 'xfinity'
	| 'straighttalk'
	| 'pageplus'
	| 'ting'
	| 'consumercellular'
	| 'republicwireless'
	| 'simplemobile'
	// canada
	| 'rogers'
	| 'bell'
	| 'telus'
	| 'fido'
	| 'koodo'
	| 'sasktel';

/**
 * Known carrier provider keys mapped to their email-to-SMS / MMS gateway domains.
 *
 * Pass a {@link Carrier} key to {@link smsAddress} to resolve an address, or pass a raw
 * gateway domain directly when a carrier is not listed here. Coverage is US + Canadian
 * carriers; the domains are best-effort and can change over time.
 *
 * @since 1.0.3
 */

// gateways are best-effort and drift over time (carriers merge, rename, or drop the service);
// a silent non-delivery usually means the gateway changed - prefer a raw domain override when unsure
export const CarrierGateways: Record<Carrier, CarrierGateway> = {
	// united states
	att: { sms: 'txt.att.net', mms: 'mms.att.net' },
	tmobile: { sms: 'tmomail.net' },
	verizon: { sms: 'vtext.com', mms: 'vzwpix.com' },
	sprint: { sms: 'messaging.sprintpcs.com', mms: 'pm.sprint.com' },
	cricket: { sms: 'sms.cricketwireless.net', mms: 'mms.cricketwireless.net' },
	uscellular: { sms: 'email.uscc.net', mms: 'mms.uscc.net' },
	metropcs: { sms: 'mymetropcs.com' },
	boost: { sms: 'sms.myboostmobile.com', mms: 'myboostmobile.com' },
	virgin: { sms: 'vmobl.com', mms: 'vmpix.com' },
	googlefi: { sms: 'msg.fi.google.com' },
	xfinity: { sms: 'vtext.com' },
	straighttalk: { sms: 'vtext.com', mms: 'mypixmessages.com' },
	pageplus: { sms: 'vtext.com' },
	ting: { sms: 'message.ting.com' },
	consumercellular: { sms: 'mailmymobile.net' },
	republicwireless: { sms: 'text.republicwireless.com' },
	simplemobile: { sms: 'smtext.com' },
	// canada
	rogers: { sms: 'pcs.rogers.com' },
	bell: { sms: 'txt.bell.ca' },
	telus: { sms: 'msg.telus.com' },
	fido: { sms: 'fido.ca' },
	koodo: { sms: 'msg.telus.com' },
	sasktel: { sms: 'sms.sasktel.com' }
};

/**
 * Resolves the email-to-SMS gateway address for a phone number and carrier.
 *
 * The number is normalized to digits only (spaces, dashes, parentheses, dots and a leading
 * `+` are removed). The carrier is either a known key from {@link CarrierGateways} - whose
 * SMS or MMS domain is picked by `opts.type` (default `'sms'`, falling back to the SMS
 * domain when no distinct MMS one exists) - or an unrecognized string treated as a raw
 * gateway domain when it looks like one (contains a `.`).
 *
 * @param number - The recipient phone number in any common format.
 * @param carrier - A known {@link Carrier} key or a raw gateway domain.
 * @param opts - Options; `type` selects the SMS or MMS gateway (default `'sms'`).
 * @returns The `number@domain` gateway address.
 * @throws {ProtocolError} If the number is empty after normalization, or the carrier is
 *   neither a known key nor a plausible gateway domain.
 * @since 1.0.3
 *
 * @example
 * ```typescript
 * import { smsAddress } from 'edgeport/smtp';
 *
 * smsAddress('+1 (555) 123-4567', 'att'); // '15551234567@txt.att.net'
 * smsAddress('5551234567', 'verizon', { type: 'mms' }); // '5551234567@vzwpix.com'
 * smsAddress('5551234567', 'sms.example.net'); // '5551234567@sms.example.net'
 * ```
 */
export function smsAddress(
	number: string,
	carrier: Carrier | string,
	opts: { type?: 'sms' | 'mms' } = {}
): string {
	// keep digits only (drops +, spaces, dashes, parens, dots)
	const digits = number.replace(/\D+/g, '');
	if (digits.length === 0) {
		throw new ProtocolError('SMS phone number is empty after normalization', {
			protocol: PROTOCOL
		});
	}

	const gateway = (CarrierGateways as Record<string, CarrierGateway>)[carrier];
	if (gateway) {
		const domain = opts.type === 'mms' ? (gateway.mms ?? gateway.sms) : gateway.sms;
		return `${digits}@${domain}`;
	}

	// unknown key: accept it only if it is a plausible raw gateway domain
	if (carrier.includes('.')) return `${digits}@${carrier}`;

	throw new ProtocolError(
		`unknown SMS carrier: ${JSON.stringify(carrier)} (pass a known key or a raw gateway domain)`,
		{ protocol: PROTOCOL }
	);
}

/**
 * Options for {@link sendSms}: SMTP connection settings plus the SMS payload.
 *
 * @since 1.0.3
 */
export interface SendSmsOptions extends SmtpConnectOptions {
	/** Recipient handset, addressed by phone number and carrier. */
	to: {
		/** The recipient phone number in any common format. */
		number: string;
		/** A known {@link Carrier} key or a raw gateway domain. */
		carrier: Carrier | string;
	};
	/** Envelope and header From address. */
	from: string;
	/** Plaintext message body; keep it short since gateways truncate long messages. */
	text: string;
	/**
	 * Optional subject. Defaults to empty because carrier gateways typically drop or prepend
	 * the subject to the body.
	 */
	subject?: string;
	/** Address the SMS or MMS gateway; defaults to `'sms'`. */
	type?: 'sms' | 'mms';
}

/**
 * Sends a short plaintext message to a phone number via its carrier's email-to-SMS gateway.
 *
 * Resolves the gateway address with {@link smsAddress}, then sends a text-only message over
 * the usual SMTP {@link send} path (connect, optional AUTH, send, quit). No HTML body is
 * sent because gateways expect plain text.
 *
 * @param opts - SMTP connection options plus the recipient, sender, and message text.
 * @returns The accepted recipients and the server's final reply.
 * @throws {ProtocolError} If the carrier or number is invalid, or the server rejects the message.
 * @throws {ConnectionError} If the socket cannot be opened.
 * @throws {AuthError} If authentication fails.
 * @since 1.0.3
 *
 * @example
 * ```typescript
 * import { sendSms } from 'edgeport/smtp';
 *
 * await sendSms({
 * 	hostname: 'smtp.example.com',
 * 	auth: { username: 'me@example.com', password: 'app-password' },
 * 	from: 'me@example.com',
 * 	to: { number: '+1 (555) 123-4567', carrier: 'att' },
 * 	text: 'Your code is 123456'
 * });
 * ```
 */
export async function sendSms(opts: SendSmsOptions): Promise<SendResult> {
	const recipient = smsAddress(opts.to.number, opts.to.carrier, { type: opts.type });
	return send({ ...opts, to: recipient, text: opts.text, subject: opts.subject ?? '' });
}
