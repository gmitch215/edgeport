/**
 * @fileoverview SSH protocol message numbers and named constants (RFC 4253/4252/4254).
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */

/** SSH message type numbers. */
export const Msg = {
	DISCONNECT: 1,
	IGNORE: 2,
	UNIMPLEMENTED: 3,
	DEBUG: 4,
	SERVICE_REQUEST: 5,
	SERVICE_ACCEPT: 6,
	KEXINIT: 20,
	NEWKEYS: 21,
	// kex-method-specific range (30-49); for ecdh:
	KEX_ECDH_INIT: 30,
	KEX_ECDH_REPLY: 31,
	USERAUTH_REQUEST: 50,
	USERAUTH_FAILURE: 51,
	USERAUTH_SUCCESS: 52,
	USERAUTH_BANNER: 53,
	// 60 is method-specific: PK_OK for publickey, INFO_REQUEST for keyboard-interactive
	USERAUTH_PK_OK: 60,
	USERAUTH_INFO_REQUEST: 60,
	USERAUTH_INFO_RESPONSE: 61,
	GLOBAL_REQUEST: 80,
	REQUEST_SUCCESS: 81,
	REQUEST_FAILURE: 82,
	CHANNEL_OPEN: 90,
	CHANNEL_OPEN_CONFIRMATION: 91,
	CHANNEL_OPEN_FAILURE: 92,
	CHANNEL_WINDOW_ADJUST: 93,
	CHANNEL_DATA: 94,
	CHANNEL_EXTENDED_DATA: 95,
	CHANNEL_EOF: 96,
	CHANNEL_CLOSE: 97,
	CHANNEL_REQUEST: 98,
	CHANNEL_SUCCESS: 99,
	CHANNEL_FAILURE: 100
} as const;

/** SSH_MSG_CHANNEL_EXTENDED_DATA data type code for stderr. */
export const EXTENDED_DATA_STDERR = 1;

/** Disconnect reason codes (RFC 4253 section 11.1), the ones we surface. */
export const Disconnect = {
	HOST_KEY_NOT_VERIFIABLE: 9,
	CONNECTION_LOST: 10,
	BY_APPLICATION: 11,
	AUTH_CANCELLED_BY_USER: 13,
	NO_MORE_AUTH_METHODS_AVAILABLE: 14
} as const;

/** The local identification string sent during version exchange. */
export const CLIENT_IDENTIFICATION = 'SSH-2.0-edgeport_1.0';
