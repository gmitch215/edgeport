/**
 * @fileoverview SSH user authentication (RFC 4252 + RFC 4256 keyboard-interactive).
 *
 * Requests the `ssh-userauth` service, then tries the methods the caller supplied in a
 * fixed order until one succeeds or all are exhausted. publickey signs the session-scoped
 * blob from RFC 4252 section 7; keyboard-interactive drives a prompt callback.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { Msg } from '../constants';
import { AuthError, ProtocolError } from '../core/errors';
import { loadUserKey } from '../crypto/keys';
import { SshReader, SshWriter } from '../wire';

const SERVICE = 'ssh-connection';

/**
 * The minimal transport contract authentication needs: send a packet, read the next one,
 * and the session identifier for publickey signatures. The SSH transport satisfies this
 * structurally, so auth does not depend on the transport implementation.
 *
 * @since 1.0.0
 */
export interface PacketTransport {
	/** The session identifier (H of the first key exchange). */
	readonly sessionId: Uint8Array;
	/** Sends one SSH packet. */
	send(payload: Uint8Array): Promise<void>;
	/** Reads the next SSH packet. */
	read(): Promise<Uint8Array>;
}

/** Prompt presented by the server during keyboard-interactive auth. */
export interface KeyboardPrompt {
	/** The prompt text to show the user. */
	prompt: string;
	/** Whether the typed response should be echoed (false for passwords). */
	echo: boolean;
}

/** Credentials and methods to attempt, in the order the caller provides them. */
export interface AuthOptions {
	username: string;
	password?: string;
	privateKey?: { pem: string; passphrase?: string } | CryptoKey;
	onKeyboardInteractive?: (prompts: KeyboardPrompt[]) => Promise<string[]>;
}

// reads the next auth reply, skipping USERAUTH_BANNER
async function readAuthReply(t: PacketTransport): Promise<Uint8Array> {
	for (;;) {
		const p = await t.read();
		if (p[0] === Msg.USERAUTH_BANNER) continue;
		return p;
	}
}

async function tryPassword(t: PacketTransport, user: string, password: string): Promise<boolean> {
	await t.send(
		new SshWriter()
			.byte(Msg.USERAUTH_REQUEST)
			.string(user)
			.string(SERVICE)
			.string('password')
			.boolean(false)
			.string(password)
			.bytes()
	);
	return (await readAuthReply(t))[0] === Msg.USERAUTH_SUCCESS;
}

async function tryPublicKey(
	t: PacketTransport,
	user: string,
	key: { pem: string; passphrase?: string } | CryptoKey
): Promise<boolean> {
	const userKey = await loadUserKey(key);
	// signed data is the request (with the signature flag set) prefixed by the session id
	const signed = new SshWriter()
		.string(t.sessionId)
		.byte(Msg.USERAUTH_REQUEST)
		.string(user)
		.string(SERVICE)
		.string('publickey')
		.boolean(true)
		.string(userKey.algorithm)
		.string(userKey.publicBlob)
		.bytes();
	const signature = await userKey.sign(signed);
	await t.send(
		new SshWriter()
			.byte(Msg.USERAUTH_REQUEST)
			.string(user)
			.string(SERVICE)
			.string('publickey')
			.boolean(true)
			.string(userKey.algorithm)
			.string(userKey.publicBlob)
			.string(signature)
			.bytes()
	);
	return (await readAuthReply(t))[0] === Msg.USERAUTH_SUCCESS;
}

async function tryKeyboardInteractive(
	t: PacketTransport,
	user: string,
	answer: (prompts: KeyboardPrompt[]) => Promise<string[]>
): Promise<boolean> {
	await t.send(
		new SshWriter()
			.byte(Msg.USERAUTH_REQUEST)
			.string(user)
			.string(SERVICE)
			.string('keyboard-interactive')
			.string('') // language tag
			.string('') // submethods
			.bytes()
	);
	for (;;) {
		const p = await readAuthReply(t);
		if (p[0] === Msg.USERAUTH_SUCCESS) return true;
		if (p[0] === Msg.USERAUTH_FAILURE) return false;
		if (p[0] !== Msg.USERAUTH_INFO_REQUEST)
			throw new ProtocolError(`unexpected auth reply ${p[0]}`);
		const r = new SshReader(p);
		r.byte();
		r.stringUtf8(); // name
		r.stringUtf8(); // instruction
		r.stringUtf8(); // language tag
		const count = r.uint32();
		const prompts: KeyboardPrompt[] = [];
		for (let i = 0; i < count; i++) prompts.push({ prompt: r.stringUtf8(), echo: r.boolean() });
		const responses = await answer(prompts);
		const w = new SshWriter().byte(Msg.USERAUTH_INFO_RESPONSE).uint32(responses.length);
		for (const resp of responses) w.string(resp);
		await t.send(w.bytes());
	}
}

/**
 * Authenticates the session, trying publickey, then password, then keyboard-interactive
 * (whichever the caller supplied).
 *
 * @param t - The handshaken transport.
 * @param opts - Username and the credentials/callbacks to attempt.
 * @throws {AuthError} If every supplied method is rejected.
 * @since 1.0.0
 */
export async function authenticate(t: PacketTransport, opts: AuthOptions): Promise<void> {
	await t.send(new SshWriter().byte(Msg.SERVICE_REQUEST).string('ssh-userauth').bytes());
	const accept = await t.read();
	if (accept[0] !== Msg.SERVICE_ACCEPT)
		throw new ProtocolError('ssh-userauth service was not accepted');

	const tried: string[] = [];
	if (opts.privateKey) {
		tried.push('publickey');
		if (await tryPublicKey(t, opts.username, opts.privateKey)) return;
	}
	if (opts.password !== undefined) {
		tried.push('password');
		if (await tryPassword(t, opts.username, opts.password)) return;
	}
	if (opts.onKeyboardInteractive) {
		tried.push('keyboard-interactive');
		if (await tryKeyboardInteractive(t, opts.username, opts.onKeyboardInteractive)) return;
	}
	if (tried.length === 0) throw new AuthError('no authentication method provided');
	throw new AuthError(`authentication failed (tried: ${tried.join(', ')})`);
}
