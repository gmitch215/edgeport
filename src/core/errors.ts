/**
 * @fileoverview The uniform error vocabulary shared by every edgeport protocol.
 *
 * Every public API in edgeport rejects with one of these four types and nothing else,
 * so callers can branch on a single, stable taxonomy regardless of which protocol raised
 * the failure. All of them extend {@link EdgeportError}, which carries the originating
 * protocol name and the underlying `cause` when one exists.
 *
 * @example
 * ```typescript
 * import { exec } from 'edgeport/ssh';
 * import { AuthError, ConnectionError } from 'edgeport';
 *
 * try {
 *   await exec({ hostname: 'h', username: 'u', password: 'nope', command: 'whoami' });
 * } catch (err) {
 *   if (err instanceof AuthError) console.error('bad credentials');
 *   else if (err instanceof ConnectionError) console.error('could not reach host');
 *   else throw err;
 * }
 * ```
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */

/** Options accepted by every edgeport error constructor. */
export interface EdgeportErrorOptions {
	/** The protocol that raised the error (e.g. `"ssh"`, `"smtp"`). */
	protocol?: string;
	/** The underlying error or value that caused this one, if any. */
	cause?: unknown;
}

/**
 * Base class for every error edgeport throws.
 *
 * You rarely construct this directly; catch one of its four subclasses instead. It exists
 * so a single `instanceof EdgeportError` check can distinguish edgeport failures from
 * unrelated runtime errors.
 *
 * @since 1.0.0
 */
export class EdgeportError extends Error {
	/** The protocol that raised the error, when known. */
	readonly protocol?: string;

	constructor(message: string, options: EdgeportErrorOptions = {}) {
		super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
		this.name = new.target.name;
		this.protocol = options.protocol;
	}
}

/**
 * A socket could not be opened, a TLS upgrade failed, or the peer closed the connection
 * unexpectedly (including a truncated read where more bytes were required).
 *
 * @since 1.0.0
 */
export class ConnectionError extends EdgeportError {}

/**
 * The peer spoke the protocol incorrectly, sent a message edgeport cannot parse, or
 * negotiated no mutually supported option (for example, an SSH server offering only
 * ciphers edgeport does not implement).
 *
 * @since 1.0.0
 */
export class ProtocolError extends EdgeportError {}

/**
 * Authentication was attempted and rejected by the peer (bad password, unaccepted key,
 * failed challenge response).
 *
 * @since 1.0.0
 */
export class AuthError extends EdgeportError {}

/**
 * A deadline elapsed before an operation completed (connect, read, or a protocol step).
 *
 * @since 1.0.0
 */
export class TimeoutError extends EdgeportError {}
