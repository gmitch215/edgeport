/**
 * @fileoverview Internal shell-quoting helpers shared by the SSH command helpers.
 *
 * Every helper that interpolates a caller-supplied path or argument into a remote shell
 * command line routes it through {@link shellQuote} so a stray space, quote, `$`, or `;`
 * cannot break out of the intended argument. {@link assertSafeDeletePath} is the guard
 * the destructive helpers (`rm`) run first so a thinko like `rm('/')` throws instead of
 * building a command that wipes the box.
 *
 * Not part of the public API surface; exported only for use within the `ssh` module.
 *
 * @author Gregory Mitchell
 * @since 1.0.2
 * @internal
 */
import { ProtocolError } from '../core/errors';

/**
 * Wraps an argument in POSIX single quotes so the remote shell treats it as one literal
 * token. Embedded single quotes are emitted as the classic `'\''` sequence (close quote,
 * escaped quote, reopen quote), which is the only thing a single-quoted string cannot
 * contain. Everything else - spaces, `$`, backticks, `;`, `&`, globs - is inert inside
 * single quotes.
 *
 * @param arg - The raw argument to quote.
 * @returns The single-quoted, shell-safe token.
 * @since 1.0.2
 * @internal
 * @example
 * ```typescript
 * shellQuote("a b");      // "'a b'"
 * shellQuote("it's");     // "'it'\''s'"
 * shellQuote("$(x); y");  // "'$(x); y'"
 * ```
 */
export function shellQuote(arg: string): string {
	return `'${arg.replace(/'/g, `'\\''`)}'`;
}

/**
 * Refuses obviously destructive delete targets before a `rm` command is ever built.
 *
 * Throws for an empty or whitespace-only path, and for the literal targets `/`, `~`, `.`,
 * and `..` - the ones where a slip would recursively delete the root, the home directory,
 * or the current/parent working directory. This is a guard against caller mistakes, not a
 * sandbox: a determined caller can still pass `/etc` or `/*`. Trailing/leading whitespace
 * is trimmed before the comparison so `' / '` is rejected too.
 *
 * @param path - The delete target to validate.
 * @returns Nothing; returns normally when the target is allowed.
 * @throws {ProtocolError} If the target is empty/whitespace-only or one of `/`, `~`, `.`, `..`.
 * @since 1.0.2
 * @internal
 */
export function assertSafeDeletePath(path: string): void {
	const trimmed = path.trim();
	if (trimmed === '')
		throw new ProtocolError('refusing to delete an empty path', { protocol: 'ssh' });
	if (trimmed === '/' || trimmed === '~' || trimmed === '.' || trimmed === '..')
		throw new ProtocolError(`refusing to delete a dangerous path: ${trimmed}`, {
			protocol: 'ssh'
		});
}
