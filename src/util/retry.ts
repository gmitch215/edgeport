/**
 * @fileoverview A small retry-with-backoff helper for flaky connects.
 *
 * A one-shot connect against an occasionally-unreachable box (a training node, a bastion, an
 * SMSC) benefits from a couple of retries, but only for transient failures: a bad password or
 * a malformed reply will never succeed on retry. The default {@link RetryOptions.retryable}
 * therefore retries only edgeport's {@link ConnectionError} / {@link TimeoutError} and leaves
 * `AuthError` / `ProtocolError` to fail fast. Delays grow exponentially and are capped.
 *
 * @author Gregory Mitchell
 * @since 1.0.3
 */
import { ConnectionError, TimeoutError } from '../core';

/** Options for {@link retry}. */
export interface RetryOptions {
	/** Total attempts including the first (default 3). */
	attempts?: number;
	/** Base delay in milliseconds before the first retry (default 200). */
	baseMs?: number;
	/** Upper bound on any single delay in milliseconds (default 5000). */
	maxMs?: number;
	/** Apply random full-jitter to each delay (default false). */
	jitter?: boolean;
	/**
	 * Predicate deciding whether an error is worth retrying. Defaults to retrying only
	 * {@link ConnectionError} and {@link TimeoutError} (transient transport failures).
	 */
	retryable?: (err: unknown) => boolean;
}

/** Retries only transient transport errors; auth/protocol failures fail fast. */
function defaultRetryable(err: unknown): boolean {
	return err instanceof ConnectionError || err instanceof TimeoutError;
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Runs `fn`, retrying it with exponential backoff while it throws a retryable error.
 *
 * The delay before retry `n` (0-based) is `min(maxMs, baseMs * 2 ** n)`, optionally with full
 * jitter. A non-retryable error (per {@link RetryOptions.retryable}) is rethrown immediately,
 * as is the last error once `attempts` is exhausted.
 *
 * @typeParam T - The resolved value of `fn`.
 * @param fn - The operation to run; typically a connect or a one-shot request.
 * @param opts - Attempt count, backoff timing, jitter, and the retryable predicate.
 * @returns Whatever `fn` resolves to.
 * @throws The last error `fn` threw, once attempts are exhausted or the error is not retryable.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { retry } from 'edgeport/util';
 * import { connect } from 'edgeport/ssh';
 *
 * // retry the connect up to 4 times on transient network errors; a bad password fails at once
 * const ssh = await retry(() => connect({ hostname: 'box', username: 'u', password: pw }), {
 * 	attempts: 4
 * });
 * ```
 */
export async function retry<T>(fn: () => Promise<T>, opts: RetryOptions = {}): Promise<T> {
	const attempts = Math.max(1, opts.attempts ?? 3);
	const baseMs = opts.baseMs ?? 200;
	const maxMs = opts.maxMs ?? 5000;
	const retryable = opts.retryable ?? defaultRetryable;

	let lastErr: unknown;
	for (let attempt = 0; attempt < attempts; attempt++) {
		try {
			return await fn();
		} catch (err) {
			lastErr = err;
			// give up on the final attempt or a non-transient error
			if (attempt === attempts - 1 || !retryable(err)) throw err;
			let delay = Math.min(maxMs, baseMs * 2 ** attempt);
			if (opts.jitter) delay = Math.random() * delay;
			if (delay > 0) await sleep(delay);
		}
	}
	// unreachable: the loop either returns or throws, but satisfies the type checker
	throw lastErr;
}
