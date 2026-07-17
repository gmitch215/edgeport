/**
 * @fileoverview A promise-deadline helper shared by the protocol codecs.
 *
 * Racing an in-flight operation against a `setTimeout` reject is the same seven lines in the
 * core framed reader, the SMPP response waiter, the SIP/MSRP transaction layer, and the NATS
 * request path. This is the single canonical version: it rejects with edgeport's
 * {@link TimeoutError} so a timed-out read is indistinguishable from any other transport
 * deadline, and it always clears its timer. Pure and transport-free (it imports only the error
 * vocabulary), so it is published under `edgeport/util` for consumers building their own
 * deadlines too.
 *
 * @author Gregory Mitchell
 * @since 1.0.4
 */
import { TimeoutError } from '../core/errors';

/**
 * Rejects with {@link TimeoutError} if `promise` does not settle within `ms` milliseconds.
 *
 * When `ms` is `undefined` or `Infinity` the original promise is returned unchanged (no timer
 * is armed), so a caller can pass an optional deadline straight through. Otherwise the returned
 * promise settles with whichever happens first: `promise` resolving/rejecting, or the deadline
 * elapsing. The internal timer is always cleared once the race settles.
 *
 * @typeParam T - The resolved value of `promise`.
 * @param promise - The operation to bound.
 * @param ms - The deadline in milliseconds; `undefined`/`Infinity` disables the timeout.
 * @param label - A short name for the operation, used in the timeout message (default
 *   `"operation"`).
 * @returns A promise that settles with `promise`'s result or rejects with {@link TimeoutError}.
 * @throws {TimeoutError} If the deadline elapses before `promise` settles.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { withTimeout } from 'edgeport/util';
 *
 * // reject if the fetch has not resolved within 5 seconds
 * const res = await withTimeout(fetch('https://example.com'), 5000, 'fetch');
 * ```
 */
export function withTimeout<T>(
	promise: Promise<T>,
	ms: number | undefined,
	label?: string
): Promise<T> {
	if (ms === undefined || ms === Infinity) return promise;
	let timer: ReturnType<typeof setTimeout>;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(
			() => reject(new TimeoutError(`${label ?? 'operation'} timed out after ${ms}ms`)),
			ms
		);
	});
	return Promise.race([promise, timeout]).finally(() => clearTimeout(timer)) as Promise<T>;
}
