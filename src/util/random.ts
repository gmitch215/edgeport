/**
 * @fileoverview Random-token helpers built on the Workers CSPRNG.
 *
 * Client ids, correlation nonces, and inbox names need unpredictable values. These wrap
 * `crypto.getRandomValues` (always available on the Workers runtime) so the library never
 * reaches for `Math.random`, and keep the "N random bytes rendered as hex" idiom in one place
 * instead of the copies scattered across the NATS and MQTT modules.
 *
 * @author Gregory Mitchell
 * @since 1.0.3
 */
import { toHex } from './encoding';

/**
 * Returns a random lowercase hex string of `byteLength` random bytes.
 *
 * @param byteLength - How many random bytes to draw; defaults to 8 (16 hex characters).
 * @returns The hex-encoded random value.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { randomHex } from 'edgeport/util';
 *
 * const nonce = randomHex(); // 16 hex chars from 8 random bytes
 * ```
 */
export function randomHex(byteLength = 8): string {
	const bytes = new Uint8Array(byteLength);
	crypto.getRandomValues(bytes);
	return toHex(bytes);
}

/**
 * Returns a random identifier of the form `${prefix}-${randomHex}`.
 *
 * @param prefix - A stable prefix (e.g. a protocol or app name).
 * @param byteLength - How many random bytes to append as hex; defaults to 8.
 * @returns The prefixed random id.
 * @since 1.0.3
 * @example
 * ```typescript
 * import { randomId } from 'edgeport/util';
 *
 * const clientId = randomId('edgeport'); // e.g. 'edgeport-3f9a...'
 * ```
 */
export function randomId(prefix: string, byteLength = 8): string {
	return `${prefix}-${randomHex(byteLength)}`;
}
