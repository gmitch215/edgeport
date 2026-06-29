/**
 * @fileoverview Internal core surface, imported by protocol modules only.
 *
 * This module is intentionally NOT part of the package's public `exports` map. Protocols
 * import from here; consumers never do.
 *
 * @internal
 */
export * from './errors';
export * from './framing';
export * from './socket';
