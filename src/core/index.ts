/**
 * @fileoverview The low-level transport core: {@link connect}, the buffered framed
 * reader/writer, and the shared error vocabulary.
 *
 * This is the one module in edgeport that imports `cloudflare:sockets`, and every protocol is
 * built on it. It is published as `edgeport/core` for consumers who need raw framed TCP - open a
 * socket, read exact byte counts or delimited frames, write lines, upgrade to TLS - without a
 * higher-level protocol on top. Most code should import a protocol subpath (`edgeport/ssh`,
 * `edgeport/smtp`, ...) instead; reach for `edgeport/core` when you are speaking a protocol
 * edgeport does not yet ship and want the same buffered transport the built-in protocols use.
 *
 * @author Gregory Mitchell
 * @since 1.0.4
 * @example
 * ```typescript
 * import { connect } from 'edgeport/core';
 *
 * // a minimal finger (RFC 1288) client on top of the raw framed transport
 * await using sock = await connect({ hostname: 'example.com', port: 79 });
 * await sock.writer.writeLine('');
 * const line = await sock.reader.readLine();
 * ```
 */
export * from './errors';
export * from './framing';
export * from './socket';
