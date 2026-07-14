/**
 * edgeport - native TCP protocol clients for the Cloudflare Workers runtime.
 *
 * This bare entry point re-exports the shared error vocabulary and each protocol as a
 * namespace for convenience. For the smallest bundles, import a protocol from its own
 * subpath instead so bundlers can drop the ones you do not use:
 *
 * ```typescript
 * import { exec } from 'edgeport/ssh';
 * import { send } from 'edgeport/smtp';
 * import { connect } from 'edgeport/ws';
 * import { AuthError } from 'edgeport';
 * ```
 *
 * @author Gregory Mitchell
 * @license MIT
 * @since 1.0.0
 */
export * from './errors';
export * as ftp from './ftp';
export * as imap from './imap';
export * as ldap from './ldap';
export * as ldaps from './ldaps';
export * as mqtt from './mqtt';
export * as nats from './nats';
export * as pop3 from './pop3';
export * as sftp from './sftp';
export * as smpp from './smpp';
export * as smtp from './smtp';
export * as ssh from './ssh';
export * as stomp from './stomp';
export * as syslog from './syslog';
export * as util from './util';
export * as ws from './ws';
