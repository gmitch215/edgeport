/**
 * @fileoverview Public SSH client API for the Cloudflare Workers runtime.
 *
 * Open a stateful {@link SshSession} with {@link connect} (usable via `await using`), or
 * run a single command with the {@link exec} one-shot. All transport, key exchange,
 * authentication, and channel handling sit behind this surface; the only runtime
 * dependency is the private core socket.
 *
 * Supported algorithms: curve25519-sha256 / ecdh-sha2-nistp256 key exchange; Ed25519,
 * ECDSA-P256, and RSA-SHA2 host/user keys; aes-gcm@openssh.com, chacha20-poly1305@openssh.com,
 * and aes-ctr+hmac-sha2 ciphers. chacha20-poly1305 is assembled from @noble/ciphers since
 * Workers WebCrypto lacks it.
 *
 * @example
 * ```typescript
 * import { exec } from 'edgeport/ssh';
 *
 * const { stdout, code } = await exec({
 *   hostname: 'example.com',
 *   username: 'deploy',
 *   privateKey: { pem: PRIVATE_KEY_PEM },
 *   command: 'uname -a'
 * });
 * console.log(code, new TextDecoder().decode(stdout));
 * ```
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { authenticate, type KeyboardPrompt } from '../auth/index';
import { connect as coreConnect } from '../core/socket';
import { concatBytes } from '../crypto/primitives';
import type { AlgorithmPrefs } from '../kex/kexinit';
import { SshConnection, type ChannelExit } from './connection';
import { SshTransport, type HostKeyVerifier } from './transport/transport';

export type { KeyboardPrompt } from '../auth/index';
export type { ChannelExit } from './connection';
export type { HostKeyVerifier } from './transport/transport';

/** Per-connection algorithm preference overrides. */
export type SshAlgorithmPrefs = AlgorithmPrefs;

/** Options for {@link connect} and {@link exec}. */
export interface SshConnectOptions {
	/** Host to connect to. */
	hostname: string;
	/** TCP port (default 22). */
	port?: number;
	/** Login username. */
	username: string;
	/** Password for password authentication. */
	password?: string;
	/** Private key for publickey authentication (PKCS8 PEM or an extractable CryptoKey). */
	privateKey?: { pem: string; passphrase?: string } | CryptoKey;
	/** Callback answering keyboard-interactive prompts. */
	onKeyboardInteractive?: (prompts: KeyboardPrompt[]) => Promise<string[]>;
	/** Host-key pinning hook (TOFU if omitted; the host signature is always verified). */
	hostKey?: HostKeyVerifier;
	/** Algorithm preference overrides (e.g. to force a cipher). */
	algorithms?: SshAlgorithmPrefs;
	/** Connect timeout in milliseconds. */
	timeoutMs?: number;
	/** Auto re-exchange keys after roughly this many bytes (default 1 GiB; 0 disables). */
	rekeyThresholdBytes?: number;
}

/** The result of running a command to completion. */
export interface ExecResult {
	stdout: Uint8Array;
	stderr: Uint8Array;
	code: number;
}

/** A live duplex channel (interactive shell or subsystem). */
export interface SshChannelHandle extends AsyncDisposable {
	readonly stdout: ReadableStream<Uint8Array>;
	readonly stderr: ReadableStream<Uint8Array>;
	write(data: Uint8Array): Promise<void>;
	eof(): Promise<void>;
	readonly exit: Promise<ChannelExit>;
	close(): Promise<void>;
}

/** A stateful SSH session. */
export interface SshSession extends AsyncDisposable {
	/** Runs a command and resolves with its captured output and exit code. */
	exec(command: string): Promise<ExecResult>;
	/** Opens an interactive shell channel. */
	shell(): Promise<SshChannelHandle>;
	/** Opens a subsystem channel (e.g. `sftp`). */
	subsystem(name: string): Promise<SshChannelHandle>;
	/** Forces a key re-exchange now; resolves when new keys are installed. */
	rekey(): Promise<void>;
	/** Closes the session and underlying transport. */
	close(): Promise<void>;
}

async function collect(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	for (;;) {
		const { value, done } = await reader.read();
		if (done) break;
		if (value) chunks.push(value);
	}
	return concatBytes(...chunks);
}

class Session implements SshSession {
	constructor(private readonly conn: SshConnection) {}

	async exec(command: string): Promise<ExecResult> {
		const ch = await this.conn.openSession();
		await ch.exec(command);
		const [stdout, stderr] = await Promise.all([collect(ch.stdout), collect(ch.stderr)]);
		const { code } = await ch.exit;
		await ch.close().catch(() => {});
		return { stdout, stderr, code: code ?? 0 };
	}

	async shell(): Promise<SshChannelHandle> {
		const ch = await this.conn.openSession();
		await ch.shell();
		return ch;
	}

	rekey(): Promise<void> {
		return this.conn.rekey();
	}

	async subsystem(name: string): Promise<SshChannelHandle> {
		const ch = await this.conn.openSession();
		await ch.subsystem(name);
		return ch;
	}

	close(): Promise<void> {
		return this.conn.close();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

/**
 * Opens an SSH session: connects, runs the transport handshake, authenticates, and
 * returns a session ready for {@link SshSession.exec}, {@link SshSession.shell}, or
 * {@link SshSession.subsystem}.
 *
 * @param opts - Connection and authentication options.
 * @returns The authenticated session.
 * @throws {ConnectionError} If the connection or handshake fails.
 * @throws {AuthError} If authentication is rejected.
 * @throws {ProtocolError} If negotiation fails (e.g. no common cipher).
 * @since 1.0.0
 * @example
 * ```typescript
 * import { connect } from 'edgeport/ssh';
 *
 * await using ssh = await connect({ hostname: 'h', username: 'u', password: 'p' });
 * const { stdout } = await ssh.exec('ls -la');
 * ```
 */
export async function connect(opts: SshConnectOptions): Promise<SshSession> {
	const socket = await coreConnect({
		hostname: opts.hostname,
		port: opts.port ?? 22,
		tls: 'off',
		connectTimeoutMs: opts.timeoutMs
	});
	const transport = new SshTransport(socket);
	if (opts.rekeyThresholdBytes !== undefined)
		transport.rekeyThresholdBytes = opts.rekeyThresholdBytes;
	try {
		await transport.handshake({ algorithms: opts.algorithms, hostKey: opts.hostKey });
		await authenticate(transport, {
			username: opts.username,
			password: opts.password,
			privateKey: opts.privateKey,
			onKeyboardInteractive: opts.onKeyboardInteractive
		});
	} catch (err) {
		await transport.close().catch(() => {});
		throw err;
	}
	return new Session(new SshConnection(transport));
}

/**
 * Runs a single command over a fresh connection and returns its output.
 *
 * @param opts - Connection options plus the `command` to run.
 * @returns The command's stdout, stderr, and exit code.
 * @since 1.0.0
 * @example
 * ```typescript
 * import { exec } from 'edgeport/ssh';
 * const { stdout, code } = await exec({ hostname: 'h', username: 'u', password: 'p', command: 'whoami' });
 * ```
 */
export async function exec(opts: SshConnectOptions & { command: string }): Promise<ExecResult> {
	const session = await connect(opts);
	try {
		return await session.exec(opts.command);
	} finally {
		await session.close().catch(() => {});
	}
}
