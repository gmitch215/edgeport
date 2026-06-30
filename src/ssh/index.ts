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
import { ProtocolError } from '../core/errors';
import { connect as coreConnect } from '../core/socket';
import { concatBytes } from '../crypto/primitives';
import type { AlgorithmPrefs } from '../kex/kexinit';
import { SshConnection, type ChannelExit } from './connection';
import { assertSafeDeletePath, shellQuote } from './shell-quote';
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
	/**
	 * Runs a command on a fresh session channel and returns the live duplex handle without
	 * waiting for it to finish, so you can stream `write()` to its stdin, read `stdout`/
	 * `stderr` as they arrive, and `await` its `exit`. Use this when you need to interact
	 * with the command (feed it stdin, react to partial output) rather than just collect a
	 * final result - {@link exec} is the collect-to-completion shortcut over this.
	 *
	 * @param command - The command line to run (interpreted by the remote login shell).
	 * @returns The live channel handle.
	 * @throws {ConnectionError} If the channel cannot be opened.
	 * @throws {ProtocolError} If the server rejects the exec request.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * await using ssh = await connect({ hostname: 'h', username: 'u', password: 'p' });
	 * await using ch = await ssh.execStream('cat'); // echoes stdin back on stdout
	 * await ch.write(new TextEncoder().encode('hello\n'));
	 * await ch.eof();
	 * const reader = ch.stdout.getReader();
	 * const { value } = await reader.read();
	 * console.log(new TextDecoder().decode(value)); // "hello"
	 * await ch.exit;
	 * ```
	 */
	execStream(command: string): Promise<SshChannelHandle>;
	/** Opens a subsystem channel (e.g. `sftp`). */
	subsystem(name: string): Promise<SshChannelHandle>;
	/**
	 * Opens a `direct-tcpip` tunnel: the server connects to `host:port` on your behalf and
	 * pipes the bytes back over a duplex channel (the `-L`-style reach-through). Use it to
	 * reach a service - a database, an internal API - that sits behind an SSH bastion.
	 *
	 * @param host - The target host the server should connect to.
	 * @param port - The target port.
	 * @returns A duplex channel: `stdout` is inbound bytes, `write()` sends outbound.
	 * @throws {ConnectionError} If the server refuses the forward (e.g. policy/host unreachable).
	 * @since 1.0.0
	 * @example
	 * ```typescript
	 * await using ssh = await connect({ hostname: 'bastion', username: 'u', password: p });
	 * await using pg = await ssh.forwardOut('10.0.0.5', 5432); // reach internal Postgres
	 * await pg.write(startupPacket);
	 * for await (const chunk of pg.stdout) handle(chunk);
	 * ```
	 */
	forwardOut(host: string, port: number): Promise<SshChannelHandle>;
	/** Forces a key re-exchange now; resolves when new keys are installed. */
	rekey(): Promise<void>;
	/**
	 * Runs a command, decodes its stdout as UTF-8, and returns it. Throws when the command
	 * exits nonzero, putting the exit code and the decoded stderr in the error message.
	 *
	 * The command is interpreted by the remote login shell, so quote/escape it yourself if
	 * it interpolates untrusted values (the typed helpers like {@link mkdirp} do this for
	 * you via single-quote wrapping).
	 *
	 * The typed helpers ({@link mkdirp}/{@link rm}/{@link chmod}/{@link stat}/{@link df}/
	 * {@link which}/{@link readTextFile}/{@link writeTextFile}/{@link spawnDetached}) assume a
	 * POSIX shell, so they work against Linux, macOS, and other Unix remotes (`stat` and
	 * `spawnDetached` handle the GNU/BSD differences). For a Windows (`cmd.exe`/PowerShell) or
	 * other non-POSIX remote, use `run`/`exec`/`execStream` directly with native commands.
	 *
	 * @param command - The command line to run.
	 * @param opts - `trim` strips leading/trailing whitespace from stdout (default `true`).
	 * @returns The command's decoded stdout.
	 * @throws {ProtocolError} If the command exits with a nonzero code.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * await using ssh = await connect({ hostname: 'h', username: 'u', password: 'p' });
	 * const host = await ssh.run('hostname');
	 * ```
	 */
	run(command: string, opts?: { trim?: boolean }): Promise<string>;
	/**
	 * Runs a command and reports whether it succeeded (exit code `0`). Never throws on a
	 * nonzero exit - that maps to `false` - so it reads cleanly as a predicate.
	 *
	 * @param command - The command line to run.
	 * @returns `true` if the command exited `0`, else `false`.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * if (await ssh.test('command -v docker')) console.log('docker present');
	 * ```
	 */
	test(command: string): Promise<boolean>;
	/**
	 * Reports whether a filesystem path exists (runs `test -e` on the quoted path).
	 *
	 * @param path - The path to check.
	 * @returns `true` if the path exists, else `false`.
	 * @since 1.0.2
	 */
	exists(path: string): Promise<boolean>;
	/**
	 * Creates a directory and any missing parents (`mkdir -p`).
	 *
	 * @param path - The directory to create.
	 * @param opts - `mode` sets the octal permission bits (passed as `mkdir -m`).
	 * @returns Nothing on success.
	 * @throws {ProtocolError} If `mkdir` exits nonzero.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * await ssh.mkdirp('/srv/app/releases', { mode: 0o755 });
	 * ```
	 */
	mkdirp(path: string, opts?: { mode?: number }): Promise<void>;
	/**
	 * Removes one or more paths (`rm`). Each target is checked by an internal guard that
	 * refuses empty, `/`, `~`, `.`, and `..`, then the paths are passed after `--` so a
	 * leading-dash name cannot be read as a flag.
	 *
	 * @param path - A path or array of paths to remove.
	 * @param opts - `recursive` adds `-r`; `force` adds `-f`.
	 * @returns Nothing on success.
	 * @throws {ProtocolError} If any target is a refused dangerous path, or `rm` exits nonzero.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * await ssh.rm('/tmp/build', { recursive: true, force: true });
	 * ```
	 */
	rm(path: string | string[], opts?: { recursive?: boolean; force?: boolean }): Promise<void>;
	/**
	 * Changes permission bits on one or more paths (`chmod`). A numeric `mode` is rendered
	 * as octal; a string mode (e.g. `'u+x'`) is passed through. Paths follow `--`.
	 *
	 * @param path - A path or array of paths.
	 * @param mode - Numeric mode (rendered octal) or a symbolic/string mode.
	 * @param opts - `recursive` adds `-R`.
	 * @returns Nothing on success.
	 * @throws {ProtocolError} If `chmod` exits nonzero.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * await ssh.chmod('/srv/app/run.sh', 0o755);
	 * ```
	 */
	chmod(
		path: string | string[],
		mode: number | string,
		opts?: { recursive?: boolean }
	): Promise<void>;
	/**
	 * Stats a single path. Portable across GNU (Linux) `stat -c` and BSD (macOS) `stat -f`:
	 * it tries the GNU form and falls back to the BSD form, then normalizes both.
	 *
	 * @param path - The path to stat.
	 * @returns Size in bytes, numeric `mode` (the full `st_mode`), `mtime` in epoch seconds,
	 *   and `isDirectory`/`isSymlink` flags.
	 * @throws {ProtocolError} If `stat` exits nonzero (e.g. the path does not exist).
	 * @since 1.0.2
	 */
	stat(path: string): Promise<{
		size: number;
		mode: number;
		mtime: number;
		isDirectory: boolean;
		isSymlink: boolean;
	}>;
	/**
	 * Reports filesystem usage via `df -Pk` (POSIX 1K-block columns).
	 *
	 * @param path - Optional path to limit the report to its filesystem.
	 * @returns One row per filesystem with sizes in kibibytes and the use percentage.
	 * @throws {ProtocolError} If `df` exits nonzero.
	 * @since 1.0.2
	 */
	df(path?: string): Promise<
		{
			filesystem: string;
			sizeKb: number;
			usedKb: number;
			availKb: number;
			usePercent: number;
			mountedOn: string;
		}[]
	>;
	/**
	 * Resolves the path of an executable on the remote `PATH` (`command -v`).
	 *
	 * @param name - The command/executable name to look up.
	 * @returns The resolved path, or `null` if not found.
	 * @since 1.0.2
	 */
	which(name: string): Promise<string | null>;
	/**
	 * Reads a text file (`cat`) and returns its contents undecorated (no trimming).
	 *
	 * @param path - The file to read.
	 * @returns The file's contents decoded as UTF-8.
	 * @throws {ProtocolError} If `cat` exits nonzero (e.g. the file does not exist).
	 * @since 1.0.2
	 */
	readTextFile(path: string): Promise<string>;
	/**
	 * Writes text to a file by streaming the bytes to `cat`'s stdin, so the payload is never
	 * shell-quoted. Truncates by default; `append` appends instead (`cat >>`).
	 *
	 * @param path - The file to write.
	 * @param content - The text to write (UTF-8 encoded onto stdin).
	 * @param opts - `append` appends rather than truncating.
	 * @returns Nothing on success.
	 * @throws {ProtocolError} If the write command exits nonzero.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * await ssh.writeTextFile('/srv/app/.env', 'PORT=8080\n');
	 * ```
	 */
	writeTextFile(path: string, content: string, opts?: { append?: boolean }): Promise<void>;
	/**
	 * Launches a command detached so it outlives the SSH channel, with stdin closed and
	 * stdout/stderr redirected (default `/dev/null`). Uses `nohup` (POSIX; works on Linux and
	 * macOS, unlike the Linux-only `setsid`). Returns once the launcher returns; it does not
	 * wait for the spawned process.
	 *
	 * @param command - The command to run in the background.
	 * @param opts - `stdout`/`stderr` redirect targets (default `/dev/null`).
	 * @returns Nothing once the process is launched.
	 * @throws {ProtocolError} If the launcher exits nonzero.
	 * @since 1.0.2
	 * @example
	 * ```typescript
	 * await ssh.spawnDetached('/srv/app/worker', { stdout: '/var/log/worker.log' });
	 * ```
	 */
	spawnDetached(command: string, opts?: { stdout?: string; stderr?: string }): Promise<void>;
	/** Closes the session and underlying transport. */
	close(): Promise<void>;
}

// shared codecs for the command helpers
const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

/** @internal collects a readable stream of bytes into a single buffer. */
export async function collect(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	for (;;) {
		const { value, done } = await reader.read();
		if (done) break;
		if (value) chunks.push(value);
	}
	return concatBytes(...chunks);
}

/** @internal the concrete session; exported only so unit tests can exercise the helpers. */
export class Session implements SshSession {
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

	async execStream(command: string): Promise<SshChannelHandle> {
		const ch = await this.conn.openSession();
		await ch.exec(command);
		return ch;
	}

	rekey(): Promise<void> {
		return this.conn.rekey();
	}

	async run(command: string, opts?: { trim?: boolean }): Promise<string> {
		const { stdout, stderr, code } = await this.exec(command);
		if (code !== 0) {
			const err = textDecoder.decode(stderr).trim();
			throw new ProtocolError(`command exited ${code}: ${command}${err ? ` - ${err}` : ''}`, {
				protocol: 'ssh'
			});
		}
		const out = textDecoder.decode(stdout);
		return opts?.trim === false ? out : out.trim();
	}

	async test(command: string): Promise<boolean> {
		const { code } = await this.exec(command);
		return code === 0;
	}

	exists(path: string): Promise<boolean> {
		return this.test(`test -e ${shellQuote(path)}`);
	}

	async mkdirp(path: string, opts?: { mode?: number }): Promise<void> {
		const mode = opts?.mode !== undefined ? ` -m ${opts.mode.toString(8)}` : '';
		await this.run(`mkdir -p${mode} ${shellQuote(path)}`);
	}

	async rm(
		path: string | string[],
		opts?: { recursive?: boolean; force?: boolean }
	): Promise<void> {
		const paths = Array.isArray(path) ? path : [path];
		for (const p of paths) assertSafeDeletePath(p);
		const flags = `${opts?.recursive ? ' -r' : ''}${opts?.force ? ' -f' : ''}`;
		const quoted = paths.map(shellQuote).join(' ');
		await this.run(`rm${flags} -- ${quoted}`);
	}

	async chmod(
		path: string | string[],
		mode: number | string,
		opts?: { recursive?: boolean }
	): Promise<void> {
		const paths = Array.isArray(path) ? path : [path];
		const m = typeof mode === 'number' ? mode.toString(8) : mode;
		const flags = opts?.recursive ? ' -R' : '';
		const quoted = paths.map(shellQuote).join(' ');
		await this.run(`chmod${flags} ${m} -- ${quoted}`);
	}

	async stat(path: string): Promise<{
		size: number;
		mode: number;
		mtime: number;
		isDirectory: boolean;
		isSymlink: boolean;
	}> {
		const q = shellQuote(path);
		// portable stat: GNU `-c` first, BSD (macOS) `-f` as the fallback. each branch prints a
		// leading tag (g/b) so we know the mode's base - GNU %f is hex, BSD %p is octal. type
		// words match after lowercasing ("directory", "symbolic link") on both.
		const out = await this.run(
			`stat -c 'g %s %f %Y %F' ${q} 2>/dev/null || stat -f 'b %z %p %m %HT' ${q}`
		);
		const parts = out.split(/\s+/);
		const size = Number(parts[1]);
		const mode = parseInt(parts[2] ?? '', parts[0] === 'b' ? 8 : 16);
		const mtime = Number(parts[3]);
		const type = parts.slice(4).join(' ').toLowerCase();
		return {
			size,
			mode,
			mtime,
			isDirectory: type === 'directory',
			isSymlink: type.includes('symbolic link')
		};
	}

	async df(path?: string): Promise<
		{
			filesystem: string;
			sizeKb: number;
			usedKb: number;
			availKb: number;
			usePercent: number;
			mountedOn: string;
		}[]
	> {
		const arg = path !== undefined ? ` ${shellQuote(path)}` : '';
		const out = await this.run(`df -Pk${arg}`);
		const lines = out.split('\n').filter((l) => l.trim() !== '');
		// drop the header row; POSIX columns are fixed: fs, 1K-blocks, used, avail, use%, mount
		return lines.slice(1).map((line) => {
			const c = line.split(/\s+/);
			return {
				filesystem: c[0] ?? '',
				sizeKb: Number(c[1]),
				usedKb: Number(c[2]),
				availKb: Number(c[3]),
				usePercent: Number((c[4] ?? '').replace('%', '')),
				mountedOn: c.slice(5).join(' ')
			};
		});
	}

	async which(name: string): Promise<string | null> {
		const { stdout, code } = await this.exec(`command -v ${shellQuote(name)}`);
		if (code !== 0) return null;
		return textDecoder.decode(stdout).trim();
	}

	readTextFile(path: string): Promise<string> {
		return this.run(`cat -- ${shellQuote(path)}`, { trim: false });
	}

	async writeTextFile(path: string, content: string, opts?: { append?: boolean }): Promise<void> {
		const redirect = opts?.append ? '>>' : '>';
		// feed bytes via stdin so the payload is never shell-quoted
		const ch = await this.execStream(`cat ${redirect} ${shellQuote(path)}`);
		try {
			await ch.write(textEncoder.encode(content));
			await ch.eof();
			const { code } = await ch.exit;
			if (code !== 0 && code !== null)
				throw new ProtocolError(`writeTextFile exited ${code}: ${path}`, {
					protocol: 'ssh'
				});
		} finally {
			await ch.close().catch(() => {});
		}
	}

	async spawnDetached(command: string, opts?: { stdout?: string; stderr?: string }): Promise<void> {
		const out = opts?.stdout ?? '/dev/null';
		const err = opts?.stderr ?? '/dev/null';
		// nohup (ignores SIGHUP) + redirected stdio + & so the child outlives the channel;
		// nohup is POSIX (linux + macos), setsid is linux-only
		await this.run(`nohup sh -c ${shellQuote(command)} >${out} 2>${err} </dev/null &`);
	}

	async subsystem(name: string): Promise<SshChannelHandle> {
		const ch = await this.conn.openSession();
		await ch.subsystem(name);
		return ch;
	}

	forwardOut(host: string, port: number): Promise<SshChannelHandle> {
		return this.conn.openDirectTcpip(host, port);
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

/**
 * One-shot: connects, runs a command, decodes stdout, and closes the session.
 *
 * Throws when the command exits nonzero (message includes the exit code and stderr), the
 * same as {@link SshSession.run}.
 *
 * @param opts - Connect options plus the `command` to run and an optional `trim` flag.
 * @returns The command's decoded stdout (trimmed unless `trim` is `false`).
 * @throws {ProtocolError} If the command exits nonzero.
 * @throws {ConnectionError} If the connection or handshake fails.
 * @throws {AuthError} If authentication is rejected.
 * @since 1.0.2
 * @example
 * ```typescript
 * import { run } from 'edgeport/ssh';
 * const host = await run({ hostname: 'h', username: 'u', password: 'p', command: 'hostname' });
 * ```
 */
export async function run(
	opts: SshConnectOptions & { command: string; trim?: boolean }
): Promise<string> {
	const session = await connect(opts);
	try {
		return await session.run(opts.command, { trim: opts.trim });
	} finally {
		await session.close().catch(() => {});
	}
}

/**
 * One-shot: connects, runs a command as a predicate, and closes the session.
 *
 * @param opts - Connect options plus the `command` to run.
 * @returns `true` if the command exited `0`, else `false`.
 * @throws {ConnectionError} If the connection or handshake fails.
 * @throws {AuthError} If authentication is rejected.
 * @since 1.0.2
 * @example
 * ```typescript
 * import { test } from 'edgeport/ssh';
 * const ok = await test({ hostname: 'h', username: 'u', password: 'p', command: 'command -v git' });
 * ```
 */
export async function test(opts: SshConnectOptions & { command: string }): Promise<boolean> {
	const session = await connect(opts);
	try {
		return await session.test(opts.command);
	} finally {
		await session.close().catch(() => {});
	}
}

/**
 * One-shot: connects, checks whether a path exists, and closes the session.
 *
 * @param opts - Connect options plus the `path` to check.
 * @returns `true` if the path exists, else `false`.
 * @throws {ConnectionError} If the connection or handshake fails.
 * @throws {AuthError} If authentication is rejected.
 * @since 1.0.2
 * @example
 * ```typescript
 * import { exists } from 'edgeport/ssh';
 * const there = await exists({ hostname: 'h', username: 'u', password: 'p', path: '/etc/hosts' });
 * ```
 */
export async function exists(opts: SshConnectOptions & { path: string }): Promise<boolean> {
	const session = await connect(opts);
	try {
		return await session.exists(opts.path);
	} finally {
		await session.close().catch(() => {});
	}
}

export { sudo, sudoExec, type SudoOptions } from './sudo';
