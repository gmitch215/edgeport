/**
 * @fileoverview Privileged-command helpers over an SSH session.
 *
 * `sudo` does not read its password from SSH auth - it prompts for it over the channel.
 * These helpers run `sudo -S -p ''` (read the password from stdin; silence sudo's own
 * prompt), feed the password to stdin, and collect the result, so callers do not have to
 * hand-roll the keyboard/stdin plumbing every time.
 *
 * @author Gregory Mitchell
 * @since 1.0.2
 */
import { ProtocolError } from '../core/errors';
import {
	collect,
	connect,
	type ExecResult,
	type SshConnectOptions,
	type SshSession
} from './index';

/** Options for {@link sudo}. */
export interface SudoOptions {
	/** Password fed to sudo's stdin prompt (the SSH user's sudo password). */
	password: string;
}

/**
 * Runs a command under `sudo` on an already-open session and collects its output.
 *
 * Internally runs `sudo -S -p '' <command>`, writes `password` followed by a newline to the
 * command's stdin (where `-S` makes sudo read it), sends EOF, then collects stdout/stderr
 * and the exit code.
 *
 * Caveats:
 * - the remote sudoers policy must allow password sudo and not require a tty (`requiretty`
 *   off - the default on most modern distros)
 * - `command` is interpreted by the remote login shell, so quote/escape it as you would on
 *   a shell command line
 *
 * @param session - An open, authenticated SSH session.
 * @param command - The command to run under sudo (interpreted by the remote shell).
 * @param opts - Sudo options; `password` is the user's sudo password.
 * @returns The command's stdout, stderr, and exit code (0 on clean exit).
 * @throws {ConnectionError} If the channel cannot be opened.
 * @throws {ProtocolError} If the server rejects the exec request.
 * @since 1.0.2
 * @example
 * ```typescript
 * import { connect, sudo } from 'edgeport/ssh';
 *
 * await using ssh = await connect({ hostname: 'h', username: 'u', password: env.PW });
 * const { stdout, code } = await sudo(ssh, 'systemctl restart myapp', { password: env.PW });
 * console.log(code, new TextDecoder().decode(stdout));
 * ```
 */
export async function sudo(
	session: SshSession,
	command: string,
	opts: SudoOptions
): Promise<ExecResult> {
	const ch = await session.execStream(`sudo -S -p '' ${command}`);
	await ch.write(new TextEncoder().encode(opts.password + '\n'));
	await ch.eof();
	const [stdout, stderr] = await Promise.all([collect(ch.stdout), collect(ch.stderr)]);
	const { code } = await ch.exit;
	await ch.close().catch(() => {});
	return { stdout, stderr, code: code ?? 0 };
}

/**
 * One-shot: connects a session, runs a command under `sudo`, and closes the session.
 *
 * Credential reuse: `sudoPassword` defaults to `password` from the connect options - the
 * common case where the login user's password is also their sudo password. Override it when
 * the sudo password differs, or when you authenticate by key and must still supply a sudo
 * password. If neither `sudoPassword` nor `password` is set, throws.
 *
 * Same caveats as {@link sudo}: the credential-reuse default only makes sense when the SSH
 * login password is also the sudo password; the remote sudoers policy must allow password
 * sudo without a tty; `command` is interpreted by the remote shell.
 *
 * @param opts - Connect options plus the `command` to run and an optional `sudoPassword`.
 * @returns The command's stdout, stderr, and exit code (0 on clean exit).
 * @throws {ProtocolError} If no sudo password is available (`sudoPassword` and `password` both unset).
 * @throws {ConnectionError} If the connection or handshake fails.
 * @throws {AuthError} If authentication is rejected.
 * @since 1.0.2
 * @example
 * ```typescript
 * import { sudoExec } from 'edgeport/ssh';
 *
 * // reuse the SSH login password as the sudo password
 * const { stdout, code } = await sudoExec({
 *   hostname: 'h',
 *   username: 'u',
 *   password: env.PW,
 *   command: 'id -u'
 * });
 * console.log(code, new TextDecoder().decode(stdout).trim()); // 0 "0"
 * ```
 */
export async function sudoExec(
	opts: SshConnectOptions & { command: string; sudoPassword?: string }
): Promise<ExecResult> {
	const password = opts.sudoPassword ?? opts.password;
	if (password === undefined)
		throw new ProtocolError('sudoExec requires a sudo password: set sudoPassword or password', {
			protocol: 'ssh'
		});
	const session = await connect(opts);
	try {
		return await sudo(session, opts.command, { password });
	} finally {
		await session.close().catch(() => {});
	}
}
