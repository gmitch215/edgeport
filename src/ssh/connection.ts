/**
 * @fileoverview The SSH connection layer (RFC 4254): channels, flow-control windows, and
 * the inbound packet pump that dispatches channel messages.
 *
 * One background pump reads decrypted packets and routes them to the right channel, so
 * `exec`/`shell`/`subsystem` can await their replies while data streams in concurrently.
 * Send-window accounting blocks writes that would overrun the peer; receive-window
 * top-ups are sent as the application drains stdout.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { EXTENDED_DATA_STDERR, Msg } from '../constants';
import { ConnectionError, ProtocolError } from '../core/errors';
import { SshReader, SshWriter } from '../wire';
import type { SshTransport } from './transport/transport';

const INITIAL_WINDOW = 2 * 1024 * 1024;
const MAX_PACKET = 32 * 1024;
const WINDOW_REFILL_THRESHOLD = INITIAL_WINDOW / 2;

/** The exit result of a channel's remote command. */
export interface ChannelExit {
	/** The command's exit code, or null if it exited via a signal. */
	code: number | null;
	/** The signal name that terminated the command, or null. */
	signal: string | null;
}

/** A live SSH channel with stdout/stderr streams and a write side. */
export class SshChannel {
	/** Remote command stdout. */
	readonly stdout: ReadableStream<Uint8Array>;
	/** Remote command stderr. */
	readonly stderr: ReadableStream<Uint8Array>;
	/** Resolves when the channel closes, with the exit status if the server sent one. */
	readonly exit: Promise<ChannelExit>;

	#stdoutCtl!: ReadableStreamDefaultController<Uint8Array>;
	#stderrCtl!: ReadableStreamDefaultController<Uint8Array>;
	#resolveExit!: (e: ChannelExit) => void;
	#exitState: ChannelExit = { code: null, signal: null };
	#closed = false;
	#streamsClosed = false;

	// flow-control state
	sendWindow = 0;
	recvWindow = INITIAL_WINDOW;
	maxPacket = MAX_PACKET;
	#windowWaiters: (() => void)[] = [];

	// in-flight CHANNEL_REQUEST reply, and the CHANNEL_OPEN reply
	#reqWaiter: ((ok: boolean) => void) | null = null;

	constructor(
		readonly localId: number,
		public remoteId: number,
		private readonly conn: SshConnection
	) {
		this.stdout = new ReadableStream({ start: (c) => (this.#stdoutCtl = c) });
		this.stderr = new ReadableStream({ start: (c) => (this.#stderrCtl = c) });
		this.exit = new Promise((r) => (this.#resolveExit = r));
	}

	/** @internal feeds a CHANNEL_DATA payload into stdout and tops up the receive window. */
	async _onData(data: Uint8Array): Promise<void> {
		if (!this.#streamsClosed) this.#stdoutCtl.enqueue(data);
		await this.#consumeWindow(data.length);
	}

	/** @internal feeds stderr extended data. */
	async _onExtended(code: number, data: Uint8Array): Promise<void> {
		if (code === EXTENDED_DATA_STDERR && !this.#streamsClosed) this.#stderrCtl.enqueue(data);
		await this.#consumeWindow(data.length);
	}

	async #consumeWindow(n: number): Promise<void> {
		this.recvWindow -= n;
		if (this.recvWindow <= WINDOW_REFILL_THRESHOLD) {
			const add = INITIAL_WINDOW - this.recvWindow;
			this.recvWindow += add;
			await this.conn._send(
				new SshWriter().byte(Msg.CHANNEL_WINDOW_ADJUST).uint32(this.remoteId).uint32(add).bytes()
			);
		}
	}

	/** @internal grants more send-window and wakes blocked writers. */
	_onWindowAdjust(n: number): void {
		this.sendWindow += n;
		const waiters = this.#windowWaiters;
		this.#windowWaiters = [];
		for (const w of waiters) w();
	}

	/** @internal records an exit-status / exit-signal channel request. */
	_onExit(code: number | null, signal: string | null): void {
		this.#exitState = { code, signal };
	}

	/** @internal resolves the pending CHANNEL_REQUEST reply. */
	_onRequestReply(ok: boolean): void {
		const w = this.#reqWaiter;
		this.#reqWaiter = null;
		if (w) w(ok);
	}

	/** @internal closes the readable streams on EOF/CLOSE. */
	_closeStreams(): void {
		if (this.#streamsClosed) return;
		this.#streamsClosed = true;
		try {
			this.#stdoutCtl.close();
		} catch {
			// already closed
		}
		try {
			this.#stderrCtl.close();
		} catch {
			// already closed
		}
	}

	/** @internal finalizes the channel after CHANNEL_CLOSE. */
	_finalize(): void {
		if (this.#closed) return;
		this.#closed = true;
		this._closeStreams();
		this.#resolveExit(this.#exitState);
		for (const w of this.#windowWaiters.splice(0)) w();
	}

	/** @internal fails the channel (transport error). */
	_fail(err: unknown): void {
		if (this.#closed) return;
		this.#closed = true;
		this.#streamsClosed = true;
		try {
			this.#stdoutCtl.error(err);
		} catch {
			/* noop */
		}
		try {
			this.#stderrCtl.error(err);
		} catch {
			/* noop */
		}
		this.#resolveExit(this.#exitState);
		for (const w of this.#windowWaiters.splice(0)) w();
	}

	// sends a CHANNEL_REQUEST and awaits SUCCESS/FAILURE
	async #request(type: string, extra: (w: SshWriter) => void): Promise<boolean> {
		const reply = new Promise<boolean>((r) => (this.#reqWaiter = r));
		const w = new SshWriter()
			.byte(Msg.CHANNEL_REQUEST)
			.uint32(this.remoteId)
			.string(type)
			.boolean(true);
		extra(w);
		await this.conn._send(w.bytes());
		return reply;
	}

	/** Runs a command on this channel. */
	async exec(command: string): Promise<void> {
		if (!(await this.#request('exec', (w) => w.string(command)))) {
			throw new ProtocolError(`exec request was rejected`);
		}
	}

	/** Requests an interactive shell on this channel. */
	async shell(): Promise<void> {
		if (!(await this.#request('shell', () => {})))
			throw new ProtocolError('shell request was rejected');
	}

	/** Starts a subsystem (e.g. `sftp`) on this channel. */
	async subsystem(name: string): Promise<void> {
		if (!(await this.#request('subsystem', (w) => w.string(name)))) {
			throw new ProtocolError(`subsystem ${name} request was rejected`);
		}
	}

	/** Writes data to the channel, respecting the peer send-window and max packet size. */
	async write(data: Uint8Array): Promise<void> {
		let off = 0;
		while (off < data.length) {
			while (this.sendWindow <= 0) {
				if (this.#closed) throw new ConnectionError('channel closed');
				await new Promise<void>((r) => this.#windowWaiters.push(r));
			}
			const n = Math.min(data.length - off, this.maxPacket, this.sendWindow);
			const chunk = data.subarray(off, off + n);
			await this.conn._send(
				new SshWriter().byte(Msg.CHANNEL_DATA).uint32(this.remoteId).string(chunk).bytes()
			);
			this.sendWindow -= n;
			off += n;
		}
	}

	/** Sends EOF on the write side. */
	async eof(): Promise<void> {
		await this.conn._send(new SshWriter().byte(Msg.CHANNEL_EOF).uint32(this.remoteId).bytes());
	}

	/** Closes the channel. */
	async close(): Promise<void> {
		if (this.#closed) return;
		await this.conn._send(new SshWriter().byte(Msg.CHANNEL_CLOSE).uint32(this.remoteId).bytes());
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

/** Manages channels over a handshaken, authenticated transport. */
export class SshConnection {
	#channels = new Map<number, SshChannel>();
	#nextId = 0;
	#openWaiters = new Map<
		number,
		(ch: { remoteId: number; window: number; maxPacket: number } | null) => void
	>();
	constructor(private readonly transport: SshTransport) {
		void this.#runPump(); // background reader; errors fail open channels internally
	}

	/** @internal sends a connection-layer packet (held during an in-flight rekey). */
	_send(payload: Uint8Array): Promise<void> {
		return this.transport.sendData(payload);
	}

	/** Triggers a key re-exchange and resolves when new keys are installed. */
	rekey(): Promise<void> {
		return this.transport.requestRekey();
	}

	async #runPump(): Promise<void> {
		try {
			for (;;) {
				const p = await this.transport.read();
				await this.#dispatch(p);
			}
		} catch (err) {
			for (const ch of this.#channels.values()) ch._fail(err);
			for (const w of this.#openWaiters.values()) w(null);
			this.#openWaiters.clear();
		}
	}

	async #dispatch(p: Uint8Array): Promise<void> {
		const r = new SshReader(p);
		const type = r.byte();
		switch (type) {
			case Msg.CHANNEL_OPEN_CONFIRMATION: {
				const local = r.uint32();
				const remoteId = r.uint32();
				const window = r.uint32();
				const maxPacket = r.uint32();
				this.#openWaiters.get(local)?.({ remoteId, window, maxPacket });
				this.#openWaiters.delete(local);
				break;
			}
			case Msg.CHANNEL_OPEN_FAILURE: {
				const local = r.uint32();
				this.#openWaiters.get(local)?.(null);
				this.#openWaiters.delete(local);
				break;
			}
			case Msg.CHANNEL_DATA: {
				const ch = this.#channels.get(r.uint32());
				if (ch) await ch._onData(r.string());
				break;
			}
			case Msg.CHANNEL_EXTENDED_DATA: {
				const ch = this.#channels.get(r.uint32());
				const code = r.uint32();
				if (ch) await ch._onExtended(code, r.string());
				break;
			}
			case Msg.CHANNEL_WINDOW_ADJUST: {
				this.#channels.get(r.uint32())?._onWindowAdjust(r.uint32());
				break;
			}
			case Msg.CHANNEL_EOF: {
				this.#channels.get(r.uint32())?._closeStreams();
				break;
			}
			case Msg.CHANNEL_CLOSE: {
				const ch = this.#channels.get(r.uint32());
				if (ch) {
					await this.transport
						.send(new SshWriter().byte(Msg.CHANNEL_CLOSE).uint32(ch.remoteId).bytes())
						.catch(() => {});
					ch._finalize();
					this.#channels.delete(ch.localId);
				}
				break;
			}
			case Msg.CHANNEL_REQUEST: {
				const ch = this.#channels.get(r.uint32());
				const req = r.stringUtf8();
				r.boolean(); // want_reply
				if (ch && req === 'exit-status') ch._onExit(r.uint32(), null);
				else if (ch && req === 'exit-signal') ch._onExit(null, r.stringUtf8());
				break;
			}
			case Msg.CHANNEL_SUCCESS:
				this.#channels.get(r.uint32())?._onRequestReply(true);
				break;
			case Msg.CHANNEL_FAILURE:
				this.#channels.get(r.uint32())?._onRequestReply(false);
				break;
			case Msg.GLOBAL_REQUEST:
				await this.transport.send(new SshWriter().byte(Msg.REQUEST_FAILURE).bytes());
				break;
			default:
				break; // ignore other connection-layer messages
		}
	}

	// opens a channel of the given type, appending any type-specific fields, and resolves
	// once the server confirms it (channel-type-agnostic; shared by session + forwarding)
	async #openChannel(type: string, extra?: (w: SshWriter) => void): Promise<SshChannel> {
		const localId = this.#nextId++;
		const opened = new Promise<{ remoteId: number; window: number; maxPacket: number } | null>(
			(r) => this.#openWaiters.set(localId, r)
		);
		const w = new SshWriter()
			.byte(Msg.CHANNEL_OPEN)
			.string(type)
			.uint32(localId)
			.uint32(INITIAL_WINDOW)
			.uint32(MAX_PACKET);
		extra?.(w);
		await this.transport.send(w.bytes());
		const result = await opened;
		if (!result)
			throw new ConnectionError(`channel open (${type}) was refused`, { protocol: 'ssh' });
		const ch = new SshChannel(localId, result.remoteId, this);
		ch.sendWindow = result.window;
		ch.maxPacket = result.maxPacket;
		this.#channels.set(localId, ch);
		return ch;
	}

	/** Opens a `session` channel. */
	openSession(): Promise<SshChannel> {
		return this.#openChannel('session');
	}

	/**
	 * Opens a `direct-tcpip` channel: asks the server to connect to `host:port` on our
	 * behalf and pipe the bytes back (RFC 4254 section 7.2). This is the `-L`-style
	 * reach-through used to tunnel to services behind an SSH bastion.
	 */
	openDirectTcpip(
		host: string,
		port: number,
		originIp = '127.0.0.1',
		originPort = 0
	): Promise<SshChannel> {
		return this.#openChannel('direct-tcpip', (w) =>
			w.string(host).uint32(port).string(originIp).uint32(originPort)
		);
	}

	/** Closes the underlying transport. */
	close(): Promise<void> {
		return this.transport.close();
	}
}
