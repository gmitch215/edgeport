/**
 * @fileoverview SFTP version 3 client (draft-ietf-secsh-filexfer-02), layered over an SSH
 * `sftp` subsystem channel.
 *
 * The session opens an SSH channel, requests the `sftp` subsystem, exchanges INIT/VERSION,
 * then frames request/response packets over the channel's byte stream. A background reader
 * correlates responses to requests by request id, so many operations can be in flight.
 *
 * @example
 * ```typescript
 * import { connect } from 'edgeport/sftp';
 *
 * await using sftp = await connect({ hostname: 'h', username: 'u', password: 'p' });
 * await sftp.writeFile('/tmp/hello.txt', new TextEncoder().encode('hi'));
 * const data = await sftp.readFile('/tmp/hello.txt');
 * ```
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
import { ConnectionError, ProtocolError } from '../core/errors';
import { StreamFramedReader, type FramedReader } from '../core/framing';
// shared SSH building blocks, consumed via their public barrels (edgeport/crypto, /wire)
import { concatBytes } from '../crypto';
import {
	connect as sshConnect,
	type SshChannelHandle,
	type SshConnectOptions,
	type SshSession
} from '../ssh/index';
import { SshReader, SshWriter } from '../wire';

const Pkt = {
	INIT: 1,
	VERSION: 2,
	OPEN: 3,
	CLOSE: 4,
	READ: 5,
	WRITE: 6,
	OPENDIR: 11,
	READDIR: 12,
	REMOVE: 13,
	MKDIR: 14,
	REALPATH: 16,
	STAT: 17,
	RENAME: 18,
	STATUS: 101,
	HANDLE: 102,
	DATA: 103,
	NAME: 104,
	ATTRS: 105
} as const;

const PFlags = { READ: 0x1, WRITE: 0x2, CREAT: 0x8, TRUNC: 0x10 };
const Status = { OK: 0, EOF: 1 };
const READ_CHUNK = 32 * 1024;

/** File attributes returned by stat/list. */
export interface SftpAttrs {
	size?: number;
	uid?: number;
	gid?: number;
	permissions?: number;
	atime?: number;
	mtime?: number;
	/** Whether the entry is a directory (derived from the permission bits). */
	isDirectory: boolean;
}

/** A directory entry from {@link SftpSession.list}. */
export interface SftpEntry {
	filename: string;
	longname: string;
	attrs: SftpAttrs;
}

/** A stateful SFTP session. */
export interface SftpSession extends AsyncDisposable {
	/** Lists a directory. */
	list(path: string): Promise<SftpEntry[]>;
	/** Stats a path (follows symlinks). */
	stat(path: string): Promise<SftpAttrs>;
	/** Reads an entire file into memory. */
	readFile(path: string): Promise<Uint8Array>;
	/** Writes (creating/truncating) an entire file. */
	writeFile(path: string, data: Uint8Array): Promise<void>;
	/** Streams a file's contents. */
	createReadStream(path: string): ReadableStream<Uint8Array>;
	/** Streams writes into a file (created/truncated). */
	createWriteStream(path: string): WritableStream<Uint8Array>;
	/** Creates a directory. */
	mkdir(path: string): Promise<void>;
	/** Removes a file. */
	remove(path: string): Promise<void>;
	/** Renames a file or directory. */
	rename(from: string, to: string): Promise<void>;
	/** Resolves a path to its canonical absolute form. */
	realpath(path: string): Promise<string>;
	/** Closes the SFTP channel (and the session if this opened it). */
	close(): Promise<void>;
}

// a routed SFTP response: its type and a reader positioned just after the request id
interface SftpResponse {
	type: number;
	r: SshReader;
}

function parseAttrs(r: SshReader): SftpAttrs {
	const flags = r.uint32();
	const attrs: SftpAttrs = { isDirectory: false };
	if (flags & 0x1) attrs.size = Number(r.uint64());
	if (flags & 0x2) {
		attrs.uid = r.uint32();
		attrs.gid = r.uint32();
	}
	if (flags & 0x4) {
		attrs.permissions = r.uint32();
		attrs.isDirectory = (attrs.permissions & 0o170000) === 0o040000;
	}
	if (flags & 0x8) {
		attrs.atime = r.uint32();
		attrs.mtime = r.uint32();
	}
	if (flags & 0x80000000) {
		const count = r.uint32();
		for (let i = 0; i < count; i++) {
			r.string();
			r.string();
		}
	}
	return attrs;
}

class Sftp implements SftpSession {
	#reader: FramedReader;
	#nextId = 1;
	#pending = new Map<
		number,
		{ resolve: (res: SftpResponse) => void; reject: (e: unknown) => void }
	>();
	#versionWaiter?: { resolve: (v: number) => void; reject: (e: unknown) => void };
	#run: Promise<void>;

	constructor(
		private readonly channel: SshChannelHandle,
		private readonly ownedSession?: SshSession
	) {
		this.#reader = new StreamFramedReader(channel.stdout);
		this.#run = this.#pump();
	}

	async init(): Promise<void> {
		await this.#sendRaw(new SshWriter().byte(Pkt.INIT).uint32(3).bytes());
		const version = await new Promise<number>(
			(resolve, reject) => (this.#versionWaiter = { resolve, reject })
		);
		if (version < 3) throw new ProtocolError(`server SFTP version ${version} < 3`);
	}

	async #pump(): Promise<void> {
		try {
			for (;;) {
				const len = new DataView((await this.#reader.readN(4)).buffer).getUint32(0, false);
				const r = new SshReader(await this.#reader.readN(len));
				const type = r.byte();
				if (type === Pkt.VERSION) {
					this.#versionWaiter?.resolve(r.uint32());
					this.#versionWaiter = undefined;
					continue;
				}
				const id = r.uint32(); // reader now sits just past the request id
				const waiter = this.#pending.get(id);
				if (waiter) {
					this.#pending.delete(id);
					waiter.resolve({ type, r });
				}
			}
		} catch (err) {
			this.#versionWaiter?.reject(err);
			for (const w of this.#pending.values()) w.reject(err);
			this.#pending.clear();
		}
	}

	#sendRaw(body: Uint8Array): Promise<void> {
		const len = new Uint8Array(4);
		new DataView(len.buffer).setUint32(0, body.length, false);
		return this.channel.write(concatBytes(len, body));
	}

	#request(build: (w: SshWriter, id: number) => void): Promise<SftpResponse> {
		const id = this.#nextId++;
		const w = new SshWriter();
		build(w, id);
		return new Promise<SftpResponse>((resolve, reject) => {
			this.#pending.set(id, { resolve, reject });
			this.#sendRaw(w.bytes()).catch(reject);
		});
	}

	// throws unless the response is STATUS with code OK (or EOF when allowed)
	#expectStatus({ type, r }: SftpResponse, allowEof = false): number {
		if (type !== Pkt.STATUS) throw new ProtocolError(`expected SFTP STATUS, got type ${type}`);
		const code = r.uint32();
		const msg = r.stringUtf8();
		if (code === Status.OK || (allowEof && code === Status.EOF)) return code;
		throw new ProtocolError(`sftp error ${code}: ${msg || 'operation failed'}`);
	}

	async #open(path: string, pflags: number): Promise<Uint8Array> {
		const res = await this.#request((w, id) =>
			w.byte(Pkt.OPEN).uint32(id).string(path).uint32(pflags).uint32(0)
		);
		if (res.type === Pkt.HANDLE) return res.r.string();
		this.#expectStatus(res); // a STATUS here is always an error
		throw new ProtocolError(`unexpected reply ${res.type} to OPEN`);
	}

	async #closeHandle(handle: Uint8Array): Promise<void> {
		await this.#request((w, id) => w.byte(Pkt.CLOSE).uint32(id).string(handle)).catch(() => {});
	}

	async stat(path: string): Promise<SftpAttrs> {
		const res = await this.#request((w, id) => w.byte(Pkt.STAT).uint32(id).string(path));
		if (res.type !== Pkt.ATTRS) {
			this.#expectStatus(res);
			throw new ProtocolError('stat returned no attributes');
		}
		return parseAttrs(res.r);
	}

	async list(path: string): Promise<SftpEntry[]> {
		const opened = await this.#request((w, id) => w.byte(Pkt.OPENDIR).uint32(id).string(path));
		if (opened.type !== Pkt.HANDLE) {
			this.#expectStatus(opened);
			throw new ProtocolError('opendir returned no handle');
		}
		const handle = opened.r.string();
		const entries: SftpEntry[] = [];
		try {
			for (;;) {
				const res = await this.#request((w, id) => w.byte(Pkt.READDIR).uint32(id).string(handle));
				if (res.type === Pkt.STATUS) break; // EOF
				if (res.type !== Pkt.NAME) throw new ProtocolError(`unexpected READDIR reply ${res.type}`);
				const count = res.r.uint32();
				for (let i = 0; i < count; i++) {
					entries.push({
						filename: res.r.stringUtf8(),
						longname: res.r.stringUtf8(),
						attrs: parseAttrs(res.r)
					});
				}
			}
		} finally {
			await this.#closeHandle(handle);
		}
		return entries;
	}

	async readFile(path: string): Promise<Uint8Array> {
		const handle = await this.#open(path, PFlags.READ);
		const chunks: Uint8Array[] = [];
		let offset = 0;
		try {
			for (;;) {
				const res = await this.#request((w, id) =>
					w.byte(Pkt.READ).uint32(id).string(handle).uint64(BigInt(offset)).uint32(READ_CHUNK)
				);
				if (res.type === Pkt.STATUS) {
					this.#expectStatus(res, true); // throws on a real error; EOF ends the loop
					break;
				}
				if (res.type !== Pkt.DATA) throw new ProtocolError(`unexpected READ reply ${res.type}`);
				const data = res.r.string();
				chunks.push(data);
				offset += data.length;
				// a short read is NOT EOF (RFC); keep going until a STATUS(EOF) arrives
			}
		} finally {
			await this.#closeHandle(handle);
		}
		return concatBytes(...chunks);
	}

	async writeFile(path: string, data: Uint8Array): Promise<void> {
		const handle = await this.#open(path, PFlags.WRITE | PFlags.CREAT | PFlags.TRUNC);
		try {
			let offset = 0;
			while (offset < data.length) {
				const chunk = data.subarray(offset, offset + READ_CHUNK);
				this.#expectStatus(
					await this.#request((w, id) =>
						w.byte(Pkt.WRITE).uint32(id).string(handle).uint64(BigInt(offset)).string(chunk)
					)
				);
				offset += chunk.length;
			}
		} finally {
			await this.#closeHandle(handle);
		}
	}

	createReadStream(path: string): ReadableStream<Uint8Array> {
		let handle: Uint8Array | null = null;
		let opening: Promise<Uint8Array> | null = null;
		let offset = 0;
		const self = this;
		return new ReadableStream<Uint8Array>({
			async pull(controller) {
				// open lazily so we never depend on start() finishing before pull()
				if (!handle) handle = await (opening ??= self.#open(path, PFlags.READ));
				const res = await self.#request((w, id) =>
					w.byte(Pkt.READ).uint32(id).string(handle!).uint64(BigInt(offset)).uint32(READ_CHUNK)
				);
				if (res.type === Pkt.STATUS) {
					self.#expectStatus(res, true); // throws on a real error; EOF closes the stream
					if (handle) await self.#closeHandle(handle);
					controller.close();
					return;
				}
				const data = res.r.string();
				offset += data.length;
				controller.enqueue(data);
				// a short read is NOT EOF; the next pull continues until STATUS(EOF)
			},
			async cancel() {
				if (handle) await self.#closeHandle(handle);
			}
		});
	}

	createWriteStream(path: string): WritableStream<Uint8Array> {
		let handle: Uint8Array | null = null;
		let opening: Promise<Uint8Array> | null = null;
		let offset = 0;
		const self = this;
		return new WritableStream<Uint8Array>({
			async write(chunk) {
				if (!handle)
					handle = await (opening ??= self.#open(path, PFlags.WRITE | PFlags.CREAT | PFlags.TRUNC));
				let o = 0;
				while (o < chunk.length) {
					const part = chunk.subarray(o, o + READ_CHUNK);
					self.#expectStatus(
						await self.#request((w, id) =>
							w.byte(Pkt.WRITE).uint32(id).string(handle!).uint64(BigInt(offset)).string(part)
						)
					);
					offset += part.length;
					o += part.length;
				}
			},
			async close() {
				if (handle) await self.#closeHandle(handle);
			}
		});
	}

	async mkdir(path: string): Promise<void> {
		this.#expectStatus(
			await this.#request((w, id) => w.byte(Pkt.MKDIR).uint32(id).string(path).uint32(0))
		);
	}

	async remove(path: string): Promise<void> {
		this.#expectStatus(await this.#request((w, id) => w.byte(Pkt.REMOVE).uint32(id).string(path)));
	}

	async rename(from: string, to: string): Promise<void> {
		this.#expectStatus(
			await this.#request((w, id) => w.byte(Pkt.RENAME).uint32(id).string(from).string(to))
		);
	}

	async realpath(path: string): Promise<string> {
		const res = await this.#request((w, id) => w.byte(Pkt.REALPATH).uint32(id).string(path));
		if (res.type !== Pkt.NAME) {
			this.#expectStatus(res);
			throw new ProtocolError('realpath returned no name');
		}
		res.r.uint32(); // count (always 1 for REALPATH)
		return res.r.stringUtf8();
	}

	async close(): Promise<void> {
		await this.channel.close().catch(() => {});
		if (this.ownedSession) await this.ownedSession.close().catch(() => {});
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

/**
 * Opens an SFTP session, either over an existing SSH session or by opening its own.
 *
 * @param opts - SSH connection options, or `{ session }` to reuse an open SSH session.
 * @returns A ready {@link SftpSession}.
 * @throws {ConnectionError} If the subsystem cannot be started.
 * @since 1.0.0
 */
export async function connect(
	opts: SshConnectOptions | { session: SshSession }
): Promise<SftpSession> {
	const ownsSession = !('session' in opts);
	const session = 'session' in opts ? opts.session : await sshConnect(opts);
	let channel: SshChannelHandle;
	try {
		channel = await session.subsystem('sftp');
	} catch (err) {
		if (ownsSession) await session.close().catch(() => {});
		throw new ConnectionError('failed to start the sftp subsystem', {
			protocol: 'sftp',
			cause: err
		});
	}
	const sftp = new Sftp(channel, ownsSession ? session : undefined);
	await sftp.init();
	return sftp;
}

/**
 * Downloads a single file over a fresh connection.
 *
 * @param opts - SSH connection options plus the `path` to read.
 * @returns The file contents.
 * @since 1.0.0
 */
export async function getFile(opts: SshConnectOptions & { path: string }): Promise<Uint8Array> {
	await using sftp = await connect(opts);
	return sftp.readFile(opts.path);
}

/**
 * Uploads a single file over a fresh connection.
 *
 * @param opts - SSH connection options plus the `path` and `data` to write.
 * @since 1.0.0
 */
export async function putFile(
	opts: SshConnectOptions & { path: string; data: Uint8Array }
): Promise<void> {
	await using sftp = await connect(opts);
	await sftp.writeFile(opts.path, opts.data);
}
