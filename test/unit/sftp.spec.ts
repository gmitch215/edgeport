import { describe, expect, it } from 'vitest';
import { ProtocolError } from '../../src/core/errors';
import { StreamFramedReader } from '../../src/core/framing';
import { _sessionOverChannel, Attr, Pkt, type SftpSession, Status } from '../../src/sftp/index';
import type { SshChannelHandle } from '../../src/ssh/index';
import { SshReader, SshWriter } from '../../src/wire';

// one framed SFTP request read from the client: type + id + a reader positioned past the id
interface ClientPacket {
	type: number;
	id: number;
	r: SshReader;
}

/**
 * A scriptable mock SFTP server over an in-memory duplex channel. The test reads the client's
 * framed requests with {@link next} and replies with the typed helpers below; framing matches
 * the real session (uint32 length, byte type, uint32 id, body).
 */
class MockSftpServer {
	readonly channel: SshChannelHandle;
	#reader: StreamFramedReader;
	#out: WritableStreamDefaultWriter<Uint8Array>;

	constructor() {
		const s2c = new TransformStream<Uint8Array, Uint8Array>(
			undefined,
			{ highWaterMark: 1 << 20 },
			{ highWaterMark: 1 << 20 }
		);
		const c2s = new TransformStream<Uint8Array, Uint8Array>(
			undefined,
			{ highWaterMark: 1 << 20 },
			{ highWaterMark: 1 << 20 }
		);
		this.#reader = new StreamFramedReader(c2s.readable);
		this.#out = s2c.writable.getWriter();
		const clientWriter = c2s.writable.getWriter();
		this.channel = {
			stdout: s2c.readable,
			stderr: new ReadableStream<Uint8Array>(),
			write: (data) => clientWriter.write(data),
			eof: async () => {},
			exit: Promise.resolve({ code: 0 } as never),
			close: async () => {
				await clientWriter.close().catch(() => {});
				await this.#out.close().catch(() => {});
			},
			[Symbol.asyncDispose]: async () => {}
		};
	}

	// reads the next framed request the client sent
	async next(): Promise<ClientPacket> {
		const len = new DataView((await this.#reader.readN(4)).buffer).getUint32(0, false);
		const r = new SshReader(await this.#reader.readN(len));
		const type = r.byte();
		if (type === Pkt.INIT) return { type, id: r.uint32(), r }; // INIT carries version, not id
		const id = r.uint32();
		return { type, id, r };
	}

	#send(body: Uint8Array): Promise<void> {
		const framed = new SshWriter().uint32(body.length).raw(body).bytes();
		return this.#out.write(framed);
	}

	sendVersion(version = 3): Promise<void> {
		return this.#send(new SshWriter().byte(Pkt.VERSION).uint32(version).bytes());
	}

	sendStatus(id: number, code: number, msg = ''): Promise<void> {
		return this.#send(
			new SshWriter().byte(Pkt.STATUS).uint32(id).uint32(code).string(msg).string('').bytes()
		);
	}

	sendHandle(id: number, handle = 'h'): Promise<void> {
		return this.#send(new SshWriter().byte(Pkt.HANDLE).uint32(id).string(handle).bytes());
	}

	// ATTRS reply; pass permissions to set the dir/file bits via the PERMISSIONS flag
	sendAttrs(id: number, opts: { size?: number; permissions?: number } = {}): Promise<void> {
		const w = new SshWriter().byte(Pkt.ATTRS).uint32(id);
		let flags = 0;
		if (opts.size !== undefined) flags |= 0x1;
		if (opts.permissions !== undefined) flags |= 0x4;
		w.uint32(flags);
		if (opts.size !== undefined) w.uint64(BigInt(opts.size));
		if (opts.permissions !== undefined) w.uint32(opts.permissions);
		return this.#send(w.bytes());
	}

	sendData(id: number, data: Uint8Array): Promise<void> {
		return this.#send(new SshWriter().byte(Pkt.DATA).uint32(id).string(data).bytes());
	}

	// NAME reply listing the given entries (filename, longname, attrs with permissions)
	sendNames(id: number, entries: { name: string; permissions: number }[]): Promise<void> {
		const w = new SshWriter().byte(Pkt.NAME).uint32(id).uint32(entries.length);
		for (const e of entries) {
			w.string(e.name).string(e.name).uint32(0x4).uint32(e.permissions);
		}
		return this.#send(w.bytes());
	}
}

const DIR = 0o040755;
const FILE = 0o100644;

// spins up a mock server, runs the INIT/VERSION handshake, hands the ready session + server to body
async function withSftp(
	body: (session: SftpSession, server: MockSftpServer) => Promise<void>
): Promise<void> {
	const server = new MockSftpServer();
	const handshake = (async () => {
		const init = await server.next();
		expect(init.type).toBe(Pkt.INIT);
		await server.sendVersion(3);
	})();
	const session = (await Promise.all([_sessionOverChannel(server.channel), handshake]))[0];
	await body(session, server);
}

describe('sftp exists', () => {
	it('maps a NO_SUCH_FILE stat status to false', async () => {
		await withSftp(async (session, server) => {
			const script = (async () => {
				const req = await server.next();
				expect(req.type).toBe(Pkt.STAT);
				await server.sendStatus(req.id, Status.NO_SUCH_FILE, 'no such file');
			})();
			const [ok] = await Promise.all([session.exists('/missing'), script]);
			expect(ok).toBe(false);
		});
	});

	it('maps a successful stat to true', async () => {
		await withSftp(async (session, server) => {
			const script = (async () => {
				const req = await server.next();
				expect(req.type).toBe(Pkt.STAT);
				await server.sendAttrs(req.id, { size: 10, permissions: FILE });
			})();
			const [ok] = await Promise.all([session.exists('/there'), script]);
			expect(ok).toBe(true);
		});
	});

	it('rethrows a non-not-found error', async () => {
		await withSftp(async (session, server) => {
			const script = (async () => {
				const req = await server.next();
				await server.sendStatus(req.id, Status.FAILURE, 'permission denied');
			})();
			await expect(Promise.all([session.exists('/denied'), script])).rejects.toBeInstanceOf(
				ProtocolError
			);
		});
	});
});

describe('sftp ensureDir', () => {
	it('issues MKDIR per cumulative segment, tolerates already-exists, verifies with stat', async () => {
		await withSftp(async (session, server) => {
			const seen: string[] = [];
			const script = (async () => {
				// MKDIR /a -> OK
				let req = await server.next();
				expect(req.type).toBe(Pkt.MKDIR);
				seen.push(req.r.stringUtf8());
				await server.sendStatus(req.id, Status.OK);
				// MKDIR /a/b -> already exists (FAILURE), swallowed
				req = await server.next();
				expect(req.type).toBe(Pkt.MKDIR);
				seen.push(req.r.stringUtf8());
				await server.sendStatus(req.id, Status.FAILURE, 'already exists');
				// MKDIR /a/b/c -> OK
				req = await server.next();
				expect(req.type).toBe(Pkt.MKDIR);
				seen.push(req.r.stringUtf8());
				await server.sendStatus(req.id, Status.OK);
				// final verify stat -> a directory
				req = await server.next();
				expect(req.type).toBe(Pkt.STAT);
				await server.sendAttrs(req.id, { permissions: DIR });
			})();
			await Promise.all([session.ensureDir('/a/b/c'), script]);
			expect(seen).toEqual(['/a', '/a/b', '/a/b/c']);
		});
	});

	it('throws when the final path exists but is not a directory', async () => {
		await withSftp(async (session, server) => {
			const script = (async () => {
				const req = await server.next();
				expect(req.type).toBe(Pkt.MKDIR);
				await server.sendStatus(req.id, Status.FAILURE, 'exists');
				const stat = await server.next();
				expect(stat.type).toBe(Pkt.STAT);
				await server.sendAttrs(stat.id, { permissions: FILE });
			})();
			await expect(Promise.all([session.ensureDir('/file'), script])).rejects.toBeInstanceOf(
				ProtocolError
			);
		});
	});
});

describe('sftp rmdir and chmod packets', () => {
	it('rmdir sends packet type 15 with the path', async () => {
		await withSftp(async (session, server) => {
			const script = (async () => {
				const req = await server.next();
				expect(req.type).toBe(Pkt.RMDIR);
				expect(req.r.stringUtf8()).toBe('/empty');
				await server.sendStatus(req.id, Status.OK);
			})();
			await Promise.all([session.rmdir('/empty'), script]);
		});
	});

	it('chmod sends SETSTAT (type 9) with only the PERMISSIONS attr flag', async () => {
		await withSftp(async (session, server) => {
			const script = (async () => {
				const req = await server.next();
				expect(req.type).toBe(Pkt.SETSTAT);
				expect(req.r.stringUtf8()).toBe('/script.sh');
				expect(req.r.uint32()).toBe(Attr.PERMISSIONS); // attr flags
				expect(req.r.uint32()).toBe(0o755); // mode
				await server.sendStatus(req.id, Status.OK);
			})();
			await Promise.all([session.chmod('/script.sh', 0o755), script]);
		});
	});

	it('rmdir maps a non-OK status to ProtocolError', async () => {
		await withSftp(async (session, server) => {
			const script = (async () => {
				const req = await server.next();
				await server.sendStatus(req.id, Status.FAILURE, 'not empty');
			})();
			await expect(Promise.all([session.rmdir('/full'), script])).rejects.toBeInstanceOf(
				ProtocolError
			);
		});
	});
});

describe('sftp text/json round-trips', () => {
	// scripts an OPEN -> single READ(DATA) -> READ(EOF) -> CLOSE read flow returning `bytes`
	async function scriptRead(server: MockSftpServer, bytes: Uint8Array): Promise<void> {
		let req = await server.next();
		expect(req.type).toBe(Pkt.OPEN);
		await server.sendHandle(req.id);
		req = await server.next();
		expect(req.type).toBe(Pkt.READ);
		await server.sendData(req.id, bytes);
		req = await server.next();
		expect(req.type).toBe(Pkt.READ);
		await server.sendStatus(req.id, Status.EOF, 'eof');
		req = await server.next();
		expect(req.type).toBe(Pkt.CLOSE);
		await server.sendStatus(req.id, Status.OK);
	}

	// scripts an OPEN -> single WRITE -> CLOSE flow, capturing the written bytes
	async function scriptWrite(server: MockSftpServer): Promise<Uint8Array> {
		let req = await server.next();
		expect(req.type).toBe(Pkt.OPEN);
		await server.sendHandle(req.id);
		req = await server.next();
		expect(req.type).toBe(Pkt.WRITE);
		req.r.string(); // handle
		req.r.uint64(); // offset
		const data = req.r.string();
		await server.sendStatus(req.id, Status.OK);
		req = await server.next();
		expect(req.type).toBe(Pkt.CLOSE);
		await server.sendStatus(req.id, Status.OK);
		return data;
	}

	it('readText decodes the file bytes as UTF-8', async () => {
		await withSftp(async (session, server) => {
			const script = scriptRead(server, new TextEncoder().encode('utf-8 text: cafe'));
			const [text] = await Promise.all([session.readText('/note.txt'), script]);
			expect(text).toBe('utf-8 text: cafe');
		});
	});

	it('writeText encodes UTF-8 and writes it', async () => {
		await withSftp(async (session, server) => {
			const script = scriptWrite(server);
			const [, written] = await Promise.all([
				session.writeText('/note.txt', 'hello world\n'),
				script
			]);
			expect(new TextDecoder().decode(written)).toBe('hello world\n');
		});
	});

	it('writeJson serializes (honoring space) and readJson parses it back', async () => {
		const value = { name: 'edge', nested: { n: 1 } };
		await withSftp(async (session, server) => {
			const script = scriptWrite(server);
			const [, written] = await Promise.all([
				session.writeJson('/config.json', value, { space: 2 }),
				script
			]);
			expect(new TextDecoder().decode(written)).toBe(JSON.stringify(value, null, 2));
		});
		await withSftp(async (session, server) => {
			const script = scriptRead(server, new TextEncoder().encode(JSON.stringify(value, null, 2)));
			const [parsed] = await Promise.all([session.readJson<typeof value>('/config.json'), script]);
			expect(parsed).toEqual(value);
		});
	});

	it('readJson throws ProtocolError on invalid JSON', async () => {
		await withSftp(async (session, server) => {
			const script = scriptRead(server, new TextEncoder().encode('{ not json'));
			await expect(Promise.all([session.readJson('/bad.json'), script])).rejects.toBeInstanceOf(
				ProtocolError
			);
		});
	});
});

describe('sftp removeAll', () => {
	it('rejects the server root', async () => {
		await withSftp(async (session) => {
			await expect(session.removeAll('/')).rejects.toBeInstanceOf(ProtocolError);
		});
	});

	it('rejects an empty path', async () => {
		await withSftp(async (session) => {
			await expect(session.removeAll('')).rejects.toBeInstanceOf(ProtocolError);
		});
	});

	it('walks a small tree depth-first: files via REMOVE, dirs via RMDIR, skipping . and ..', async () => {
		// /top
		//   a.txt   (file)
		//   sub/    (dir)
		//     b.txt (file)
		await withSftp(async (session, server) => {
			const removes: string[] = [];
			const rmdirs: string[] = [];
			const script = (async () => {
				// list /top: OPENDIR -> READDIR(names) -> READDIR(EOF) -> CLOSE
				let req = await server.next();
				expect(req.type).toBe(Pkt.OPENDIR);
				await server.sendHandle(req.id, 'top');
				req = await server.next();
				expect(req.type).toBe(Pkt.READDIR);
				await server.sendNames(req.id, [
					{ name: '.', permissions: DIR },
					{ name: '..', permissions: DIR },
					{ name: 'a.txt', permissions: FILE },
					{ name: 'sub', permissions: DIR }
				]);
				req = await server.next();
				expect(req.type).toBe(Pkt.READDIR);
				await server.sendStatus(req.id, Status.EOF, 'eof');
				req = await server.next();
				expect(req.type).toBe(Pkt.CLOSE);
				await server.sendStatus(req.id, Status.OK);
				// remove /top/a.txt
				req = await server.next();
				expect(req.type).toBe(Pkt.REMOVE);
				removes.push(req.r.stringUtf8());
				await server.sendStatus(req.id, Status.OK);
				// recurse into /top/sub: OPENDIR -> READDIR(names) -> READDIR(EOF) -> CLOSE
				req = await server.next();
				expect(req.type).toBe(Pkt.OPENDIR);
				await server.sendHandle(req.id, 'sub');
				req = await server.next();
				expect(req.type).toBe(Pkt.READDIR);
				await server.sendNames(req.id, [{ name: 'b.txt', permissions: FILE }]);
				req = await server.next();
				expect(req.type).toBe(Pkt.READDIR);
				await server.sendStatus(req.id, Status.EOF, 'eof');
				req = await server.next();
				expect(req.type).toBe(Pkt.CLOSE);
				await server.sendStatus(req.id, Status.OK);
				// remove /top/sub/b.txt
				req = await server.next();
				expect(req.type).toBe(Pkt.REMOVE);
				removes.push(req.r.stringUtf8());
				await server.sendStatus(req.id, Status.OK);
				// rmdir /top/sub
				req = await server.next();
				expect(req.type).toBe(Pkt.RMDIR);
				rmdirs.push(req.r.stringUtf8());
				await server.sendStatus(req.id, Status.OK);
				// rmdir /top
				req = await server.next();
				expect(req.type).toBe(Pkt.RMDIR);
				rmdirs.push(req.r.stringUtf8());
				await server.sendStatus(req.id, Status.OK);
			})();
			await Promise.all([session.removeAll('/top'), script]);
			expect(removes).toEqual(['/top/a.txt', '/top/sub/b.txt']);
			expect(rmdirs).toEqual(['/top/sub', '/top']);
		});
	});
});

describe('sftp removeMany', () => {
	it('removes each path; with ignoreMissing swallows not-found', async () => {
		await withSftp(async (session, server) => {
			const removed: string[] = [];
			const script = (async () => {
				let req = await server.next();
				expect(req.type).toBe(Pkt.REMOVE);
				removed.push(req.r.stringUtf8());
				await server.sendStatus(req.id, Status.OK);
				req = await server.next();
				expect(req.type).toBe(Pkt.REMOVE);
				removed.push(req.r.stringUtf8());
				await server.sendStatus(req.id, Status.NO_SUCH_FILE, 'gone'); // swallowed
				req = await server.next();
				expect(req.type).toBe(Pkt.REMOVE);
				removed.push(req.r.stringUtf8());
				await server.sendStatus(req.id, Status.OK);
			})();
			await Promise.all([session.removeMany(['/a', '/b', '/c'], { ignoreMissing: true }), script]);
			expect(removed).toEqual(['/a', '/b', '/c']);
		});
	});

	it('without ignoreMissing a not-found rejects', async () => {
		await withSftp(async (session, server) => {
			const script = (async () => {
				const req = await server.next();
				await server.sendStatus(req.id, Status.NO_SUCH_FILE, 'gone');
			})();
			await expect(Promise.all([session.removeMany(['/a']), script])).rejects.toBeInstanceOf(
				ProtocolError
			);
		});
	});
});
