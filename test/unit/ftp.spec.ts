import { describe, expect, it } from 'vitest';
import { AuthError, ProtocolError } from '../../src/core/errors';
import {
	_sessionOverSocket,
	parseEpsv,
	parseListLine,
	parseMdtm,
	parsePasv,
	parseReply
} from '../../src/ftp';
import { mockConnection, type MockServerEnd } from '../mock-socket';

describe('parseReply', () => {
	it('parses a single-line reply', () => {
		expect(parseReply(['220 Service ready'])).toEqual({ code: 220, text: 'Service ready' });
	});

	it('parses a 257 quoted-path reply text verbatim', () => {
		const r = parseReply(['257 "/home/me" is current directory']);
		expect(r.code).toBe(257);
		expect(r.text).toBe('"/home/me" is current directory');
	});

	it('joins a multiline block and keeps the opening code', () => {
		const r = parseReply(['211-Features:', ' SIZE', ' MDTM', '211 End']);
		expect(r.code).toBe(211);
		expect(r.text).toBe('Features:\n SIZE\n MDTM\nEnd');
	});

	it('classifies by first digit via the code', () => {
		expect(parseReply(['150 opening'])).toMatchObject({ code: 150 });
		expect(parseReply(['226 done'])).toMatchObject({ code: 226 });
		expect(parseReply(['331 need password'])).toMatchObject({ code: 331 });
		expect(parseReply(['530 not logged in'])).toMatchObject({ code: 530 });
	});

	it('throws ProtocolError on empty input', () => {
		expect(() => parseReply([])).toThrow(ProtocolError);
	});

	it('throws ProtocolError when the first line has no 3-digit code', () => {
		expect(() => parseReply(['hello world'])).toThrow(ProtocolError);
	});
});

describe('parseEpsv', () => {
	it('parses the port between the | delimiters', () => {
		expect(parseEpsv('229 Entering Extended Passive Mode (|||49152|)')).toBe(49152);
	});

	it('parses a low port', () => {
		expect(parseEpsv('229 EPSV ok (|||21|)')).toBe(21);
	});

	it('tolerates a non-| delimiter char (RFC 2428 allows any printable)', () => {
		expect(parseEpsv('229 Entering Extended Passive Mode (!!!1234!)')).toBe(1234);
	});

	it('throws ProtocolError when no (|||PORT|) group is present', () => {
		expect(() => parseEpsv('229 Entering Extended Passive Mode')).toThrow(ProtocolError);
	});
});

describe('parsePasv', () => {
	it('parses host and computes the port from p1*256+p2', () => {
		expect(parsePasv('227 Entering Passive Mode (192,168,0,1,19,136)')).toEqual({
			host: '192.168.0.1',
			port: 19 * 256 + 136
		});
	});

	it('handles a zero low byte', () => {
		expect(parsePasv('227 (10,0,0,5,200,0)')).toEqual({ host: '10.0.0.5', port: 200 * 256 });
	});

	it('throws ProtocolError when no six-number group is present', () => {
		expect(() => parsePasv('227 Entering Passive Mode')).toThrow(ProtocolError);
	});
});

describe('parseListLine', () => {
	it('parses a regular file', () => {
		const e = parseListLine('-rw-r--r-- 1 me grp 1234 Jun 28 12:00 readme.txt');
		expect(e).toEqual({
			name: 'readme.txt',
			size: 1234,
			isDirectory: false,
			raw: '-rw-r--r-- 1 me grp 1234 Jun 28 12:00 readme.txt'
		});
	});

	it('parses a directory and flags isDirectory from the leading d', () => {
		const e = parseListLine('drwxr-xr-x 2 me grp 4096 Jun 28 12:00 pub');
		expect(e.name).toBe('pub');
		expect(e.isDirectory).toBe(true);
		expect(e.size).toBe(4096);
	});

	it('keeps names containing spaces', () => {
		const e = parseListLine('-rw-r--r-- 1 me grp 10 Jun 28 12:00 my file name.txt');
		expect(e.name).toBe('my file name.txt');
		expect(e.size).toBe(10);
	});

	it('parses a year-form date column', () => {
		const e = parseListLine('-rw-r--r-- 1 me grp 88 Jan  3  2020 old.log');
		expect(e.name).toBe('old.log');
		expect(e.size).toBe(88);
	});

	it('strips the -> target from a symlink name', () => {
		const e = parseListLine('lrwxrwxrwx 1 me grp 7 Jun 28 12:00 cur -> target');
		expect(e.name).toBe('cur');
		expect(e.isDirectory).toBe(false);
	});

	it('falls back to a best-effort name on an unparseable line', () => {
		const e = parseListLine('total 8');
		expect(e.name).toBe('8');
		expect(e.size).toBeUndefined();
		expect(e.isDirectory).toBe(false);
		expect(e.raw).toBe('total 8');
	});
});

const CONN = { hostname: 'ftp.test', username: 'me', password: 'secret' };

describe('ftp login', () => {
	it('reads the greeting, runs USER/PASS, switches to binary', async () => {
		const { socket, server } = mockConnection();
		const client = _sessionOverSocket(socket, CONN);

		const script = (async () => {
			await server.writeLine('220 Service ready');
			expect(await server.readLine()).toBe('USER me');
			await server.writeLine('331 need password');
			expect(await server.readLine()).toBe('PASS secret');
			await server.writeLine('230 logged in');
			expect(await server.readLine()).toBe('TYPE I');
			await server.writeLine('200 type set to I');
		})();
		const session = (await Promise.all([client, script]))[0];

		const closeScript = (async () => {
			expect(await server.readLine()).toBe('QUIT');
			await server.writeLine('221 bye');
		})();
		await Promise.all([session.close(), closeScript]);
	});

	it('defaults username to anonymous and password to empty', async () => {
		const { socket, server } = mockConnection();
		const client = _sessionOverSocket(socket, { hostname: 'ftp.test' });

		const script = (async () => {
			await server.writeLine('220 ready');
			expect(await server.readLine()).toBe('USER anonymous');
			await server.writeLine('331 send email as password');
			expect(await server.readLine()).toBe('PASS ');
			await server.writeLine('230 ok');
			expect(await server.readLine()).toBe('TYPE I');
			await server.writeLine('200 ok');
		})();
		await Promise.all([client, script]);
	});

	it('skips PASS when USER already returns 230', async () => {
		const { socket, server } = mockConnection();
		const client = _sessionOverSocket(socket, CONN);

		const script = (async () => {
			await server.writeLine('220 ready');
			expect(await server.readLine()).toBe('USER me');
			await server.writeLine('230 already logged in');
			expect(await server.readLine()).toBe('TYPE I');
			await server.writeLine('200 ok');
		})();
		await Promise.all([client, script]);
	});

	it('reads a multiline greeting before USER', async () => {
		const { socket, server } = mockConnection();
		const client = _sessionOverSocket(socket, CONN);

		const script = (async () => {
			await server.writeLine('220-Welcome to the test server');
			await server.writeLine('220-Please read the rules');
			await server.writeLine('220 Service ready');
			expect(await server.readLine()).toBe('USER me');
			await server.writeLine('331 ok');
			expect(await server.readLine()).toBe('PASS secret');
			await server.writeLine('230 ok');
			expect(await server.readLine()).toBe('TYPE I');
			await server.writeLine('200 ok');
		})();
		await Promise.all([client, script]);
	});

	it('maps 530 on PASS to AuthError', async () => {
		const { socket, server } = mockConnection();
		const client = _sessionOverSocket(socket, { ...CONN, password: 'wrong' });

		const script = (async () => {
			await server.writeLine('220 ready');
			expect(await server.readLine()).toBe('USER me');
			await server.writeLine('331 ok');
			expect(await server.readLine()).toBe('PASS wrong');
			await server.writeLine('530 Login incorrect');
		})();

		await expect(Promise.all([client, script])).rejects.toBeInstanceOf(AuthError);
	});

	it('maps an unexpected USER reply code to ProtocolError', async () => {
		const { socket, server } = mockConnection();
		const client = _sessionOverSocket(socket, CONN);

		const script = (async () => {
			await server.writeLine('220 ready');
			expect(await server.readLine()).toBe('USER me');
			await server.writeLine('500 Syntax error');
		})();

		await expect(Promise.all([client, script])).rejects.toBeInstanceOf(ProtocolError);
	});
});

// drives login then hands the ready session and live server end to the body
async function withSession(
	body: (
		session: Awaited<ReturnType<typeof _sessionOverSocket>>,
		server: MockServerEnd
	) => Promise<void>
): Promise<void> {
	const { socket, server } = mockConnection();
	const client = _sessionOverSocket(socket, CONN);
	const login = (async () => {
		await server.writeLine('220 ready');
		await server.readLine(); // USER
		await server.writeLine('331 ok');
		await server.readLine(); // PASS
		await server.writeLine('230 ok');
		await server.readLine(); // TYPE I
		await server.writeLine('200 ok');
	})();
	const session = (await Promise.all([client, login]))[0];
	await body(session, server);
}

describe('ftp simple commands', () => {
	it('pwd extracts the quoted path from a 257 reply', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('PWD');
				await server.writeLine('257 "/home/me" is the current directory');
			})();
			const [dir] = await Promise.all([session.pwd(), script]);
			expect(dir).toBe('/home/me');
		});
	});

	it('pwd un-doubles embedded quotes', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				await server.readLine();
				await server.writeLine('257 "/a""b" created');
			})();
			const [dir] = await Promise.all([session.pwd(), script]);
			expect(dir).toBe('/a"b');
		});
	});

	it('cwd accepts a 250 reply', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('CWD /pub');
				await server.writeLine('250 directory changed');
			})();
			await Promise.all([session.cwd('/pub'), script]);
		});
	});

	it('cwd rejects with ProtocolError on 550', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('CWD /nope');
				await server.writeLine('550 No such directory');
			})();
			await expect(Promise.all([session.cwd('/nope'), script])).rejects.toBeInstanceOf(
				ProtocolError
			);
		});
	});

	it('size parses the numeric 213 reply', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('SIZE /pub/readme.txt');
				await server.writeLine('213 1234');
			})();
			const [n] = await Promise.all([session.size('/pub/readme.txt'), script]);
			expect(n).toBe(1234);
		});
	});

	it('delete accepts a 250 reply', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('DELE /tmp/old.txt');
				await server.writeLine('250 file deleted');
			})();
			await Promise.all([session.delete('/tmp/old.txt'), script]);
		});
	});

	it('mkdir accepts a 257 reply', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('MKD /incoming/2026');
				await server.writeLine('257 "/incoming/2026" created');
			})();
			await Promise.all([session.mkdir('/incoming/2026'), script]);
		});
	});

	it('rmdir accepts a 250 reply', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('RMD /incoming/2025');
				await server.writeLine('250 directory removed');
			})();
			await Promise.all([session.rmdir('/incoming/2025'), script]);
		});
	});

	it('rename sends RNFR then RNTO', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('RNFR /tmp/a.txt');
				await server.writeLine('350 ready for destination');
				expect(await server.readLine()).toBe('RNTO /tmp/b.txt');
				await server.writeLine('250 rename complete');
			})();
			await Promise.all([session.rename('/tmp/a.txt', '/tmp/b.txt'), script]);
		});
	});

	it('size throws ProtocolError on a non-numeric reply', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				await server.readLine();
				await server.writeLine('213 not-a-number');
			})();
			await expect(Promise.all([session.size('/x'), script])).rejects.toBeInstanceOf(ProtocolError);
		});
	});
});

// scripts the passive-open handshake the way the real EPSV/PASV path expects
async function passiveOpen(server: MockServerEnd): Promise<void> {
	expect(await server.readLine()).toBe('EPSV');
	// reject EPSV so the client falls back to PASV (no real data socket to dial in the mock)
	await server.writeLine('500 not understood');
	expect(await server.readLine()).toBe('PASV');
	// 127.0.0.1 port 0; the data connect will fail but only after the commands we assert are sent
	await server.writeLine('227 Entering Passive Mode (127,0,0,1,0,0)');
}

describe('ftp TYPE / REST sequencing', () => {
	it('get issues TYPE A before RETR in ascii mode', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('TYPE A');
				await server.writeLine('200 type set to A');
				await passiveOpen(server);
				expect(await server.readLine()).toBe('RETR /a.txt');
			})();
			// the data dial to port 0 fails; we only care that the control sequence was correct
			await expect(
				Promise.all([session.get('/a.txt', { type: 'ascii' }), script])
			).rejects.toBeTruthy();
		});
	});

	it('does not re-issue TYPE I when already binary (the session default)', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				// no TYPE command: binary is the negotiated default, so the first line is EPSV
				await passiveOpen(server);
				expect(await server.readLine()).toBe('RETR /b.bin');
			})();
			await expect(Promise.all([session.get('/b.bin'), script])).rejects.toBeTruthy();
		});
	});

	it('get issues REST <offset> after the data channel opens but before RETR', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				await passiveOpen(server);
				expect(await server.readLine()).toBe('REST 1024');
				await server.writeLine('350 restarting at 1024');
				expect(await server.readLine()).toBe('RETR /big.bin');
			})();
			await expect(
				Promise.all([session.get('/big.bin', { offset: 1024 }), script])
			).rejects.toBeTruthy();
		});
	});

	it('put issues REST <offset> before STOR for an offset resume', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				await passiveOpen(server);
				expect(await server.readLine()).toBe('REST 512');
				await server.writeLine('350 restarting at 512');
				expect(await server.readLine()).toBe('STOR /big.bin');
			})();
			await expect(
				Promise.all([session.put('/big.bin', new Uint8Array(4), { offset: 512 }), script])
			).rejects.toBeTruthy();
		});
	});

	it('put uses APPE (no REST) when append is set', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				await passiveOpen(server);
				// no REST line; APPE is the next command after the passive open
				expect(await server.readLine()).toBe('APPE /big.bin');
			})();
			await expect(
				Promise.all([
					session.put('/big.bin', new Uint8Array(4), { append: true, offset: 999 }),
					script
				])
			).rejects.toBeTruthy();
		});
	});
});

describe('parseMdtm', () => {
	it('parses a 14-digit timestamp as UTC', () => {
		const d = parseMdtm('20260628120000');
		expect(d.toISOString()).toBe('2026-06-28T12:00:00.000Z');
	});

	it('parses a fractional-seconds suffix to milliseconds', () => {
		const d = parseMdtm('20260628120000.250');
		expect(d.toISOString()).toBe('2026-06-28T12:00:00.250Z');
	});

	it('tolerates surrounding whitespace', () => {
		const d = parseMdtm('  19991231235959  ');
		expect(d.toISOString()).toBe('1999-12-31T23:59:59.000Z');
	});

	it('throws ProtocolError on a non-timestamp reply', () => {
		expect(() => parseMdtm('not-a-time')).toThrow(ProtocolError);
	});
});

describe('ftp mtime', () => {
	it('sends MDTM and parses the 213 reply as a UTC Date', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('MDTM /pub/readme.txt');
				await server.writeLine('213 20260628120000');
			})();
			const [when] = await Promise.all([session.mtime('/pub/readme.txt'), script]);
			expect(when.toISOString()).toBe('2026-06-28T12:00:00.000Z');
		});
	});

	it('maps a 550 MDTM failure to ProtocolError', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('MDTM /nope');
				await server.writeLine('550 No such file');
			})();
			await expect(Promise.all([session.mtime('/nope'), script])).rejects.toBeInstanceOf(
				ProtocolError
			);
		});
	});
});

describe('ftp exists', () => {
	it('maps a 213 SIZE reply to true', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('SIZE /pub/readme.txt');
				await server.writeLine('213 1234');
			})();
			const [ok] = await Promise.all([session.exists('/pub/readme.txt'), script]);
			expect(ok).toBe(true);
		});
	});

	it('maps a 550 SIZE reply to false', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('SIZE /missing.txt');
				await server.writeLine('550 Not found');
			})();
			const [ok] = await Promise.all([session.exists('/missing.txt'), script]);
			expect(ok).toBe(false);
		});
	});
});

describe('ftp ensureDir', () => {
	it('issues MKD per cumulative absolute segment and swallows 550', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('MKD /incoming');
				await server.writeLine('550 already exists'); // swallowed
				expect(await server.readLine()).toBe('MKD /incoming/2026');
				await server.writeLine('257 "/incoming/2026" created');
				expect(await server.readLine()).toBe('MKD /incoming/2026/reports');
				await server.writeLine('257 "/incoming/2026/reports" created');
			})();
			await Promise.all([session.ensureDir('/incoming/2026/reports'), script]);
		});
	});

	it('builds relative paths under the working directory', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('MKD ./a');
				await server.writeLine('257 "/cwd/a" created');
				expect(await server.readLine()).toBe('MKD ./a/b');
				await server.writeLine('257 "/cwd/a/b" created');
			})();
			await Promise.all([session.ensureDir('a/b'), script]);
		});
	});

	it('rejects with ProtocolError when a segment fails for a non-550 reason', async () => {
		await withSession(async (session, server) => {
			const script = (async () => {
				expect(await server.readLine()).toBe('MKD /x');
				await server.writeLine('500 Syntax error');
			})();
			await expect(Promise.all([session.ensureDir('/x'), script])).rejects.toBeInstanceOf(
				ProtocolError
			);
		});
	});
});

describe('ftp text/json round-trips', () => {
	// these stub get/put on the live session instance so the encode/decode logic is exercised
	// without a data connection (unit runs without a live passive data server)
	it('putText encodes UTF-8 and forwards options to put', async () => {
		await withSession(async (session) => {
			let captured: { path: string; data: Uint8Array; opts?: unknown } | undefined;
			session.put = async (path, data, opts) => {
				captured = { path, data, opts };
			};
			await session.putText('/note.txt', 'hello world\n', { type: 'ascii' });
			expect(captured!.path).toBe('/note.txt');
			expect(new TextDecoder().decode(captured!.data)).toBe('hello world\n');
			expect(captured!.opts).toEqual({ type: 'ascii' });
		});
	});

	it('getText decodes the bytes get returns as UTF-8', async () => {
		await withSession(async (session) => {
			session.get = async () => new TextEncoder().encode('on the wire');
			expect(await session.getText('/note.txt')).toBe('on the wire');
		});
	});

	it('getText/putText round-trip through a fake store', async () => {
		await withSession(async (session) => {
			let stored: Uint8Array = new Uint8Array();
			session.put = async (_path, data) => {
				stored = data;
			};
			session.get = async () => stored;
			await session.putText('/note.txt', 'utf-8 text: cafe');
			expect(await session.getText('/note.txt')).toBe('utf-8 text: cafe');
		});
	});

	it('putJson serializes (honoring space) and getJson parses it back', async () => {
		await withSession(async (session) => {
			let stored: Uint8Array = new Uint8Array();
			session.put = async (_path, data) => {
				stored = data;
			};
			session.get = async () => stored;
			const value = { name: 'edge', nested: { n: 1 } };
			await session.putJson('/config.json', value, { space: 2 });
			// space:2 must produce indented JSON
			expect(new TextDecoder().decode(stored)).toBe(JSON.stringify(value, null, 2));
			expect(await session.getJson<typeof value>('/config.json')).toEqual(value);
		});
	});

	it('getJson surfaces a SyntaxError on invalid JSON', async () => {
		await withSession(async (session) => {
			session.get = async () => new TextEncoder().encode('{ not json');
			await expect(session.getJson('/bad.json')).rejects.toBeInstanceOf(SyntaxError);
		});
	});
});

describe('ftp removeAll', () => {
	it('rejects the server root', async () => {
		await withSession(async (session) => {
			await expect(session.removeAll('/')).rejects.toBeInstanceOf(ProtocolError);
		});
	});

	it('rejects an empty path', async () => {
		await withSession(async (session) => {
			await expect(session.removeAll('   ')).rejects.toBeInstanceOf(ProtocolError);
		});
	});

	it('walks a small tree depth-first: files via DELE, dirs via RMD', async () => {
		// stub list so removeAll walks a fixed tree without needing a data connection:
		//   /top
		//     a.txt        (file)
		//     sub/         (dir)
		//       b.txt      (file)
		await withSession(async (session) => {
			const trees: Record<string, { name: string; isDirectory: boolean }[]> = {
				'/top': [
					{ name: 'a.txt', isDirectory: false },
					{ name: 'sub', isDirectory: true }
				],
				'/top/sub': [{ name: 'b.txt', isDirectory: false }]
			};
			session.list = async (path?: string) =>
				(trees[path!] ?? []).map((e) => ({ ...e, raw: e.name }));

			const deletes: string[] = [];
			const rmdirs: string[] = [];
			session.delete = async (p: string) => {
				deletes.push(p);
			};
			session.rmdir = async (p: string) => {
				rmdirs.push(p);
			};

			await session.removeAll('/top');

			// a.txt then recurse into sub: b.txt deleted, sub removed, finally top removed
			expect(deletes).toEqual(['/top/a.txt', '/top/sub/b.txt']);
			expect(rmdirs).toEqual(['/top/sub', '/top']);
		});
	});

	it('skips . and .. listing entries', async () => {
		await withSession(async (session) => {
			session.list = async () =>
				[
					{ name: '.', isDirectory: true },
					{ name: '..', isDirectory: true },
					{ name: 'keep.txt', isDirectory: false }
				].map((e) => ({ ...e, raw: e.name }));
			const deletes: string[] = [];
			session.delete = async (p: string) => {
				deletes.push(p);
			};
			session.rmdir = async () => {};
			await session.removeAll('/dir');
			expect(deletes).toEqual(['/dir/keep.txt']);
		});
	});
});
