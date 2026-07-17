import { describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/errors';
import {
	_connectOverSocket,
	ERR_NICKNAMEINUSE,
	escapeTagValue,
	formatMessage,
	isChannelName,
	NUMERICS,
	parseCtcp,
	parseMessage,
	RPL_WELCOME,
	unescapeTagValue,
	type IrcSession
} from '../../src/irc';
import { mockConnection, type MockServerEnd } from '../mock-socket';

// reads the plaintext registration the client sends (NICK then USER) and welcomes it
async function register(server: MockServerEnd, nick = 'edgebot'): Promise<void> {
	expect(await server.readLine()).toBe(`NICK ${nick}`);
	expect((await server.readLine()).startsWith('USER ')).toBe(true);
	await server.writeLine(`:irc.test 001 ${nick} :Welcome to EdgePortTest, ${nick}`);
}

// opens a fully registered plaintext session and returns it + the server end
async function connected(
	opts: Record<string, unknown> = {}
): Promise<{ session: IrcSession; server: MockServerEnd }> {
	const { socket, server } = mockConnection();
	const nick = (opts.nick as string) ?? 'edgebot';
	const session = (
		await Promise.all([
			_connectOverSocket(socket, { hostname: 'irc.test', nick, ...opts }),
			register(server, nick)
		])
	)[0];
	return { session, server };
}

describe('irc message codec', () => {
	it('parses tags, prefix, command, middle params, and a trailing param with spaces', () => {
		const msg = parseMessage(
			'@time=2024-01-01T00:00:00.000Z;account=bob :bob!b@h PRIVMSG #chan :hello world here'
		);
		expect(msg.tags).toEqual({ time: '2024-01-01T00:00:00.000Z', account: 'bob' });
		expect(msg.prefix).toEqual({ raw: 'bob!b@h', nick: 'bob', user: 'b', host: 'h' });
		expect(msg.command).toBe('PRIVMSG');
		expect(msg.params).toEqual(['#chan', 'hello world here']);
	});

	it('uppercases an alphabetic command and keeps a 3-digit numeric verbatim', () => {
		expect(parseMessage('privmsg #x :hi').command).toBe('PRIVMSG');
		expect(parseMessage(':irc.test 353 me = #x :a b').command).toBe('353');
	});

	it('parses a bare-nick prefix and a servername prefix distinctly', () => {
		expect(parseMessage(':nick PART #x').prefix).toEqual({ raw: 'nick', nick: 'nick' });
		const server = parseMessage(':irc.example.com NOTICE * :hi there').prefix;
		expect(server?.raw).toBe('irc.example.com');
		expect(server?.nick).toBeUndefined();
	});

	it('parses nick@host with no user part', () => {
		expect(parseMessage(':nick@host QUIT').prefix).toEqual({
			raw: 'nick@host',
			nick: 'nick',
			host: 'host'
		});
	});

	it('round-trips through parse then format', () => {
		const line = 'PRIVMSG #chan :hello world';
		expect(formatMessage(parseMessage(line))).toBe(line);
		const joinLine = 'JOIN #chan';
		expect(formatMessage(parseMessage(joinLine))).toBe(joinLine);
	});

	it('auto-prefixes the last param with : when it has a space, is empty, or starts with :', () => {
		expect(formatMessage({ command: 'PRIVMSG', params: ['#c', 'a b'] })).toBe('PRIVMSG #c :a b');
		expect(formatMessage({ command: 'PRIVMSG', params: ['#c', ''] })).toBe('PRIVMSG #c :');
		expect(formatMessage({ command: 'PRIVMSG', params: ['#c', ':lead'] })).toBe(
			'PRIVMSG #c ::lead'
		);
		expect(formatMessage({ command: 'JOIN', params: ['#c'] })).toBe('JOIN #c');
	});

	it('emits tags and a prefix when present', () => {
		expect(
			formatMessage({ command: 'PRIVMSG', params: ['#c', 'hi there'], tags: { time: '2024' } })
		).toBe('@time=2024 PRIVMSG #c :hi there');
		expect(formatMessage({ command: 'PONG', params: ['x'], prefix: 'irc.test' })).toBe(
			':irc.test PONG x'
		);
	});

	it('escapes and unescapes IRCv3 tag values round-trip', () => {
		const raw = 'a;b c\\d\re\nf';
		const escaped = escapeTagValue(raw);
		expect(escaped).toBe('a\\:b\\sc\\\\d\\re\\nf');
		expect(unescapeTagValue(escaped)).toBe(raw);
	});

	it('drops the backslash on an unknown escape and on a trailing lone backslash', () => {
		expect(unescapeTagValue('a\\qb')).toBe('aqb');
		expect(unescapeTagValue('abc\\')).toBe('abc');
	});

	it('parses tags that are flags (no value)', () => {
		const msg = parseMessage('@a;b=2;c PING :x');
		expect(msg.tags).toEqual({ a: '', b: '2', c: '' });
	});

	it('extracts CTCP and recognizes channel names', () => {
		expect(parseCtcp('\x01ACTION waves\x01')).toEqual({ command: 'ACTION', args: 'waves' });
		expect(parseCtcp('plain text')).toBeUndefined();
		expect(isChannelName('#ops')).toBe(true);
		expect(isChannelName('alice')).toBe(false);
	});

	it('exposes numeric constants', () => {
		expect(RPL_WELCOME).toBe('001');
		expect(ERR_NICKNAMEINUSE).toBe('433');
		expect(NUMERICS.RPL_NAMREPLY).toBe('353');
		expect(NUMERICS.RPL_ENDOFNAMES).toBe('366');
		expect(NUMERICS.RPL_TOPIC).toBe('332');
	});
});

describe('irc registration', () => {
	it('registers with NICK/USER and reaches RPL_WELCOME', async () => {
		const { session } = await connected();
		expect(session.nick).toBe('edgebot');
		await session.close();
	});

	it('sends PASS before NICK when a password is given', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			expect(await server.readLine()).toBe('PASS s3cr3t');
			expect(await server.readLine()).toBe('NICK edgebot');
			expect((await server.readLine()).startsWith('USER ')).toBe(true);
			await server.writeLine(':irc.test 001 edgebot :Welcome');
		})();
		const session = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'irc.test', nick: 'edgebot', password: 's3cr3t' }),
				script
			])
		)[0];
		await session.close();
	});

	it('rejects a 433 nick-in-use with AuthError', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			expect(await server.readLine()).toBe('NICK taken');
			expect((await server.readLine()).startsWith('USER ')).toBe(true);
			await server.writeLine(':irc.test 433 * taken :Nickname is already in use');
		})();
		await expect(
			Promise.all([_connectOverSocket(socket, { hostname: 'irc.test', nick: 'taken' }), script])
		).rejects.toBeInstanceOf(AuthError);
	});

	it('answers a PING during registration before welcome', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			expect(await server.readLine()).toBe('NICK edgebot');
			expect((await server.readLine()).startsWith('USER ')).toBe(true);
			await server.writeLine('PING :startup');
			expect(await server.readLine()).toBe('PONG :startup');
			await server.writeLine(':irc.test 001 edgebot :Welcome');
		})();
		const session = (
			await Promise.all([
				_connectOverSocket(socket, { hostname: 'irc.test', nick: 'edgebot' }),
				script
			])
		)[0];
		await session.close();
	});
});

describe('irc SASL (CAP + PLAIN)', () => {
	it('completes CAP LS/REQ/AUTHENTICATE and 903 success', async () => {
		const { socket, server } = mockConnection();
		let authLine = '';
		const script = (async () => {
			expect(await server.readLine()).toBe('CAP LS 302');
			await server.writeLine(':irc.test CAP * LS :sasl multi-prefix message-tags server-time');
			expect(await server.readLine()).toBe('CAP REQ :sasl');
			await server.writeLine(':irc.test CAP * ACK :sasl');
			expect(await server.readLine()).toBe('AUTHENTICATE PLAIN');
			await server.writeLine('AUTHENTICATE +');
			authLine = await server.readLine();
			await server.writeLine(':irc.test 900 edgebot edgebot!u@h edgeacct :You are now logged in');
			await server.writeLine(':irc.test 903 edgebot :SASL authentication successful');
			expect(await server.readLine()).toBe('CAP END');
			expect(await server.readLine()).toBe('NICK edgebot');
			expect((await server.readLine()).startsWith('USER ')).toBe(true);
			await server.writeLine(':irc.test 001 edgebot :Welcome');
		})();
		const session = (
			await Promise.all([
				_connectOverSocket(socket, {
					hostname: 'irc.test',
					nick: 'edgebot',
					sasl: { user: 'edgeacct', password: 'hunter2' }
				}),
				script
			])
		)[0];
		// PLAIN payload is base64(\0authcid\0passwd)
		const decoded = atob(authLine.slice('AUTHENTICATE '.length));
		expect(decoded).toBe('\0edgeacct\0hunter2');
		await session.close();
	});

	it('rejects 904 SASL failure with AuthError', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			expect(await server.readLine()).toBe('CAP LS 302');
			await server.writeLine(':irc.test CAP * LS :sasl');
			expect(await server.readLine()).toBe('CAP REQ :sasl');
			await server.writeLine(':irc.test CAP * ACK :sasl');
			expect(await server.readLine()).toBe('AUTHENTICATE PLAIN');
			await server.writeLine('AUTHENTICATE +');
			await server.readLine();
			await server.writeLine(':irc.test 904 edgebot :SASL authentication failed');
		})();
		await expect(
			Promise.all([
				_connectOverSocket(socket, {
					hostname: 'irc.test',
					nick: 'edgebot',
					sasl: { user: 'bad', password: 'creds' }
				}),
				script
			])
		).rejects.toBeInstanceOf(AuthError);
	});

	it('rejects with AuthError when the server does not offer sasl', async () => {
		const { socket, server } = mockConnection();
		const script = (async () => {
			expect(await server.readLine()).toBe('CAP LS 302');
			await server.writeLine(':irc.test CAP * LS :multi-prefix server-time');
		})();
		await expect(
			Promise.all([
				_connectOverSocket(socket, {
					hostname: 'irc.test',
					nick: 'edgebot',
					sasl: { user: 'x', password: 'y' }
				}),
				script
			])
		).rejects.toBeInstanceOf(AuthError);
	});
});

describe('irc send formatting', () => {
	it('formats PRIVMSG, NOTICE, and a CTCP ACTION with exact bytes', async () => {
		const { session, server } = await connected();

		await Promise.all([
			session.say('#chan', 'hello there'),
			(async () => expect(await server.readLine()).toBe('PRIVMSG #chan :hello there'))()
		]);
		await Promise.all([
			session.notice('alice', 'heads up'),
			(async () => expect(await server.readLine()).toBe('NOTICE alice :heads up'))()
		]);
		await Promise.all([
			session.action('#chan', 'waves'),
			(async () => expect(await server.readLine()).toBe('PRIVMSG #chan :\x01ACTION waves\x01'))()
		]);
		await session.close();
	});

	it('splits multiline say into one PRIVMSG per line', async () => {
		const { session, server } = await connected();
		const lines: string[] = [];
		await Promise.all([
			session.say('#chan', 'line one\nline two'),
			(async () => {
				lines.push(await server.readLine());
				lines.push(await server.readLine());
			})()
		]);
		expect(lines).toEqual(['PRIVMSG #chan :line one', 'PRIVMSG #chan :line two']);
		await session.close();
	});

	it('send() applies the trailing rule and sendRaw() passes through', async () => {
		const { session, server } = await connected();
		await Promise.all([
			session.send('MODE', '#chan', '+o', 'alice'),
			(async () => expect(await server.readLine()).toBe('MODE #chan +o alice'))()
		]);
		await Promise.all([
			session.sendRaw('WHO #chan'),
			(async () => expect(await server.readLine()).toBe('WHO #chan'))()
		]);
		await session.close();
	});
});

describe('irc messages()', () => {
	it('routes a channel PRIVMSG with tags and server-time', async () => {
		const { session, server } = await connected();
		const iter = session.messages()[Symbol.asyncIterator]();
		await server.writeLine('@time=2024-05-01T12:00:00.000Z :alice!a@h PRIVMSG #chan :hi everyone');
		const { value } = await iter.next();
		expect(value).toMatchObject({
			from: 'alice',
			target: '#chan',
			text: 'hi everyone',
			type: 'privmsg',
			isChannel: true
		});
		expect(value!.tags.time).toBe('2024-05-01T12:00:00.000Z');
		expect(value!.ctcp).toBeUndefined();
		await session.close();
	});

	it('routes a direct message (PM) as non-channel', async () => {
		const { session, server } = await connected();
		const iter = session.messages()[Symbol.asyncIterator]();
		await server.writeLine(':bob!b@h PRIVMSG edgebot :ping you directly');
		const { value } = await iter.next();
		expect(value).toMatchObject({ from: 'bob', target: 'edgebot', isChannel: false });
		expect(value!.text).toBe('ping you directly');
		await session.close();
	});

	it('extracts a CTCP ACTION from a PRIVMSG', async () => {
		const { session, server } = await connected();
		const iter = session.messages()[Symbol.asyncIterator]();
		await server.writeLine(':carol!c@h PRIVMSG #chan :\x01ACTION dances\x01');
		const { value } = await iter.next();
		expect(value!.ctcp).toEqual({ command: 'ACTION', args: 'dances' });
		expect(value!.text).toBe('dances');
		await session.close();
	});

	it('distinguishes NOTICE from PRIVMSG', async () => {
		const { session, server } = await connected();
		const iter = session.messages()[Symbol.asyncIterator]();
		await server.writeLine(':serv NOTICE edgebot :a notice');
		const { value } = await iter.next();
		expect(value!.type).toBe('notice');
		await session.close();
	});
});

describe('irc events()', () => {
	it('surfaces JOIN/PART/QUIT/NICK as events', async () => {
		const { session, server } = await connected();
		const iter = session.events()[Symbol.asyncIterator]();

		await server.writeLine(':alice!a@h JOIN #chan');
		expect((await iter.next()).value).toMatchObject({ command: 'JOIN', params: ['#chan'] });

		await server.writeLine(':alice!a@h PART #chan :bye');
		expect((await iter.next()).value).toMatchObject({ command: 'PART', params: ['#chan', 'bye'] });

		await server.writeLine(':bob!b@h QUIT :leaving');
		expect((await iter.next()).value).toMatchObject({ command: 'QUIT', params: ['leaving'] });

		await server.writeLine(':carol!c@h NICK caroline');
		const nickEvent = (await iter.next()).value;
		expect(nickEvent).toMatchObject({ command: 'NICK', params: ['caroline'] });
		expect(nickEvent!.prefix?.nick).toBe('carol');

		await session.close();
	});

	it('does not surface a server PING as an event but auto-answers it', async () => {
		const { session, server } = await connected();
		await server.writeLine('PING :keepalive');
		expect(await server.readLine()).toBe('PONG :keepalive');
		await session.close();
	});
});

describe('irc names()', () => {
	it('aggregates 353 replies until 366 and strips membership prefixes', async () => {
		const { session, server } = await connected();
		const namesPromise = session.names('#chan');
		expect(await server.readLine()).toBe('NAMES #chan');
		await server.writeLine(':irc.test 353 edgebot = #chan :@alice +bob carol');
		await server.writeLine(':irc.test 353 edgebot = #chan :dave');
		await server.writeLine(':irc.test 366 edgebot #chan :End of /NAMES list');
		expect(await namesPromise).toEqual(['alice', 'bob', 'carol', 'dave']);
		await session.close();
	});
});

describe('irc topic()', () => {
	it('gets a topic via RPL_TOPIC', async () => {
		const { session, server } = await connected();
		const topicPromise = session.topic('#chan');
		expect(await server.readLine()).toBe('TOPIC #chan');
		await server.writeLine(':irc.test 332 edgebot #chan :the channel topic');
		expect(await topicPromise).toBe('the channel topic');
		await session.close();
	});

	it('returns empty string when there is no topic (331)', async () => {
		const { session, server } = await connected();
		const topicPromise = session.topic('#empty');
		expect(await server.readLine()).toBe('TOPIC #empty');
		await server.writeLine(':irc.test 331 edgebot #empty :No topic is set');
		expect(await topicPromise).toBe('');
		await session.close();
	});

	it('sets a topic', async () => {
		const { session, server } = await connected();
		await Promise.all([
			session.topic('#chan', 'new topic'),
			(async () => expect(await server.readLine()).toBe('TOPIC #chan :new topic'))()
		]);
		await session.close();
	});
});

describe('irc changeNick()', () => {
	it('updates the readonly nick when the change is echoed', async () => {
		const { session, server } = await connected();
		const changePromise = session.changeNick('edgebot2');
		expect(await server.readLine()).toBe('NICK edgebot2');
		await server.writeLine(':edgebot!u@h NICK edgebot2');
		await changePromise;
		expect(session.nick).toBe('edgebot2');
		await session.close();
	});

	it('rejects the change with AuthError on 433', async () => {
		const { session, server } = await connected();
		const changePromise = session.changeNick('taken');
		expect(await server.readLine()).toBe('NICK taken');
		await server.writeLine(':irc.test 433 edgebot taken :Nickname is already in use');
		await expect(changePromise).rejects.toBeInstanceOf(AuthError);
		expect(session.nick).toBe('edgebot');
		await session.close();
	});
});

describe('irc whois()', () => {
	it('aggregates WHOIS numerics until RPL_ENDOFWHOIS', async () => {
		const { session, server } = await connected();
		const whoisPromise = session.whois('alice');
		expect(await server.readLine()).toBe('WHOIS alice');
		await server.writeLine(':irc.test 311 edgebot alice aliceuser ahost * :Alice Real');
		await server.writeLine(':irc.test 312 edgebot alice irc.test :EdgePort test net');
		await server.writeLine(':irc.test 319 edgebot alice :@#chan +#other');
		await server.writeLine(':irc.test 317 edgebot alice 42 :seconds idle');
		await server.writeLine(':irc.test 330 edgebot alice aliceacct :is logged in as');
		await server.writeLine(':irc.test 318 edgebot alice :End of /WHOIS list');
		const info = await whoisPromise;
		expect(info).toMatchObject({
			nick: 'alice',
			user: 'aliceuser',
			host: 'ahost',
			realname: 'Alice Real',
			server: 'irc.test',
			idleSeconds: 42,
			account: 'aliceacct'
		});
		expect(info.channels).toEqual(['#chan', '#other']);
		await session.close();
	});
});
