/**
 * @fileoverview IRC message model, line codec, and numeric-reply constants (RFC 1459 / 2812
 * plus the IRCv3 message-tags extension).
 *
 * An IRC message is a single CRLF-terminated line of the shape
 * `[@tags] [:prefix] COMMAND [params...] [:trailing]`. This module is pure (no I/O): it turns a
 * line into an {@link IrcMessage} and back, handling IRCv3 tag value escaping, prefix parsing
 * into `{ nick, user, host }`, and the trailing-parameter rule. It also carries the CTCP
 * helper ({@link parseCtcp}), a channel-name test ({@link isChannelName}), and the numeric
 * reply/error constants the session layer keys on. Framing (reading exactly one line off a
 * socket) is the shared core reader's job; this module only parses a complete line string.
 *
 * @author Gregory Mitchell
 * @since 1.0.4
 */

/**
 * A parsed message prefix (`:nick!user@host` or `:servername`).
 *
 * `raw` is always the verbatim prefix; `nick`/`user`/`host` are filled in when the prefix
 * parses as a `nick!user@host` form (a bare servername leaves them undefined).
 *
 * @since 1.0.4
 */
export interface IrcPrefix {
	/** The nickname, when the prefix is a user prefix (not a bare servername). */
	nick?: string;
	/** The user/ident part (between `!` and `@`), when present. */
	user?: string;
	/** The hostname (after `@`), when present. */
	host?: string;
	/** The verbatim prefix as it appeared on the wire, without the leading `:`. */
	raw: string;
}

/**
 * A parsed IRC message.
 *
 * @since 1.0.4
 */
export interface IrcMessage {
	/** IRCv3 message tags (unescaped); absent when the line carried no `@tags`. */
	tags?: Record<string, string>;
	/** The parsed source prefix; absent when the line carried no `:prefix`. */
	prefix?: IrcPrefix;
	/** The command, uppercased for alphabetic verbs (a numeric stays its 3-digit string). */
	command: string;
	/** The positional parameters, the last of which may be a space-bearing trailing param. */
	params: string[];
}

/** `001` - the welcome reply that marks a completed registration. */
export const RPL_WELCOME = '001';
/** `002` - "your host is" reply. */
export const RPL_YOURHOST = '002';
/** `003` - server creation date reply. */
export const RPL_CREATED = '003';
/** `004` - server info (name, version, modes) reply. */
export const RPL_MYINFO = '004';
/** `005` - `ISUPPORT` feature advertisement. */
export const RPL_ISUPPORT = '005';
/** `221` - user mode string reply. */
export const RPL_UMODEIS = '221';
/** `301` - the target is away (carries the away message). */
export const RPL_AWAY = '301';
/** `311` - WHOIS user (nick, user, host, realname). */
export const RPL_WHOISUSER = '311';
/** `312` - WHOIS server. */
export const RPL_WHOISSERVER = '312';
/** `313` - WHOIS operator line. */
export const RPL_WHOISOPERATOR = '313';
/** `317` - WHOIS idle time. */
export const RPL_WHOISIDLE = '317';
/** `318` - end of WHOIS. */
export const RPL_ENDOFWHOIS = '318';
/** `319` - WHOIS channel list. */
export const RPL_WHOISCHANNELS = '319';
/** `330` - WHOIS "is logged in as" (account name). */
export const RPL_WHOISACCOUNT = '330';
/** `321` - LIST start. */
export const RPL_LISTSTART = '321';
/** `322` - a LIST entry. */
export const RPL_LIST = '322';
/** `323` - end of LIST. */
export const RPL_LISTEND = '323';
/** `324` - channel mode string reply. */
export const RPL_CHANNELMODEIS = '324';
/** `331` - the channel has no topic set. */
export const RPL_NOTOPIC = '331';
/** `332` - the channel topic. */
export const RPL_TOPIC = '332';
/** `333` - who set the topic and when. */
export const RPL_TOPICWHOTIME = '333';
/** `353` - a NAMES reply line (space-separated members, possibly prefixed). */
export const RPL_NAMREPLY = '353';
/** `366` - end of NAMES. */
export const RPL_ENDOFNAMES = '366';
/** `372` - a line of the MOTD. */
export const RPL_MOTD = '372';
/** `375` - start of the MOTD. */
export const RPL_MOTDSTART = '375';
/** `376` - end of the MOTD. */
export const RPL_ENDOFMOTD = '376';
/** `401` - no such nick/channel. */
export const ERR_NOSUCHNICK = '401';
/** `403` - no such channel. */
export const ERR_NOSUCHCHANNEL = '403';
/** `421` - unknown command. */
export const ERR_UNKNOWNCOMMAND = '421';
/** `431` - no nickname given. */
export const ERR_NONICKNAMEGIVEN = '431';
/** `432` - erroneous nickname (bad characters). */
export const ERR_ERRONEUSNICKNAME = '432';
/** `433` - the requested nickname is already in use. */
export const ERR_NICKNAMEINUSE = '433';
/** `436` - nickname collision. */
export const ERR_NICKCOLLISION = '436';
/** `451` - you have not registered. */
export const ERR_NOTREGISTERED = '451';
/** `461` - not enough parameters. */
export const ERR_NEEDMOREPARAMS = '461';
/** `464` - password incorrect. */
export const ERR_PASSWDMISMATCH = '464';
/** `465` - you are banned from this server. */
export const ERR_YOUREBANNEDCREEP = '465';
/** `471` - the channel is full (`+l`). */
export const ERR_CHANNELISFULL = '471';
/** `473` - the channel is invite-only (`+i`). */
export const ERR_INVITEONLYCHAN = '473';
/** `474` - you are banned from the channel (`+b`). */
export const ERR_BANNEDFROMCHAN = '474';
/** `475` - bad channel key (`+k`). */
export const ERR_BADCHANNELKEY = '475';
/** `900` - SASL: you are now logged in. */
export const RPL_LOGGEDIN = '900';
/** `901` - SASL: you are now logged out. */
export const RPL_LOGGEDOUT = '901';
/** `902` - SASL: account is locked. */
export const ERR_NICKLOCKED = '902';
/** `903` - SASL authentication succeeded. */
export const RPL_SASLSUCCESS = '903';
/** `904` - SASL authentication failed. */
export const ERR_SASLFAIL = '904';
/** `905` - SASL message too long. */
export const ERR_SASLTOOLONG = '905';
/** `906` - SASL aborted. */
export const ERR_SASLABORTED = '906';
/** `907` - SASL: already authenticated. */
export const ERR_SASLALREADY = '907';

/**
 * The numeric reply/error constants collected into one object for iteration or lookup.
 *
 * Each named export above is also a member here (e.g. `NUMERICS.RPL_WELCOME === '001'`).
 *
 * @since 1.0.4
 */
export const NUMERICS = {
	RPL_WELCOME,
	RPL_YOURHOST,
	RPL_CREATED,
	RPL_MYINFO,
	RPL_ISUPPORT,
	RPL_UMODEIS,
	RPL_AWAY,
	RPL_WHOISUSER,
	RPL_WHOISSERVER,
	RPL_WHOISOPERATOR,
	RPL_WHOISIDLE,
	RPL_ENDOFWHOIS,
	RPL_WHOISCHANNELS,
	RPL_WHOISACCOUNT,
	RPL_LISTSTART,
	RPL_LIST,
	RPL_LISTEND,
	RPL_CHANNELMODEIS,
	RPL_NOTOPIC,
	RPL_TOPIC,
	RPL_TOPICWHOTIME,
	RPL_NAMREPLY,
	RPL_ENDOFNAMES,
	RPL_MOTD,
	RPL_MOTDSTART,
	RPL_ENDOFMOTD,
	ERR_NOSUCHNICK,
	ERR_NOSUCHCHANNEL,
	ERR_UNKNOWNCOMMAND,
	ERR_NONICKNAMEGIVEN,
	ERR_ERRONEUSNICKNAME,
	ERR_NICKNAMEINUSE,
	ERR_NICKCOLLISION,
	ERR_NOTREGISTERED,
	ERR_NEEDMOREPARAMS,
	ERR_PASSWDMISMATCH,
	ERR_YOUREBANNEDCREEP,
	ERR_CHANNELISFULL,
	ERR_INVITEONLYCHAN,
	ERR_BANNEDFROMCHAN,
	ERR_BADCHANNELKEY,
	RPL_LOGGEDIN,
	RPL_LOGGEDOUT,
	ERR_NICKLOCKED,
	RPL_SASLSUCCESS,
	ERR_SASLFAIL,
	ERR_SASLTOOLONG,
	ERR_SASLABORTED,
	ERR_SASLALREADY
} as const;

/** The RFC 2811 channel-type prefixes (`#` regular, `&` local, `+` no-modes, `!` safe). */
export const CHANNEL_PREFIXES = '#&+!';

// ---- tag escaping (IRCv3 message-tags) ----------------------------------------------------

/**
 * Escapes a tag value for the wire per the IRCv3 message-tags spec.
 *
 * Encodes the five reserved octets so a value stays unambiguous inside the semicolon-separated
 * tag list: `;` becomes `\:`, space becomes `\s`, backslash becomes `\\`, CR becomes `\r`, and
 * LF becomes `\n`.
 *
 * @param value - The raw tag value.
 * @returns The escaped value safe to place after `key=`.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { escapeTagValue } from 'edgeport/irc';
 *
 * escapeTagValue('a;b c'); // 'a\\:b\\s c' -> on the wire: a\:b\s
 * ```
 */
export function escapeTagValue(value: string): string {
	let out = '';
	for (const ch of value) {
		if (ch === ';') out += '\\:';
		else if (ch === ' ') out += '\\s';
		else if (ch === '\\') out += '\\\\';
		else if (ch === '\r') out += '\\r';
		else if (ch === '\n') out += '\\n';
		else out += ch;
	}
	return out;
}

/**
 * Unescapes a tag value read from the wire per the IRCv3 message-tags spec.
 *
 * Reverses {@link escapeTagValue}: `\:` -> `;`, `\s` -> space, `\\` -> `\`, `\r` -> CR,
 * `\n` -> LF. An unrecognized escape drops the backslash and keeps the following character; a
 * trailing lone backslash is dropped.
 *
 * @param value - The escaped tag value.
 * @returns The decoded literal value.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { unescapeTagValue } from 'edgeport/irc';
 *
 * unescapeTagValue('a\\:b\\sc'); // 'a;b c'
 * ```
 */
export function unescapeTagValue(value: string): string {
	let out = '';
	for (let i = 0; i < value.length; i++) {
		if (value[i] !== '\\') {
			out += value[i];
			continue;
		}
		const next = value[++i];
		if (next === undefined) break; // trailing lone backslash is dropped
		if (next === ':') out += ';';
		else if (next === 's') out += ' ';
		else if (next === '\\') out += '\\';
		else if (next === 'r') out += '\r';
		else if (next === 'n') out += '\n';
		else out += next; // unknown escape: drop the backslash, keep the char
	}
	return out;
}

// parses the `@`-less tag string (`key1=val;key2;key3=val`) into an unescaped record
function parseTags(raw: string): Record<string, string> {
	const tags: Record<string, string> = {};
	for (const part of raw.split(';')) {
		if (part === '') continue;
		const eq = part.indexOf('=');
		if (eq === -1) tags[part] = '';
		else tags[part.slice(0, eq)] = unescapeTagValue(part.slice(eq + 1));
	}
	return tags;
}

// serializes a tag record into the `@`-less wire string
function formatTags(tags: Record<string, string>): string {
	const parts: string[] = [];
	for (const [key, value] of Object.entries(tags)) {
		parts.push(value === '' ? key : `${key}=${escapeTagValue(value)}`);
	}
	return parts.join(';');
}

// splits a prefix token into nick/user/host (a bare servername leaves nick/user/host unset)
function parsePrefix(raw: string): IrcPrefix {
	const prefix: IrcPrefix = { raw };
	const at = raw.indexOf('@');
	let namePart = raw;
	if (at !== -1) {
		prefix.host = raw.slice(at + 1);
		namePart = raw.slice(0, at);
	}
	const bang = namePart.indexOf('!');
	if (bang !== -1) {
		prefix.nick = namePart.slice(0, bang);
		prefix.user = namePart.slice(bang + 1);
	} else if (at !== -1) {
		// nick@host with no user part
		prefix.nick = namePart;
	} else if (!namePart.includes('.')) {
		// no '!' / '@' and no dot: treat as a bare nick, not a servername
		prefix.nick = namePart;
	}
	return prefix;
}

/**
 * Parses one IRC line into an {@link IrcMessage}.
 *
 * Handles a leading `@tags` block (semicolon-separated, IRCv3-unescaped), a leading `:prefix`,
 * the command (alphabetic verbs are uppercased; a 3-digit numeric is kept verbatim), the
 * space-separated middle params, and the final `:trailing` param (which keeps its spaces). The
 * line must not include the terminating CRLF (the framed reader strips it).
 *
 * @param line - A single IRC line without its CRLF terminator.
 * @returns The parsed message.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { parseMessage } from 'edgeport/irc';
 *
 * const msg = parseMessage('@time=2024-01-01T00:00:00.000Z :nick!u@h PRIVMSG #chan :hello world');
 * msg.command;       // 'PRIVMSG'
 * msg.params;        // ['#chan', 'hello world']
 * msg.prefix?.nick;  // 'nick'
 * msg.tags?.time;    // '2024-01-01T00:00:00.000Z'
 * ```
 */
export function parseMessage(line: string): IrcMessage {
	let rest = line;
	const msg: IrcMessage = { command: '', params: [] };

	// leading @tags (up to the first space)
	if (rest.startsWith('@')) {
		const sp = rest.indexOf(' ');
		const tagStr = sp === -1 ? rest.slice(1) : rest.slice(1, sp);
		msg.tags = parseTags(tagStr);
		rest = sp === -1 ? '' : rest.slice(sp + 1);
	}
	// collapse any extra spaces between fields
	rest = rest.replace(/^ +/, '');

	// leading :prefix (up to the next space)
	if (rest.startsWith(':')) {
		const sp = rest.indexOf(' ');
		const prefixStr = sp === -1 ? rest.slice(1) : rest.slice(1, sp);
		msg.prefix = parsePrefix(prefixStr);
		rest = sp === -1 ? '' : rest.slice(sp + 1);
	}
	rest = rest.replace(/^ +/, '');

	// command (first token)
	{
		const sp = rest.indexOf(' ');
		if (sp === -1) {
			msg.command = rest.toUpperCase();
			return msg;
		}
		msg.command = rest.slice(0, sp).toUpperCase();
		rest = rest.slice(sp + 1);
	}

	// params: middle tokens, then a single `:trailing` that keeps spaces
	for (;;) {
		rest = rest.replace(/^ +/, '');
		if (rest === '') break;
		if (rest.startsWith(':')) {
			msg.params.push(rest.slice(1));
			break;
		}
		const sp = rest.indexOf(' ');
		if (sp === -1) {
			msg.params.push(rest);
			break;
		}
		msg.params.push(rest.slice(0, sp));
		rest = rest.slice(sp + 1);
	}
	return msg;
}

// renders a prefix (string is passed through; an object prefers raw, else rebuilds from parts)
function formatPrefix(prefix: IrcPrefix | string): string {
	if (typeof prefix === 'string') return prefix;
	if (prefix.raw) return prefix.raw;
	let s = prefix.nick ?? '';
	if (prefix.user) s += `!${prefix.user}`;
	if (prefix.host) s += `@${prefix.host}`;
	return s;
}

/**
 * Formats an {@link IrcMessage} (or a message-shaped object) into a single line, without the
 * trailing CRLF (the writer appends it).
 *
 * The last parameter is automatically prefixed with `:` when it contains a space, is empty, or
 * itself starts with `:` - the cases where it must be sent as a trailing parameter. `tags` and
 * `prefix` are emitted when present (a `prefix` may be a raw string or an {@link IrcPrefix}).
 *
 * @param msg - The command, params, and optional tags/prefix to serialize.
 * @returns The formatted line (no CRLF).
 * @since 1.0.4
 * @example
 * ```typescript
 * import { formatMessage } from 'edgeport/irc';
 *
 * formatMessage({ command: 'PRIVMSG', params: ['#chan', 'hello world'] });
 * // 'PRIVMSG #chan :hello world'
 * formatMessage({ command: 'JOIN', params: ['#chan'] }); // 'JOIN #chan'
 * ```
 */
export function formatMessage(msg: {
	command: string;
	params?: string[];
	tags?: Record<string, string>;
	prefix?: IrcPrefix | string;
}): string {
	let out = '';
	if (msg.tags && Object.keys(msg.tags).length > 0) out += `@${formatTags(msg.tags)} `;
	if (msg.prefix !== undefined) out += `:${formatPrefix(msg.prefix)} `;
	out += msg.command;
	const params = msg.params ?? [];
	for (let i = 0; i < params.length; i++) {
		const p = params[i]!;
		const last = i === params.length - 1;
		if (last && (p === '' || p.includes(' ') || p.startsWith(':'))) out += ` :${p}`;
		else out += ` ${p}`;
	}
	return out;
}

/**
 * Tests whether a target name is a channel (starts with one of {@link CHANNEL_PREFIXES}).
 *
 * @param target - A PRIVMSG/NOTICE target (channel or nick).
 * @returns True when `target` names a channel rather than a user.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { isChannelName } from 'edgeport/irc';
 *
 * isChannelName('#ops'); // true
 * isChannelName('alice'); // false
 * ```
 */
export function isChannelName(target: string): boolean {
	return target.length > 0 && CHANNEL_PREFIXES.includes(target[0]!);
}

/**
 * Extracts a CTCP command and its arguments from a message body.
 *
 * CTCP wraps the payload in `\x01` delimiters, e.g. an action is `\x01ACTION waves\x01`. Returns
 * the uppercased command and the remaining argument string, or `undefined` when the text is not
 * CTCP-wrapped.
 *
 * @param text - The PRIVMSG/NOTICE body.
 * @returns `{ command, args }` for a CTCP payload, else `undefined`.
 * @since 1.0.4
 * @example
 * ```typescript
 * import { parseCtcp } from 'edgeport/irc';
 *
 * parseCtcp('\x01ACTION waves\x01'); // { command: 'ACTION', args: 'waves' }
 * parseCtcp('just text'); // undefined
 * ```
 */
export function parseCtcp(text: string): { command: string; args: string } | undefined {
	const X = '\x01';
	if (text.length < 2 || text[0] !== X) return undefined;
	let inner = text.slice(1);
	if (inner.endsWith(X)) inner = inner.slice(0, -1);
	const sp = inner.indexOf(' ');
	if (sp === -1) return { command: inner.toUpperCase(), args: '' };
	return { command: inner.slice(0, sp).toUpperCase(), args: inner.slice(sp + 1) };
}
