/**
 * @fileoverview The RESP wire codec (Redis Serialization Protocol), versions 2 and 3.
 *
 * A client always sends a command the same way - an array of bulk strings, `*<n>\r\n` followed by
 * `$<len>\r\n<bytes>\r\n` per argument - which is what {@link encodeCommand} builds. A reply is
 * self-describing: the first byte names the type and the rest of the frame follows from it, so
 * decoding is a recursive descent over the buffered reader ({@link readReply}) rather than a pass
 * over a pre-sized buffer - RESP carries no total length. {@link RespValue} is the faithful tagged
 * union of every RESP2 and RESP3 type; {@link makeReply} wraps one in the {@link RedisReply}
 * accessors most callers want.
 *
 * Two wire quirks the codec keeps straight. A **bulk** payload (`$`, `=`, `!`) is length-prefixed
 * and binary-safe, so it must be read by byte count and can legally contain CR or LF - reading it
 * as a line corrupts it. An **attribute** (`|`) is not a reply at all but metadata for the value
 * that follows it, so it is decoded and hung off that value's {@link RespValue.attributes} instead
 * of being returned on its own.
 *
 * @author Gregory Mitchell
 * @since 1.0.6
 */
import { ProtocolError, type FramedReader } from '../core';

const PROTO = 'redis';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// guards against a peer nesting aggregates deeply enough to blow the JS stack
const MAX_DEPTH = 128;

/** An argument accepted in a command: text, a number, or raw bytes. */
export type RedisArg = string | number | Uint8Array;

/** Auxiliary key-value metadata carried by a RESP3 attribute (`|`). */
export type RespAttributes = [RespValue, RespValue][];

/**
 * The attribute slot every {@link RespValue} carries.
 *
 * @since 1.0.6
 */
export interface RespAttributed {
	/**
	 * Auxiliary metadata the server attached to this value with a RESP3 attribute (`|`).
	 *
	 * Attributes are not part of the reply proper - they annotate the value that follows them -
	 * so they are preserved here and otherwise ignored.
	 */
	attributes?: RespAttributes;
}

/**
 * One decoded RESP value as a tag-on-`kind` discriminated union.
 *
 * Covers every RESP2 and RESP3 type; branch on `kind` to read the type-specific `value`. The
 * RESP2 null forms (`$-1`, `*-1`) and the RESP3 null (`_`) all decode to `{ kind: 'null' }`, so
 * callers never have to tell them apart. The optional `attributes` slot is spread onto every
 * member.
 *
 * @since 1.0.6
 */
export type RespValue = RespAttributed &
	(
		| {
				kind: 'string';
				/** A RESP2 simple string (`+`), which never contains CR or LF. */
				value: string;
		  }
		| {
				kind: 'error';
				/** The error message, from either a simple error (`-`) or a bulk error (`!`). */
				value: string;
		  }
		| {
				kind: 'number';
				/** A signed 64-bit integer (`:`); values past 2^53 lose precision as a JS number. */
				value: number;
		  }
		| {
				kind: 'bulk';
				/** The raw bytes of a bulk string (`$`), which may hold any binary data. */
				value: Uint8Array;
		  }
		| {
				kind: 'verbatim';
				/** The raw bytes of a verbatim string (`=`), with the encoding prefix stripped. */
				value: Uint8Array;
				/** The 3-byte encoding hint the server sent, e.g. `'txt'`. */
				format: string;
		  }
		| { kind: 'null' }
		| {
				kind: 'boolean';
				/** A RESP3 boolean (`#`). */
				value: boolean;
		  }
		| {
				kind: 'double';
				/** A RESP3 double (`,`); `inf`, `-inf`, and `nan` decode to their JS counterparts. */
				value: number;
		  }
		| {
				kind: 'bignum';
				/** A RESP3 big number (`(`), outside the range of a signed 64-bit integer. */
				value: bigint;
		  }
		| {
				kind: 'array';
				/** The array's elements (`*`), which may be of mixed kinds and nested. */
				value: RespValue[];
		  }
		| {
				kind: 'set';
				/** The set's members (`~`): unordered and unique. */
				value: RespValue[];
		  }
		| {
				kind: 'map';
				/** The map's entries (`%`) as key-value tuples; keys need not be strings. */
				value: [RespValue, RespValue][];
		  }
		| {
				kind: 'push';
				/** The push's elements (`>`), the first of which names the kind of push. */
				value: RespValue[];
		  }
	);

/**
 * A RESP value projected onto plain JavaScript.
 *
 * Bulk and verbatim strings are UTF-8 decoded, maps become objects (keys stringified), sets and
 * pushes become arrays. Use {@link RedisReply.bytes} when a value is binary rather than text.
 *
 * @since 1.0.6
 */
export type RedisNative =
	string | number | boolean | bigint | null | RedisNative[] | { [key: string]: RedisNative };

/**
 * A single reply with accessors for the shapes callers actually want.
 *
 * `raw` is always the faithful {@link RespValue}; the accessors sit on top of it. Every accessor
 * except {@link RedisReply.error} and {@link RedisReply.raw} throws when the reply is an error, so
 * a failed command in a {@link RedisSession.pipeline} batch can never be read as data by accident.
 *
 * @since 1.0.6
 */
export interface RedisReply {
	/** The decoded RESP value, exactly as the server sent it. */
	readonly raw: RespValue;
	/** The error message when the server replied with an error (`-` or `!`), otherwise undefined. */
	readonly error?: string;
	/** Whether the reply is a null (RESP3 `_`, or the RESP2 `$-1` / `*-1` forms). */
	readonly isNull: boolean;
	/** The reply projected onto plain JavaScript. */
	readonly value: RedisNative;
	/**
	 * Decodes the reply as text: simple and bulk strings verbatim, numbers stringified, null as
	 * the empty string (check {@link RedisReply.isNull} to tell them apart).
	 *
	 * @returns The reply as a string.
	 * @throws {ProtocolError} If the reply is an error or an aggregate.
	 */
	text(): string;
	/**
	 * Returns the reply's raw bytes, for values that are binary rather than text.
	 *
	 * @returns The bytes; empty for a null reply.
	 * @throws {ProtocolError} If the reply is an error or an aggregate.
	 */
	bytes(): Uint8Array;
	/**
	 * Returns the reply as a number (integer, double, or a numeric string).
	 *
	 * @returns The numeric value.
	 * @throws {ProtocolError} If the reply is an error, null, or not numeric.
	 */
	number(): number;
	/**
	 * Returns the reply as a boolean: a RESP3 boolean directly, a non-zero integer, `OK`, or a
	 * non-null bulk string as true; null and zero as false.
	 *
	 * @returns The boolean value.
	 * @throws {ProtocolError} If the reply is an error.
	 */
	boolean(): boolean;
	/**
	 * Decodes the reply as UTF-8 then parses it as JSON.
	 *
	 * @typeParam T - The expected shape of the decoded value.
	 * @returns The parsed value.
	 * @throws {ProtocolError} If the reply is an error or is not valid JSON.
	 */
	json<T = unknown>(): T;
	/**
	 * Wraps each element of an aggregate reply (array, set, push, or a map flattened to
	 * key-value pairs) as its own {@link RedisReply}.
	 *
	 * @returns The element replies.
	 * @throws {ProtocolError} If the reply is an error or not an aggregate.
	 */
	items(): RedisReply[];
	/**
	 * Decodes an aggregate reply as a list of strings.
	 *
	 * @returns The elements as text; a null element becomes the empty string.
	 * @throws {ProtocolError} If the reply is an error or not an aggregate.
	 */
	strings(): string[];
	/**
	 * Decodes a field-value reply as an object, accepting either a RESP3 map or the flat
	 * even-length array RESP2 uses for the same data.
	 *
	 * @returns The fields as a string-to-string object.
	 * @throws {ProtocolError} If the reply is an error, not an aggregate, or has an odd length.
	 */
	map(): Record<string, string>;
}

/**
 * Encodes a command as a RESP array of bulk strings.
 *
 * Strings are UTF-8 encoded and numbers stringified, so `encodeCommand(['SET', 'k', 1])` and
 * `encodeCommand(['SET', 'k', '1'])` are the same bytes. Byte arguments pass through untouched,
 * which is what keeps values binary-safe.
 *
 * @param args - The command name followed by its arguments.
 * @returns The encoded command frame.
 * @throws {ProtocolError} If `args` is empty.
 * @since 1.0.6
 * @example
 * ```typescript
 * import { encodeCommand } from 'edgeport/redis';
 *
 * encodeCommand(['LLEN', 'mylist']); // *2\r\n$4\r\nLLEN\r\n$6\r\nmylist\r\n
 * ```
 */
export function encodeCommand(args: readonly RedisArg[]): Uint8Array {
	if (args.length === 0)
		throw new ProtocolError('a command needs at least a name', { protocol: PROTO });
	const parts = args.map((a) =>
		typeof a === 'string'
			? encoder.encode(a)
			: typeof a === 'number'
				? encoder.encode(String(a))
				: a
	);
	const head = encoder.encode(`*${parts.length}\r\n`);
	let size = head.length;
	const heads = parts.map((p) => encoder.encode(`$${p.length}\r\n`));
	for (let i = 0; i < parts.length; i++) size += heads[i]!.length + parts[i]!.length + 2;

	const out = new Uint8Array(size);
	let off = 0;
	out.set(head, off);
	off += head.length;
	for (let i = 0; i < parts.length; i++) {
		out.set(heads[i]!, off);
		off += heads[i]!.length;
		out.set(parts[i]!, off);
		off += parts[i]!.length;
		out[off] = 0x0d;
		out[off + 1] = 0x0a;
		off += 2;
	}
	return out;
}

/**
 * Encodes several commands into one frame for pipelining.
 *
 * @param commands - The commands to encode, in order.
 * @returns The concatenated command frames.
 * @throws {ProtocolError} If `commands` is empty or any command is.
 * @since 1.0.6
 */
export function encodeCommands(commands: readonly (readonly RedisArg[])[]): Uint8Array {
	if (commands.length === 0) throw new ProtocolError('no commands to encode', { protocol: PROTO });
	const frames = commands.map(encodeCommand);
	const out = new Uint8Array(frames.reduce((n, f) => n + f.length, 0));
	let off = 0;
	for (const f of frames) {
		out.set(f, off);
		off += f.length;
	}
	return out;
}

/**
 * Reads and decodes exactly one RESP value from a buffered reader.
 *
 * Consumes a whole frame including any nested aggregates, so consecutive calls walk a pipelined
 * stream of replies. A RESP3 attribute (`|`) is folded into the value it describes rather than
 * returned on its own, so this never resolves to an attribute.
 *
 * @param reader - The buffered reader to consume.
 * @param timeoutMs - Optional per-read deadline.
 * @returns The decoded value.
 * @throws {ProtocolError} If the frame is malformed or nests past the depth limit.
 * @throws {ConnectionError} If the stream ends mid-frame.
 * @throws {TimeoutError} If `timeoutMs` elapses.
 * @since 1.0.6
 */
export function readReply(reader: FramedReader, timeoutMs?: number): Promise<RespValue> {
	return readValue(reader, timeoutMs, 0);
}

async function readValue(
	reader: FramedReader,
	timeoutMs: number | undefined,
	depth: number
): Promise<RespValue> {
	if (depth > MAX_DEPTH) {
		throw new ProtocolError(`resp reply nested deeper than ${MAX_DEPTH} levels`, {
			protocol: PROTO
		});
	}
	const line = await reader.readLine(timeoutMs);
	if (line.length === 0) throw new ProtocolError('empty resp frame', { protocol: PROTO });
	const body = line.slice(1);
	switch (line[0]) {
		case '+':
			return { kind: 'string', value: body };
		case '-':
			return { kind: 'error', value: body };
		case ':':
			return { kind: 'number', value: parseIntegerBody(body) };
		case '$': {
			const n = parseIntegerBody(body);
			if (n < 0) return { kind: 'null' }; // RESP2 null bulk string
			return { kind: 'bulk', value: await readBulk(reader, n, timeoutMs) };
		}
		case '!': {
			const n = parseIntegerBody(body);
			if (n < 0) throw new ProtocolError('bulk error with negative length', { protocol: PROTO });
			return { kind: 'error', value: decoder.decode(await readBulk(reader, n, timeoutMs)) };
		}
		case '=': {
			const n = parseIntegerBody(body);
			if (n < 4) {
				throw new ProtocolError(`verbatim string too short for its encoding prefix: ${n}`, {
					protocol: PROTO
				});
			}
			const raw = await readBulk(reader, n, timeoutMs);
			if (raw[3] !== 0x3a) {
				throw new ProtocolError('verbatim string missing the : after its encoding', {
					protocol: PROTO
				});
			}
			return {
				kind: 'verbatim',
				format: decoder.decode(raw.subarray(0, 3)),
				value: raw.slice(4)
			};
		}
		case '_':
			if (body.length > 0)
				throw new ProtocolError(`malformed resp null: ${line}`, { protocol: PROTO });
			return { kind: 'null' };
		case '#':
			if (body !== 't' && body !== 'f') {
				throw new ProtocolError(`malformed resp boolean: ${line}`, { protocol: PROTO });
			}
			return { kind: 'boolean', value: body === 't' };
		case ',':
			return { kind: 'double', value: parseDoubleBody(body) };
		case '(':
			return { kind: 'bignum', value: parseBigNumBody(body) };
		case '*': {
			const n = parseIntegerBody(body);
			if (n < 0) return { kind: 'null' }; // RESP2 null array
			return { kind: 'array', value: await readElements(reader, n, timeoutMs, depth) };
		}
		case '~': {
			const n = parseIntegerBody(body);
			if (n < 0) throw new ProtocolError('set with negative length', { protocol: PROTO });
			return { kind: 'set', value: await readElements(reader, n, timeoutMs, depth) };
		}
		case '>': {
			const n = parseIntegerBody(body);
			if (n < 0) throw new ProtocolError('push with negative length', { protocol: PROTO });
			return { kind: 'push', value: await readElements(reader, n, timeoutMs, depth) };
		}
		case '%': {
			const n = parseIntegerBody(body);
			if (n < 0) throw new ProtocolError('map with negative length', { protocol: PROTO });
			return { kind: 'map', value: await readPairs(reader, n, timeoutMs, depth) };
		}
		case '|': {
			const n = parseIntegerBody(body);
			if (n < 0) throw new ProtocolError('attribute with negative length', { protocol: PROTO });
			// an attribute annotates the NEXT value; decode both and fold it in
			const attributes = await readPairs(reader, n, timeoutMs, depth);
			const next = await readValue(reader, timeoutMs, depth);
			return { ...next, attributes };
		}
		default:
			throw new ProtocolError(`unknown resp type byte '${line[0]}'`, { protocol: PROTO });
	}
}

// reads an n-byte bulk payload plus its trailing CRLF
async function readBulk(
	reader: FramedReader,
	n: number,
	timeoutMs: number | undefined
): Promise<Uint8Array> {
	const data = await reader.readN(n, timeoutMs);
	await reader.readN(2, timeoutMs);
	return data;
}

async function readElements(
	reader: FramedReader,
	n: number,
	timeoutMs: number | undefined,
	depth: number
): Promise<RespValue[]> {
	const out: RespValue[] = [];
	for (let i = 0; i < n; i++) out.push(await readValue(reader, timeoutMs, depth + 1));
	return out;
}

async function readPairs(
	reader: FramedReader,
	n: number,
	timeoutMs: number | undefined,
	depth: number
): Promise<[RespValue, RespValue][]> {
	const out: [RespValue, RespValue][] = [];
	for (let i = 0; i < n; i++) {
		const key = await readValue(reader, timeoutMs, depth + 1);
		out.push([key, await readValue(reader, timeoutMs, depth + 1)]);
	}
	return out;
}

function parseIntegerBody(body: string): number {
	if (!/^[+-]?\d+$/.test(body)) {
		throw new ProtocolError(`malformed resp integer: ${body}`, { protocol: PROTO });
	}
	return Number(body);
}

function parseDoubleBody(body: string): number {
	const lower = body.toLowerCase();
	if (lower === 'inf' || lower === '+inf') return Infinity;
	if (lower === '-inf') return -Infinity;
	if (lower === 'nan' || lower === '-nan') return NaN;
	if (!/^[+-]?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(body)) {
		throw new ProtocolError(`malformed resp double: ${body}`, { protocol: PROTO });
	}
	return Number(body);
}

function parseBigNumBody(body: string): bigint {
	if (!/^[+-]?\d+$/.test(body)) {
		throw new ProtocolError(`malformed resp big number: ${body}`, { protocol: PROTO });
	}
	return BigInt(body);
}

/**
 * Projects a {@link RespValue} onto plain JavaScript.
 *
 * Bulk and verbatim strings are UTF-8 decoded, arrays / sets / pushes become arrays, and maps
 * become objects keyed by the stringified key. Errors project to their message; check
 * `kind === 'error'` (or use {@link RedisReply.error}) when that matters.
 *
 * @param value - The value to project.
 * @returns The plain-JavaScript view.
 * @since 1.0.6
 */
export function respToNative(value: RespValue): RedisNative {
	switch (value.kind) {
		case 'string':
		case 'error':
			return value.value;
		case 'number':
		case 'double':
			return value.value;
		case 'boolean':
			return value.value;
		case 'bignum':
			return value.value;
		case 'bulk':
		case 'verbatim':
			return decoder.decode(value.value);
		case 'null':
			return null;
		case 'array':
		case 'set':
		case 'push':
			return value.value.map(respToNative);
		case 'map': {
			const out: Record<string, RedisNative> = {};
			for (const [k, v] of value.value) out[nativeKey(k)] = respToNative(v);
			return out;
		}
	}
}

// map keys are usually bulk strings but RESP permits any type; stringify whatever arrives
function nativeKey(value: RespValue): string {
	const native = respToNative(value);
	return typeof native === 'object' && native !== null ? JSON.stringify(native) : String(native);
}

/**
 * Wraps a decoded {@link RespValue} in the {@link RedisReply} accessors.
 *
 * @param raw - The value to wrap.
 * @returns The reply wrapper.
 * @since 1.0.6
 */
export function makeReply(raw: RespValue): RedisReply {
	const failed = raw.kind === 'error';
	const guard = (): void => {
		if (failed) {
			throw new ProtocolError(`redis error reply: ${(raw as { value: string }).value}`, {
				protocol: PROTO
			});
		}
	};
	return {
		raw,
		error: failed ? (raw as { value: string }).value : undefined,
		isNull: raw.kind === 'null',
		get value() {
			return respToNative(raw);
		},
		text(): string {
			guard();
			return replyText(raw);
		},
		bytes(): Uint8Array {
			guard();
			switch (raw.kind) {
				case 'bulk':
				case 'verbatim':
					return raw.value;
				case 'null':
					return new Uint8Array(0);
				case 'string':
				case 'number':
				case 'double':
				case 'bignum':
				case 'boolean':
					return encoder.encode(replyText(raw));
				default:
					throw new ProtocolError(`cannot read a ${raw.kind} reply as bytes`, { protocol: PROTO });
			}
		},
		number(): number {
			guard();
			if (raw.kind === 'number' || raw.kind === 'double') return raw.value;
			if (raw.kind === 'boolean') return raw.value ? 1 : 0;
			if (raw.kind === 'bignum') return Number(raw.value);
			if (raw.kind === 'bulk' || raw.kind === 'verbatim' || raw.kind === 'string') {
				const text = replyText(raw);
				const n = Number(text);
				if (text.trim() === '' || Number.isNaN(n)) {
					throw new ProtocolError(`reply is not numeric: ${text}`, { protocol: PROTO });
				}
				return n;
			}
			throw new ProtocolError(`cannot read a ${raw.kind} reply as a number`, { protocol: PROTO });
		},
		boolean(): boolean {
			guard();
			switch (raw.kind) {
				case 'boolean':
					return raw.value;
				case 'number':
				case 'double':
					return raw.value !== 0;
				case 'null':
					return false;
				case 'string':
				case 'bulk':
				case 'verbatim':
					return replyText(raw) !== '';
				default:
					return true;
			}
		},
		json<T = unknown>(): T {
			guard();
			const text = replyText(raw);
			try {
				return JSON.parse(text) as T;
			} catch (cause) {
				throw new ProtocolError('redis reply is not valid json', { protocol: PROTO, cause });
			}
		},
		items(): RedisReply[] {
			guard();
			return aggregate(raw).map(makeReply);
		},
		strings(): string[] {
			guard();
			return aggregate(raw).map((v) => (v.kind === 'null' ? '' : replyText(v)));
		},
		map(): Record<string, string> {
			guard();
			if (raw.kind === 'map') {
				const out: Record<string, string> = {};
				for (const [k, v] of raw.value) out[nativeKey(k)] = v.kind === 'null' ? '' : replyText(v);
				return out;
			}
			const flat = aggregate(raw);
			if (flat.length % 2 !== 0) {
				throw new ProtocolError(`cannot read ${flat.length} elements as field-value pairs`, {
					protocol: PROTO
				});
			}
			const out: Record<string, string> = {};
			for (let i = 0; i < flat.length; i += 2) {
				out[nativeKey(flat[i]!)] = flat[i + 1]!.kind === 'null' ? '' : replyText(flat[i + 1]!);
			}
			return out;
		}
	};
}

// the elements of an aggregate; a map flattens to alternating keys and values
function aggregate(raw: RespValue): RespValue[] {
	switch (raw.kind) {
		case 'array':
		case 'set':
		case 'push':
			return raw.value;
		case 'map':
			return raw.value.flat();
		default:
			throw new ProtocolError(`cannot read a ${raw.kind} reply as a list`, { protocol: PROTO });
	}
}

function replyText(raw: RespValue): string {
	switch (raw.kind) {
		case 'string':
		case 'error':
			return raw.value;
		case 'bulk':
		case 'verbatim':
			return decoder.decode(raw.value);
		case 'number':
			return String(raw.value);
		case 'double':
			return formatDouble(raw.value);
		case 'bignum':
			return raw.value.toString();
		case 'boolean':
			return raw.value ? '1' : '0';
		case 'null':
			return '';
		default:
			throw new ProtocolError(`cannot read a ${raw.kind} reply as text`, { protocol: PROTO });
	}
}

// doubles render the way RESP writes them, so inf/nan survive a text round-trip
function formatDouble(n: number): string {
	if (n === Infinity) return 'inf';
	if (n === -Infinity) return '-inf';
	if (Number.isNaN(n)) return 'nan';
	return String(n);
}
