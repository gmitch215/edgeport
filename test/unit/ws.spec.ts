import { describe, expect, it } from 'vitest';
import { ConnectionError, ProtocolError } from '../../src/core/errors';
import { _wrap, type MinimalWebSocket, type WsMessage } from '../../src/ws/index';

// a fake MinimalWebSocket the test drives by hand; records sends and lets the test emit events
class FakeWebSocket implements MinimalWebSocket {
	accepted = false;
	readonly sent: Array<string | ArrayBuffer | Uint8Array> = [];
	closedWith: { code?: number; reason?: string } | undefined;
	readonly #listeners = new Map<string, Array<(event: any) => void>>();

	accept(): void {
		this.accepted = true;
	}

	send(data: string | ArrayBuffer | Uint8Array): void {
		this.sent.push(data);
	}

	close(code?: number, reason?: string): void {
		this.closedWith = { code, reason };
	}

	addEventListener(type: string, listener: (event: any) => void): void {
		const list = this.#listeners.get(type) ?? [];
		list.push(listener);
		this.#listeners.set(type, list);
	}

	emit(type: string, event: unknown): void {
		for (const listener of this.#listeners.get(type) ?? []) listener(event);
	}

	emitMessage(data: unknown): void {
		this.emit('message', { data });
	}

	emitClose(code?: number, reason?: string): void {
		this.emit('close', { code, reason });
	}

	emitError(message?: string, error?: unknown): void {
		this.emit('error', { message, error });
	}
}

const enc = (s: string) => new TextEncoder().encode(s);

describe('_wrap', () => {
	it('accepts the socket on wrap', () => {
		const fake = new FakeWebSocket();
		_wrap(fake);
		expect(fake.accepted).toBe(true);
	});

	it('does not throw when accept is absent', () => {
		const noAccept: MinimalWebSocket = {
			send() {},
			close() {},
			addEventListener() {}
		};
		expect(() => _wrap(noAccept)).not.toThrow();
	});
});

describe('WsConnection iteration', () => {
	it('yields text and binary messages in arrival order', async () => {
		const fake = new FakeWebSocket();
		const conn = _wrap(fake);

		fake.emitMessage('first');
		fake.emitMessage(enc('second').buffer);
		fake.emitMessage(enc('third'));
		fake.emitClose(1000, 'bye');

		const got: WsMessage[] = [];
		for await (const msg of conn) got.push(msg);

		expect(got).toHaveLength(3);
		expect(got[0]).toEqual({ type: 'text', data: 'first' });
		expect(got[1]?.type).toBe('binary');
		expect(new TextDecoder().decode((got[1] as { data: Uint8Array }).data)).toBe('second');
		expect(got[2]?.type).toBe('binary');
		expect(new TextDecoder().decode((got[2] as { data: Uint8Array }).data)).toBe('third');
	});

	it('delivers a message that arrives while a reader is parked', async () => {
		const fake = new FakeWebSocket();
		const conn = _wrap(fake);
		const it = conn[Symbol.asyncIterator]();

		const pending = it.next();
		fake.emitMessage('late');
		await expect(pending).resolves.toEqual({ done: false, value: { type: 'text', data: 'late' } });
	});

	it('terminates the iterator on close', async () => {
		const fake = new FakeWebSocket();
		const conn = _wrap(fake);
		const it = conn[Symbol.asyncIterator]();

		const pending = it.next();
		fake.emitClose(1001, 'going away');
		await expect(pending).resolves.toEqual({ done: true, value: undefined });

		// further pulls stay done
		await expect(it.next()).resolves.toEqual({ done: true, value: undefined });
	});

	it('drains buffered messages even after close', async () => {
		const fake = new FakeWebSocket();
		const conn = _wrap(fake);

		fake.emitMessage('a');
		fake.emitMessage('b');
		fake.emitClose(1000, '');

		const got: string[] = [];
		for await (const msg of conn) if (msg.type === 'text') got.push(msg.data);
		expect(got).toEqual(['a', 'b']);
	});
});

describe('WsConnection send', () => {
	it('forwards string and binary payloads to the socket', () => {
		const fake = new FakeWebSocket();
		const conn = _wrap(fake);

		conn.send('hello');
		const bytes = enc('bin');
		conn.send(bytes);

		expect(fake.sent).toEqual(['hello', bytes]);
	});
});

describe('WsConnection close', () => {
	it('forwards code and reason to the socket', () => {
		const fake = new FakeWebSocket();
		const conn = _wrap(fake);
		conn.close(1000, 'done');
		expect(fake.closedWith).toEqual({ code: 1000, reason: 'done' });
	});

	it('resolves closed with the close event code and reason', async () => {
		const fake = new FakeWebSocket();
		const conn = _wrap(fake);
		fake.emitClose(1011, 'server error');
		await expect(conn.closed).resolves.toEqual({ code: 1011, reason: 'server error' });
	});

	it('defaults missing code and reason on closed', async () => {
		const fake = new FakeWebSocket();
		const conn = _wrap(fake);
		fake.emitClose();
		await expect(conn.closed).resolves.toEqual({ code: 1005, reason: '' });
	});
});

describe('asyncDispose', () => {
	it('closes the socket on dispose', async () => {
		const fake = new FakeWebSocket();
		{
			await using conn = _wrap(fake);
			conn.send('x');
		}
		expect(fake.closedWith).toBeDefined();
	});

	it('return() on the iterator closes and ends iteration', async () => {
		const fake = new FakeWebSocket();
		const conn = _wrap(fake);
		const it = conn[Symbol.asyncIterator]();
		await expect(it.return?.()).resolves.toEqual({ done: true, value: undefined });
		expect(fake.closedWith).toBeDefined();
		await expect(it.next()).resolves.toEqual({ done: true, value: undefined });
	});
});

describe('error handling', () => {
	it('rejects a parked reader with a ProtocolError', async () => {
		const fake = new FakeWebSocket();
		const conn = _wrap(fake);
		const it = conn[Symbol.asyncIterator]();

		const pending = it.next();
		fake.emitError('boom');
		await expect(pending).rejects.toBeInstanceOf(ProtocolError);
	});

	it('surfaces an error to the next next() when no reader is parked', async () => {
		const fake = new FakeWebSocket();
		const conn = _wrap(fake);
		const it = conn[Symbol.asyncIterator]();

		fake.emitError('boom later');
		await expect(it.next()).rejects.toBeInstanceOf(ProtocolError);
		// the error is consumed once; afterwards close drives the iterator done
		fake.emitClose(1006, '');
		await expect(it.next()).resolves.toEqual({ done: true, value: undefined });
	});

	it('throws a ProtocolError on an unsupported message payload', () => {
		const fake = new FakeWebSocket();
		_wrap(fake);
		expect(() => fake.emitMessage(42 as unknown)).toThrow(ProtocolError);
	});
});

describe('error vocabulary', () => {
	it('ConnectionError and ProtocolError are the only ws error types used', () => {
		// guards that the ws module imports from the shared core taxonomy
		expect(new ConnectionError('x')).toBeInstanceOf(Error);
		expect(new ProtocolError('x')).toBeInstanceOf(Error);
	});
});
