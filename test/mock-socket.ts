import {
	StreamFramedReader,
	StreamFramedWriter,
	type FramedReader,
	type FramedWriter
} from '../src/core/framing';
import type { CoreSocket } from '../src/core/socket';

/** The server half of a mock connection, driven by the test. */
export interface MockServerEnd {
	/** Reads one line the client sent (CRLF/LF stripped). */
	readLine(timeoutMs?: number): Promise<string>;
	/** Reads exactly `n` bytes the client sent. */
	readN(n: number, timeoutMs?: number): Promise<Uint8Array>;
	/** Sends a line to the client (CRLF appended). */
	writeLine(s: string): Promise<void>;
	/** Sends raw bytes to the client. */
	write(b: Uint8Array): Promise<void>;
	/** Closes the server->client stream, simulating a spontaneous disconnect. */
	close(): Promise<void>;
}

/** A mock {@link CoreSocket} plus the server end the test scripts against it. */
export interface MockConnection {
	socket: CoreSocket;
	server: MockServerEnd;
	/** Number of times startTls was invoked on the client socket. */
	startTlsCount(): number;
}

class MockCoreSocket implements CoreSocket {
	reader: FramedReader;
	writer: FramedWriter;
	#tlsCount = 0;
	#closed = false;
	readonly #onClose: () => void;
	readonly closed: Promise<void>;

	constructor(
		reader: FramedReader,
		writer: FramedWriter,
		onCloseResolved: Promise<void>,
		onClose: () => void
	) {
		this.reader = reader;
		this.writer = writer;
		this.closed = onCloseResolved;
		this.#onClose = onClose;
	}

	get tlsCount(): number {
		return this.#tlsCount;
	}

	// mock upgrade: the same in-memory channel keeps flowing (no real TLS)
	startTls(): CoreSocket {
		this.#tlsCount++;
		return this;
	}

	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		this.#onClose();
	}

	[Symbol.asyncDispose](): Promise<void> {
		return this.close();
	}
}

/** Creates a connected mock socket and the server end the test drives. */
export function mockConnection(): MockConnection {
	// generous buffers so `await server.write(...)` resolves before the client reads
	// (the default readable highWaterMark of 0 would deadlock write-then-read tests)
	const strat = { highWaterMark: 1 << 20 };
	const c2s = new TransformStream<Uint8Array, Uint8Array>(undefined, strat, strat);
	const s2c = new TransformStream<Uint8Array, Uint8Array>(undefined, strat, strat);

	let resolveClosed!: () => void;
	const closed = new Promise<void>((r) => (resolveClosed = r));

	const socket = new MockCoreSocket(
		new StreamFramedReader(s2c.readable),
		new StreamFramedWriter(c2s.writable),
		closed,
		resolveClosed
	);

	const serverReader = new StreamFramedReader(c2s.readable);
	const serverWriter = new StreamFramedWriter(s2c.writable);
	const server: MockServerEnd = {
		readLine: (timeoutMs) => serverReader.readLine(timeoutMs),
		readN: (n, timeoutMs) => serverReader.readN(n, timeoutMs),
		writeLine: (s) => serverWriter.writeLine(s),
		write: (b) => serverWriter.write(b),
		close: () => serverWriter.close()
	};

	return { socket, server, startTlsCount: () => socket.tlsCount };
}
