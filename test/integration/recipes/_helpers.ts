// shared helpers for the cross-module recipe integration tests
import { connect } from 'cloudflare:sockets';

/**
 * Reads back everything sent to the Dockerized syslog ingest port (5514) by connecting to
 * the readback port (5515), which cats the captured log file and closes. Use it to assert
 * what a recipe actually logged.
 */
export async function readSyslog(host = '127.0.0.1', port = 5515): Promise<string> {
	const socket = connect({ hostname: host, port });
	try {
		const reader = (socket.readable as ReadableStream<Uint8Array>).getReader();
		const chunks: Uint8Array[] = [];
		for (;;) {
			const { value, done } = await reader.read();
			if (done) break;
			if (value) chunks.push(value);
		}
		let total = 0;
		for (const c of chunks) total += c.length;
		const out = new Uint8Array(total);
		let o = 0;
		for (const c of chunks) {
			out.set(c, o);
			o += c.length;
		}
		return new TextDecoder().decode(out);
	} finally {
		await socket.close().catch(() => {});
	}
}

/** A short, per-test-unique suffix (no Date/random in the hot path; derived from a counter). */
let counter = 0;
export function uniqueId(prefix = 'ep'): string {
	counter = (counter + 1) % 1_000_000;
	return `${prefix}-${counter.toString(36)}-${Math.floor(performance.now()).toString(36)}`;
}

/** Polls `fn` until it returns truthy or the deadline elapses; returns the value or null. */
export async function waitFor<T>(
	fn: () => Promise<T> | T,
	timeoutMs = 5000,
	stepMs = 100
): Promise<T | null> {
	const deadline = performance.now() + timeoutMs;
	for (;;) {
		const v = await fn();
		if (v) return v;
		if (performance.now() > deadline) return null;
		await new Promise((r) => setTimeout(r, stepMs));
	}
}

/** Synthesizes a deterministic binary artifact of `n` bytes (for upload/resume tests). */
export function artifact(n: number): Uint8Array {
	const b = new Uint8Array(n);
	for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) & 0xff;
	return b;
}
