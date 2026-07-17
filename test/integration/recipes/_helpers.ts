// shared helpers for the cross-module recipe integration tests
import { connect } from 'cloudflare:sockets';
import { connect as imapConnect } from '../../../src/imap/index';

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

/**
 * Polls greenmail's INBOX over IMAP until a message whose subject contains `marker` arrives,
 * returning its decoded body (or null on timeout). Recipes use it to prove an SMTP send actually
 * landed. Defaults to the shared tester mailbox (tester:testpass on 127.0.0.1:3143, tls off).
 */
export async function waitForMail(
	marker: string,
	opts: { host?: string; port?: number; auth?: { username: string; password: string } } = {}
): Promise<string | null> {
	const host = opts.host ?? '127.0.0.1';
	const port = opts.port ?? 3143;
	const auth = opts.auth ?? { username: 'tester', password: 'testpass' };
	const dec = new TextDecoder();
	return waitFor(
		async () => {
			await using imap = await imapConnect({ hostname: host, port, tls: 'off', auth });
			await imap.select('INBOX');
			const uids = await imap.search({ subject: marker });
			if (uids.length === 0) return null;
			const messages = await imap.fetch(uids, { body: true });
			return (
				messages.map((m) => (m.body ? dec.decode(m.body) : '')).find((b) => b.includes(marker)) ??
				null
			);
		},
		15_000,
		300
	);
}

/** Reads syslog and returns the lines carrying `runId`, once every marker appears (in any order). */
export async function waitForLog(runId: string, markers: string[]): Promise<string | null> {
	return waitFor(
		async () => {
			const mine = (await readSyslog())
				.split('\n')
				.filter((line) => line.includes(runId))
				.join('\n');
			return markers.every((m) => mine.includes(m)) ? mine : null;
		},
		15_000,
		300
	);
}
