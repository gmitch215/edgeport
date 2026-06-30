import { describe, expect, it } from 'vitest';
import { connect } from '../../src/ws/index';

it('connects, sends a frame and receives the echo', async () => {
	const ws = await connect('ws://127.0.0.1:8081/.ws');
	const payload = 'edgeport-ws-' + Math.floor(Date.now()).toString(36);
	ws.send(payload);

	// jmalloc/echo-server emits a greeting first, then echoes; scan a few frames
	let echoed = false;
	const it = ws[Symbol.asyncIterator]();
	for (let i = 0; i < 5 && !echoed; i++) {
		const { value, done } = await it.next();
		if (done || !value) break;
		if (value.type === 'text' && value.data.includes(payload)) echoed = true;
	}
	expect(echoed).toBe(true);
	ws.close();
});

describe('json helpers', () => {
	it('sendJson is echoed back and parsed via the text frame json()', async () => {
		const ws = await connect('ws://127.0.0.1:8081/.ws');
		const tag = 'edgeport-' + Math.floor(Date.now()).toString(36);
		ws.sendJson({ tag, n: 7 });

		// the echo server greets first then echoes; scan a few frames for our tagged JSON
		let parsed: { tag: string; n: number } | undefined;
		const it = ws[Symbol.asyncIterator]();
		for (let i = 0; i < 5 && !parsed; i++) {
			const { value, done } = await it.next();
			if (done || !value) break;
			if (value.type === 'text' && value.data.includes(tag)) {
				parsed = value.json<{ tag: string; n: number }>();
			}
		}
		expect(parsed).toEqual({ tag, n: 7 });
		ws.close();
	});
});
