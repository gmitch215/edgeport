import { expect, it } from 'vitest';
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
