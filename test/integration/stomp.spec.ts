import { describe, expect, it } from 'vitest';
import { connect } from '../../src/stomp/index';

const base = { hostname: '127.0.0.1', port: 61613, login: 'admin', passcode: 'admin' };

it('sends and receives a message on a queue', async () => {
	await using stomp = await connect(base);
	const sub = stomp.subscribe('/queue/edgeport.test');
	const it = sub[Symbol.asyncIterator]();
	await stomp.send('/queue/edgeport.test', 'hello-stomp');
	const { value } = await it.next();
	expect(value).toBeDefined();
	expect(new TextDecoder().decode(value!.body)).toBe('hello-stomp');
});

describe('json helpers', () => {
	it('sendJson sets application/json and the message decodes via json() / text()', async () => {
		await using stomp = await connect(base);
		const sub = stomp.subscribe('/queue/edgeport.json');
		const it = sub[Symbol.asyncIterator]();
		await stomp.sendJson('/queue/edgeport.json', { job: 'reindex', n: 7 });
		const { value } = await it.next();
		expect(value).toBeDefined();
		expect(value!.headers['content-type']).toBe('application/json');
		expect(value!.text()).toBe('{"job":"reindex","n":7}');
		expect(value!.json()).toEqual({ job: 'reindex', n: 7 });
	});
});
