import { expect, it } from 'vitest';
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
