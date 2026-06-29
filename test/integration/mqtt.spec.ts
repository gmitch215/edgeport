import { expect, it } from 'vitest';
import { connect } from '../../src/mqtt/index';

it('publishes and receives a QoS 1 message', async () => {
	await using mqtt = await connect({
		hostname: '127.0.0.1',
		port: 1883,
		clientId: 'edgeport-test'
	});
	const sub = mqtt.subscribe('edge/test', { qos: 1 });
	const it = sub[Symbol.asyncIterator]();
	await mqtt.publish('edge/test', 'hello-mqtt', { qos: 1 });
	const { value } = await it.next();
	expect(value).toBeDefined();
	expect(new TextDecoder().decode(value!.payload)).toBe('hello-mqtt');
});

it('delivers across wildcard subscriptions', async () => {
	await using mqtt = await connect({
		hostname: '127.0.0.1',
		port: 1883,
		clientId: 'edgeport-wild'
	});
	const sub = mqtt.subscribe('edge/+/temp');
	const it = sub[Symbol.asyncIterator]();
	await mqtt.publish('edge/room1/temp', '21');
	const { value } = await it.next();
	expect(new TextDecoder().decode(value!.payload)).toBe('21');
});
