// resilience: the transport surfaces server DISCONNECT and transparently skips IGNORE/DEBUG
import { expect, it } from 'vitest';
import { Msg } from '../../src/constants';
import { ConnectionError } from '../../src/core/errors';
import { NoneCipher } from '../../src/crypto/packet';
import { SshTransport } from '../../src/ssh/transport/transport';
import { SshWriter } from '../../src/wire';
import { mockConnection } from '../mock-socket';

it('throws ConnectionError on SSH_MSG_DISCONNECT', async () => {
	const { socket, server } = mockConnection();
	const transport = new SshTransport(socket);
	const none = new NoneCipher();
	const disconnect = new SshWriter()
		.byte(Msg.DISCONNECT)
		.uint32(11)
		.string('bye')
		.string('')
		.bytes();
	await server.write(await none.seal(0, disconnect));
	await expect(transport.read()).rejects.toBeInstanceOf(ConnectionError);
});

it('skips IGNORE and DEBUG packets and returns the next real one', async () => {
	const { socket, server } = mockConnection();
	const transport = new SshTransport(socket);
	const none = new NoneCipher();
	await server.write(await none.seal(0, new SshWriter().byte(Msg.IGNORE).string('noise').bytes()));
	await server.write(
		await none.seal(
			1,
			new SshWriter().byte(Msg.DEBUG).boolean(false).string('dbg').string('').bytes()
		)
	);
	await server.write(await none.seal(2, new SshWriter().byte(Msg.NEWKEYS).bytes()));
	const p = await transport.read();
	expect(p[0]).toBe(Msg.NEWKEYS);
});
