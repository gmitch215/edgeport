// resilience + security: auth success/failure paths, banner skipping, keyboard-interactive,
// and a spontaneous disconnect mid-authentication
import { describe, expect, it } from 'vitest';
import { authenticate, type PacketTransport } from '../../src/auth';
import { Msg } from '../../src/constants';
import { AuthError, ConnectionError, ProtocolError } from '../../src/core/errors';
import { SshReader, SshWriter } from '../../src/wire';

const serviceAccept = () => new SshWriter().byte(Msg.SERVICE_ACCEPT).string('ssh-userauth').bytes();
const success = () => new SshWriter().byte(Msg.USERAUTH_SUCCESS).bytes();
const failure = () =>
	new SshWriter().byte(Msg.USERAUTH_FAILURE).nameList(['publickey']).boolean(false).bytes();
const banner = () => new SshWriter().byte(Msg.USERAUTH_BANNER).string('hi').string('en').bytes();
const infoRequest = () =>
	new SshWriter()
		.byte(Msg.USERAUTH_INFO_REQUEST)
		.string('')
		.string('')
		.string('')
		.uint32(1)
		.string('Password:')
		.boolean(false)
		.bytes();

// a mock transport: scripted server replies (FIFO), recorded client sends, optional disconnect
function mockTransport(replies: Uint8Array[], disconnectWhenDrained = false) {
	const sent: Uint8Array[] = [];
	const queue = [...replies];
	const t = {
		sessionId: new Uint8Array(32),
		async send(p: Uint8Array) {
			sent.push(p);
		},
		async read(): Promise<Uint8Array> {
			if (queue.length === 0) {
				if (disconnectWhenDrained) throw new ConnectionError('connection closed');
				throw new ConnectionError('no more scripted replies');
			}
			return queue.shift()!;
		}
	};
	return { t: t as PacketTransport, sent };
}

const typeOf = (p: Uint8Array) => new SshReader(p).byte();

describe('authenticate', () => {
	it('succeeds with password and sends the right requests', async () => {
		const { t, sent } = mockTransport([serviceAccept(), success()]);
		await authenticate(t, { username: 'u', password: 'p' });
		expect(typeOf(sent[0]!)).toBe(Msg.SERVICE_REQUEST);
		expect(typeOf(sent[1]!)).toBe(Msg.USERAUTH_REQUEST);
	});

	it('throws AuthError when password is rejected', async () => {
		const { t } = mockTransport([serviceAccept(), failure()]);
		await expect(authenticate(t, { username: 'u', password: 'bad' })).rejects.toBeInstanceOf(
			AuthError
		);
	});

	it('throws AuthError when no method is supplied', async () => {
		const { t } = mockTransport([serviceAccept()]);
		await expect(authenticate(t, { username: 'u' })).rejects.toBeInstanceOf(AuthError);
	});

	it('skips USERAUTH_BANNER before the result', async () => {
		const { t } = mockTransport([serviceAccept(), banner(), success()]);
		await expect(authenticate(t, { username: 'u', password: 'p' })).resolves.toBeUndefined();
	});

	it('drives keyboard-interactive prompts and responds', async () => {
		const { t, sent } = mockTransport([serviceAccept(), infoRequest(), success()]);
		let seen: string[] = [];
		await authenticate(t, {
			username: 'u',
			onKeyboardInteractive: async (prompts) => {
				seen = prompts.map((p) => p.prompt);
				return ['otp-123'];
			}
		});
		expect(seen).toEqual(['Password:']);
		expect(typeOf(sent[sent.length - 1]!)).toBe(Msg.USERAUTH_INFO_RESPONSE);
	});

	it('rejects with ProtocolError if the service is not accepted', async () => {
		const { t } = mockTransport([success()]); // wrong reply to SERVICE_REQUEST
		await expect(authenticate(t, { username: 'u', password: 'p' })).rejects.toBeInstanceOf(
			ProtocolError
		);
	});

	it('propagates a spontaneous disconnect mid-authentication', async () => {
		const { t } = mockTransport([serviceAccept()], true); // drops after accepting the service
		await expect(authenticate(t, { username: 'u', password: 'p' })).rejects.toBeInstanceOf(
			ConnectionError
		);
	});
});
