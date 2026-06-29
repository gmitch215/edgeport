import { connect } from 'cloudflare:sockets';
import { expect, it } from 'vitest';

it('reads the SSH banner from the openssh container over a raw socket', async () => {
	const socket = connect({ hostname: '127.0.0.1', port: 2222 });
	try {
		const reader = socket.readable.getReader();
		const { value } = await reader.read();
		reader.releaseLock();
		const banner = new TextDecoder().decode(value ?? new Uint8Array());
		expect(banner.startsWith('SSH-2.0')).toBe(true);
	} finally {
		await socket.close().catch(() => {});
	}
});
