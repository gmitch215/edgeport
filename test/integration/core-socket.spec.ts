import { expect, it } from 'vitest';
import { EdgeportError } from '../../src/core/errors';
import { connect } from '../../src/core/socket';

it('connects to openssh and reads the banner line via the framed reader', async () => {
	await using socket = await connect({ hostname: '127.0.0.1', port: 2222 });
	const banner = await socket.reader.readLine(5000);
	expect(banner.startsWith('SSH-2.0')).toBe(true);
});

it('rejects with an EdgeportError when the peer cannot be reached in time', async () => {
	// 127.0.0.1:1 is unused; opening either refuses or never completes - both wrap to EdgeportError
	await expect(
		connect({ hostname: '127.0.0.1', port: 1, connectTimeoutMs: 200 })
	).rejects.toBeInstanceOf(EdgeportError);
});
