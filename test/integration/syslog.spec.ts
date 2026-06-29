import { it } from 'vitest';
import { connect, Severity } from '../../src/syslog/index';

it('connects and ships RFC 5424 messages over TCP (octet-counting)', async () => {
	await using log = await connect({ hostname: '127.0.0.1', port: 5514, appName: 'edgeport' });
	await log.log({ severity: Severity.info, message: 'service started' });
	await log.log({
		severity: Severity.error,
		message: 'something failed',
		structuredData: [{ id: 'meta@1', params: { run: '7' } }]
	});
	await log.emit('<14>1 2026-06-29T00:00:00Z host edgeport - - - raw line');
});

it('ships LF-framed messages', async () => {
	await using log = await connect({
		hostname: '127.0.0.1',
		port: 5514,
		framing: 'lf',
		appName: 'edgeport'
	});
	await log.log({ severity: 'warning', message: 'lf framed' });
});
