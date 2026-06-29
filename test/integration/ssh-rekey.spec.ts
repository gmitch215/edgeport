// integration: in-session key re-exchange (RFC 4253 section 9) against real OpenSSH,
// both manual and auto-triggered, with data integrity verified across the rekey
import { expect, it } from 'vitest';
import { connect } from '../../src/ssh/index';

const base = { hostname: '127.0.0.1', port: 2222, username: 'tester', password: 'testpass' };
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

it('manual rekey: session keeps working after session.rekey()', async () => {
	await using ssh = await connect(base);
	expect(dec((await ssh.exec('echo before')).stdout)).toContain('before');
	await ssh.rekey(); // client-initiated re-exchange; resolves when new keys are installed
	expect(dec((await ssh.exec('echo after')).stdout)).toContain('after');
	// a second rekey on the same session must also work
	await ssh.rekey();
	expect((await ssh.exec('true')).code).toBe(0);
});

it('auto-rekey: a large transfer past a low byte threshold stays intact', async () => {
	await using ssh = await connect({ ...base, rekeyThresholdBytes: 4096 });
	// ~100 KB of output forces several auto-rekeys mid-stream; output must be complete + ordered
	const r = await ssh.exec('seq 1 20000');
	expect(r.code).toBe(0);
	const lines = dec(r.stdout).trim().split('\n');
	expect(lines.length).toBe(20000);
	expect(lines[0]).toBe('1');
	expect(lines[lines.length - 1]).toBe('20000');
});
