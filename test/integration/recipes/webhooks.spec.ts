// recipe: idempotent webhook fan-out. a webhook lands on a Worker that dedupes it against shared
// Redis state (SET NX EX), discovers the downstream endpoint over DNS (edgeport/dns), queues the
// job on a Redis list, publishes it to a Redis channel for whichever isolate is listening, then the
// consumer drains the queue, audits to Syslog and emails a digest over SMTP (verified over IMAP).
// uses Redis + DNS + Syslog + SMTP together.
//
// PLAINTEXT NOTE: redis is plaintext on 6379 with requirepass; coredns answers over tcp on 5354;
// greenmail smtp/imap use tls:'off'; syslog 5514 ingest / 5515 readback. SHARED-SERVER NOTE: the
// redis keyspace, greenmail, and the syslog file are shared, so keys/channels/subjects are per-run.
import { describe, expect, it } from 'vitest';
import { resolve4 } from '../../../src/dns/index';
import {
	connect as redisConnect,
	type RedisMessage,
	type RedisSession
} from '../../../src/redis/index';
import { send as smtpSend } from '../../../src/smtp/index';
import { connect as syslogConnect } from '../../../src/syslog/index';
import { uniqueId, waitForLog, waitForMail } from './_helpers';

const HOST = '127.0.0.1';
const DNS = { server: HOST, port: 5354 };
const REDIS_PORT = 6379;
const SMTP_PORT = 3025;
const SYSLOG_PORT = 5514;
const OPS = 'tester@localhost';
const mailAuth = { username: 'tester', password: 'testpass' };

function redis(overrides: Record<string, unknown> = {}): Promise<RedisSession> {
	return redisConnect({
		hostname: HOST,
		port: REDIS_PORT,
		password: 'testpass',
		timeoutMs: 10_000,
		...overrides
	});
}

// the edge half of the recipe: claim the delivery id, then queue and announce the job
async function accept(
	session: RedisSession,
	runId: string,
	deliveryId: string
): Promise<'accepted' | 'duplicate'> {
	const claimed = await session.set(`webhook:${runId}:${deliveryId}`, '1', {
		nx: true,
		ex: 3600
	});
	if (!claimed) return 'duplicate';

	// configuration discovery: where the job should be delivered downstream
	const [ip] = await resolve4('host.edgeport.test', DNS);
	const job = JSON.stringify({ deliveryId, target: ip });

	await session.rpush(`queue:${runId}`, job);
	await session.hset(`status:${runId}`, { [deliveryId]: 'queued' });
	await session.publish(`jobs:${runId}`, job);
	return 'accepted';
}

describe('recipe: idempotent webhook fan-out (Redis + DNS + Syslog + SMTP)', () => {
	// 1. a replayed delivery is claimed once, so the job is enqueued exactly once
	it('dedupes a replayed webhook so the work is queued exactly once', async () => {
		const runId = uniqueId('hook');
		const deliveryId = 'gh-7f3a91';
		await using edge = await redis();

		expect(await accept(edge, runId, deliveryId)).toBe('accepted');
		// the same delivery arriving twice more (retry, or a second isolate) must not requeue
		expect(await accept(edge, runId, deliveryId)).toBe('duplicate');
		expect(await accept(edge, runId, deliveryId)).toBe('duplicate');

		expect(await edge.llen(`queue:${runId}`)).toBe(1);
		expect(await edge.hgetall(`status:${runId}`)).toEqual({ [deliveryId]: 'queued' });

		// a different delivery id is independent
		expect(await accept(edge, runId, 'gh-0c22de')).toBe('accepted');
		expect(await edge.llen(`queue:${runId}`)).toBe(2);

		// the claim carries a ttl, so the dedupe window expires rather than leaking keys
		expect(await edge.ttl(`webhook:${runId}:${deliveryId}`)).toBeGreaterThan(0);
		await edge.del(`queue:${runId}`, `status:${runId}`);
	});

	// 2. the queued job reaches a live subscriber and the DNS-discovered target rides along
	it('fans the job out to a live subscriber with the resolved target attached', async () => {
		const runId = uniqueId('hook-pub');
		const deliveryId = 'gh-a10b42';
		await using consumer = await redis({ protocol: 3 });
		await using edge = await redis();
		await using sub = await consumer.subscribe(`jobs:${runId}`);

		expect(await accept(edge, runId, deliveryId)).toBe('accepted');

		const { value } = await sub[Symbol.asyncIterator]().next();
		const delivered = value as RedisMessage;
		const job = delivered.json<{ deliveryId: string; target: string }>();
		expect(job.deliveryId).toBe(deliveryId);
		expect(job.target).toBe('93.184.216.34'); // host.edgeport.test

		// RESP3 lets the consumer stay subscribed while it drains the queue on the same connection
		const drained = await consumer.lpop(`queue:${runId}`);
		expect(drained).not.toBeNull();
		await consumer.hset(`status:${runId}`, { [deliveryId]: 'done' });
		expect(await consumer.hgetall(`status:${runId}`)).toEqual({ [deliveryId]: 'done' });
		expect(await consumer.llen(`queue:${runId}`)).toBe(0);
		await consumer.del(`queue:${runId}`, `status:${runId}`);
	});

	// 3. the drained job is audited to syslog and a digest is emailed to ops (verified over IMAP)
	it('audits the drained job to syslog and emails a digest delivered to ops', async () => {
		const runId = uniqueId('hook-audit');
		const deliveryId = 'gh-55e1cc';
		await using edge = await redis();
		expect(await accept(edge, runId, deliveryId)).toBe('accepted');

		await using log = await syslogConnect({
			hostname: HOST,
			port: SYSLOG_PORT,
			tls: 'off',
			appName: 'webhook-fanout',
			procId: runId
		});
		await log.info(`webhook-claimed ${runId} delivery=${deliveryId}`);

		const job = await edge.lpop(`queue:${runId}`);
		const target = JSON.parse(job!).target as string;
		await edge.hset(`status:${runId}`, { [deliveryId]: 'done' });
		await log.info(`webhook-drained ${runId} delivery=${deliveryId} target=${target}`);

		const audit = await waitForLog(runId, [`webhook-claimed ${runId}`, `webhook-drained ${runId}`]);
		expect(audit, 'both stages should be audited to syslog').not.toBeNull();
		// the claim is logged before the drain
		expect(audit!.indexOf('webhook-claimed')).toBeLessThan(audit!.indexOf('webhook-drained'));

		const counted = await edge.incr(`processed:${runId}`);
		await smtpSend({
			hostname: HOST,
			port: SMTP_PORT,
			tls: 'off',
			auth: mailAuth,
			from: OPS,
			to: OPS,
			subject: `${runId} webhook digest`,
			text: `Processed ${counted} delivery for ${runId}: ${deliveryId} -> ${target}`
		});

		const body = await waitForMail(runId);
		expect(body, 'the webhook digest should be delivered').not.toBeNull();
		expect(body!).toContain(deliveryId);
		expect(body!).toContain(target);
		await edge.del(`queue:${runId}`, `status:${runId}`, `processed:${runId}`);
	});

	// 4. a burst of distinct deliveries is claimed once each, even when they race
	it('claims each delivery once when a burst of retries races', async () => {
		const runId = uniqueId('hook-race');
		await using edge = await redis();
		const ids = ['a1', 'a2', 'a3', 'a4'];

		// every id submitted three times concurrently; only the first claim of each may win
		const outcomes = await Promise.all(
			[...ids, ...ids, ...ids].map((id) => accept(edge, runId, id))
		);
		expect(outcomes.filter((o) => o === 'accepted')).toHaveLength(ids.length);
		expect(await edge.llen(`queue:${runId}`)).toBe(ids.length);
		expect(Object.keys(await edge.hgetall(`status:${runId}`)).sort()).toEqual(ids);
		await edge.del(`queue:${runId}`, `status:${runId}`);
	});
});
