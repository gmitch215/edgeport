// recipe: resilience + message continuity across reconnects, spanning NATS (JetStream),
// MQTT (persistent session), and Syslog (ordered event audit).
//
// IMPORTANT: these tests run under workerd and cannot restart/kill the Docker servers, so a
// "node failover" is modeled purely as a CLIENT reconnect - we close() the connection and open
// a fresh one against the same still-running server. that exercises the same client-side
// recovery paths (re-bind a durable consumer, resume a persistent session, drain queued msgs)
// without touching the server lifecycle.
import { describe, expect, it } from 'vitest';
import { connect as mqttConnect } from '../../../src/mqtt/index';
import { connect as natsConnect } from '../../../src/nats/index';
import { Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const HOST = '127.0.0.1';
const NATS_PORT = 4222;
const MQTT_PORT = 1883;
const SYSLOG_PORT = 5514;
const natsAuth = { hostname: HOST, port: NATS_PORT, username: 'tester', password: 'testpass' };

const dec = (b: Uint8Array) => new TextDecoder().decode(b);

describe('recipe: resilience + message continuity across reconnects', () => {
	// ---- 1. NATS JetStream durable continuity: no loss, no dup across a client reconnect ----
	// JetStream is required here (server runs with -js); we drive it through the public
	// nc.jetstream() client rather than hand-rolling $JS.API.* requests.
	it('re-binds the SAME durable after reconnect: acked msgs not redelivered, un-acked are', async () => {
		// unique per run so reruns never collide (perf-derived, same shape as nats.spec.ts)
		const suffix = `${Math.floor(performance.now() * 1000)}_${Math.floor(Math.random() * 1e6)}`;
		const stream = `S_${suffix}`;
		const durable = `D_${suffix}`;
		const subject = `recovery.${suffix}`;
		const ackWaitMs = 1500; // un-acked msgs become redeliverable after this
		const sent = ['msg-1', 'msg-2', 'msg-3', 'msg-4'];

		// connection #1: ensure the stream, publish 4, pull all, ack only the first 2, then drop
		{
			await using setup = await natsConnect(natsAuth);
			const js = setup.jetstream();
			await js.ensureStream(stream, { subjects: [subject] });

			for (let i = 0; i < sent.length; i++) {
				const ack = await js.publish(subject, sent[i]!);
				expect(ack.stream).toBe(stream);
				expect(ack.seq).toBe(i + 1);
			}

			const consumer = await js.pullSubscribe(stream, durable, { ackWaitMs });
			const pulled = await consumer.fetch(sent.length, { expiresMs: 2000 });
			expect(pulled.map((m) => dec(m.data))).toEqual(sent);

			// ACK only msg-1 + msg-2; leave msg-3 + msg-4 un-acked (must redeliver after reconnect)
			await pulled[0]!.ack();
			await pulled[1]!.ack();
			await setup.close(); // simulate failover: drop the client mid-stream
		}

		// wait out ackWait so the un-acked msgs become redeliverable again
		await new Promise((r) => setTimeout(r, ackWaitMs + 750));

		try {
			// connection #2: re-bind the SAME durable and drain what remains
			await using reconnected = await natsConnect(natsAuth);
			const js = reconnected.jetstream();
			const consumer = await js.pullSubscribe(stream, durable, { ackWaitMs });
			const redelivered: string[] = [];
			for (let round = 0; round < 3 && redelivered.length < 2; round++) {
				const batch = await consumer.fetch(4, { expiresMs: 1500 });
				for (const m of batch) {
					redelivered.push(dec(m.data));
					await m.ack();
				}
				if (batch.length === 0) break;
			}

			// no loss: every un-acked message comes back
			expect(redelivered.sort()).toEqual(['msg-3', 'msg-4']);
			// no dup: the already-acked msg-1 / msg-2 are NOT redelivered
			expect(redelivered).not.toContain('msg-1');
			expect(redelivered).not.toContain('msg-2');
		} finally {
			await using cleanup = await natsConnect(natsAuth);
			await cleanup
				.request(`$JS.API.STREAM.DELETE.${stream}`, '', { timeoutMs: 4000 })
				.catch(() => {});
		}
	}, 60_000); // ackWait + redelivery sleep means this path is intentionally slow

	// ---- 2. MQTT persistent-session drain across an offline window -----------------------------
	it('drains QoS1 messages queued while a persistent-session subscriber was offline', async () => {
		const id = uniqueId('mq').replace(/[^a-zA-Z0-9]/g, '');
		const clientId = `edgeport-persist-${id}`; // fixed id is what ties the two sessions together
		const topic = `recovery/persist/${id}`;
		const sent = ['q-1', 'q-2', 'q-3', 'q-4'];

		// phase A: subscriber connects with a persistent session and subscribes QoS1, then leaves.
		// cleanSession:false + a fixed clientId tells mosquitto (persistence ON) to retain the
		// subscription and queue inbound QoS>=1 msgs while the client is gone.
		{
			await using sub = await mqttConnect({
				hostname: HOST,
				port: MQTT_PORT,
				clientId,
				cleanSession: false
			});
			// register the subscription, then confirm a live roundtrip so the SUBACK is durable
			const s = sub.subscribe(topic, { qos: 1 });
			const it = s[Symbol.asyncIterator]();
			await sub.publish(topic, 'warmup', { qos: 1 });
			const warm = await it.next();
			expect(dec(warm.value!.payload)).toBe('warmup');
			await sub.close({ graceful: false }); // abrupt drop -> session + sub persist on broker
		}

		// phase B: a separate publisher sends several QoS1 msgs while the subscriber is OFFLINE.
		{
			await using pub = await mqttConnect({
				hostname: HOST,
				port: MQTT_PORT,
				clientId: `edgeport-pub-${id}`,
				cleanSession: true
			});
			for (const m of sent) {
				await pub.publish(topic, m, { qos: 1 }); // resolves on PUBACK = broker stored it
			}
		}

		// phase C: subscriber reconnects with the SAME clientId + cleanSession:false and drains
		// the queue. all four offline msgs must arrive, in order, with no loss.
		{
			await using sub = await mqttConnect({
				hostname: HOST,
				port: MQTT_PORT,
				clientId,
				cleanSession: false
			});
			// resuming the session restores the QoS1 subscription; the broker replays the queue.
			const s = sub.subscribe(topic, { qos: 1 });
			const it = s[Symbol.asyncIterator]();
			const drained: string[] = [];
			for (let i = 0; i < sent.length; i++) {
				const next = await Promise.race([
					it.next(),
					new Promise<null>((r) => setTimeout(() => r(null), 5000))
				]);
				if (next === null || next.done) break;
				const text = dec(next.value.payload);
				if (sent.includes(text)) drained.push(text);
			}
			expect(drained).toEqual(sent); // in-order, no loss, no dup
		}
	}, 45_000); // broker may be slow to replay the offline queue on session resume

	// ---- 3. Syslog ordered audit of the failover events ----------------------------------------
	it('logs reconnect events to syslog in the correct order', async () => {
		const marker = uniqueId('audit').replace(/[^a-zA-Z0-9-]/g, '');
		const events = ['nats-reconnect', 'mqtt-drain-start', 'mqtt-drain-end'];

		await using log = await syslogConnect({
			hostname: HOST,
			port: SYSLOG_PORT,
			tls: 'off',
			appName: 'recovery'
		});
		// each line carries the unique marker as MSGID so we can isolate this run from the sink's
		// accumulated history, and the event name in the message body.
		for (const ev of events) {
			await log.log({ severity: Severity.notice, msgId: marker, message: `${marker} ${ev}` });
		}

		// read the sink back and assert our three events appear in the order we sent them
		const found = await waitFor(
			async () => {
				const all = await readSyslog();
				return events.every((e) => all.includes(`${marker} ${e}`)) ? all : null;
			},
			10_000,
			250
		);
		expect(found, 'all three audit events should reach the syslog sink').not.toBeNull();

		const positions = events.map((e) => found!.indexOf(`${marker} ${e}`));
		// strictly increasing positions = correct order
		for (let i = 1; i < positions.length; i++) {
			expect(positions[i]).toBeGreaterThan(positions[i - 1]!);
		}
	});

	// ---- 4. Edge cases: reconnect during an in-flight subscription, transient error -----------
	it('reconnects mid-subscription with no duplicate delivery, and handles a transient error cleanly', async () => {
		const id = uniqueId('edge').replace(/[^a-zA-Z0-9]/g, '');
		const subject = `recovery.edge.${id}`;

		// in-flight subscription: subscribe, receive one msg, drop the client, reconnect, and
		// confirm the FIRST msg is not re-delivered on the new connection (core NATS has no
		// replay), while a newly published msg is delivered exactly once.
		await using producer = await natsConnect(natsAuth);

		await using c1 = await natsConnect(natsAuth);
		const s1 = c1.subscribe(subject);
		const i1 = s1[Symbol.asyncIterator]();
		// the producer is a SEPARATE connection, so subscribe() (fire-and-forget SUB write) is not
		// ordered against producer.publish(); let the server register the SUB before publishing or
		// the message is dropped and i1.next() would block forever. guard the read with a race too.
		await new Promise((r) => setTimeout(r, 150));
		await producer.publish(subject, 'first');
		const first = await Promise.race([
			i1.next(),
			new Promise<null>((r) => setTimeout(() => r(null), 3000))
		]);
		expect(first, 'first message should arrive on the live subscription').not.toBeNull();
		expect(dec(first!.value!.data)).toBe('first');
		await c1.close(); // drop mid-subscription

		await using c2 = await natsConnect(natsAuth);
		const s2 = c2.subscribe(subject);
		const i2 = s2[Symbol.asyncIterator]();
		// give the SUB time to register before publishing the next msg
		await new Promise((r) => setTimeout(r, 150));
		await producer.publish(subject, 'second');

		const seen: string[] = [];
		for (let n = 0; n < 2; n++) {
			const next = await Promise.race([
				i2.next(),
				new Promise<null>((r) => setTimeout(() => r(null), 1500))
			]);
			if (next === null || next.done) break;
			seen.push(dec(next.value.data));
		}
		expect(seen).toContain('second');
		// no duplicate of the pre-reconnect message on the fresh connection
		expect(seen).not.toContain('first');
		expect(seen.filter((m) => m === 'second').length).toBe(1);

		// transient error handled cleanly: a request with no responder times out (TimeoutError),
		// and the connection stays usable for a subsequent successful roundtrip.
		await expect(
			c2.request(`recovery.noresponder.${id}`, 'ping', { timeoutMs: 500 })
		).rejects.toBeTruthy();

		const svc = c2.subscribe(`recovery.echo.${id}`);
		void (async () => {
			for await (const m of svc) {
				if (m.reply) await c2.publish(m.reply, m.data);
				break;
			}
		})();
		await new Promise((r) => setTimeout(r, 150));
		const reply = await c2.request(`recovery.echo.${id}`, 'still-alive', { timeoutMs: 3000 });
		expect(dec(reply.data)).toBe('still-alive');
	}, 45_000); // multiple reconnects + a deliberate no-responder timeout add up
});
