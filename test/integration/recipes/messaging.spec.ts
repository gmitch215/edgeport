// recipe: transactional messaging with a cross-protocol fan-out bridge. an ActiveMQ STOMP
// broker carries the transactional source-of-truth (BEGIN/COMMIT/ABORT staging), client-ack
// consumers settle delivery, and an application-level bridge consumes each committed STOMP
// message and republishes it to two separate brokers - mosquitto (MQTT QoS 1) and NATS - so a
// downstream consumer on either sees the same payload byte-for-byte. every stage (delivery,
// ack, commit/abort, ERROR) is written to a Syslog audit trail keyed by the run's unique id.
//
// BRIDGE NOTE: the three brokers are entirely separate processes (ActiveMQ vs mosquitto vs
// nats) with no built-in interconnect, so the "bridge" is APPLICATION code living in this
// worker: read a committed STOMP MESSAGE, then publish() the identical bytes to MQTT and NATS.
// fidelity across the bridge means the bytes are preserved end to end, not that the brokers
// talk to each other.
import { describe, expect, it } from 'vitest';
import { connect as mqttConnect } from '../../../src/mqtt/index';
import { connect as natsConnect } from '../../../src/nats/index';
import { connect as stompConnect, type StompMessage } from '../../../src/stomp/index';
import { Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

const stompBase = { hostname: '127.0.0.1', port: 61613, login: 'admin', passcode: 'admin' };
const mqttBase = { hostname: '127.0.0.1', port: 1883 };
const natsBase = { hostname: '127.0.0.1', port: 4222, username: 'tester', password: 'testpass' };
const syslogBase = {
	hostname: '127.0.0.1',
	port: 5514,
	tls: 'off' as const,
	appName: 'messaging-bridge',
	framing: 'lf' as const
};

// a bounded reader over one subscription. the subscriptions back a single shared message queue,
// so a timed-out read must NOT discard its pending next() (that would steal the next message into
// a dropped promise); instead we hold the pending next() across calls and reuse it. returns null
// on timeout, the message on arrival.
function reader<T>(sub: AsyncIterable<T>): (timeoutMs?: number) => Promise<T | null> {
	const iter = sub[Symbol.asyncIterator]();
	let pending: Promise<IteratorResult<T>> | null = null;
	return (timeoutMs = 8000) => {
		const next = pending ?? iter.next();
		pending = next; // keep it live until it actually resolves
		const timeout = new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs));
		const value = next.then((r) => {
			pending = null; // resolved: free the slot for the next read
			return r.done ? null : r.value;
		});
		return Promise.race([value, timeout]);
	};
}

describe('transactional messaging + cross-protocol bridge (stomp + mqtt + nats + syslog)', () => {
	// 1 + 2 + 5. STOMP transactions on ActiveMQ: a committed send is delivered, an aborted send
	// never leaks (proven by a sentinel committed after the abort), and the trail is audited.
	it('commits a transactional send, rolls back an aborted one, and never leaks the rollback', async () => {
		const tag = uniqueId('tx');
		const audit: string[] = [];

		await using log = await syslogConnect(syslogBase);
		const stage = async (event: string, message: string, severity = Severity.info) => {
			audit.push(event);
			await log.log({
				severity,
				message: `${event} ${tag} ${message}`,
				structuredData: [{ id: 'msg@1', params: { event, tag } }]
			});
		};

		await using stomp = await stompConnect(stompBase);
		const dest = `/queue/tx.${tag}`;

		// subscriber is up before any send so it cannot miss a committed message.
		await using sub = stomp.subscribe(dest, { ack: 'auto' });
		const read = reader(sub);
		await new Promise((r) => setTimeout(r, 300));

		// --- ROLLBACK first: stage a send inside a tx, then abort it. it must never arrive. ---
		const tx1 = await stomp.begin();
		await stage('tx-begin', `id=${tx1.id} kind=rollback`);
		await tx1.send(dest, enc(`ROLLED-BACK-${tag}`), { contentType: 'text/plain' });
		await tx1.abort();
		await stage('tx-abort', `id=${tx1.id}`);

		// --- COMMIT: a fresh tx whose send is the sentinel proving ordering after the abort. ---
		const committedBody = `COMMITTED-${tag}`;
		const tx2 = await stomp.begin();
		await stage('tx-begin', `id=${tx2.id} kind=commit`);
		await tx2.send(dest, enc(committedBody), { contentType: 'text/plain' });
		// before commit, nothing should be deliverable yet: staged sends are held by the broker.
		const beforeCommit = await read(1500);
		expect(beforeCommit, 'a staged (uncommitted) send must not be delivered').toBeNull();
		await tx2.commit();
		await stage('tx-commit', `id=${tx2.id}`);

		// the FIRST message delivered must be the committed sentinel, never the aborted one. if the
		// rollback had leaked, the aborted body would arrive ahead of (or instead of) the sentinel.
		const got = await read(8000);
		expect(got, 'committed message was not delivered').not.toBeNull();
		expect(dec(got!.body)).toBe(committedBody);
		expect(dec(got!.body)).not.toBe(`ROLLED-BACK-${tag}`);
		await stage('delivered', `body=${dec(got!.body)}`);

		// belt-and-braces: drain briefly to confirm the aborted body is not lurking behind it.
		const trailing = await read(1500);
		expect(
			trailing === null || dec(trailing.body) !== `ROLLED-BACK-${tag}`,
			'aborted message leaked onto the queue after the committed one'
		).toBe(true);

		// `await using sub` unsubscribes on scope exit; a second UNSUBSCRIBE would be rejected.
		await log.close();

		// audit trail: every stage landed for this tag, in order.
		const captured = await waitFor(
			async () => {
				const text = await readSyslog();
				return audit.every((e) => text.includes(`${e} ${tag}`)) ? text : null;
			},
			15000,
			250
		);
		expect(captured, 'syslog audit trail missing a stage for this tag').not.toBeNull();
		const text = captured!;
		const order = ['tx-begin', 'tx-abort', 'tx-begin', 'tx-commit', 'delivered'];
		expect(audit).toEqual(order);
		// the structured-data element rendered on the wire with the tag.
		expect(text).toContain('[msg@1 event=');
		expect(text).toContain(`tag="${tag}"`);
	});

	// 3. ack-mode correctness. client + client-individual: an acked message is settled off the
	// queue and a fresh subscription does not get it redelivered; client-individual acks one of
	// two messages and leaves the other to be redelivered.
	it('settles acked messages so they are not redelivered (client and client-individual)', async () => {
		const tag = uniqueId('ack');
		await using stomp = await stompConnect(stompBase);

		// --- client ack: send one, receive it, ack it, confirm a fresh sub does not get it back. ---
		const destClient = `/queue/ack.client.${tag}`;
		{
			await using sub = stomp.subscribe(destClient, { ack: 'client' });
			const read = reader(sub);
			await new Promise((r) => setTimeout(r, 300));
			await stomp.send(destClient, enc(`client-${tag}`), { contentType: 'text/plain' });

			const msg = await read(8000);
			expect(msg, 'client-ack subscriber did not receive the message').not.toBeNull();
			expect(dec(msg!.body)).toBe(`client-${tag}`);
			expect(msg!.ack, 'client-ack message must expose ack()').toBeTypeOf('function');
			await msg!.ack!();
			// note: `await using` unsubscribes on scope exit; calling unsubscribe() again would
			// write a second UNSUBSCRIBE for an already-removed id, which ActiveMQ rejects with
			// "No subscription matched". so rely on disposal for the single unsubscribe.
		}
		// fresh subscription: the acked message must NOT be redelivered (settled off the queue).
		{
			await using sub2 = stomp.subscribe(destClient, { ack: 'client' });
			const redelivered = await reader(sub2)(2500);
			expect(redelivered, 'an acked message must not be redelivered to a fresh sub').toBeNull();
		}

		// --- client-individual: send two, ack only the first, confirm only the second redelivers. ---
		const destIndiv = `/queue/ack.indiv.${tag}`;
		{
			await using sub = stomp.subscribe(destIndiv, { ack: 'client-individual' });
			const read = reader(sub);
			await new Promise((r) => setTimeout(r, 300));
			await stomp.send(destIndiv, enc(`one-${tag}`), { contentType: 'text/plain' });
			await stomp.send(destIndiv, enc(`two-${tag}`), { contentType: 'text/plain' });

			// collect both messages, ack ONLY the first one.
			const got: StompMessage[] = [];
			const m1 = await read(8000);
			expect(m1, 'first message not received').not.toBeNull();
			got.push(m1!);
			const m2 = await read(8000);
			expect(m2, 'second message not received').not.toBeNull();
			got.push(m2!);

			const bodies = got.map((m) => dec(m.body)).sort();
			expect(bodies).toEqual([`one-${tag}`, `two-${tag}`]);

			const first = got.find((m) => dec(m.body) === `one-${tag}`)!;
			expect(first.ack, 'client-individual message must expose ack()').toBeTypeOf('function');
			await first.ack!(); // per-message ack: settles ONLY this one, not the other
			// disposal (`await using`) handles the single unsubscribe; see note above.
		}
		// fresh sub: only the un-acked `two-` must redeliver (client-individual is per-message).
		{
			await using sub2 = stomp.subscribe(destIndiv, { ack: 'client' });
			const read2 = reader(sub2);
			const seen: string[] = [];
			const r1 = await read2(5000);
			if (r1) {
				seen.push(dec(r1.body));
				await r1.ack!(); // settle it so the queue is clean for the next run
			}
			const r2 = await read2(1500);
			if (r2) {
				seen.push(dec(r2.body));
				await r2.ack!();
			}
			// the acked `one-` is gone; the un-acked `two-` is redelivered exactly once.
			expect(seen, 'client-individual: only the un-acked message should redeliver').toEqual([
				`two-${tag}`
			]);
		}
	});

	// 4 + 5. cross-protocol bridge fidelity (see BRIDGE NOTE at top). a committed STOMP message is
	// consumed by the worker and republished, byte-for-byte, to mosquitto (MQTT QoS 1) and nats;
	// downstream subscribers on each broker must receive the exact same payload. audited to syslog.
	it('bridges a committed STOMP message to MQTT (qos 1) and NATS with byte-for-byte fidelity', async () => {
		const tag = uniqueId('br');
		const audit: string[] = [];

		await using log = await syslogConnect(syslogBase);
		const stage = async (event: string, message: string) => {
			audit.push(event);
			await log.log({
				severity: Severity.info,
				message: `${event} ${tag} ${message}`,
				structuredData: [{ id: 'msg@1', params: { event, tag } }]
			});
		};

		// a payload with non-ASCII + control bytes so "byte-for-byte" actually means something.
		const payload = enc(`bridge é\u{1f680}-${tag}`);

		await using stomp = await stompConnect(stompBase);
		await using mqtt = await mqttConnect(mqttBase);
		await using nats = await natsConnect(natsBase);

		const stompDest = `/queue/bridge.src.${tag}`;
		const mqttTopic = `bridge/out/${tag}`;
		const natsSubject = `bridge.out.${tag}`;

		// downstream consumers on the two SEPARATE target brokers, up before the bridge publishes.
		await using mqttSub = mqtt.subscribe(mqttTopic, { qos: 1 });
		await using natsSub = nats.subscribe(natsSubject);
		// the bridge's own consumer on the STOMP source queue.
		await using srcSub = stomp.subscribe(stompDest, { ack: 'client' });
		const readStomp = reader(srcSub);
		const readMqtt = reader(mqttSub);
		const readNats = reader(natsSub);
		await new Promise((r) => setTimeout(r, 400));

		// produce the source message transactionally so only a committed message is ever bridged.
		const tx = await stomp.begin();
		await tx.send(stompDest, payload, { contentType: 'application/octet-stream' });
		await tx.commit();
		await stage('source-committed', `dest=${stompDest} bytes=${payload.length}`);

		// --- the application-level bridge: consume committed STOMP -> republish to MQTT + NATS. ---
		const srcMsg = await readStomp(8000);
		expect(srcMsg, 'bridge did not consume the committed source message').not.toBeNull();
		expect(srcMsg!.body).toEqual(payload); // source bytes intact
		await srcMsg!.ack!();
		await stage('bridge-consumed', `message-id=${srcMsg!.messageId}`);

		// republish the exact bytes to both target brokers.
		await mqtt.publish(mqttTopic, srcMsg!.body, { qos: 1 }); // resolves on PUBACK (qos1 confirm)
		await stage('bridge-mqtt', `topic=${mqttTopic}`);
		await nats.publish(natsSubject, srcMsg!.body);
		await stage('bridge-nats', `subject=${natsSubject}`);

		// both downstream subscribers receive the identical payload, byte-for-byte.
		const mqttRecv = await readMqtt(8000);
		expect(mqttRecv, 'mqtt subscriber did not receive the bridged message').not.toBeNull();
		expect(mqttRecv!.topic).toBe(mqttTopic);
		expect(mqttRecv!.qos).toBe(1);
		expect(mqttRecv!.payload).toEqual(payload);

		const natsRecv = await readNats(8000);
		expect(natsRecv, 'nats subscriber did not receive the bridged message').not.toBeNull();
		expect(natsRecv!.subject).toBe(natsSubject);
		expect(natsRecv!.data).toEqual(payload);

		// fidelity across the whole bridge: source == mqtt == nats, byte-for-byte.
		expect(mqttRecv!.payload).toEqual(srcMsg!.body);
		expect(natsRecv!.data).toEqual(srcMsg!.body);
		expect(mqttRecv!.payload).toEqual(natsRecv!.data);
		await stage('bridged', `fidelity=ok`);

		// `await using` unsubscribes each sub on scope exit; do not unsubscribe again here (a second
		// STOMP UNSUBSCRIBE for a removed id is rejected by ActiveMQ).
		await log.close();

		// audit trail asserts the ordered bridge stages for this run.
		const captured = await waitFor(
			async () => {
				const text = await readSyslog();
				return audit.every((e) => text.includes(`${e} ${tag}`)) ? text : null;
			},
			15000,
			250
		);
		expect(captured, 'syslog audit trail missing a bridge stage for this tag').not.toBeNull();
		const text = captured!;
		const order = ['source-committed', 'bridge-consumed', 'bridge-mqtt', 'bridge-nats', 'bridged'];
		expect(audit).toEqual(order);
		let cursor = -1;
		for (const event of order) {
			const at = text.indexOf(`${event} ${tag}`, cursor + 1);
			expect(at, `stage ${event} missing or out of order`).toBeGreaterThan(cursor);
			cursor = at;
		}
	});
});
