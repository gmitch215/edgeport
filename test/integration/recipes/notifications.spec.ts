// recipe: a notification fan-out hub. a notification "core" publishes ONE event on a NATS
// subject; the Worker is the BRIDGE that forwards each event to THREE transports at once -
// WebSocket (the ws-echo box echoes the frame back, standing in for a browser client; there
// is no real ws pub/sub server), MQTT (QoS 1), and STOMP (a queue, subscriber acks client-side).
// every hop and delivery is audited to Syslog with a per-run unique id.
//
// the brokers are independent (NATS, mosquitto, ActiveMQ never talk to each other), so the
// fan-out is application code: the bridge reads NATS and re-publishes onto each transport. the
// tests assert byte-exact fidelity across transports, per-transport ordering, the per-protocol
// delivery semantics (NATS core has no ack, MQTT QoS 1 confirms on PUBACK, STOMP client-ack is
// settled with m.ack()), slow-consumer isolation (a stalled consumer on one transport does not
// stall the others), and the ordered syslog audit trail.
//
// ws note: the echo box has no pub/sub. we send each event as a frame and treat the echo as the
// "browser client received it" - the round-trip stands in for delivery to a subscribed client.
// stomp note: ActiveMQ wants /queue/<name>; client-ack means an un-acked message would be
// redelivered, so we ack and then assert no redelivery arrives.
import { describe, expect, it } from 'vitest';
import { connect as mqttConnect, type MqttSession } from '../../../src/mqtt/index';
import { connect as natsConnect } from '../../../src/nats/index';
import { connect as stompConnect, type StompSession } from '../../../src/stomp/index';
import {
	Facility,
	Severity,
	connect as syslogConnect,
	type SyslogSession
} from '../../../src/syslog/index';
import { connect as wsConnect, type WsConnection } from '../../../src/ws/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const HOST = '127.0.0.1';
const SYSLOG_PORT = 5514;
const WS_ECHO = 'ws://127.0.0.1:8081/.ws';

const natsBase = { hostname: HOST, port: 4222, username: 'tester', password: 'testpass' };
const mqttBase = { hostname: HOST, port: 1883 };
const stompBase = { hostname: HOST, port: 61613, login: 'admin', passcode: 'admin' };

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

// opens the plaintext syslog audit channel; Facility.local0 keeps these events self-labelling
function openSyslog(runId: string): Promise<SyslogSession> {
	return syslogConnect({ hostname: HOST, port: SYSLOG_PORT, appName: 'notify-hub', procId: runId });
}

// polls the syslog readback until every marker for this run is present, in the given order
async function waitForAudit(runId: string, markers: string[]): Promise<string | null> {
	return waitFor(
		async () => {
			const all = await readSyslog();
			// scope to this run so concurrent suites don't pollute the ordering check
			const mine = all
				.split('\n')
				.filter((line) => line.includes(runId))
				.join('\n');
			let from = 0;
			for (const m of markers) {
				const at = mine.indexOf(m, from);
				if (at < 0) return null;
				from = at + m.length;
			}
			return mine;
		},
		15_000,
		300
	);
}

// the bridge: forwards one event to all three transports at once and audits each hop. ws.send is
// sync (fire-and-forget); mqtt QoS 1 and stomp SEND are awaited so the hop reflects real progress.
async function fanOut(
	log: SyslogSession,
	runId: string,
	ws: WsConnection,
	mqtt: MqttSession,
	stomp: StompSession,
	mqttTopic: string,
	stompDest: string,
	event: string
): Promise<void> {
	ws.send(event);
	await Promise.all([mqtt.publish(mqttTopic, event, { qos: 1 }), stomp.send(stompDest, event)]);
	await log.log({
		severity: Severity.info,
		facility: Facility.local0,
		message: `bridge-hop ${runId} event=${event} -> ws,mqtt,stomp`
	});
}

describe('recipe: notification fan-out hub (NATS + WebSocket + MQTT + STOMP + Syslog)', () => {
	// 1+2. one event fans out to all three transports; every subscriber sees the SAME payload
	// byte-for-byte. the NATS core delivery drives the bridge; the bridge re-publishes onto each.
	it('fans one nats event out to ws + mqtt + stomp with byte-exact fidelity', async () => {
		const runId = uniqueId('nf-fid');
		await using log = await openSyslog(runId);
		await using nc = await natsConnect(natsBase);
		const ws = await wsConnect(WS_ECHO);
		await using mqtt = await mqttConnect({ ...mqttBase, clientId: uniqueId('mqtt') });
		await using stomp = await stompConnect(stompBase);

		const subject = `notify.${runId}`;
		const mqttTopic = `notify/${runId}`;
		const stompDest = `/queue/notify.${runId}`;
		const event = `event:${runId}:hello-world`;
		const wantBytes = enc(event);

		// stand up the three transport subscribers up front, then the bridge subscriber
		const wsIt = ws[Symbol.asyncIterator]();
		const mqttSub = mqtt.subscribe(mqttTopic, { qos: 1 });
		const mqttIt = mqttSub[Symbol.asyncIterator]();
		await using stompSub = stomp.subscribe(stompDest, { ack: 'client' });
		const stompIt = stompSub[Symbol.asyncIterator]();

		const bridgeSub = nc.subscribe(subject);
		// let SUBSCRIBE / SUB register on each broker before the core publishes
		await new Promise((r) => setTimeout(r, 400));

		// the bridge: one NATS event in, fan out to all three
		void (async () => {
			for await (const m of bridgeSub) {
				await fanOut(log, runId, ws, mqtt, stomp, mqttTopic, stompDest, dec(m.data));
				break; // single event for this test
			}
		})();

		// the notification core publishes ONE event
		await nc.publish(subject, event);

		// ws delivery: scan a few frames (the echo box may greet first)
		const wsGot = await waitFor(
			async () => {
				for (let i = 0; i < 6; i++) {
					const { value, done } = await wsIt.next();
					if (done || !value) return null;
					if (value.type === 'text' && value.data === event) return value.data;
					if (value.type === 'binary' && dec(value.data) === event) return dec(value.data);
				}
				return null;
			},
			10_000,
			100
		);
		expect(wsGot, 'ws client should receive the event').toBe(event);

		const mqttMsg = await mqttIt.next();
		expect(mqttMsg.done).toBe(false);
		expect(mqttMsg.value!.payload).toEqual(wantBytes); // byte-exact
		expect(mqttMsg.value!.qos).toBe(1);

		const stompMsg = await stompIt.next();
		expect(stompMsg.done).toBe(false);
		expect(stompMsg.value!.body).toEqual(wantBytes); // byte-exact
		await stompMsg.value!.ack!(); // client-ack settles it

		const audit = await waitForAudit(runId, [`bridge-hop ${runId}`]);
		expect(audit, 'the bridge hop should be audited').not.toBeNull();

		ws.close(1000, 'done');
		await mqttSub.unsubscribe();
	});

	// 3. ordering: a burst of N events; each transport receives them IN ORDER (per-transport
	// ordering preserved). the single writer per transport keeps publish order intact.
	it('preserves per-transport ordering across a burst of events', async () => {
		const runId = uniqueId('nf-ord');
		await using log = await openSyslog(runId);
		await using nc = await natsConnect(natsBase);
		const ws = await wsConnect(WS_ECHO);
		await using mqtt = await mqttConnect({ ...mqttBase, clientId: uniqueId('mqtt') });
		await using stomp = await stompConnect(stompBase);

		const subject = `notify.${runId}`;
		const mqttTopic = `notify/${runId}`;
		const stompDest = `/queue/notify.${runId}`;
		const N = 12;

		const wsIt = ws[Symbol.asyncIterator]();
		const mqttSub = mqtt.subscribe(mqttTopic, { qos: 1 });
		await using stompSub = stomp.subscribe(stompDest, { ack: 'client' });

		const wsGot: number[] = [];
		const mqttGot: number[] = [];
		const stompGot: number[] = [];

		// each transport collector records arrival order; ws filters to our own event frames
		const wsDone = (async () => {
			while (wsGot.length < N) {
				const { value, done } = await wsIt.next();
				if (done || !value) break;
				const text = value.type === 'text' ? value.data : dec(value.data);
				const m = /^evt:(\d+)$/.exec(text);
				if (m) wsGot.push(Number(m[1]));
			}
		})();
		const mqttDone = (async () => {
			for await (const msg of mqttSub) {
				mqttGot.push(Number(dec(msg.payload).slice(4)));
				if (mqttGot.length >= N) break;
			}
		})();
		const stompDone = (async () => {
			for await (const msg of stompSub) {
				stompGot.push(Number(dec(msg.body).slice(4)));
				await msg.ack!();
				if (stompGot.length >= N) break;
			}
		})();

		// the bridge forwards every NATS event to all three transports, in order
		const bridgeSub = nc.subscribe(subject);
		await new Promise((r) => setTimeout(r, 400));
		const bridgeDone = (async () => {
			let seen = 0;
			for await (const m of bridgeSub) {
				await fanOut(log, runId, ws, mqtt, stomp, mqttTopic, stompDest, dec(m.data));
				if (++seen >= N) break;
			}
		})();

		// the core publishes the burst in order
		for (let i = 0; i < N; i++) await nc.publish(subject, `evt:${i}`);
		await bridgeDone;

		const order = [...Array(N).keys()];
		await waitFor(() => wsGot.length >= N, 10_000, 50);
		await waitFor(() => mqttGot.length >= N, 10_000, 50);
		await waitFor(() => stompGot.length >= N, 10_000, 50);

		expect(wsGot, 'ws receives all events in publish order').toEqual(order);
		expect(mqttGot, 'mqtt receives all events in publish order').toEqual(order);
		expect(stompGot, 'stomp receives all events in publish order').toEqual(order);

		ws.close(1000, 'done');
		await mqttSub.unsubscribe();
		await Promise.allSettled([wsDone, mqttDone, stompDone]);
	});

	// 4. per-protocol ack/QoS mapping. NATS core: fire-and-forget (no ack frame). MQTT QoS 1:
	// publish() resolves on PUBACK (broker confirmation). STOMP client-ack: settle with m.ack(),
	// then assert the acked message is NOT redelivered (the decisive client-ack semantic).
	it('honors per-protocol delivery semantics (nats core, mqtt qos1, stomp client-ack)', async () => {
		const runId = uniqueId('nf-ack');
		await using log = await openSyslog(runId);
		await using nc = await natsConnect(natsBase);
		await using mqtt = await mqttConnect({ ...mqttBase, clientId: uniqueId('mqtt') });
		await using stomp = await stompConnect(stompBase);

		const subject = `notify.${runId}`;
		const mqttTopic = `notify/${runId}`;
		const stompDest = `/queue/notify.${runId}`;
		const event = `event:${runId}:ack-check`;

		// NATS core: publish() has no ack; it resolves once the PUB frame is written. delivery is
		// proven by the subscriber actually receiving the event below, not by an ack.
		const natsSub = nc.subscribe(subject);
		const natsIt = natsSub[Symbol.asyncIterator]();

		const mqttSub = mqtt.subscribe(mqttTopic, { qos: 1 });
		const mqttIt = mqttSub[Symbol.asyncIterator]();

		await using stompSub = stomp.subscribe(stompDest, { ack: 'client' });
		const stompIt = stompSub[Symbol.asyncIterator]();

		await new Promise((r) => setTimeout(r, 400));

		await nc.publish(subject, event); // core delivery
		const natsMsg = await natsIt.next();
		expect(natsMsg.done).toBe(false);
		expect(dec(natsMsg.value!.data)).toBe(event);
		await log.log({
			severity: Severity.info,
			facility: Facility.local0,
			message: `delivered-nats ${runId}`
		});
		await natsSub.unsubscribe();

		// MQTT QoS 1: the publish promise resolving IS the PUBACK confirmation
		await mqtt.publish(mqttTopic, event, { qos: 1 });
		const mqttMsg = await mqttIt.next();
		expect(mqttMsg.done).toBe(false);
		expect(mqttMsg.value!.qos).toBe(1);
		expect(dec(mqttMsg.value!.payload)).toBe(event);
		await log.log({
			severity: Severity.info,
			facility: Facility.local0,
			message: `delivered-mqtt ${runId}`
		});
		await mqttSub.unsubscribe();

		// STOMP client-ack: deliver, ack, then assert NO redelivery. an un-acked client-ack message
		// would be redelivered by ActiveMQ on the same subscription; acking suppresses that.
		await stomp.send(stompDest, event);
		const stompMsg = await stompIt.next();
		expect(stompMsg.done).toBe(false);
		expect(dec(stompMsg.value!.body)).toBe(event);
		expect(typeof stompMsg.value!.ack).toBe('function'); // client-ack exposes ack()
		await stompMsg.value!.ack!();
		await log.log({
			severity: Severity.info,
			facility: Facility.local0,
			message: `delivered-stomp ${runId}`
		});

		// no redelivery: race the next iterator step against a short timeout; nothing should arrive
		const redelivered = await Promise.race([
			stompIt.next().then((r) => (r.done ? false : dec(r.value.body))),
			new Promise<false>((r) => setTimeout(() => r(false), 1500))
		]);
		expect(redelivered, 'acked stomp message must not be redelivered').toBe(false);

		const audit = await waitForAudit(runId, [
			`delivered-nats ${runId}`,
			`delivered-mqtt ${runId}`,
			`delivered-stomp ${runId}`
		]);
		expect(audit, 'each transport delivery should be audited in order').not.toBeNull();
	});

	// 5. slow-consumer isolation: make ONE transport's consumer slow (delay draining its iterator)
	// and assert the OTHER two still receive all their events promptly. a slow consumer on one
	// transport does not stall the others, because each transport has its own buffered queue.
	it('isolates a slow consumer so the other transports are not stalled', async () => {
		const runId = uniqueId('nf-slow');
		await using log = await openSyslog(runId);
		await using nc = await natsConnect(natsBase);
		const ws = await wsConnect(WS_ECHO);
		await using mqtt = await mqttConnect({ ...mqttBase, clientId: uniqueId('mqtt') });
		await using stomp = await stompConnect(stompBase);

		const subject = `notify.${runId}`;
		const mqttTopic = `notify/${runId}`;
		const stompDest = `/queue/notify.${runId}`;
		const N = 8;

		const wsIt = ws[Symbol.asyncIterator]();
		const mqttSub = mqtt.subscribe(mqttTopic, { qos: 1 });
		await using stompSub = stomp.subscribe(stompDest, { ack: 'client' });

		const mqttGot: number[] = [];
		const stompGot: number[] = [];
		const wsGot: number[] = [];

		// mqtt and stomp drain promptly (the fast consumers)
		const mqttDone = (async () => {
			for await (const msg of mqttSub) {
				mqttGot.push(Number(dec(msg.payload).slice(4)));
				if (mqttGot.length >= N) break;
			}
		})();
		const stompDone = (async () => {
			for await (const msg of stompSub) {
				stompGot.push(Number(dec(msg.body).slice(4)));
				await msg.ack!();
				if (stompGot.length >= N) break;
			}
		})();
		// the WS consumer is SLOW: it sleeps before pulling each frame. its events buffer in the
		// connection's queue and are read late; the other transports must not wait on it.
		const wsDone = (async () => {
			while (wsGot.length < N) {
				await new Promise((r) => setTimeout(r, 400)); // the deliberate slow drain
				const { value, done } = await wsIt.next();
				if (done || !value) break;
				const text = value.type === 'text' ? value.data : dec(value.data);
				const m = /^evt:(\d+)$/.exec(text);
				if (m) wsGot.push(Number(m[1]));
			}
		})();

		const bridgeSub = nc.subscribe(subject);
		await new Promise((r) => setTimeout(r, 400));
		const bridgeDone = (async () => {
			let seen = 0;
			for await (const m of bridgeSub) {
				await fanOut(log, runId, ws, mqtt, stomp, mqttTopic, stompDest, dec(m.data));
				if (++seen >= N) break;
			}
		})();

		const t0 = performance.now();
		for (let i = 0; i < N; i++) await nc.publish(subject, `evt:${i}`);
		await bridgeDone;

		// the fast transports must complete WELL BEFORE the slow ws consumer could (N*400ms ~= 3.2s).
		// give them a generous bound but one that the slow drain cannot meet.
		const fastReady = await waitFor(() => mqttGot.length >= N && stompGot.length >= N, 6000, 25);
		const elapsed = performance.now() - t0;
		expect(fastReady, 'mqtt + stomp must drain despite the slow ws consumer').not.toBeNull();
		expect(mqttGot.length, 'mqtt got every event').toBe(N);
		expect(stompGot.length, 'stomp got every event').toBe(N);
		// the slow consumer would need ~N*400ms; the fast ones finished before that floor
		expect(elapsed, 'fast transports were not stalled by the slow consumer').toBeLessThan(N * 400);

		await log.log({
			severity: Severity.notice,
			facility: Facility.local0,
			message: `slow-isolated ${runId} fastMs=${Math.round(elapsed)} mqtt=${mqttGot.length} stomp=${stompGot.length}`
		});

		// the slow consumer still eventually receives everything (isolated, not dropped)
		await waitFor(() => wsGot.length >= N, 10_000, 100);
		expect(wsGot.length, 'the slow ws consumer eventually got every event too').toBe(N);

		const audit = await waitForAudit(runId, [`slow-isolated ${runId}`]);
		expect(audit, 'the slow-consumer isolation outcome should be audited').not.toBeNull();

		ws.close(1000, 'done');
		await mqttSub.unsubscribe();
		await Promise.allSettled([mqttDone, stompDone, wsDone]);
	});

	// 6. audit: a full lifecycle logs each bridge hop + delivery to Syslog with the unique id, and
	// the readback shows the per-transport delivery trail in order.
	it('writes a per-transport delivery audit trail to syslog', async () => {
		const runId = uniqueId('nf-audit');
		await using log = await openSyslog(runId);
		await using nc = await natsConnect(natsBase);
		const ws = await wsConnect(WS_ECHO);
		await using mqtt = await mqttConnect({ ...mqttBase, clientId: uniqueId('mqtt') });
		await using stomp = await stompConnect(stompBase);

		const subject = `notify.${runId}`;
		const mqttTopic = `notify/${runId}`;
		const stompDest = `/queue/notify.${runId}`;
		const event = `event:${runId}:audit`;
		const wantBytes = enc(event);

		const wsIt = ws[Symbol.asyncIterator]();
		const mqttSub = mqtt.subscribe(mqttTopic, { qos: 1 });
		const mqttIt = mqttSub[Symbol.asyncIterator]();
		await using stompSub = stomp.subscribe(stompDest, { ack: 'client' });
		const stompIt = stompSub[Symbol.asyncIterator]();

		const bridgeSub = nc.subscribe(subject);
		await new Promise((r) => setTimeout(r, 400));

		// bridge with a per-transport delivery audit after each subscriber confirms receipt
		void (async () => {
			for await (const m of bridgeSub) {
				const ev = dec(m.data);
				// log the hop FIRST: it marks "bridge received, fanning out", so it always precedes
				// any per-transport delivery confirmation (those are logged by the receivers below)
				await log.log({
					severity: Severity.info,
					facility: Facility.local0,
					message: `bridge-hop ${runId} event=${ev}`
				});
				ws.send(ev);
				await mqtt.publish(mqttTopic, ev, { qos: 1 });
				await stomp.send(stompDest, ev);
				break;
			}
		})();

		await nc.publish(subject, event);

		// each transport receiver logs its own delivery as it confirms
		const wsGot = await waitFor(
			async () => {
				for (let i = 0; i < 6; i++) {
					const { value, done } = await wsIt.next();
					if (done || !value) return null;
					const text = value.type === 'text' ? value.data : dec(value.data);
					if (text === event) return text;
				}
				return null;
			},
			10_000,
			100
		);
		expect(wsGot).toBe(event);
		await log.log({
			severity: Severity.info,
			facility: Facility.local0,
			message: `deliver-ws ${runId}`
		});

		const mqttMsg = await mqttIt.next();
		expect(mqttMsg.value!.payload).toEqual(wantBytes);
		await log.log({
			severity: Severity.info,
			facility: Facility.local0,
			message: `deliver-mqtt ${runId}`
		});

		const stompMsg = await stompIt.next();
		expect(stompMsg.value!.body).toEqual(wantBytes);
		await stompMsg.value!.ack!();
		await log.log({
			severity: Severity.info,
			facility: Facility.local0,
			message: `deliver-stomp ${runId}`
		});

		// the audit must show: bridge hop, then each transport delivery, all tied to this run id
		const audit = await waitForAudit(runId, [
			`bridge-hop ${runId}`,
			`deliver-ws ${runId}`,
			`deliver-mqtt ${runId}`,
			`deliver-stomp ${runId}`
		]);
		expect(audit, 'the full per-transport delivery trail should be in syslog').not.toBeNull();
		expect(audit!).toContain(`deliver-ws ${runId}`);
		expect(audit!).toContain(`deliver-mqtt ${runId}`);
		expect(audit!).toContain(`deliver-stomp ${runId}`);

		ws.close(1000, 'done');
		await mqttSub.unsubscribe();
	});
});
