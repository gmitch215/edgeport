// recipe: HL7 interface/integration engine. a lab drops an HL7 batch file via FTP; the engine
// ingests it, parses HL7 messages/segments, archives the batch to SFTP, republishes each parsed
// event to two downstream consumers (MQTT for one EHR feed, STOMP for another), the STOMP EHR
// subscriber ACKs delivery (client ack), and every stage is written to a Syslog audit trail.
//
// ADAPTATION: the classic interface-engine recipe uses FTPS for the lab drop, but edgeport does
// not support FTPS - the Workers runtime's startTls cannot reuse the FTP control-channel TLS
// session, so FTPS was dropped from v1. we use plaintext edgeport/ftp here; a real PHI deployment
// would tunnel this over a VPN/private link or use SFTP exclusively.
import { describe, expect, it } from 'vitest';
import { connect as ftpConnect } from '../../../src/ftp/index';
import { connect as mqttConnect } from '../../../src/mqtt/index';
import { connect as sftpConnect } from '../../../src/sftp/index';
import { connect as stompConnect, type StompMessage } from '../../../src/stomp/index';
import { Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

const ftpBase = { hostname: '127.0.0.1', port: 21, username: 'tester', password: 'testpass' };
const sftpBase = { hostname: '127.0.0.1', port: 2222, username: 'tester', password: 'testpass' };
const mqttBase = { hostname: '127.0.0.1', port: 1883 };
const stompBase = { hostname: '127.0.0.1', port: 61613, login: 'admin', passcode: 'admin' };

// CR is the HL7 segment separator; messages in a batch are separated by a blank line (CR CR).
const CR = '\r';
const MSG_SEP = '\r\r';

// one synthesized HL7 v2 message: MSH, PID (carries the patient id), one OBX observation.
function hl7Message(controlId: string, patientId: string, value: string): string {
	return [
		`MSH|^~\\&|LAB|HOSP|EHR|HOSP|20260629||ORU^R01|${controlId}|P|2.5`,
		`PID|1||${patientId}^^^HOSP^MR||DOE^JOHN||19800101|M`,
		`OBX|1|NM|GLU^Glucose||${value}|mg/dL|70_110|N|||F`
	].join(CR);
}

// a parsed HL7 message: its segments split on CR, plus the fields we route on.
interface ParsedHl7 {
	segments: string[];
	controlId: string;
	patientId: string;
	valid: boolean;
}

// parses one HL7 message: split on CR into segments, pull MSH-10 (control id) and PID-3 (patient
// id). a message missing its MSH or PID segment is marked invalid rather than throwing, so one bad
// message in a batch never crashes the engine.
function parseHl7(message: string): ParsedHl7 {
	const segments = message.split(CR).filter((s) => s.length > 0);
	const msh = segments.find((s) => s.startsWith('MSH|'));
	const pid = segments.find((s) => s.startsWith('PID|'));
	if (!msh || !pid) return { segments, controlId: '', patientId: '', valid: false };
	const mshFields = msh.split('|');
	const pidFields = pid.split('|');
	// MSH-10 is the message control id; note MSH-1 is the field separator itself, so MSH-10 is
	// index 9 counting the "MSH" token as field 0.
	const controlId = mshFields[9] ?? '';
	// PID-3 is the patient identifier list; take the first component before the first '^'.
	const patientId = (pidFields[3] ?? '').split('^')[0] ?? '';
	return { segments, controlId, patientId, valid: controlId.length > 0 && patientId.length > 0 };
}

// splits an HL7 batch file into individual messages on the blank-line convention.
function splitBatch(batch: string): string[] {
	return batch
		.split(MSG_SEP)
		.map((m) => m.trim())
		.filter((m) => m.length > 0);
}

// reads the first STOMP message off a subscription, or null if none arrives before the deadline.
async function firstMessage(
	sub: AsyncIterable<StompMessage>,
	timeoutMs = 8000
): Promise<StompMessage | null> {
	const iter = sub[Symbol.asyncIterator]();
	const timeout = new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs));
	const next = iter.next().then((r) => (r.done ? null : r.value));
	return Promise.race([next, timeout]);
}

describe('hl7 integration engine (ftp + sftp + mqtt + stomp + syslog)', () => {
	it('ingests an HL7 batch, parses it, fans out to mqtt + stomp, acks, and audits every stage', async () => {
		const tag = uniqueId('hl7');
		const audit: string[] = [];

		// open the syslog audit channel first; the engine logs every stage with the unique tag.
		await using log = await syslogConnect({
			hostname: '127.0.0.1',
			port: 5514,
			tls: 'off',
			appName: 'hl7-engine',
			framing: 'lf'
		});
		const stage = async (event: string, message: string, severity = Severity.info) => {
			const line = `${event} ${tag} ${message}`;
			audit.push(event);
			await log.log({
				severity,
				message: line,
				structuredData: [{ id: 'hl7@1', params: { event, tag } }]
			});
		};

		// synthesize a small batch of 3 well-formed messages + 1 malformed (missing PID).
		const patients = [`P${tag}-A`, `P${tag}-B`, `P${tag}-C`];
		const messages = [
			hl7Message(`${tag}-1`, patients[0]!, '95'),
			hl7Message(`${tag}-2`, patients[1]!, '102'),
			hl7Message(`${tag}-3`, patients[2]!, '88')
		];
		// malformed: an MSH with no PID segment - the engine must log+skip, not crash.
		const malformed = [
			`MSH|^~\\&|LAB|HOSP|EHR|HOSP|20260629||ORU^R01|${tag}-BAD|P|2.5`,
			`OBX|1|NM|GLU||0||||F`
		].join(CR);
		const batchText = [...messages, malformed].join(MSG_SEP);
		const batchBytes = enc(batchText);
		const fileName = `lab-batch-${tag}.hl7`;

		// 1. lab drops the HL7 batch file via FTP (plaintext; see ADAPTATION note above).
		{
			await using ftp = await ftpConnect(ftpBase);
			await ftp.put(fileName, batchBytes);
			const size = await ftp.size(fileName);
			expect(size).toBe(batchBytes.length);
		}
		await stage('received-batch', `file=${fileName} bytes=${batchBytes.length}`);

		// 2. integration engine ingests: FTP get the file back and parse it into messages/segments.
		let fetched: Uint8Array;
		{
			await using ftp = await ftpConnect(ftpBase);
			fetched = await ftp.get(fileName);
		}
		expect(dec(fetched)).toBe(batchText);

		const rawMessages = splitBatch(dec(fetched));
		expect(rawMessages.length).toBe(4); // 3 valid + 1 malformed
		const parsed = rawMessages.map(parseHl7);
		const valid = parsed.filter((p) => p.valid);
		const invalid = parsed.filter((p) => !p.valid);

		// parse recovered the expected count and the PID field of the first message.
		expect(valid.length).toBe(3);
		expect(invalid.length).toBe(1);
		expect(valid[0]!.patientId).toBe(patients[0]);
		expect(valid[0]!.segments).toContain(`PID|1||${patients[0]}^^^HOSP^MR||DOE^JOHN||19800101|M`);
		await stage('parsed', `valid=${valid.length} invalid=${invalid.length}`);

		// 6a. edge case: the malformed message is logged as an error, not crashed on.
		expect(invalid[0]!.controlId).toBe('');
		await stage('parse-error', `malformed segment skipped`, Severity.error);

		// archive the original batch to SFTP (a second file transport in the flow; durable copy of
		// the source-of-truth before downstream fan-out).
		const archivePath = `/config/archive-${tag}.hl7`;
		{
			await using sftp = await sftpConnect(sftpBase);
			await sftp.writeFile(archivePath, batchBytes);
			const st = await sftp.stat(archivePath);
			expect(st.size).toBe(batchBytes.length);
			const back = await sftp.readFile(archivePath);
			expect(back).toEqual(batchBytes); // byte-exact archive
		}

		// the event we fan out: the first parsed message, as a compact JSON envelope.
		const event = valid[0]!;
		const envelope = JSON.stringify({
			tag,
			controlId: event.controlId,
			patientId: event.patientId,
			segments: event.segments.length
		});
		const mqttTopic = `hl7/adt/${tag}`;
		const stompDest = `/queue/hl7.${tag}`;

		// 3 + 4. fan out to two different downstream consumers and have the EHR (STOMP) subscriber
		// ACK delivery. set up both subscribers BEFORE publishing so neither misses the message.
		await using mqtt = await mqttConnect(mqttBase);
		await using stomp = await stompConnect(stompBase);

		await using mqttSub = mqtt.subscribe(mqttTopic, { qos: 1 });
		const stompSub = stomp.subscribe(stompDest, { ack: 'client' });
		// give the brokers a moment to register the subscriptions before publishing.
		await new Promise((r) => setTimeout(r, 300));

		// publish to MQTT (consumer 1: real-time ADT feed).
		await mqtt.publish(mqttTopic, envelope, { qos: 1 });
		await stage('published-mqtt', `topic=${mqttTopic}`);

		// send to STOMP (consumer 2: the EHR queue).
		await stomp.send(stompDest, envelope, { contentType: 'application/json' });
		await stage('published-stomp', `dest=${stompDest}`);

		// MQTT subscriber receives its copy.
		const mqttIter = mqttSub[Symbol.asyncIterator]();
		const mqttRecv = await Promise.race([
			mqttIter.next().then((r) => (r.done ? null : r.value)),
			new Promise<null>((resolve) => setTimeout(() => resolve(null), 8000))
		]);
		expect(mqttRecv, 'mqtt subscriber did not receive the event').not.toBeNull();
		expect(mqttRecv!.topic).toBe(mqttTopic);
		expect(dec(mqttRecv!.payload)).toBe(envelope);

		// STOMP EHR subscriber receives + ACKs (client ack mode).
		const stompRecv = await firstMessage(stompSub);
		expect(stompRecv, 'stomp subscriber did not receive the event').not.toBeNull();
		expect(dec(stompRecv!.body)).toBe(envelope);
		expect(stompRecv!.ack, 'client-ack message must expose ack()').toBeTypeOf('function');
		await stompRecv!.ack!();
		await stage('acked', `message-id=${stompRecv!.messageId}`);

		// 4 (cont). transactional ack semantics: a fresh subscription to the same queue must NOT
		// redeliver the already-acked message (ack settled it off the queue).
		await using stompSub2 = stomp.subscribe(stompDest, { ack: 'client' });
		const redelivered = await firstMessage(stompSub2, 2500);
		expect(redelivered, 'an acked message must not be redelivered').toBeNull();

		await stompSub.unsubscribe();

		// 5. full audit trail to syslog. close the syslog socket so the sink flushes the file,
		// then read it back and assert the ordered stages are all present for this tag.
		await log.close();

		const captured = await waitFor(
			async () => {
				const text = await readSyslog();
				// every stage line carries the tag; wait until all of them have landed.
				const haveAll = audit.every((event) => text.includes(`${event} ${tag}`));
				return haveAll ? text : null;
			},
			15000,
			250
		);
		expect(captured, 'syslog audit trail did not contain every stage for this tag').not.toBeNull();
		const text = captured!;

		// the full ordered audit trail is present, in order, for this run.
		const expectedOrder = [
			'received-batch',
			'parsed',
			'parse-error',
			'published-mqtt',
			'published-stomp',
			'acked'
		];
		expect(audit).toEqual(expectedOrder);
		let cursor = -1;
		for (const event of expectedOrder) {
			const at = text.indexOf(`${event} ${tag}`, cursor + 1);
			expect(at, `stage ${event} missing or out of order in audit trail`).toBeGreaterThan(cursor);
			cursor = at;
		}
		// the structured-data audit element rendered on the wire with the tag.
		expect(text).toContain(`[hl7@1 event=`);
		expect(text).toContain(`tag="${tag}"`);
		// the error-severity parse-error line: PRI for user.error = <11>.
		expect(text).toContain('<11>1 ');
	});

	it('handles a fully malformed batch without crashing the parser', async () => {
		// a batch where no message has both MSH and PID: every message is invalid, none routed.
		const garbage = ['not-an-hl7-line', 'PID|1||orphan', 'MSH|^~\\&|only-msh'].join('\r\r');
		const parsed = splitBatch(garbage).map(parseHl7);
		expect(parsed.length).toBe(3);
		expect(parsed.every((p) => !p.valid)).toBe(true);
		// parsing never threw; the engine would log each as a parse-error and skip it.
	});
});
