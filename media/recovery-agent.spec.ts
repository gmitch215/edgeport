// recipe: IoT edge-device fleet management loop across four protocols.
// MQTT for telemetry + LWT offline detection; SSH to reach the flagged device; SFTP for a
// firmware push with a sha256 integrity check + resume-on-drop; SSH again to apply/restart;
// Syslog to confirm the new version booted. exercises ssh + sftp + mqtt + syslog end to end.
import { expect, it } from 'vitest';
import { connect as mqttConnect } from '../../../src/mqtt/index';
import { connect as sftpConnect } from '../../../src/sftp/index';
import { connect as sshConnect } from '../../../src/ssh/index';
import { Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { artifact, readSyslog, uniqueId, waitFor } from './_helpers';

const ssh = { hostname: '127.0.0.1', port: 2222, username: 'tester', password: 'testpass' };
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

// lowercase hex sha256 of `data`, matching the format `sha256sum` prints on the device
async function sha256Hex(data: Uint8Array): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', data.slice());
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// the mqtt broker (mosquitto) is anonymous plaintext on 1883; caller supplies per-client overrides
type MqttOverrides = Omit<Parameters<typeof mqttConnect>[0], 'hostname' | 'port' | 'tls'>;
async function openMqtt(opts: MqttOverrides) {
	return mqttConnect({ hostname: '127.0.0.1', port: 1883, tls: 'off', ...opts });
}

// the syslog sink is a plaintext capture on 5514; readback via readSyslog()
async function openSyslog() {
	return syslogConnect({ hostname: '127.0.0.1', port: 5514, tls: 'off', appName: 'edge-device' });
}

it('runs the full IoT edge ops loop: telemetry+LWT, ssh, sftp firmware push w/ checksum+resume, apply, syslog confirm', async () => {
	const tag = uniqueId('iot');
	const deviceId = `dev-${tag}`;
	const version = `fw-1.4.2-${tag}`;
	const statusTopic = `devices/${deviceId}/status`;
	const telemetryTopic = `devices/${deviceId}/telemetry`;

	// ---- 1. telemetry + LWT-based offline detection over MQTT ----
	// the fleet controller subscribes to both this device's status and telemetry topics first,
	// so it sees every health message and, later, the broker-published will.
	await using fleet = await openMqtt({ clientId: `fleet-${tag}` });
	await using statusSub = fleet.subscribe(statusTopic, { qos: 1 });
	await using telemetrySub = fleet.subscribe(telemetryTopic, { qos: 1 });

	// collect inbound messages off both subscriptions in the background
	const telemetrySeen: string[] = [];
	const statusSeen: string[] = [];
	const telemetryPump = (async () => {
		for await (const m of telemetrySub) telemetrySeen.push(dec(m.payload));
	})();
	const statusPump = (async () => {
		for await (const m of statusSub) statusSeen.push(dec(m.payload));
	})();

	// the device connects with a Last Will; an unclean drop makes the broker publish 'offline'
	const device = await openMqtt({
		clientId: deviceId,
		keepAliveSeconds: 0, // no background pings; this test drives everything explicitly
		will: { topic: statusTopic, payload: 'offline', qos: 1 }
	});

	// device announces itself online, then publishes a few QoS1 health/telemetry messages
	await device.publish(statusTopic, 'online', { qos: 1 });
	const telemetry = ['cpu=12;mem=40', 'cpu=18;mem=42', 'cpu=91;mem=88']; // last one looks unhealthy
	for (const t of telemetry) await device.publish(telemetryTopic, t, { qos: 1 });

	// the fleet controller should receive all three telemetry messages (poll; delivery is async)
	const gotTelemetry = await waitFor(() => telemetrySeen.length >= telemetry.length);
	expect(gotTelemetry, 'fleet did not receive all telemetry messages').toBe(true);
	for (const t of telemetry) expect(telemetrySeen).toContain(t);
	expect(statusSeen).toContain('online');

	// the device drops uncleanly (no DISCONNECT) -> broker fires the Last Will -> 'offline'
	await device.close({ graceful: false });
	const wentOffline = await waitFor(() => statusSeen.includes('offline'), 15000, 200);
	expect(wentOffline, 'LWT offline message was never delivered to the fleet').toBe(true);

	// ---- 2. operator SSHs into the flagged device and reads identity ----
	await using session = await sshConnect(ssh);
	const uname = await session.exec('uname -a');
	expect(uname.code).toBe(0);
	expect(dec(uname.stdout).toLowerCase()).toContain('linux');
	const host = await session.exec('cat /etc/hostname');
	expect(host.code).toBe(0);
	expect(dec(host.stdout).trim().length).toBeGreaterThan(0);

	// ---- 3. firmware push over SFTP with a sha256 integrity check ----
	const firmware = artifact(80_000);
	const expectedHash = await sha256Hex(firmware);
	const remotePath = `/config/firmware-${tag}.bin`;

	// reuse the open ssh session for sftp so the whole ops loop runs over one connection
	await using sftp = await sftpConnect({ session });
	await sftp.writeFile(remotePath, firmware);

	const uploaded = await sftp.stat(remotePath);
	expect(uploaded.size).toBe(firmware.length);

	// verify integrity: the device computes sha256sum, compare to the in-test digest
	const sumOut = await session.exec(`sha256sum ${remotePath}`);
	expect(sumOut.code).toBe(0);
	const deviceHash = dec(sumOut.stdout).trim().split(/\s+/)[0];
	expect(deviceHash).toBe(expectedHash);

	// ---- 3b. resume-on-drop: simulate a half-uploaded firmware, then resume at the offset ----
	const resumePath = `/config/firmware-resume-${tag}.bin`;
	const half = Math.floor(firmware.length / 2);

	// first leg: only the first half lands (the "connection dropped" mid-transfer)
	await sftp.writeFile(resumePath, firmware.subarray(0, half));
	const partial = await sftp.stat(resumePath);
	expect(partial.size).toBe(half);

	// resume from the partial size without truncating; write the remaining bytes at that offset
	await sftp.writeFile(resumePath, firmware.subarray(partial.size), { offset: partial.size });
	const resumed = await sftp.stat(resumePath);
	expect(resumed.size).toBe(firmware.length);

	// re-verify the resumed file matches byte-for-byte via the same checksum
	const resumeSum = await session.exec(`sha256sum ${resumePath}`);
	expect(resumeSum.code).toBe(0);
	expect(dec(resumeSum.stdout).trim().split(/\s+/)[0]).toBe(expectedHash);

	// ---- 4. apply + restart (simulated), assert success exit code ----
	const apply = await session.exec(`echo applied ${version} && true`);
	expect(apply.code).toBe(0);
	expect(dec(apply.stdout)).toContain(`applied ${version}`);

	// ---- 5. the device confirms the new version + reboot over syslog, in order ----
	{
		await using log = await openSyslog();
		await log.log({
			severity: Severity.notice,
			message: `firmware applied ${version} [${tag}]`,
			structuredData: [{ id: 'fw@1', params: { version, sha256: expectedHash } }]
		});
		await log.log({ severity: Severity.warning, message: `rebooting [${tag}]` });
	}

	// poll the readback until both tagged lines are captured
	const captured = await waitFor(
		async () => {
			const text = await readSyslog();
			return text.includes(`firmware applied ${version} [${tag}]`) &&
				text.includes(`rebooting [${tag}]`)
				? text
				: null;
		},
		15000,
		250
	);
	expect(captured, 'syslog confirmation lines were not captured').not.toBeNull();
	const text = captured!;

	// ordering: 'firmware applied' must appear before 'rebooting'
	const appliedAt = text.indexOf(`firmware applied ${version} [${tag}]`);
	const rebootAt = text.indexOf(`rebooting [${tag}]`);
	expect(appliedAt).toBeGreaterThanOrEqual(0);
	expect(rebootAt).toBeGreaterThan(appliedAt);

	// the structured-data element carried the version + the verified checksum
	expect(text).toContain(`version="${version}"`);
	expect(text).toContain(`sha256="${expectedHash}"`);

	// cleanup remote artifacts; the loop is done
	await sftp.remove(remotePath).catch(() => {});
	await sftp.remove(resumePath).catch(() => {});

	// drain the fleet subscription pumps (unsubscribe ends the iterators on dispose)
	await statusSub.unsubscribe();
	await telemetrySub.unsubscribe();
	await Promise.all([telemetryPump, statusPump]);
});
