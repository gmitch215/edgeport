// recipe: a credential-protecting auth gateway over LDAPS (LDAPS + SSH/SFTP + Syslog).
//
// the pattern: a Workers auth gateway must verify a user's credentials against the directory
// WITHOUT ever putting that password on the wire in cleartext. so the identity leg runs over
// LDAPS (implicit TLS, port 636), not plain LDAP. once the directory confirms the user, the
// gateway runs the downstream privileged action (an SSH exec + an SFTP transfer) and audits
// every step to Syslog. the security property under test is fail-closed: if the directory's
// TLS cannot be trusted, the bind never happens and the credential is never sent.
//
// =====================================================================================
// WORKERD LIMITATIONS (confirmed locally; why the LDAPS leg is asserted as a fail-closed gate
// rather than a happy-path bind):
//
//  1. workerd VALIDATES outbound TLS certificates and REJECTS untrusted ones. the dockerized
//     openldap on 636 serves a self-signed + expired + hostname-mismatched cert, so an LDAPS
//     connect FAILS CLOSED with a ConnectionError ("failed to open 127.0.0.1:636") - the TLS
//     handshake fails before any LDAP bind is sent. this is the correct security behavior, so
//     the tests assert the fail-closed gate.
//  2. workerd cannot be made to trust a private CA. startTls/implicit-TLS exposes only
//     `expectedServerHostname`, not a CA/cert override, so a trusted-CA happy-path LDAPS bind
//     and an on-wire packet capture of the (never-sent) cleartext password are NOT possible
//     locally. where a happy path would normally be exercised, the production note is given in
//     comments and the local leg uses plain LDAP 389 (the only one that can complete here).
// =====================================================================================
import { describe, expect, it } from 'vitest';
import { AuthError, ConnectionError } from '../../../src/core/errors';
import { connect as ldapConnect, type LdapSession } from '../../../src/ldap/index';
import { connect as ldapsConnect } from '../../../src/ldaps/index';
import { connect as sftpConnect } from '../../../src/sftp/index';
import { connect as sshConnect } from '../../../src/ssh/index';
import { Facility, Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const HOST = '127.0.0.1';
const LDAP_PORT = 389;
const LDAPS_PORT = 636;
const SSH_PORT = 2222;
const SYSLOG_PORT = 5514;

// the seeded directory (docker/ldap-bootstrap/seed.ldif)
const PEOPLE_DN = 'ou=people,dc=example,dc=org';

// the box authenticates this LOCAL user; the LDAPS gate is the app auth in front of it
const SSH_BOX = { hostname: HOST, port: SSH_PORT, username: 'tester', password: 'testpass' };

// the seeded user whose credential the gateway protects
const ALICE = { uid: 'alice', password: 'alicepw' } as const;

const dec = (b: Uint8Array) => new TextDecoder().decode(b);
const enc = (s: string) => new TextEncoder().encode(s);
const userDn = (uid: string) => `uid=${uid},${PEOPLE_DN}`;

// opens the plaintext syslog audit channel; Facility.auth keeps these events self-labelling
async function openSyslog(runId: string) {
	return syslogConnect({
		hostname: HOST,
		port: SYSLOG_PORT,
		tls: 'off',
		appName: 'cred-gateway',
		procId: runId
	});
}

// audits one step of the gateway flow, tagged with the run id for scoped readback
async function audit(
	log: Awaited<ReturnType<typeof openSyslog>>,
	runId: string,
	step: string,
	severity: Severity,
	detail: string
) {
	await log.log({
		severity,
		facility: Facility.auth,
		message: `cred ${runId} step=${step} ${detail}`,
		structuredData: [{ id: 'cred@gateway', params: { run: runId, step } }]
	});
}

// polls the syslog readback until every expected marker for this run is present, in order
async function waitForAudit(runId: string, markers: string[]): Promise<string | null> {
	return waitFor(
		async () => {
			const all = await readSyslog();
			// keep only this run's lines so concurrent suites don't pollute the ordering check
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

describe('recipe: credential-protecting auth gateway over LDAPS (LDAPS + SSH/SFTP + Syslog)', () => {
	// 1. fail-closed on an untrusted cert: the LDAPS connect rejects with ConnectionError, and
	// crucially NO bind/credential is sent - the TLS handshake fails before the LDAP bind. over
	// plain LDAP the same bind would put alice's password on the wire in cleartext (the exact
	// thing LDAPS prevents); capturing that absence isn't possible from workerd (see header), so
	// we assert the rejection type - the proof the gateway refused to transmit the credential.
	it('fails closed on an untrusted LDAPS cert: no bind, no credential on the wire', async () => {
		await expect(
			ldapsConnect({
				hostname: HOST,
				port: LDAPS_PORT,
				bindDN: userDn(ALICE.uid),
				password: ALICE.password // never leaves the client: TLS fails before the bind frame
			})
		).rejects.toBeInstanceOf(ConnectionError);
	});

	// 2. server-identity verification: passing expectedServerHostname does not relax the check -
	// the mismatched/self-signed cert still fails closed. workerd validates the cert against its
	// trust store regardless; a matching trusted cert cannot be provided locally (see header), so
	// the assertion is that identity verification keeps the gate shut, not that it can open.
	it('keeps the gate shut even with expectedServerHostname set (identity is still verified)', async () => {
		await expect(
			ldapsConnect({
				hostname: HOST,
				port: LDAPS_PORT,
				expectedServerHostname: 'ldaps.example.org', // the name a real trusted cert would carry
				bindDN: userDn(ALICE.uid),
				password: ALICE.password
			})
		).rejects.toBeInstanceOf(ConnectionError);
	});

	// 3. no silent downgrade: the LDAPS failure is terminal - edgeport never falls back to
	// plaintext LDAP. shown two ways: (a) the LDAPS connect throws and never yields a session, and
	// (b) a plain LDAP connect to 389 succeeds independently, proving 636 and 389 are distinct
	// endpoints the client never auto-rewrites (636 -> 389).
	it('does not silently downgrade LDAPS->plaintext: 636 is terminal, 389 is a separate endpoint', async () => {
		// (a) LDAPS never returns a usable session; assert by type and that the value is never read
		let ldapsSession: LdapSession | undefined;
		await expect(
			(async () => {
				ldapsSession = await ldapsConnect({
					hostname: HOST,
					port: LDAPS_PORT,
					bindDN: userDn(ALICE.uid),
					password: ALICE.password
				});
			})()
		).rejects.toBeInstanceOf(ConnectionError);
		expect(ldapsSession, 'LDAPS must never hand back a session on cert failure').toBeUndefined();

		// (b) a plain LDAP bind to 389 completes - a genuinely separate endpoint. if the client
		// auto-downgraded 636->389 the LDAPS connect above would have SUCCEEDED; it did not.
		await using plain = await ldapConnect({
			hostname: HOST,
			port: LDAP_PORT,
			tls: 'off',
			bindDN: userDn(ALICE.uid),
			password: ALICE.password
		});
		const [self] = await plain.search({
			base: userDn(ALICE.uid),
			scope: 'base',
			attributes: ['mail']
		});
		expect(self?.attributes.mail).toEqual(['alice@example.org']);
	});

	// 4. gateway flow once authorized: the identity check authenticates alice against the
	// directory, then the gateway runs the downstream SSH exec + SFTP write/read and audits every
	// step to Syslog. step order asserted: ldaps-refused -> ldap-bind-ok -> ssh-cmd -> sftp-write.
	//
	// NOTE on the identity leg: in production this bind is LDAPS (port 636). locally only the plain
	// LDAP 389 bind can complete (workerd rejects the untrusted 636 cert - see header), so the
	// audit first records the real ldaps-refused fail-closed event, then performs the identity
	// check over 389 to drive the rest of the gateway flow end to end.
	it('audits the full gateway flow once authorized: ldaps-refused, ldap-bind-ok, ssh-cmd, sftp-write', async () => {
		const runId = uniqueId('cred-flow');
		await using log = await openSyslog(runId);

		// step 1: the protected identity leg is LDAPS; locally it fails closed on the cert. audit it
		// as the security event it is (a refused, never-transmitted credential).
		let ldapsThrew = false;
		try {
			await ldapsConnect({
				hostname: HOST,
				port: LDAPS_PORT,
				bindDN: userDn(ALICE.uid),
				password: ALICE.password
			});
		} catch (err) {
			expect(err).toBeInstanceOf(ConnectionError);
			ldapsThrew = true;
		}
		expect(ldapsThrew, 'the LDAPS identity leg must fail closed locally').toBe(true);
		await audit(
			log,
			runId,
			'ldaps-refused',
			Severity.warning,
			`who=${ALICE.uid} reason=untrusted-cert`
		);

		// step 2: identity check (production: LDAPS; local: 389). a successful bind IS the auth.
		await using id = await ldapConnect({
			hostname: HOST,
			port: LDAP_PORT,
			tls: 'off',
			bindDN: userDn(ALICE.uid),
			password: ALICE.password
		});
		// prove the session is live and authorized before letting any downstream action run
		const [entry] = await id.search({
			base: userDn(ALICE.uid),
			scope: 'base',
			attributes: ['mail']
		});
		expect(entry?.attributes.mail).toEqual(['alice@example.org']);
		await audit(log, runId, 'ldap-bind-ok', Severity.notice, `who=${ALICE.uid}`);

		// step 3: authorized -> downstream SSH exec on the box (the gated privileged action)
		await using ssh = await sshConnect(SSH_BOX);
		const cmd = `echo cred-gateway ${ALICE.uid} ${runId}`;
		const exec = await ssh.exec(cmd);
		expect(exec.code).toBe(0);
		expect(dec(exec.stdout)).toContain(`cred-gateway ${ALICE.uid} ${runId}`);
		await audit(
			log,
			runId,
			'ssh-cmd',
			Severity.info,
			`who=${ALICE.uid} cmd=${JSON.stringify(cmd)}`
		);

		// step 4: gated SFTP write + byte-exact read-back over the SAME ssh session
		await using sftp = await sftpConnect({ session: ssh });
		const remote = `/config/${runId}.txt`;
		const payload = enc(`secured-by ${ALICE.uid}`);
		await sftp.writeFile(remote, payload);
		const back = await sftp.readFile(remote);
		expect(back).toEqual(payload);
		await audit(log, runId, 'sftp-write', Severity.info, `who=${ALICE.uid} path=${remote}`);
		await sftp.remove(remote).catch(() => {});

		// the audit trail must show every step, in order
		const trail = await waitForAudit(runId, [
			`step=ldaps-refused who=${ALICE.uid} reason=untrusted-cert`,
			`step=ldap-bind-ok who=${ALICE.uid}`,
			`step=ssh-cmd who=${ALICE.uid} cmd=`,
			`step=sftp-write who=${ALICE.uid} path=${remote}`
		]);
		expect(trail, 'the full gateway flow should be audited in order').not.toBeNull();
	});

	// 5. a wrong directory password is rejected with AuthError (result code 49). the identity leg
	// is plain LDAP 389 here (the only leg that can complete locally); the same rejection mapping
	// holds over LDAPS in production.
	it('rejects a wrong directory password with AuthError', async () => {
		await expect(
			ldapConnect({
				hostname: HOST,
				port: LDAP_PORT,
				tls: 'off',
				bindDN: userDn(ALICE.uid),
				password: 'wrong-password'
			})
		).rejects.toBeInstanceOf(AuthError);
	});
});
