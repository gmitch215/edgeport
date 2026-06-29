// recipe: centralized LDAP-backed auth across a fleet (LDAP + SSH + SFTP + Syslog).
//
// the pattern: LDAP is the single identity source and the application authorization gate that
// sits IN FRONT of every fleet action. before a privileged op (an SSH exec, an SFTP transfer)
// runs, authorize() (1) verifies the user's password by binding as their own DN, (2) checks the
// account is not locked (employeeType:locked), and (3) checks the user is a member of the
// privileged group (cn=admins) by reading the group's `member` attribute as admin. allow -> the
// gated action runs; deny -> it is skipped. every decision and every gated command is written to
// Syslog as the audit trail (who / what / where / allow|deny).
//
// IMPORTANT scoping notes (honest record of what is and isn't exercised):
//  - the dockerized openssh box authenticates its OWN local user tester/testpass; it is NOT
//    literally LDAP-PAM-backed here. the LDAP bind + group check is the APPLICATION authorization
//    gate the Workers job enforces before it ever touches the box - the standard "LDAP-backed
//    fleet" shape. so an authorized user's action targets the box as tester; a denied user's
//    action is never attempted (the gate refused it).
//  - the edgeport ldap module is BIND + SEARCH only (no writes), so live LDAP mutation (moving a
//    user in/out of a group, setting the lock flag) is not possible from here. "group change gates
//    access" and "lockout" are therefore demonstrated against the SEEDED membership/lock state:
//    alice (in admins, unlocked) is allowed; bob (not in admins) is denied; carol (locked) is
//    denied. that is the same allow/deny logic a real group change would flip, shown statically.
import { describe, expect, it } from 'vitest';
import { AuthError } from '../../../src/core/errors';
import { connect as ldapConnect, type LdapSession } from '../../../src/ldap/index';
import { connect as sftpConnect } from '../../../src/sftp/index';
import { connect as sshConnect } from '../../../src/ssh/index';
import { Facility, Severity, connect as syslogConnect } from '../../../src/syslog/index';
import { readSyslog, uniqueId, waitFor } from './_helpers';

const HOST = '127.0.0.1';
const LDAP_PORT = 389;
const SSH_PORT = 2222;
const SYSLOG_PORT = 5514;

// the seeded directory (docker/ldap-bootstrap/seed.ldif)
const BASE_DN = 'dc=example,dc=org';
const PEOPLE_DN = 'ou=people,dc=example,dc=org';
const ADMINS_DN = 'cn=admins,ou=groups,dc=example,dc=org';
const ADMIN_BIND = { dn: 'cn=admin,dc=example,dc=org', password: 'admin' };

// the box authenticates this LOCAL user; the LDAP gate is the app authorization in front of it
const SSH_BOX = { hostname: HOST, port: SSH_PORT, username: 'tester', password: 'testpass' };

// the seeded users and their LDAP passwords; userDn() builds the DN authorize() binds as
const USERS = {
	alice: { uid: 'alice', password: 'alicepw' }, // in admins, unlocked  -> allow
	bob: { uid: 'bob', password: 'bobpw' }, // not in admins         -> deny
	carol: { uid: 'carol', password: 'carolpw' } // locked                -> deny
} as const;

const dec = (b: Uint8Array) => new TextDecoder().decode(b);
const enc = (s: string) => new TextEncoder().encode(s);
const userDn = (uid: string) => `uid=${uid},${PEOPLE_DN}`;

// opens the plaintext syslog audit channel; Facility.auth keeps these events self-labelling
async function openSyslog(runId: string) {
	return syslogConnect({
		hostname: HOST,
		port: SYSLOG_PORT,
		tls: 'off',
		appName: 'auth-gate',
		procId: runId
	});
}

interface AuthDecision {
	/** the user uid the decision is about */
	user: string;
	/** allow only when the password is valid, the account is unlocked, and the user is in admins */
	allow: boolean;
	/** machine-readable reason: 'ok' | 'bad-credentials' | 'locked' | 'not-a-member' */
	reason: 'ok' | 'bad-credentials' | 'locked' | 'not-a-member';
}

/**
 * The application authorization gate. LDAP is the identity source: it verifies the user's own
 * password (bind as their DN), then - reading the directory as admin - checks the account is not
 * locked and is a member of the privileged group. Returns allow/deny with a reason; never throws
 * for an ordinary deny (bad password is caught and mapped to a deny).
 *
 * @param admin - an already-bound admin session used to READ group membership and the lock flag
 * @param uid - the user being authorized
 * @param password - the user's claimed password (verified by binding as their DN)
 */
async function authorize(admin: LdapSession, uid: string, password: string): Promise<AuthDecision> {
	// 1. identity: verify the password by binding as the user's OWN dn (the bind is the auth)
	{
		await using probe = await ldapConnect({ hostname: HOST, port: LDAP_PORT, tls: 'off' });
		try {
			await probe.bind(userDn(uid), password);
		} catch (err) {
			if (err instanceof AuthError) return { user: uid, allow: false, reason: 'bad-credentials' };
			throw err; // a non-auth failure (connection/protocol) is a real error, not a deny
		}
	}

	// 2. lockout: read the user entry as admin; employeeType:locked is an immediate deny
	const [entry] = await admin.search({
		base: userDn(uid),
		scope: 'base',
		attributes: ['employeeType']
	});
	const locked = (entry?.attributes.employeeType ?? []).some((v) => v === 'locked');
	if (locked) return { user: uid, allow: false, reason: 'locked' };

	// 3. group-based authorization: is this user's dn listed in cn=admins `member`?
	const [group] = await admin.search({
		base: ADMINS_DN,
		scope: 'base',
		attributes: ['member']
	});
	const members = group?.attributes.member ?? [];
	const isAdmin = members.some((m) => m.toLowerCase() === userDn(uid).toLowerCase());
	if (!isAdmin) return { user: uid, allow: false, reason: 'not-a-member' };

	return { user: uid, allow: true, reason: 'ok' };
}

// audits one decision: who / what / where / allow|deny, tagged with the run id for scoped readback
async function auditDecision(
	log: Awaited<ReturnType<typeof openSyslog>>,
	runId: string,
	d: AuthDecision,
	action: string
) {
	const verdict = d.allow ? 'allow' : 'deny';
	await log.log({
		severity: d.allow ? Severity.notice : Severity.warning,
		facility: Facility.auth,
		message: `authz ${runId} who=${d.user} what=${action} where=${SSH_BOX.hostname}:${SSH_BOX.port} verdict=${verdict} reason=${d.reason}`,
		structuredData: [
			{
				id: 'authz@gate',
				params: { run: runId, who: d.user, what: action, verdict, reason: d.reason }
			}
		]
	});
}

// audits a gated command that actually ran (only reached for an authorized user)
async function auditCommand(
	log: Awaited<ReturnType<typeof openSyslog>>,
	runId: string,
	user: string,
	command: string
) {
	await log.log({
		severity: Severity.info,
		facility: Facility.auth,
		message: `gated-cmd ${runId} who=${user} cmd=${JSON.stringify(command)} where=${SSH_BOX.hostname}:${SSH_BOX.port}`,
		structuredData: [{ id: 'authz@gate', params: { run: runId, who: user, cmd: command } }]
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

describe('recipe: centralized LDAP-backed auth across a fleet (LDAP + SSH + SFTP + Syslog)', () => {
	// 1. LDAP is the identity source: a correct password binds, a wrong one is an AuthError.
	it('uses LDAP as the identity source: good bind succeeds, bad password is AuthError', async () => {
		// alice's real password binds as her own dn (the bind IS the authentication)
		await using ok = await ldapConnect({
			hostname: HOST,
			port: LDAP_PORT,
			tls: 'off',
			bindDN: userDn('alice'),
			password: USERS.alice.password
		});
		// reaching here means the bind succeeded; prove the session is live with a base search
		const [self] = await ok.search({ base: userDn('alice'), scope: 'base', attributes: ['mail'] });
		expect(self?.attributes.mail).toEqual(['alice@example.org']);

		// a wrong password is rejected with AuthError (result code 49 -> AuthError in the module)
		await expect(
			ldapConnect({
				hostname: HOST,
				port: LDAP_PORT,
				tls: 'off',
				bindDN: userDn('alice'),
				password: 'wrong-password'
			})
		).rejects.toBeInstanceOf(AuthError);
	});

	// 2. group-based authorization + lockout, computed by authorize() against the seeded directory.
	it('authorizes by group membership and lock state: alice allow, bob deny, carol deny', async () => {
		await using admin = await ldapConnect({
			hostname: HOST,
			port: LDAP_PORT,
			tls: 'off',
			bindDN: ADMIN_BIND.dn,
			password: ADMIN_BIND.password
		});

		const alice = await authorize(admin, USERS.alice.uid, USERS.alice.password);
		expect(alice).toEqual({ user: 'alice', allow: true, reason: 'ok' });

		// bob authenticates fine (good password) but is NOT in cn=admins -> denied
		const bob = await authorize(admin, USERS.bob.uid, USERS.bob.password);
		expect(bob).toEqual({ user: 'bob', allow: false, reason: 'not-a-member' });

		// carol is locked (employeeType:locked) -> denied before group membership even matters
		const carol = await authorize(admin, USERS.carol.uid, USERS.carol.password);
		expect(carol).toEqual({ user: 'carol', allow: false, reason: 'locked' });

		// a valid user with a WRONG password is denied as bad-credentials, never throwing past the gate
		const badPw = await authorize(admin, USERS.alice.uid, 'nope');
		expect(badPw).toEqual({ user: 'alice', allow: false, reason: 'bad-credentials' });
	});

	// 3. gated SSH + SFTP for an AUTHORIZED user (alice): the action runs only after allow.
	it('runs the gated SSH exec + SFTP write/read for an authorized user', async () => {
		const runId = uniqueId('authz-allow');
		await using log = await openSyslog(runId);
		await using admin = await ldapConnect({
			hostname: HOST,
			port: LDAP_PORT,
			tls: 'off',
			bindDN: ADMIN_BIND.dn,
			password: ADMIN_BIND.password
		});

		const decision = await authorize(admin, USERS.alice.uid, USERS.alice.password);
		await auditDecision(log, runId, decision, 'ssh-exec+sftp-write');
		expect(decision.allow).toBe(true);

		// allow -> perform the fleet action. the box authenticates its local tester user; the gate
		// above is the application authorization that permitted us to get here.
		await using ssh = await sshConnect(SSH_BOX);
		const cmd = `echo gated-by ${decision.user} ${runId}`;
		const exec = await ssh.exec(cmd);
		expect(exec.code).toBe(0);
		expect(dec(exec.stdout)).toContain(`gated-by ${decision.user} ${runId}`);
		await auditCommand(log, runId, decision.user, cmd);

		// gated SFTP write + read-back over the SAME ssh session, byte-exact
		await using sftp = await sftpConnect({ session: ssh });
		const remote = `/config/${runId}.txt`;
		const payload = enc(`owned-by ${decision.user}`);
		await sftp.writeFile(remote, payload);
		const back = await sftp.readFile(remote);
		expect(back).toEqual(payload);
		await auditCommand(log, runId, decision.user, `sftp-write ${remote}`);
		await sftp.remove(remote).catch(() => {});

		// the audit must show: allow decision, then both gated commands, in order
		const audit = await waitForAudit(runId, [
			`verdict=allow reason=ok`,
			`gated-cmd ${runId} who=alice cmd=`,
			`sftp-write ${remote}`
		]);
		expect(audit, 'allow + both gated commands should be audited in order').not.toBeNull();
	});

	// 4. a DENIED user's action is NEVER performed - the gate refuses before any SSH/SFTP touch.
	it('refuses the gated action for denied users (bob not-a-member, carol locked)', async () => {
		const runId = uniqueId('authz-deny');
		await using log = await openSyslog(runId);
		await using admin = await ldapConnect({
			hostname: HOST,
			port: LDAP_PORT,
			tls: 'off',
			bindDN: ADMIN_BIND.dn,
			password: ADMIN_BIND.password
		});

		for (const u of [USERS.bob, USERS.carol]) {
			const decision = await authorize(admin, u.uid, u.password);
			await auditDecision(log, runId, decision, 'ssh-exec');
			expect(decision.allow).toBe(false);

			// the decisive assertion: because allow is false, no SSH session is ever opened. we make
			// that structural by only entering the action branch on allow.
			let actionRan = false;
			if (decision.allow) {
				await using ssh = await sshConnect(SSH_BOX);
				await ssh.exec(`echo should-not-run ${runId}`);
				actionRan = true;
			}
			expect(actionRan, `${u.uid}'s gated action must not run`).toBe(false);
		}

		// the audit shows two denies and ZERO gated-cmd lines for this run
		const audit = await waitForAudit(runId, [
			`who=bob what=ssh-exec where=${HOST}:${SSH_PORT} verdict=deny reason=not-a-member`,
			`who=carol what=ssh-exec where=${HOST}:${SSH_PORT} verdict=deny reason=locked`
		]);
		expect(audit, 'both denies should be audited in order').not.toBeNull();
		expect(audit!).not.toContain(`gated-cmd ${runId}`); // nothing privileged ever ran
	});

	// 5. "group change gates access" + lockout, end to end: one run authorizes all three users,
	// runs the gated action for the allowed one only, and the syslog audit captures who-did-what.
	it('produces a who/what/allow|deny audit trail covering the whole fleet decision', async () => {
		const runId = uniqueId('authz-fleet');
		await using log = await openSyslog(runId);
		await using admin = await ldapConnect({
			hostname: HOST,
			port: LDAP_PORT,
			tls: 'off',
			bindDN: ADMIN_BIND.dn,
			password: ADMIN_BIND.password
		});

		// authorize each user in turn; only alice (in admins, unlocked) clears the gate. this is the
		// SAME allow/deny logic a live group change would flip - shown against the seeded state since
		// the module cannot write to the directory.
		const order = [USERS.alice, USERS.bob, USERS.carol];
		const decisions: AuthDecision[] = [];
		for (const u of order) {
			const d = await authorize(admin, u.uid, u.password);
			await auditDecision(log, runId, d, 'fleet-restart');
			decisions.push(d);
			if (d.allow) {
				await using ssh = await sshConnect(SSH_BOX);
				const cmd = `echo fleet-restart ${d.user} ${runId}`;
				const r = await ssh.exec(cmd);
				expect(r.code).toBe(0);
				await auditCommand(log, runId, d.user, cmd);
			}
		}

		expect(decisions.map((d) => `${d.user}:${d.reason}`)).toEqual([
			'alice:ok',
			'bob:not-a-member',
			'carol:locked'
		]);

		// the audit trail captures who did what, in order: alice allow -> her gated cmd -> bob deny
		// -> carol deny. exactly one gated command (alice's) appears.
		const audit = await waitForAudit(runId, [
			`who=alice what=fleet-restart where=${HOST}:${SSH_PORT} verdict=allow reason=ok`,
			`gated-cmd ${runId} who=alice`,
			`who=bob what=fleet-restart where=${HOST}:${SSH_PORT} verdict=deny reason=not-a-member`,
			`who=carol what=fleet-restart where=${HOST}:${SSH_PORT} verdict=deny reason=locked`
		]);
		expect(audit, 'the full fleet decision lifecycle should be audited in order').not.toBeNull();
		// only one gated command ran across the whole fleet (alice's); bob/carol never reached one
		const gatedCount = audit!.split('\n').filter((l) => l.includes(`gated-cmd ${runId}`)).length;
		expect(gatedCount).toBe(1);
	});
});
