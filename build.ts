// builds each subpath entry to dist/<name>/index.js (ESM), then tsc emits the .d.ts tree
// run: bun run build
import { $ } from 'bun';
import { rm } from 'node:fs/promises';

const entries = {
	index: 'src/index.ts',
	ssh: 'src/ssh/index.ts',
	sftp: 'src/sftp/index.ts',
	smtp: 'src/smtp/index.ts',
	imap: 'src/imap/index.ts',
	pop3: 'src/pop3/index.ts',
	ws: 'src/ws/index.ts',
	nats: 'src/nats/index.ts',
	mqtt: 'src/mqtt/index.ts',
	stomp: 'src/stomp/index.ts',
	ftp: 'src/ftp/index.ts',
	ldap: 'src/ldap/index.ts',
	ldaps: 'src/ldaps/index.ts',
	syslog: 'src/syslog/index.ts',
	smpp: 'src/smpp/index.ts',
	util: 'src/util/index.ts',
	// building-block subpaths (edgeport/wire, /crypto, /kex, /auth)
	wire: 'src/wire.ts',
	crypto: 'src/crypto/index.ts',
	kex: 'src/kex/index.ts',
	auth: 'src/auth/index.ts'
};

await rm('dist', { recursive: true, force: true });

const result = await Bun.build({
	entrypoints: Object.values(entries),
	outdir: 'dist',
	root: 'src', // keep dist paths relative to src (dist/ssh/wire.js, not dist/src/ssh/wire.js)
	target: 'node', // workerd-compatible ESM; cloudflare:sockets stays external
	format: 'esm',
	sourcemap: 'linked',
	splitting: true,
	external: ['cloudflare:sockets', '@noble/ciphers', 'bcrypt-pbkdf'],
	naming: '[dir]/[name].[ext]'
});

if (!result.success) {
	for (const log of result.logs) console.error(log);
	process.exit(1);
}

// emit declaration files (and maps) alongside the bundled js
await $`tsc -p tsconfig.build.json`;

console.log(`built ${result.outputs.length} files`);
