import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

const integration = process.env.INTEGRATION === '1';
const all = process.env.COVERAGE_ALL === '1';

const unitGlobs = ['test/unit/**/*.spec.ts', 'test/kat/**/*.spec.ts'];
const integrationGlobs = ['test/integration/**/*.spec.ts'];

export default defineConfig({
	test: {
		// integration runs serially (shared docker servers limit concurrent connections)
		maxWorkers: process.env.CI || integration || all ? 1 : 2,
		fileParallelism: !(integration || all),
		testTimeout: integration || all ? 30000 : 15000,
		// gate run stays hermetic; integration / combined runs are opt-in
		include: all ? [...unitGlobs, ...integrationGlobs] : integration ? integrationGlobs : unitGlobs,
		coverage: {
			provider: 'istanbul',
			reporter: ['text', 'clover', 'json'],
			include: ['src/**/*.ts'],
			// drop only the pure re-export barrels; protocol/kex logic lives in the other index.ts
			exclude: ['src/index.ts', 'src/core/index.ts', 'src/crypto/index.ts', 'test/**']
		}
	},
	plugins: [
		cloudflareTest({
			remoteBindings: false,
			wrangler: { configPath: './test/wrangler.jsonc' }
		})
	]
});
