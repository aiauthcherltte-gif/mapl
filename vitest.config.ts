import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';
export default defineWorkersConfig({ resolve: { alias: { tslib: new URL('./node_modules/tslib/tslib.es6.mjs', import.meta.url).pathname } }, test: { include: ['tests/**/*.test.ts'], setupFiles: ['tests/setup.ts'], testTimeout: 60000, hookTimeout: 60000, poolOptions: { workers: { singleWorker: true, wrangler: { configPath: './wrangler.local.toml' }, miniflare: { bindings: { SETUP_CODE: 'LOCAL-TEST-SETUP-ONLY', REQUESTER_TOKEN: 'local-requester-fixture-'.repeat(3), RUNNER_TOKEN: 'local-runner-fixture-'.repeat(3), MUTANT: (globalThis as unknown as {
                            process: {
                                env: Record<string, string>;
                            };
                        }).process.env.MAPL_TEST_MUTANT === '1' ? '1' : '0' } } } } } });
