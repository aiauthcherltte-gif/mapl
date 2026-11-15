import { readFileSync, writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
export function profile() { return JSON.parse(readFileSync(new URL('../deploy-profile.json', import.meta.url))); }
export function origin() { const p = profile(); assert.match(p.SUBDOMAIN, /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/); return `https://mapl-test.${p.SUBDOMAIN}.workers.dev`; }
export function render() {
 const p=profile(), url=origin();
 for(const key of ['RUNNER_TOKEN_SHA256','REQUESTER_TOKEN_SHA256']) assert.match(p[key], /^[0-9a-f]{64}$/, key+' placeholder must be replaced by reviewed public digest');
 assert.notEqual(p.RUNNER_TOKEN_SHA256,p.REQUESTER_TOKEN_SHA256,'role digests must differ');
 if(p.TEST_ROOT_ID !== undefined) assert.match(p.TEST_ROOT_ID,/^[0-9a-f]{32}$/);
 const local=readFileSync('wrangler.local.toml','utf8');
 const config=local.replace('[dev]', '[build]\ncommand = \"node scripts/check-deploy.mjs\"\n[dev]').replace('mapl-local-only','mapl-test').replace('workers_dev = false','workers_dev = true').replace('http://localhost:8790',url).replace('RP_ID = "localhost"',`RP_ID = "${new URL(url).hostname}"`).replace('[vars]',`[vars]\nSUBDOMAIN = "${p.SUBDOMAIN}"\nRUNNER_TOKEN_SHA256 = "${p.RUNNER_TOKEN_SHA256}"\nREQUESTER_TOKEN_SHA256 = "${p.REQUESTER_TOKEN_SHA256}"`);
 return ( p.TEST_ROOT_ID ? config.replace('TEST_ROOT_ID = "22222222222222222222222222222222"', `TEST_ROOT_ID = "${p.TEST_ROOT_ID}"`) : config);
}
export function configure() {
 writeFileSync('wrangler.toml', render());
}
if (process.argv[1] === new URL(import.meta.url).pathname) configure();
