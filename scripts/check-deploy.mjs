import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { render } from './configure.mjs';
// Runs in Wrangler's custom build before publishing, including default npx deploy.
const pkg=JSON.parse(readFileSync('package.json'));
const installed=JSON.parse(readFileSync('node_modules/wrangler/package.json'));
assert.equal(installed.version,pkg.devDependencies.wrangler,'pinned Wrangler required; run npm ci --ignore-scripts');
assert.equal(readFileSync('wrangler.toml','utf8'),render(),'committed config differs from reviewed profile');
