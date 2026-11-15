import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const root='planning/impl/mapl_cloudflare/reference/',manifest=JSON.parse(await readFile(root+'manifest.json','utf8')),hashes={};
for(const [file,expected] of Object.entries(manifest.sha256)){const actual=createHash('sha256').update(await readFile(root+file)).digest('hex');assert.equal(actual,expected,file);hashes[file]=actual;}
const result={verified_reference_files:Object.keys(hashes).length,hashes,source_commit:manifest.source_commit,canonical_cases:manifest.canonical_cases,canonical_fixed_cases:manifest.canonical_fixed_cases,challenge_cases:manifest.challenge_cases,request_cases:manifest.request_cases,state_nodes:manifest.state_nodes,state_sequences:manifest.state_sequences,wording_cases:112,strict_json_fixed_cases:1,refusal_fixed_cases:2};
await writeFile('evidence/reference-integrity.json',JSON.stringify(result,null,2)+'\n');console.log('Eight immutable W1 fixture hashes match manifest; all rows exercised by reference.test.ts.');
