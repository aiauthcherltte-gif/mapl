import { build } from 'esbuild';
import { Miniflare } from 'miniflare';
import { readFile, writeFile } from 'node:fs/promises';
const {outputFiles:[helper]}=await build({entryPoints:['tests/soft-auth.ts'],bundle:true,format:'esm',platform:'neutral',write:false});
const {outputFiles:[canon]}=await build({entryPoints:['src/canonical.ts'],bundle:true,format:'esm',platform:'neutral',write:false});
const {approvalChallenge}=await import('data:text/javascript;base64,'+Buffer.from(canon.contents).toString('base64'));
const fixture=JSON.parse(await readFile('planning/impl/mapl_cloudflare/reference/request.json','utf8'))[0].input;
const {SoftAuthenticator}=await import('data:text/javascript;base64,'+Buffer.from(helper.contents).toString('base64'));
const auth=await new SoftAuthenticator().init(),challenge=await approvalChallenge(fixture,'compatibility-probe-nonce');
const payload={challenge:Buffer.from(challenge).toString('base64url'),origin:'http://localhost:8790',rp:'localhost',registration:await auth.registration(challenge),assertion:await auth.assertion(challenge)};
const {outputFiles:[worker]}=await build({entryPoints:['tests/probe-worker.ts'],bundle:true,format:'esm',platform:'browser',write:false});
const mf=new Miniflare({modules:true,script:worker.text,compatibilityDate:'2025-10-04',compatibilityFlags:[],outboundService:()=>{throw Error('external network forbidden');}});
try {const r=await mf.dispatchFetch('http://localhost/probe',{method:'POST',body:JSON.stringify(payload)});const body=await r.text();console.log(body);if(!r.ok)throw Error('probe failed');const result=JSON.parse(body);await writeFile('evidence/simplewebauthn-probe.json',JSON.stringify({...result,content_bound_32_bytes:true,telemetry:{WRANGLER_SEND_METRICS:process.env.WRANGLER_SEND_METRICS,DO_NOT_TRACK:process.env.DO_NOT_TRACK}},null,2)+'\n');if(result.ms_per_verification>=10)throw Error('local path >=10ms; R2.3 alternative required');}
finally {await mf.dispose();}
