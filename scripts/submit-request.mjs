import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { profile } from './configure.mjs';
// Token is stdin only; the public prepared mock state is the only file input.
export async function submit({state, token, deployment=profile(), origin=`https://mapl-test.${deployment.SUBDOMAIN}.workers.dev`, request=fetch}) {
 assert.match(deployment.SUBDOMAIN,/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/,'reviewed subdomain required');
 assert.equal(origin,`https://mapl-test.${deployment.SUBDOMAIN}.workers.dev`,'fixed mapl-test target only');
 assert.match(token,/^[A-Za-z0-9_-]{32,}$/,'invalid requester token format');
 assert.equal(state.mode,'test','test mock state required');
 assert.equal(state.root_id,deployment.TEST_ROOT_ID,'reviewed test root mismatch');
 assert.equal(state.request.mode,'test','test request required');
 assert.equal(state.request.action_type,'screen_publication/1','test publication only');
 assert.equal(state.request.target.test_root_id,state.root_id,'request target mismatch');
 assert.equal(state.request.target.pointer,'test-screen/CURRENT.json','test pointer only');
 assert.equal(state.request.kit.name,'mock-kit/1','mock kit only');
 const r=await request(origin+'/api/requester/requests',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({request:state.request}),redirect:'manual',signal:AbortSignal.timeout(10000)});
 assert.equal(r.status,200,'requester submission refused');
 return {status:r.status};
}
if(process.argv[1]===new URL(import.meta.url).pathname) {
 try {
  assert.equal(process.argv.length,3,'usage: node scripts/submit-request.mjs <public-mock-state.json>; token on stdin');
  let token='';for await(const chunk of process.stdin) {token+=chunk;assert(token.length<=4096,'stdin too large');}
  const result=await submit({state:JSON.parse(readFileSync(process.argv[2],'utf8')),token:token.trim()});
  console.log(JSON.stringify(result));
 }catch {console.error('Test requester submission refused');process.exitCode=1;}
}
