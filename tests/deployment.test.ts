import { it, expect } from 'vitest';
import { world } from './support';
import { validProfile } from '../src/profile';
import { sha256, utf8 } from '../src/canonical';
it('accepts exactly local and pinned mapl-test profile, refuses operational and other hosts',()=>world(async w=>{
 const local={...w.bindings};expect(validProfile(local)).toBe(true);
 const deployed={...local,SUBDOMAIN:'visibly-fake-fixture',RUNNER_TOKEN_SHA256:'a'.repeat(64),REQUESTER_TOKEN_SHA256:'b'.repeat(64),RP_ID:'mapl-test.visibly-fake-fixture.workers.dev',ORIGIN:'https://mapl-test.visibly-fake-fixture.workers.dev'};
 expect(validProfile(deployed)).toBe(true);
 expect(validProfile({...local,RUNNER_TOKEN_SHA256:'a'.repeat(64),REQUESTER_TOKEN_SHA256:'a'.repeat(64)})).toBe(false);
 const consistent=(host:string,sub=deployed.SUBDOMAIN)=>({...deployed,SUBDOMAIN:sub,RP_ID:host,ORIGIN:'https://'+host});
 for(const bad of [consistent('evil.invalid'),consistent('mapl-prod.visibly-fake-fixture.workers.dev'),consistent('mapl-test.REPLACE_ME.workers.dev','REPLACE_ME'),{...deployed,REQUESTER_TOKEN_SHA256:deployed.RUNNER_TOKEN_SHA256},{...deployed,MODE:'operational'},{...deployed,ORIGIN:'https://mapl.visibly-fake-fixture.workers.dev'},{...deployed,SUBDOMAIN:'REPLACE_ME'},{...deployed,RP_ID:'evil.invalid'},{...deployed,ORIGIN:'http://'+deployed.RP_ID}]) {
  w.instance.env=bad;expect(validProfile(bad)).toBe(false);expect((await w.http('GET','/version')).status).toBe(503);
 }
}));
it('deployed hashes authorise scoped role operations and cannot register, approve, add keys or manage',()=>world(async w=>{
 const tokens={runner:'visibly-fake-runner-fixture-0000000000',requester:'visibly-fake-requester-fixture-0000000'};
 const hash=async(t:string)=>Array.from(await sha256(utf8(t)),b=>b.toString(16).padStart(2,'0')).join('');
 w.instance.env={...w.bindings,SUBDOMAIN:'visibly-fake-fixture',ORIGIN:'https://mapl-test.visibly-fake-fixture.workers.dev',RP_ID:'mapl-test.visibly-fake-fixture.workers.dev',RUNNER_TOKEN_SHA256:await hash(tokens.runner),REQUESTER_TOKEN_SHA256:await hash(tokens.requester),BUILD_COMMIT:'a'.repeat(40)};
 const call=async(method:string,path:string,body?:unknown,token?:string)=>w.instance.fetch(new Request(w.instance.env.ORIGIN+path,{method,headers:{Origin:w.instance.env.ORIGIN,...(token?{Authorization:'Bearer '+token}:{})},body:method==='POST'?JSON.stringify(body??{}):undefined}));
 expect((await call('GET','/api/runner/approved',undefined,tokens.runner)).status).toBe(200);
 expect((await call('POST','/api/requester/requests',{request:{...w.request,request_id:'e'.repeat(32)}},tokens.requester)).status).toBe(200);
 expect((await call('GET','/api/runner/approved',undefined,w.bindings.RUNNER_TOKEN)).status).toBe(403);
 for(const token of Object.values(tokens)) {
  for(const path of ['/api/register/options','/api/register/verify','/api/login/options','/api/login/verify'])expect((await call('POST',path,{},token)).status).toBe(403);
  for(const path of ['/api/credential-add/options','/api/credential-add/verify','/api/requests/'+w.rid+'/approve/options','/api/requests/'+w.rid+'/approve/verify','/api/logout','/api/recovery'])expect((await call('POST',path,{},token)).status).toBe(401);
 }
 const version=await (await call('GET','/version')).json();expect(version).toMatchObject({mode:'test',operational:false,commit:'a'.repeat(40),registration:'code_required'});
 expect((await call('POST','/api/register/options',{})).status).toBe(403);
 for(const digest of ['invalid','REPLACE_WITH_REVIEWED_SHA256',undefined]) {
  w.instance.env.RUNNER_TOKEN_SHA256=digest;
  expect((await call('GET','/api/runner/approved',undefined,tokens.runner)).status).toBe(403);
  expect((await call('GET','/api/runner/approved',undefined,w.bindings.RUNNER_TOKEN)).status).toBe(403);
 }
},false));
