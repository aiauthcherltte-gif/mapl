import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { origin as configuredOrigin } from './configure.mjs';
const git=(...args)=>execFileSync('git',args);
export function reviewedTree(reviewed, merge='main') {
 assert.match(reviewed,/^[0-9a-f]{40}$/);
 assert.equal(git('rev-parse',`${merge}^2`).toString().trim(), reviewed, 'merge second parent differs');
 git('diff','--quiet',reviewed,merge);
 return git('rev-parse',merge).toString().trim();
}
// Public, unauthenticated GitHub reads only. Fixtures supply request in tests.
export async function publicBinding({reviewed, repository='aiauthcherltte-gif/mapl', request=fetch}) {
 assert.match(reviewed,/^[0-9a-f]{40}$/);
 assert.equal(repository,'aiauthcherltte-gif/mapl','fixed public repository only');
 const get=async ref=>{
  const r=await request(`https://api.github.com/repos/${repository}/commits/${ref}`,{method:'GET',headers:{Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'},redirect:'manual',signal:AbortSignal.timeout(10000)});
  assert.equal(r.status,200,'public GitHub commit unavailable');return r.json();
 };
 const head=await get('main');assert.match(head.sha,/^[0-9a-f]{40}$/);
 assert.equal(head.parents?.length,2,'main head is not a merge commit; Require linear history or squash/rebase merge must be off');
 assert.equal(head.parents[1].sha,reviewed,'public merge second parent differs');
 const commit=await get(reviewed);assert.equal(commit.sha,reviewed);
 assert.match(commit.commit?.tree?.sha,/^[0-9a-f]{40}$/);
 assert.equal(head.commit?.tree?.sha,commit.commit.tree.sha,'public merge tree differs');
 return {repository,branch:'main',head:head.sha,reviewed,tree:commit.commit.tree.sha};
}
export function securityHeaders(r,label) {
 for(const [key,value] of Object.entries({'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",'X-Frame-Options':'DENY','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})) assert.equal(r.headers.get(key),value,label+': '+key);
}
export async function verify({reviewed, origin, read, request=fetch, registrationClosed=false}) {
 assert.match(reviewed,/^[0-9a-f]{40}$/);
 const observations=[];
 const call=async(path, options={})=>request(origin+path,{...options,redirect:'manual',signal:AbortSignal.timeout(10000)});
 for(const [path,file] of [['/login','public/index.html'],['/register','public/index.html'],['/static/app.js','public/app.js.txt'],['/static/app.css','public/app.css.txt']]) {
  const r=await call(path);assert.equal(r.status,200,path);securityHeaders(r,path);const actual=Buffer.from(await r.arrayBuffer()), expected=read(file);assert.deepEqual(actual,expected,path+' byte mismatch');
  const hash=bytes=>createHash('sha256').update(bytes).digest('hex');const sha256=hash(actual);assert.equal(sha256,hash(expected),path+' hash mismatch');observations.push({path,status:200,bytes:'equal',sha256});
 }
 const v=await call('/version');assert.equal(v.status,200);securityHeaders(v,'/version');const version=await v.json();
 assert.equal(version.mode,'test');assert.equal(version.operational,false);
 assert(['closed','code_required'].includes(version.registration));
 if(registrationClosed)assert.equal(version.registration,'closed','registration must be closed after iPhone registration');
 // Default Builds cannot stamp committed vars; /version remains read-only state.
 // Commit binding is established separately by publicBinding plus asset hashes.
 return {observations,version,limits:['self-reported version cannot attest server code','public byte comparison covers only public assets','nine signed W4 scenarios not replayed']};
}
export function compareResults(actual, expected, {registrationClosed=false}={}) {
 if(registrationClosed) {
  const registration=actual.filter(r=>r.label==='no-setup-code');assert.equal(registration.length,2);
  for(const row of registration) {assert.equal(row.status,409,'registration must be closed');assert.equal(row.error,'registration_closed','registration must be closed');}
 }
 const normalize=rows=>rows.map(r=>JSON.stringify(r.label==='no-setup-code'?{...r,status:'refused',error:'registration_refused'}:r)).sort();
 assert.deepEqual(normalize(actual),normalize(expected),'deployed/local unsigned results differ');
}
export function browserScenarios(rid='1'.repeat(32)) {
 const html=['/','/r/'+rid,'/history','/credential-add'];
 const get=['/api/requests','/api/requests/'+rid,'/api/requests/'+rid+'/history','/api/history'];
 const post=['/api/requests/'+rid+'/approve/options','/api/requests/'+rid+'/approve/verify','/api/requests/'+rid+'/decline','/api/requests/'+rid+'/withdraw','/api/credential-add/options','/api/credential-add/prepare','/api/credential-add/verify','/api/logout','/api/logout/options','/api/session-revoke/options','/api/session-revoke/verify'];
 return [...html.map(path=>['GET',path,303]),...get.map(path=>['GET',path,401]),...post.map(path=>['POST',path,401])];
}
export async function unsigned({origin, tokens={}, request=fetch, registrationClosed=false}) {
 const rows=[];
 const call=async(label,method,path,body,headers,status,error)=>{
  const r=await request(origin+path,{method,headers:{Origin:origin,'Content-Type':'application/json',...headers},body:method==='POST'?typeof body==='string'?body:JSON.stringify(body??{}):undefined,redirect:'manual',signal:AbortSignal.timeout(10000)});
  assert.equal(r.status,status,label+': '+path);securityHeaders(r,label);
  if(error)assert.equal((await r.json()).error,error,label+': '+path);
  if(status===303)assert.equal(r.headers.get('location'),'/login'+(/^\/r\/[0-9a-f]{32}$/.test(path)?'#'+path:''));
  rows.push({label,method,path,status,error:error??null});return r;
 };
 for(const kind of ['none','forged-cookie','spoofed','wrong-token',...Object.keys(tokens)]) {
  const headers=kind==='none'?{}:kind==='forged-cookie'?{Cookie:'__Host-mapl_session=visibly-fake'}:kind==='spoofed'?{Origin:'https://evil.invalid','X-Authenticated-User':'owner'}:{Authorization:'Bearer '+(tokens[kind]??'visibly-fake-invalid-token')};
  for(const [method,path,status] of browserScenarios())await call(kind,method,path,'{invalid',headers,status,status===401?'session_required':null);
 }
 for(const role of ['runner','requester']) await call('wrong-role-token','POST',`/api/${role}/${role==='runner'?'claim':'requests'}`,{}, {Authorization:'Bearer visibly-fake-invalid-token'},403,'token_scope_refused');
 for(const path of ['/api/register/options','/api/register/verify']) {
  const r=await request(origin+path,{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:'{}',redirect:'manual',signal:AbortSignal.timeout(10000)});
  securityHeaders(r,path);const error=(await r.json()).error;
  if(registrationClosed){assert.equal(r.status,409,'registration must be closed');assert.equal(error,'registration_closed','registration must be closed');}assert(['setup_code_invalid','setup_code_expired','registration_closed'].includes(error), error);assert([403,409].includes(r.status));rows.push({label:'no-setup-code',method:'POST',path,status:r.status,error});
 }
 for(const path of ['/login?probe=1'])await call('invalid-route','GET',path,undefined,{},404,'route_not_found');
 if(tokens.requester) {
  const h={Authorization:'Bearer '+tokens.requester};
  await call('percent-route','POST','/api/requester/%61',{},h,404,'route_not_found');
  await call('body-limit','POST','/api/requester/requests','x'.repeat(131073),h,413,'body_too_large');
  for(const body of ['{invalid','{"request":{},"request":{}}'])await call('bad-json','POST','/api/requester/requests',body,h,400,'json_malformed');
 }
 for(const [role,token] of Object.entries(tokens)) {
  const h={Authorization:'Bearer '+token};
  for(const path of ['/api/register/options','/api/register/verify','/api/login/options','/api/login/verify'])await call(role,'POST',path,{},h,403,'token_scope_refused');
  await call(role,'POST',role==='runner'?'/api/requester/requests':'/api/runner/claim',{},h,403,'token_scope_refused');
 }
 if(tokens.runner)await call('runner-poll','GET','/api/runner/approved',undefined,{Authorization:'Bearer '+tokens.runner},200);
 if(tokens.requester&&tokens.runner) {
  const fixture=JSON.parse(readFileSync(new URL('../planning/impl/mapl_cloudflare/reference/request.json',import.meta.url)))[0].input;
  const version=await (await request(origin+'/version',{redirect:'manual',signal:AbortSignal.timeout(10000)})).json();
  assert.match(version.test_root_id,/^[0-9a-f]{32}$/);fixture.target.test_root_id=version.test_root_id;
  const h={Authorization:'Bearer '+tokens.requester}, runner={Authorization:'Bearer '+tokens.runner};
  const id=()=>crypto.randomUUID().replaceAll('-','');
  const requestBody={...fixture,request_id:id()};
  await call('operational-mode','POST','/api/requester/requests',{request:{...requestBody,mode:'operational'}},h,400,'request_invalid');
  await call('management-action','POST','/api/requester/requests',{request:{...requestBody,action_type:'credential_add/1'}},h,409,'action_type_refused');
  // Expired fixture and pending request cannot be claimed or reported as executed.
  for(const expired of [true,false]) {
   const now=Date.now(), stamp=t=>new Date(t).toISOString().replace(/\.\d{3}Z$/,'Z');
   const q={...requestBody,request_id:id(),created_at:stamp(now-3600000),expires_at:stamp(now+(expired?-1000:3600000)),window_utc:[stamp(now-3600000),stamp(now+3600000)]};
   await call('submit-'+expired,'POST','/api/requester/requests',{request:q},h,200);
   const body={request_id:q.request_id,revision:1,claim_id:'a'.repeat(32)};
   await call('unapproved-claim-'+expired,'POST','/api/runner/claim',body,runner,409,'not_claimable:'+(expired?'expired':'pending'));
   await call('unsigned-report-'+expired,'POST','/api/runner/report',{...body,event:'result',evidence:{}},runner,409,'claim_mismatch');
   if(!expired) {
    await call('revision','POST','/api/requester/requests',{request:{...q,revision:2}},h,200);
    await call('superseded','POST','/api/runner/claim',body,runner,409,'not_claimable:superseded');
    await call('cancel','POST','/api/requester/cancel',{request_id:q.request_id},h,200);
    for(let repeat=0;repeat<2;repeat++)await call('cancelled-reuse','POST','/api/runner/claim',{...body,revision:2},runner,409,'not_claimable:cancelled');
   }
  }
 }
 return rows;
}
if(process.argv[1]===new URL(import.meta.url).pathname) {
 let sensitive=[];
 try {
  const [reviewed,origin,merge='main',scenarioFlag,baseline,closedFlag]=process.argv.slice(2);assert.equal(origin,configuredOrigin(),'fixed mapl-test target only');
  assert(closedFlag===undefined||closedFlag==='--registration-closed','unknown verification option');const registrationClosed=closedFlag==='--registration-closed';
  assert.equal(merge,'main','fixed main branch only');
  const binding=await publicBinding({reviewed});
  const result=await verify({reviewed,origin,registrationClosed,read:file=>git('show',`${reviewed}:${file}`)});
  assert.deepEqual(await publicBinding({reviewed}),binding,'public main changed during verification');
  result.binding=binding;
  // Default is strictly public GET-only. Explicit --unsigned allows scoped test writes;
  // token input is stdin JSON, never CLI argv, environment, output, or setup code.
  if(scenarioFlag==='--unsigned') {
   let data='';for await(const chunk of process.stdin)data+=chunk;
   let tokens;try {tokens=JSON.parse(data||'{}');}catch {throw Error('stdin role-token JSON malformed');}
   sensitive=Object.values(tokens).filter(v=>typeof v==='string'&&v.length>0);assert(Object.keys(tokens).every(k=>['runner','requester'].includes(k)),'stdin accepts only runner and requester fields');
   result.unsigned=await unsigned({origin,tokens,registrationClosed});
   if(baseline) {
    compareResults(result.unsigned,JSON.parse(readFileSync(baseline,'utf8')),{registrationClosed});
    result.local_comparison=registrationClosed?'equal; registration_closed strictly observed':'equal (registration refusal category normalised; post-iPhone closure not verified)';
   }
  } else assert.equal(scenarioFlag,undefined);
  console.log(JSON.stringify({success:true,...result},null,2));
 } catch(e) { let message=e.message;for(const token of sensitive)message=message.replaceAll(token,'[redacted]');console.error('Verification failed: '+message+'; no passkey action is authorised.');process.exitCode=1; }
}
