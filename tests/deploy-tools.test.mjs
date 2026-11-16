import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { verify, unsigned, compareResults, publicBinding } from '../scripts/verify-deployed.mjs';
import { generate, outsideSync } from '../scripts/generate-token.mjs';
// CI uses neutral test-only policy when no local policy was supplied.
process.env.MAPL_FORBIDDEN_PATHS ||= JSON.stringify(['/sync-fixture/', '/worktree-fixture/']);
test('configure refuses placeholders and renders one valid test profile',()=>{
 const dir=mkdtempSync(join(tmpdir(),'mapl-config-fixture-'));
 try {
  mkdirSync(join(dir,'scripts'));writeFileSync(join(dir,'scripts/configure.mjs'),readFileSync('scripts/configure.mjs'));
  writeFileSync(join(dir,'wrangler.local.toml'),readFileSync('wrangler.local.toml'));
  const valid={SUBDOMAIN:'visibly-fake-fixture',RUNNER_TOKEN_SHA256:'a'.repeat(64),REQUESTER_TOKEN_SHA256:'b'.repeat(64)};
  for(const patch of [{SUBDOMAIN:'REPLACE_ME'},{RUNNER_TOKEN_SHA256:'REPLACE_WITH_REVIEWED_SHA256'},{REQUESTER_TOKEN_SHA256:'REPLACE_WITH_REVIEWED_SHA256'},{REQUESTER_TOKEN_SHA256:valid.RUNNER_TOKEN_SHA256}]) {
   writeFileSync(join(dir,'deploy-profile.json'),JSON.stringify({...valid,...patch}));
   assert.throws(()=>execFileSync(process.execPath,['scripts/configure.mjs'],{cwd:dir,stdio:'pipe'}));
  }
  writeFileSync(join(dir,'deploy-profile.json'),JSON.stringify({SUBDOMAIN:'visibly-fake-fixture',RUNNER_TOKEN_SHA256:'a'.repeat(64),REQUESTER_TOKEN_SHA256:'b'.repeat(64)}));
  execFileSync(process.execPath,['scripts/configure.mjs'],{cwd:dir,stdio:'pipe',env:{...process.env,WORKERS_CI_COMMIT_SHA:'c'.repeat(40)}});
  const text=readFileSync(join(dir,'wrangler.toml'),'utf8');assert(text.includes('main = "src/worker.ts"'));assert(text.includes('name = "mapl-test"'));assert(text.includes('https://mapl-test.visibly-fake-fixture.workers.dev'));assert(!text.includes('BUILD_COMMIT'));assert(text.includes('send_metrics = false'));assert(text.includes('command = "node scripts/check-deploy.mjs"')); assert(text.includes('new_sqlite_classes = ["MaplApproval"]'));
 }finally {rmSync(dir,{recursive:true});}
});
test('synthetic generator fixture is exclusive 0600 and reports only length and hash prefix',()=>{
 const dir=mkdtempSync(join(tmpdir(),'mapl-token-fixture-'));
 try {
  const path=join(dir,'visibly-fake-token');const info=generate(path,()=>Buffer.alloc(32,0));
  assert.deepEqual(Object.keys(info),['length','hash_prefix']);assert.equal(info.hash_prefix.length,8);assert.equal(info.length,43);
  assert.equal(statSync(path).mode&0o777,0o600);assert.throws(()=>generate(path,()=>Buffer.alloc(32,0)));
  for(const part of JSON.parse(process.env.MAPL_FORBIDDEN_PATHS)) { assert.equal(outsideSync(part.toUpperCase()+'/work'),false); }
 } finally {rmSync(dir,{recursive:true});}
});
test('token helpers fail clearly without required local policy',()=>{
 const saved=process.env.MAPL_FORBIDDEN_PATHS;
 try {delete process.env.MAPL_FORBIDDEN_PATHS;assert.throws(()=>outsideSync('/fixture'),/set MAPL_FORBIDDEN_PATHS/);}
 finally {process.env.MAPL_FORBIDDEN_PATHS=saved;}
});
test('optional Python mock adapter sync guard uses PATH, never a Mac venv',t=>{
 const probe=spawnSync(process.env.MAPL_PYTHON||'python3',['-I','-B','-c','import cryptography'],{encoding:'utf8'});
 if(probe.error||probe.status!==0){t.skip('Python mock adapter check needs python3 with cryptography on PATH; Worker build has no Python dependency');return;}
 execFileSync(process.env.MAPL_PYTHON||'python3',['-I','-B','tests/mock-mac-fixture.py'],{stdio:'pipe'});
 execFileSync(process.env.MAPL_PYTHON||'python3',['-I','-B','-c',"import runpy; m=runpy.run_path('scripts/mock-mac.py'); import os,json; assert all(not m['outside_sync'](p.upper()+'/work') for p in json.loads(os.environ['MAPL_FORBIDDEN_PATHS']))"],{stdio:'pipe'});
});
test('public check against local HTTP server detects mismatches with no build stamp',async()=>{
 let mutation='';const commit='a'.repeat(40);
 const assets={'/login':'public/index.html','/register':'public/index.html','/static/app.js':'public/app.js.txt','/static/app.css':'public/app.css.txt'};
 const headers={'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",'X-Frame-Options':'DENY','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
 const server=createServer((req,res)=>{
  for(const [key,value] of Object.entries(headers))if(mutation!=='headers')res.setHeader(key,value);
  if(req.url==='/version'){res.end(JSON.stringify({mode:mutation==='mode'?'operational':'test',operational:false,commit:null,registration:'closed'}));return;}
  if(!assets[req.url]){res.writeHead(404).end();return;}
  res.end(mutation==='asset'?Buffer.from('modified'):readFileSync(assets[req.url]));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try {
  const options={reviewed:commit,origin:`http://127.0.0.1:${server.address().port}`,read:readFileSync};
  assert.equal((await verify(options)).observations.length,4);
  for(mutation of ['asset','mode','headers'])await assert.rejects(verify(options));
 }finally {await new Promise(resolve=>server.close(resolve));}
});
test('signature-free W7 replay against real isolated Worker and SQLite',async()=>{
 process.env.WRANGLER_SEND_METRICS='false';process.env.DO_NOT_TRACK='1';
 const {build}=await import('esbuild');const {Miniflare}=await import('miniflare');
 const {outputFiles:[worker]}=await build({stdin:{contents: "import Worker, {MaplApproval as Base} from './src/worker'; export class MaplApproval extends Base { async fetch(req) { if(req.headers.get('X-Test-Fixture-Closed')==='yes') this.store.saveCredential({id:'visibly-fake-public-credential',revoked:false}); return super.fetch(req); } } export default { async fetch(req, env) { const body = req.body ? await req.arrayBuffer() : undefined; const headers = new Headers(req.headers); headers.set('Host', new URL(env.ORIGIN).host); return Worker.fetch(new Request(env.ORIGIN + (new URL(req.url).pathname + new URL(req.url).search), {method:req.method,headers,body,redirect:'manual'}), env); } };",resolveDir:process.cwd(),loader:'ts'},bundle:true,format:'esm',platform:'browser',loader:{'.html':'text','.txt':'text'},write:false});
 const tokens={runner:'visibly-fake-runner-fixture-0000000000',requester:'visibly-fake-requester-fixture-0000000'};
 const hash=t=>createHash('sha256').update(t).digest('hex');
 const origin='https://mapl-test.visibly-fake-fixture.workers.dev';
 const mf=new Miniflare({modules:true,script:worker.text,compatibilityDate:'2025-10-04',cf:false,durableObjectsPersist:false,durableObjects:{APPROVAL:{className:'MaplApproval',useSQLite:true}},bindings:{SETUP_CODE:'LOCAL-TEST-SETUP-ONLY',MODE:'test',SUBDOMAIN:'visibly-fake-fixture',ORIGIN:origin,RP_ID:new URL(origin).hostname,TEST_ROOT_ID:'2'.repeat(32),RUNNER_TOKEN_SHA256:hash(tokens.runner),REQUESTER_TOKEN_SHA256:hash(tokens.requester),BUILD_COMMIT:'a'.repeat(40)},outboundService:()=>{throw Error('outgoing network forbidden');}});
 try {
  let fixtureClosed=false;
  const request=async(url,opts)=>{try{return await mf.dispatchFetch(url,{...opts,headers:{...opts.headers,...(fixtureClosed?{'X-Test-Fixture-Closed':'yes'}:{}),...(opts.body===undefined?{}:{'Content-Length':String(Buffer.byteLength(opts.body))})},body:opts.body===undefined?undefined:Buffer.from(opts.body)});}catch(e){throw new Error(opts.method+' '+new URL(url).pathname,{cause:e});}};
  const verified=await verify({reviewed:'a'.repeat(40),origin,read:readFileSync,request});assert.equal(verified.observations.length,4);for(const row of verified.observations)assert.match(row.sha256,/^[0-9a-f]{64}$/);
  const rows=await unsigned({origin,tokens,request});assert(rows.length>100);
  writeFileSync('evidence/w7-local.json',JSON.stringify(rows,null,2)+'\n'); compareResults(rows,[...rows].reverse());console.log('W7 local comparison scenarios:',rows.length);
  await assert.rejects(unsigned({origin,tokens,request,registrationClosed:true}),/registration must be closed/);
  await assert.rejects(verify({reviewed:'a'.repeat(40),origin,read:readFileSync,request,registrationClosed:true}),/registration must be closed/);
  fixtureClosed=true;
  const closed=await unsigned({origin,tokens,request,registrationClosed:true});compareResults(closed,rows,{registrationClosed:true});
  assert.equal((await verify({reviewed:'a'.repeat(40),origin,read:readFileSync,request,registrationClosed:true})).version.registration,'closed');
  writeFileSync('evidence/w7-local-closed.json',JSON.stringify(closed,null,2)+'\n');
 }finally {await mf.dispose();}
});

test('local/deployed comparison tolerates registration-state refusal and row ordering only',()=>{
 const a=[{label:'scope',status:403},{label:'no-setup-code',status:403,error:'setup_code_invalid'}];
 compareResults(a,[{label:'no-setup-code',status:409,error:'registration_closed'},a[0]]);
 assert.throws(()=>compareResults(a,[{label:'scope',status:200},a[1]]));
 const closed=[a[0],...['/api/register/options','/api/register/verify'].map(path=>({label:'no-setup-code',path,status:409,error:'registration_closed'}))];
 compareResults(closed,closed,{registrationClosed:true});
 assert.throws(()=>compareResults([closed[0],{...closed[1],status:403,error:'setup_code_invalid'},closed[2]],closed,{registrationClosed:true}));
});
test('check ③ requires reviewed second parent and an identical merge tree',async()=>{
 const {reviewedTree}=await import('../scripts/verify-deployed.mjs');
 const dir=mkdtempSync(join(tmpdir(),'mapl-merge-fixture-')), previous=process.cwd();
 const git=(...args)=>execFileSync('git',['-c','user.name=Fixture','-c','user.email=fixture@localhost','-c','commit.gpgsign=false','-c','core.hooksPath=/dev/null',...args],{cwd:dir,stdio:['ignore','pipe','pipe']}).toString().trim();
 try {
  git('init');writeFileSync(join(dir,'public.txt'),'base');git('add','.');git('commit','-m','base');const base=git('rev-parse','HEAD');
  writeFileSync(join(dir,'public.txt'),'reviewed');git('commit','-am','reviewed');const reviewed=git('rev-parse','HEAD');
  const merge=git('commit-tree',git('rev-parse','HEAD^{tree}'),'-p',base,'-p',reviewed,'-m','merge');git('update-ref','refs/heads/main',merge);
  process.chdir(dir);assert.equal(reviewedTree(reviewed),merge);assert.throws(()=>reviewedTree(base));assert.throws(()=>reviewedTree('short'));
  const wrongParent=git('commit-tree',git('rev-parse',reviewed+'^{tree}'),'-p',base,'-m','different history');
  const sameTree=git('commit-tree',git('rev-parse',reviewed+'^{tree}'),'-p',base,'-p',wrongParent,'-m','same tree wrong second parent');git('update-ref','refs/heads/main',sameTree);
  git('diff','--quiet',reviewed,'main');assert.throws(()=>reviewedTree(reviewed),/merge second parent differs/);
  const altered=git('commit-tree',git('rev-parse',base+'^{tree}'),'-p',base,'-p',reviewed,'-m','altered');git('update-ref','refs/heads/main',altered);assert.throws(()=>reviewedTree(reviewed));
 }finally {process.chdir(previous);rmSync(dir,{recursive:true});}
});

test('committed configuration equals deterministic output with or without CI stamp',async()=>{
 const {render}=await import('../scripts/configure.mjs');
 const current=readFileSync('wrangler.toml','utf8');
 const committed=execFileSync('git',['show','HEAD:wrangler.toml']).toString();
 assert.equal(committed,render(),'committed config must equal configure output');
 assert.equal(current,render());assert(current.includes('main = "src/worker.ts"'));
 const saved=process.env.WORKERS_CI_COMMIT_SHA;
 try {process.env.WORKERS_CI_COMMIT_SHA='c'.repeat(40);assert.equal(render(),current);}
 finally {if(saved===undefined)delete process.env.WORKERS_CI_COMMIT_SHA;else process.env.WORKERS_CI_COMMIT_SHA=saved;}
 execFileSync(process.execPath,['scripts/check-deploy.mjs'],{stdio:'pipe'});
});
test('public GitHub binding refuses wrong parent/tree, missing commit, redirect and non-merge',async()=>{
 const reviewed='a'.repeat(40),head='b'.repeat(40),tree='c'.repeat(40);let mutation='';const calls=[];
 const request=async(url,opts)=>{
  calls.push(url);assert.equal(opts.method,'GET');assert.equal(opts.redirect,'manual');assert(!('Authorization' in opts.headers));
  assert(url.startsWith('https://api.github.com/repos/aiauthcherltte-gif/mapl/commits/'));
  if(mutation==='unavailable')return new Response('{}',{status:403});
  if(mutation==='redirect')return new Response('{}',{status:302});
  const main=url.endsWith('/main');
  return Response.json({sha:main?head:mutation==='sha'?'d'.repeat(40):reviewed,parents:main?(mutation==='single'?[{sha:reviewed}]:[{sha:'d'.repeat(40)},{sha:mutation==='parent'?'d'.repeat(40):reviewed}]):[],commit:{tree:{sha:main&&mutation==='tree'?'e'.repeat(40):tree}}});
 };
 assert.deepEqual(await publicBinding({reviewed,request}),{repository:'aiauthcherltte-gif/mapl',branch:'main',head,reviewed,tree});
 mutation='single';await assert.rejects(publicBinding({reviewed,request}),/main head is not a merge commit; Require linear history or squash\/rebase merge must be off/);
 for(mutation of ['parent','tree','sha','single','unavailable','redirect'])await assert.rejects(publicBinding({reviewed,request}));
 await assert.rejects(publicBinding({reviewed:'short',request}));
 await assert.rejects(publicBinding({reviewed,repository:'other/repo',request}));
 assert(calls.length>2);
});
test('default npx cannot silently install missing Wrangler',()=>{
 assert.match(readFileSync('.npmrc','utf8'),/^yes=false$/m);
 const dir=mkdtempSync(join(tmpdir(),'mapl-npx-fixture-'));
 try {
  writeFileSync(join(dir,'.npmrc'),readFileSync('.npmrc'));
  mkdirSync(join(dir,'fixture'));
  writeFileSync(join(dir,'fixture','package.json'),JSON.stringify({name:'mapl-visibly-fake-package',version:'1.0.0',bin:{'mapl-fake':'bin.js'}}));
  writeFileSync(join(dir,'fixture','bin.js'),'#!/usr/bin/env node\nthrow Error("MUST_NOT_EXECUTE")');
  const blocked=spawnSync('npx',['--offline','--package',join(dir,'fixture'),'--','mapl-fake'],{cwd:dir,encoding:'utf8',env:{...process.env,npm_config_cache:join(dir,'empty-cache'),npm_config_userconfig:join(dir,'empty-user'),npm_config_globalconfig:join(dir,'empty-global')}});
  assert.notEqual(blocked.status,0);assert.match(blocked.stderr,/npx canceled/);assert(!blocked.stderr.includes('MUST_NOT_EXECUTE'));
  assert.throws(()=>execFileSync('npx',['--offline','wrangler','--version'],{cwd:dir,stdio:'pipe',env:{...process.env,npm_config_cache:join(dir,'empty-cache'),npm_config_userconfig:join(dir,'empty-user'),npm_config_globalconfig:join(dir,'empty-global')}}));
 }finally {rmSync(dir,{recursive:true});}
});
test('requester helper uses stdin only and refuses non-test destinations and state',async()=>{
 const {submit}=await import('../scripts/submit-request.mjs');
 const requestBody=JSON.parse(readFileSync('planning/impl/mapl_cloudflare/reference/request.json'))[0].input;
 const state={mode:'test',root_id:requestBody.target.test_root_id,request:requestBody};
 const deployment={SUBDOMAIN:'visibly-fake-fixture',TEST_ROOT_ID:state.root_id};
 const token='visibly-fake-requester-fixture-0000000';let calls=0;
 const request=async(url,opts)=>{calls++;assert.equal(url,'https://mapl-test.visibly-fake-fixture.workers.dev/api/requester/requests');assert.equal(opts.headers.Authorization,'Bearer '+token);assert.deepEqual(JSON.parse(opts.body),{request:requestBody});return new Response('{}',{status:200});};
 const opts={state,deployment,token,request};assert.deepEqual(await submit(opts),{status:200});
 for(const patch of [{origin:'https://mapl.visibly-fake-fixture.workers.dev'},{state:{...state,mode:'operational'}},{state:{...state,request:{...requestBody,mode:'operational'}}},{deployment:{...deployment,TEST_ROOT_ID:'e'.repeat(32)}},{state:{...state,request:{...requestBody,action_type:'credential_add/1'}}}])await assert.rejects(submit({...opts,...patch}));
 assert.equal(calls,1);
 for(const purpose of ['v2','withdraw-target']) {
  assert.deepEqual(await submit({...opts,state:{...state,device_requests:{[purpose]:requestBody}},purpose}),{status:200});
 }
 await assert.rejects(submit({...opts,purpose:'other'}));
 await assert.rejects(submit({...opts,purpose:'v2'}));
 const dir=mkdtempSync(join(tmpdir(),'mapl-submit-fixture-'));
 try {
  mkdirSync(join(dir,'scripts'));for(const f of ['submit-request.mjs','configure.mjs'])writeFileSync(join(dir,'scripts',f),readFileSync('scripts/'+f));
  writeFileSync(join(dir,'deploy-profile.json'),JSON.stringify(deployment));writeFileSync(join(dir,'state.json'),JSON.stringify(state));
  writeFileSync(join(dir,'preload.mjs'),"globalThis.fetch=async (url,opts)=>{if(opts.headers.Authorization!=='Bearer visibly-fake-requester-fixture-0000000')throw Error('wrong stdin token');return new Response('{}',{status:200});};");
  const stdout=execFileSync(process.execPath,['--import',join(dir,'preload.mjs'),'scripts/submit-request.mjs','state.json'],{cwd:dir,input:token+'\n',stdio:['pipe','pipe','pipe']}).toString();assert.deepEqual(JSON.parse(stdout),{status:200});assert(!stdout.includes(token));
  assert.throws(()=>execFileSync(process.execPath,['scripts/submit-request.mjs','state.json','forbidden-extra-argument'],{cwd:dir,input:token,stdio:'pipe'}));
 }finally {rmSync(dir,{recursive:true});}
});
test('verification CLI exposes labelled failure without tokens',()=>{
 try {execFileSync(process.execPath,['scripts/verify-deployed.mjs','short','https://wrong.invalid'],{stdio:'pipe'});assert.fail('must refuse');}
 catch(e){assert.match(e.stderr.toString(),/Verification failed:/);assert.match(e.stderr.toString(),/fixed mapl-test target only|input did not match/);assert(!e.stderr.toString().includes('Bearer '));}
});
