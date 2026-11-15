import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync,mkdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
import {scanText as scanWithNames,check as checkWithNames,readInternalNames,entropy,publicBlobPins} from '../scripts/check-public-exposure.mjs';
// Unit fixtures never inherit private runtime policy.
const internalNames=['private-fixture-name','fixture/workspace'];
const scanText=(text,location,options={})=>scanWithNames(text,location,{internalNames,...options});
const check=(options={})=>checkWithNames({internalNames,...options});
const cliEnv={...process.env,MAPL_EXPOSURE_NAMES:JSON.stringify(internalNames)};
const secret=['0123456789','abcdefABCDEF','ghijklMNOPQR','stuvWXYZ_-'].join('');
const email=['fixture','example.invalid'].join('@');
const noreply=['fixture','users.noreply.github.com'].join('@');
test('path forms, account and configured internal names are detected',()=>{
 for(const path of [['','Users','fixture','work'],['','home','fixture','work'],['','private','var','folders','abc'],['','Volumes','disk','work'],['','tmp','work'],['','var','folders','abc'],['','var','tmp','abc']].map(parts=>parts.join('/')).concat('C:'+'\\Users\\fixture\\work'))assert(scanText(path,'fixture').some(f=>f.rule==='local-path'));
 for(const name of internalNames)assert(scanText(name,'fixture').some(f=>f.rule==='internal-name'));
});
test('email rules cover files, metadata and exact noreply domain',()=>{
 assert(scanText(email,'fixture').some(f=>f.rule==='email'));
 assert.equal(scanText(noreply,'fixture').length,0);
 assert(scanText(noreply+'.invalid','fixture').some(f=>f.rule==='email'));
 assert(scanText('author-email=','fixture',{metadata:true}).some(f=>f.rule==='metadata-email'));
});
test('secret atoms, explicit public values and repeated-digit threshold',()=>{
 assert(entropy(secret)>=4.5);
 for(const value of [secret,'abcdef0123456789'.repeat(4),['aB3dE5gH7jK9mN2pQ4sT6','vW8yZ0cF1iL3oR5uX7z'].join('')])assert(scanText(value,'fixture').some(f=>f.rule==='secret-like'));
 assert.equal(scanText('2'.repeat(32),'fixture').length,0);
 assert(scanText('2'.repeat(31)+'3','fixture').some(f=>f.rule==='secret-like'));
 assert.equal(scanText(secret,'fixture',{publicValues:new Set([secret])}).length,0);
 assert(scanText('committer-email=local','fixture',{metadata:true}).some(f=>f.rule==='metadata-email'));
 const finding=scanText(secret,'fixture')[0];assert.equal(finding.hash.length,12);assert(!JSON.stringify(finding).includes(secret));
});
test('exact structural digest fields preserve other rules and reject impostors',()=>{
 const integrity='  "integrity": "sha512-'+Buffer.from(secret.padEnd(64,'x')).toString('base64')+'",';
 assert.equal(scanText(integrity,'package-lock.json').length,0);
 assert(scanText(integrity,'other.json').length>0);
 assert(scanText('  "integrity": "sha512-'+secret+'",','package-lock.json').length>0);
 assert(scanText('"other": "'+secret+'"','package-lock.json').length>0);
 const requirement='fixture==1.0 --hash=sha256:'+'abcdef0123456789'.repeat(4);
 assert.equal(scanText(requirement,'planning/impl/mapl_test/requirements.lock').length,0);
 assert(scanText(requirement,'other.lock').length>0);
 assert(scanText(email,'fixture',{skipSecrets:true}).some(f=>f.rule==='email'));
 assert(scanText(internalNames[0],'fixture',{skipSecrets:true}).some(f=>f.rule==='internal-name'));
});
test('git tree, commit/range metadata and CLI use committed data and redact',()=>{
 const dir=mkdtempSync(join(tmpdir(),'mapl-public-fixture-'));
 const git=(...args)=>execFileSync('git',args,{cwd:dir,stdio:['ignore','pipe','pipe']}).toString().trim();
 const commit=(address)=>{git('-c','user.name=Fixture','-c','user.email='+address,'commit','-qm','fixture');return git('rev-parse','HEAD');};
 try {
  git('init','-q');writeFileSync(join(dir,'safe.txt'),'safe');git('add','.');const first=commit(noreply);
  assert.equal(check({cwd:dir}).findings.length,0);
  writeFileSync(join(dir,'unsafe.txt'),secret+'\n'+email+'\n'+internalNames[1]);writeFileSync(join(dir,internalNames[0]),'safe');git('add','.');const second=commit(email);
  writeFileSync(join(dir,'unsafe.txt'),'safe uncommitted');
  const result=check({cwd:dir,commits:first+'..'+second});assert.equal(result.commits,1);assert(result.findings.some(f=>f.location.startsWith('commit:')));assert(result.findings.some(f=>f.location==='unsafe.txt'&&f.line===1));
  assert.equal(check({cwd:dir,tree:first,commits:first}).findings.length,0);
  assert(result.findings.some(f=>f.location==='<filename>'&&f.rule==='internal-name'));
  assert(result.findings.some(f=>f.location==='unsafe.txt'&&f.line===3&&f.rule==='internal-name'));
  const cli=spawnSync(process.execPath,[join(process.cwd(),'scripts/check-public-exposure.mjs')],{cwd:dir,encoding:'utf8',env:cliEnv});assert.equal(cli.status,1);assert(!cli.stdout.includes(secret));assert(!cli.stdout.includes(email));assert.match(cli.stdout,/internal-name/);for(const name of internalNames)assert(!cli.stdout.includes(name));
  const invalid=spawnSync(process.execPath,[join(process.cwd(),'scripts/check-public-exposure.mjs'),'--tree','invalid'],{cwd:dir,encoding:'utf8',env:cliEnv});assert.equal(invalid.status,2);
 }finally{rmSync(dir,{recursive:true});}
});
test('blob pins cease to apply after a file changes',()=>{
 const [path,oid]=Object.entries(publicBlobPins)[0];
 const dir=mkdtempSync(join(tmpdir(),'mapl-pin-fixture-'));
 const git=(...args)=>execFileSync('git',args,{cwd:dir,stdio:['ignore','pipe','pipe']}).toString().trim();
 try {
  git('init','-q');
  // Preserve the exact source blob in a temporary Git database.
  const source=execFileSync('git',['cat-file','blob',oid]);
  mkdirSync(join(dir,path,'..'),{recursive:true});writeFileSync(join(dir,path),source);
  git('add','.');const tree=git('write-tree');
  assert.equal(check({cwd:dir,tree,filesOnly:true}).findings.length,0);
  writeFileSync(join(dir,path),source.toString()+'\n'+secret);git('add','.');
  const changed=check({cwd:dir,tree:git('write-tree'),filesOnly:true});
  assert(changed.findings.some(f=>f.rule==='secret-like'));
  writeFileSync(join(dir,path),source.toString()+'\n'+email);git('add','.');
  assert(check({cwd:dir,tree:git('write-tree'),filesOnly:true}).findings.some(f=>f.rule==='email'));
 }finally{rmSync(dir,{recursive:true});}
});

test('runtime policy rejects missing, empty and invalid configuration without disclosure',()=>{
 for(const value of [undefined,'','[]','null','{}','[null]','[1]','[""]','[" "]','invalid']) {
  const env={...process.env};delete env.MAPL_EXPOSURE_NAMES;
  if(value!==undefined)env.MAPL_EXPOSURE_NAMES=value;
  assert.throws(()=>readInternalNames(env),/Set MAPL_EXPOSURE_NAMES/);
  const result=spawnSync(process.execPath,['scripts/check-public-exposure.mjs'],{encoding:'utf8',env});
  assert.equal(result.status,2);
  assert.match(result.stderr,/MAPL_EXPOSURE_NAMES.*nonempty JSON array/);
  assert.equal(result.stdout,'');
 }
 assert.deepEqual(readInternalNames(cliEnv),internalNames);
 assert(scanWithNames(internalNames[0].toUpperCase(),'fixture',{internalNames:readInternalNames(cliEnv)}).some(f=>f.rule==='internal-name'));
});
test('committed tree contains none of the runtime internal names',{
 skip:process.env.MAPL_EXPOSURE_NAMES===undefined?'MAPL_EXPOSURE_NAMES unset; supply local policy to audit the committed tree':false,
},()=>{
 const result=checkWithNames({filesOnly:true});
 assert.deepEqual(result.findings.filter(f=>f.rule==='internal-name'),[]);
});
