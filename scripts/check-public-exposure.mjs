import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';

export function readInternalNames(env=process.env) {
 const message='Set MAPL_EXPOSURE_NAMES to a nonempty JSON array of nonblank internal names (local configuration only).';
 let names;
 try { names=JSON.parse(env.MAPL_EXPOSURE_NAMES); } catch { throw Error(message); }
 if(!Array.isArray(names)||!names.length||names.some(name=>typeof name!=='string'||!name.trim()))throw Error(message);
 return names;
}
export const publicBlobPins = {
 "planning/impl/mapl_cloudflare/reference/manifest-v2.json": "775dce6e6a8312363ec9"+"4b1c42fc7cbcaab485d5",
 "planning/impl/mapl_cloudflare/reference/canonical-v2.json": "feea4644e50edf3eb555"+"9f290002297f612bc357",
 "planning/impl/mapl_cloudflare/reference/request-v2.json": "0c619a9256ec9e971d58"+"7ccea826b5772db40543",
 "planning/impl/mapl_cloudflare/reference/state-v2.json": "0fe5c81f146f121fcfce"+"24f637cb447184d36616",
 "planning/impl/mapl_cloudflare/generate_reference.py": "b5012a7aea06c2fbed12"+"7da5e7c756718f05e124",
 "planning/impl/mapl_cloudflare/reference/canonical.json": "8fd8fc1dbce6278717f2"+"2832accb43cfebe645a3",
 "planning/impl/mapl_cloudflare/reference/challenge.json": "fc02849d20b4b53e482d"+"97d294549819446e29d8",
 "planning/impl/mapl_cloudflare/reference/manifest.json": "f175364df6b97dcae50d"+"773ee907039178a2d1dc",
 "planning/impl/mapl_cloudflare/reference/request.json": "8deba491cd0e58f5e72f"+"95131932ce01a5f5c8c7",
 "planning/impl/mapl_cloudflare/reference/state.json": "41c4e359a00146b9ea86"+"2e5c7437b3876869aa6e",
 "planning/impl/mapl_cloudflare/reference/wording.json": "f30c7f407ef71707a7b5"+"cc709845cb153b1f7f50",
};
export const exampleEmails = []; // No example address exceptions.
export function entropy(value) { return [...new Set(value)].reduce((sum,c)=>{const p=[...value].filter(x=>x===c).length/value.length;return sum-p*Math.log2(p);},0); }
const hash = value => createHash('sha256').update(value).digest('hex').slice(0,12);
const git = (cwd,args) => execFileSync('git',args,{cwd,maxBuffer:64*1024*1024,stdio:['ignore','pipe','pipe']});
export function scanText(text, location, {publicValues=new Set(), metadata=false, skipSecrets=false, internalNames=readInternalNames()}={}) {
 const findings=[];
 const add=(line,rule,value)=>findings.push({location,line,rule,hash:hash(value)});
 text.split('\n').forEach((line,i)=>{
  for(const m of line.matchAll(/(?:\/(?:Users|home)\/[^\s"'<>]+|\/(?:private\/)?var\/(?:folders|tmp)\/[^\s"'<>]*|\/Volumes\/[^\s"'<>]+|(?:[A-Za-z]:\\Users\\)[^\s"'<>]+|\/(?:private\/)?tmp\/[^\s"'<>]+)/gi))add(i+1,'local-path',m[0]);
  for(const name of internalNames)if(line.toLowerCase().includes(name.toLowerCase()))add(i+1,'internal-name',name);
  for(const m of line.matchAll(/[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi)) {
   if(!/^[^@]+@users\.noreply\.github\.com$/i.test(m[0])&&!exampleEmails.includes(m[0]))add(i+1,'email',m[0]);
  }
  // Long hex or base64(url) atoms. Hash fixtures and lock integrity are
  // public content too: exception values are independently derived below.
  for(const m of line.matchAll(/(?<![A-Za-z0-9_+/-])[A-Za-z0-9_+/-]{32,}={0,2}(?![A-Za-z0-9_+/-])/g)) {
   const value=m[0];
   if(skipSecrets||publicValues.has(value)||new Set(value).size===1)continue;
   // Only these exact standard lockfile fields are public digest syntax.
   if(location==='package-lock.json' && /^\s*"integrity":\s*"sha(?:512-[A-Za-z0-9+/]{86}==|1-[A-Za-z0-9+/]{27}=)",?\s*$/.test(line))continue;
   if(location==='planning/impl/mapl_test/requirements.lock' && /^[a-zA-Z0-9_-]+==[0-9.]+ --hash=sha256:[0-9a-f]{64}$/.test(line))continue;
   if(/^[0-9a-f]{32,}$/i.test(value)||value.length>=40&&/[a-z]/i.test(value)&&/[0-9]/.test(value)&&entropy(value)>=4.5)add(i+1,'secret-like',value);
  }
  if(metadata && /^(author|committer)-email=/.test(line) && !/^(author|committer)-email=[^@\s]+@users\.noreply\.github\.com$/i.test(line))add(i+1,'metadata-email',line);
 });
 return findings;
}
export function check({cwd=process.cwd(),tree='HEAD',commits='HEAD',filesOnly=false,internalNames=readInternalNames()}={}) {
 const listing=git(cwd,['ls-tree','-rz','--full-tree',tree]).toString().split('\0').filter(Boolean);
 const files=listing.map(row=>{const tab=row.indexOf('\t');const [mode,type,oid]=row.slice(0,tab).split(' ');if(type!=='blob')throw Error('unsupported tree entry');return {name:row.slice(tab+1),mode,oid};});
 // Only the reviewed public deployment bindings are exempt from secret rules.
 const publicValues=new Set([
  "90795500328ee763"+"fef9d9340ee49004"+"331a480bf25667e5"+"e32abaeb105f6ecf",
  "78e5650b5aaf87ca"+"6339b063bc367276"+"4e504d7586834f77"+"a69a7cafd1b354c3",
  "358aa38c4e0ecb6c"+"d913970dea380e12",
 ]);
 const findings=[];
 for(const f of files) {
  findings.push(...scanText(f.name,'<filename>',{publicValues,internalNames}));
  const location=scanText(f.name,'<filename>',{internalNames}).length?'file-sha256:'+hash(f.name):f.name;
  findings.push(...scanText(git(cwd,['cat-file','blob',f.oid]).toString('utf8'),location,{publicValues,internalNames,skipSecrets:publicBlobPins[f.name]===f.oid}));
 }
 let commitCount=0;
 if(!filesOnly){
  const ids=commits.includes('..')?git(cwd,['rev-list',commits]).toString().trim().split('\n').filter(Boolean):[git(cwd,['rev-parse','--verify',commits+'^{commit}']).toString().trim()];
  for(const id of ids){
   commitCount++;
   const meta=git(cwd,['show','-s','--format=author-name=%an%nauthor-email=%ae%ncommitter-name=%cn%ncommitter-email=%ce%nmessage=%B',id]).toString();
   findings.push(...scanText(meta,'commit:'+id.slice(0,12),{metadata:true,internalNames}));
  }
 }
 return {files:files.length,commits:commitCount,findings};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 try {
  const options={};const args=process.argv.slice(2);
  while(args.length){const arg=args.shift();if(arg==='--files-only')options.filesOnly=true;else if(['--tree','--commits'].includes(arg)){if(!args.length||args[0].startsWith('--'))throw Error('missing argument');options[arg.slice(2)]=args.shift();}else throw Error('unknown argument');}
  const result=check(options);
  for(const f of result.findings)console.log(`${f.location}:${f.line}: ${f.rule} sha256:${f.hash}`);
  console.log(`Public exposure: ${result.files} files, ${result.commits} commits, ${result.findings.length} findings`);
  process.exitCode=result.findings.length?1:0;
 }catch{console.error('Public exposure check failed: set MAPL_EXPOSURE_NAMES to a nonempty JSON array of nonblank internal names; also check arguments, tree and metadata.');process.exitCode=2;}
}
