import { randomBytes, createHash } from 'node:crypto';
import { openSync, writeFileSync, fsyncSync, closeSync, realpathSync, statSync } from 'node:fs';
import { dirname, resolve, isAbsolute } from 'node:path';
import assert from 'node:assert/strict';
export function outsideSync(path) { const lower=path.toLowerCase(); return !lower.includes('/drives/sync')&&!lower.includes('/.worktrees/'); }
export function generate(path, entropy=randomBytes) {
 assert(isAbsolute(path),'absolute destination required');
 const parent=realpathSync(dirname(path)), target=resolve(parent,path.split('/').at(-1));
 assert(outsideSync(parent),'outside sync and worktrees only');
 const bytes=entropy(32);assert.equal(bytes.length,32);
 const token=bytes.toString('base64url'), hash=createHash('sha256').update(token).digest('hex');
 const fd=openSync(target,'wx',0o600);
 try {writeFileSync(fd,token+'\n');fsyncSync(fd);}finally {closeSync(fd);}
 assert.equal(statSync(target).mode&0o777,0o600);
 return {length:token.length,hash_prefix:hash.slice(0,8)};
}
if(process.argv[1]===new URL(import.meta.url).pathname) {
 try {console.log(JSON.stringify(generate(process.argv[2])));}catch {console.error('Token generation refused or failed');process.exitCode=1;}
}
