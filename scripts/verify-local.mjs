import {spawnSync} from 'node:child_process';
import {writeFile,mkdir} from 'node:fs/promises';
await mkdir('evidence',{recursive:true});
process.env.WRANGLER_SEND_METRICS='false';process.env.DO_NOT_TRACK='1';
const results=[];
for(const [label,args] of [['reference integrity',['scripts/check-reference.mjs']],['strict typecheck',['node_modules/typescript/bin/tsc','--noEmit']],['source lint and static controls',['scripts/check-source.mjs']],['Workers/SQLite suite',['node_modules/vitest/vitest.mjs','run']],['Node VM client witnesses',['tests/client-witnesses.mjs']]]){
  console.log('\n'+label);const result=spawnSync(process.execPath,args,{stdio:'inherit'});results.push({check:label,exit_code:result.status});if(result.error||result.status!==0){await writeFile('evidence/full-result.json',JSON.stringify({success:false,results},null,2)+'\n');process.exit(result.status??1);}
}
await writeFile('evidence/full-result.json',JSON.stringify({success:true,results},null,2)+'\n');
