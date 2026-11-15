import ts from 'typescript';
import { readdir,readFile,writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
function inspect(text,file){
  const source=ts.createSourceFile(file,text,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS),errors=[];let callbacks=0;
  const complain=(node,why)=>errors.push(`${file}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line+1}: ${why}`);
  for(const e of source.parseDiagnostics)errors.push(file+': '+ts.flattenDiagnosticMessageText(e.messageText,' '));
  function walk(node,inPhase2=false){
    if(ts.isDebuggerStatement(node)||ts.isWithStatement(node))complain(node,'debugger/with forbidden');
    if(ts.isVariableDeclarationList(node)&&!(node.flags&(ts.NodeFlags.Let|ts.NodeFlags.Const)))complain(node,'use const/let');
    if(ts.isBinaryExpression(node)&&[ts.SyntaxKind.EqualsEqualsToken,ts.SyntaxKind.ExclamationEqualsToken].includes(node.operatorToken.kind))complain(node,'use strict equality');
    if(ts.isImportDeclaration(node)){const name=node.moduleSpecifier.text;if(!name.startsWith('.')&&name!=='@simplewebauthn/server')complain(node,'unapproved runtime import');}
    if(ts.isCallExpression(node)){
      const e=node.expression,s=e.getText(source);
      if(['fetch','globalThis.fetch','self.fetch','eval','Function','require'].includes(s))complain(node,'outgoing fetch/dynamic execution forbidden');
      if(ts.isPropertyAccessExpression(e)&&e.name.text==='fetch'&&s!=="env.APPROVAL.get(env.APPROVAL.idFromName('mapl-approval-local-test')).fetch")complain(node,'only the fixed local DO service binding may receive fetch');
      if(ts.isElementAccessExpression(e)&&e.argumentExpression.getText(source).includes('fetch'))complain(node,'computed fetch forbidden');
      if(e.kind===ts.SyntaxKind.ImportKeyword)complain(node,'dynamic import forbidden');
    }
    if(ts.isNewExpression(node)&&['WebSocket','XMLHttpRequest','Function'].includes(node.expression.getText(source)))complain(node,'external network/dynamic execution forbidden');
    if(ts.isMethodDeclaration(node)&&node.name.getText(source)==='phase2'){
      const find=child=>{if(ts.isCallExpression(child)&&ts.isPropertyAccessExpression(child.expression)&&child.expression.name.text==='transactionSync'){
        const callback=child.arguments[0];callbacks++;if(!ts.isArrowFunction(callback)&&!ts.isFunctionExpression(callback))complain(callback,'phase2 must have inspectable callback');
        if(callback.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword))complain(callback,'phase2 callback cannot be async');
        const owner = node.parent, methods = new Map((owner.members ?? []).filter(ts.isMethodDeclaration).map(m => [m.name.getText(source), m])), visited = new Set();
        const syncWalk=n=>{
          if(n.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword))complain(n,'phase2 reachable method cannot be async');
          if(ts.isTypeReferenceNode(n)&&/^Promise(?:Like)?$/.test(n.typeName.getText(source)))complain(n,'phase2 reachable method cannot return Promise');
          if(ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)&&n.expression.expression.kind===ts.SyntaxKind.ThisKeyword){
            const name=n.expression.name.text, target=methods.get(name);
            if(target&&!visited.has(name)){visited.add(name);syncWalk(target);}
          }
          if(ts.isAwaitExpression(n))complain(n,'phase2 cannot await');if((ts.isNewExpression(n)||ts.isCallExpression(n))&&/^Promise(?:\.|$)/.test(n.expression.getText(source)))complain(n,'phase2 cannot create/return a Promise');ts.forEachChild(n,syncWalk);};syncWalk(callback);
      }ts.forEachChild(child,find);};find(node);
    }
    ts.forEachChild(node,n=>walk(n,inPhase2));
  }
  walk(source);return {errors,callbacks};
}
const files=(await readdir('src')).filter(n=>n.endsWith('.ts')&&!n.endsWith('.d.ts')),errors=[];let callbacks=0;
for(const file of files){const r=inspect(await readFile('src/'+file,'utf8'),file);errors.push(...r.errors);callbacks+=r.callbacks;}
assert.equal(callbacks,1,'one named approval phase2 transaction callback must be inspected');
// Resolve return types as well as token checks, so an async helper cannot be returned unnoticed.
const config=ts.readConfigFile('tsconfig.json',ts.sys.readFile),parsed=ts.parseJsonConfigFileContent(config.config,ts.sys,'.'),program=ts.createProgram(parsed.fileNames,parsed.options),checker=program.getTypeChecker();
const store=program.getSourceFile('src/store.ts');let checkedReturnTypes=0;
function typedWalk(n){if(ts.isMethodDeclaration(n)&&n.name.getText()==='phase2'){
  const find=x=>{if(ts.isCallExpression(x)&&ts.isPropertyAccessExpression(x.expression)&&x.expression.name.text==='transactionSync'){
    const callback=x.arguments[0],visited=new Set();
    const checkCalls=y=>{
      if(ts.isCallExpression(y)){
        const call=checker.getResolvedSignature(y);
        if(call){ const result=checker.getReturnTypeOfSignature(call); const types=result.isUnion()?result.types:[result]; assert(!types.some(t=>t.getProperty('then')), 'phase2 reachable call returns thenable: '+y.expression.getText()); }
        if(ts.isPropertyAccessExpression(y.expression)&&y.expression.expression.kind===ts.SyntaxKind.ThisKeyword){
          const symbol=checker.getSymbolAtLocation(y.expression.name);
          for(const declaration of symbol?.declarations??[])if(ts.isMethodDeclaration(declaration)&&!visited.has(declaration)){visited.add(declaration);checkCalls(declaration);}
        }
      }
      ts.forEachChild(y,checkCalls);
    };checkCalls(callback);
    const signature=checker.getSignatureFromDeclaration(callback),type=checker.getReturnTypeOfSignature(signature);assert(!type.getProperty('then'),'phase2 transaction callback returns thenable');assert(!(type.flags&ts.TypeFlags.Any),'phase2 callback return must be typed');checkedReturnTypes++;
  }ts.forEachChild(x,find);};find(n);
}ts.forEachChild(n,typedWalk);}typedWalk(store);assert.equal(checkedReturnTypes,1);
// Static rule negative controls: no production file is altered.
for(const [label,source] of [['await','class S { phase2(){return this.storage.transactionSync(async()=>{await f();});}}'],['promise','class S { phase2(){return this.storage.transactionSync(()=>Promise.resolve(1));}}'],['async recheckApproval', 'class S { phase2(){return this.storage.transactionSync(()=>{this.recheckApproval();return 1;});} async recheckApproval(){await f();} }'],['transitive Promise', 'class S { phase2(){return this.storage.transactionSync(()=>this.record());} record(){this.helper();} helper(){return Promise.resolve(1);} }'],['fetch','fetch("https://example.invalid")'],['member fetch','globalThis.fetch("https://example.invalid")']])assert(inspect(source,'static-mutant.ts').errors.length>0,label+' static negative control must fail');
assert.equal(errors.length,0,errors.join('\n'));
const result={lint:'PASS',rules:['syntax','no var','strict equality','no debugger/with','approved imports','no dynamic execution','no outgoing Worker fetch','phase2 and transitive this-methods no async/await/Promise','phase2 reachable call return types are synchronous'],runtime_files:files.length,phase2_callbacks:callbacks,typed_callbacks:checkedReturnTypes,static_negative_controls:6};
console.log(JSON.stringify(result,null,2));await writeFile('evidence/static-checks.json',JSON.stringify(result,null,2)+'\n');
