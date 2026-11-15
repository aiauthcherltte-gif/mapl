"""Audit locked npm archives without executing package code; registry only."""
import base64, hashlib, io, json, platform, sys, tarfile, urllib.request
from pathlib import Path
from urllib.parse import urlparse
ROOT=Path(__file__).resolve().parents[1]
CACHE=Path('/Users/rcp/AIFrameworkRuns/MAPLW2-npm-cache/locked-archives')
LIFECYCLE={'preinstall','install','postinstall','prepublish','preprepare','prepare','postprepare'}
MAGIC=(b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe',b'\x7fELF',b'MZ',b'\x00asm',b'\xfe\xed\xfa\xcf')
lock=json.loads((ROOT/'package-lock.json').read_text())['packages']
def host(p):
 def allows(values,actual): return not values or (actual not in [v[1:] for v in values if v.startswith('!')] and (all(v.startswith('!') for v in values) or actual in values))
 return allows(p.get('os'), 'darwin') and allows(p.get('cpu'), 'arm64' if platform.machine()=='arm64' else 'x64')
def sha(b): return hashlib.sha256(b).hexdigest()
def emit(name,v): (ROOT/'evidence'/name).write_text(json.dumps(v,indent=2)+'\n')
if sys.argv[1]=='before':
 CACHE.mkdir(parents=True,exist_ok=True); rows=[]
 for key,pkg in lock.items():
  if not key or not host(pkg): continue
  url=pkg['resolved']; assert urlparse(url).netloc=='registry.npmjs.org'
  dest=CACHE/(sha(url.encode())+'.tgz')
  if not dest.exists():
   with urllib.request.urlopen(url) as r:
    assert urlparse(r.url).netloc=='registry.npmjs.org'
    dest.write_bytes(r.read())
  data=dest.read_bytes(); alg,expected=pkg['integrity'].split('-',1)
  assert base64.b64encode(hashlib.new(alg,data).digest()).decode()==expected,key
  with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as tar:
   manifest=next(m for m in tar.getmembers() if m.name.endswith('/package.json') and m.name.count('/')==1)
   prefix_dir=manifest.name.rsplit('/',1)[0]+'/'
   meta=json.load(tar.extractfile(manifest))
   scripts={k:v for k,v in meta.get('scripts',{}).items() if k in LIFECYCLE}
   binaries=[]
   for member in tar.getmembers():
    if not member.isfile(): continue
    f=tar.extractfile(member); prefix=f.read(4)
    if prefix in MAGIC or member.name.endswith(('.node','.wasm','.exe')):
     content=prefix+f.read(); binaries.append({'path':member.name.removeprefix(prefix_dir),'sha256':sha(content),'bytes':len(content),'source_url':url})
  assert bool(scripts)==bool(pkg.get('hasInstallScript')) or not scripts.keys() & {'preinstall','install','postinstall'},key
  rows.append({'path':key,'name':meta['name'],'version':meta['version'],'source_url':url,'tarball_sha256':sha(data),'integrity':pkg['integrity'],'install_scripts':scripts,'binaries':binaries})
 emit('install-before.json',rows)
 print('Registered host archives',len(rows),'scripts',sum(bool(r['install_scripts']) for r in rows),'binaries',sum(len(r['binaries']) for r in rows))
else:
 before=json.loads((ROOT/'evidence/install-before.json').read_text()); expected={r['path']:r for r in before}; actual=[]
 for file in (ROOT/'node_modules').rglob('package.json'):
  key=file.parent.relative_to(ROOT).as_posix()
  if key not in lock: continue # package-owned fixture manifests are not installed modules
  m=json.loads(file.read_text()); assert key in expected,key
  r=expected[key]; assert m['version']==r['version'],key
  assert {k:v for k,v in m.get('scripts',{}).items() if k in LIFECYCLE}==r['install_scripts'],key
  for b in r['binaries']: assert sha((file.parent/b['path']).read_bytes())==b['sha256'],(key,b['path'])
  actual.append(r)
 # Unexpected node_modules module roots (including scoped and nested) are forbidden.
 for directory in [ROOT/'node_modules',*(ROOT/'node_modules').rglob('node_modules')]:
  for entry in directory.iterdir():
   if entry.name.startswith('.'): continue
   for candidate in (entry.iterdir() if entry.name.startswith('@') else [entry]):
    if candidate.is_dir(): assert candidate.relative_to(ROOT).as_posix() in expected,str(candidate)
 emit('install-after.json',sorted(actual,key=lambda r:r['path']))
 omitted=set(expected)-set(r['path'] for r in actual)
 assert all(lock[k].get('optional') for k in omitted),omitted
 emit('optional-omitted.json',sorted(omitted))
 print('Installed modules match lock, scripts and binary hashes:',len(actual))
if sys.argv[1]=='after':
 tree=json.loads((ROOT/'evidence/npm-ls-all.json').read_text()); edge_count=0
 def compare(row,parent=''):
  global edge_count
  for name,node in row.get('dependencies',{}).items():
   if not node: continue
   assert not node.get('extraneous') and not node.get('invalid') and not node.get('missing'),(name,node)
   if 'version' not in node: continue
   path=parent+'/node_modules/'+name if parent else 'node_modules/'+name
   while path not in lock:
    assert '/node_modules/' in path,path
    path=path.rsplit('/node_modules/',1)[0]
    path=(path.rsplit('/node_modules/',1)[0]+'/node_modules/'+name) if '/node_modules/' in path else 'node_modules/'+name
   assert node['version']==lock[path]['version'],path
   if node.get('resolved'): assert node['resolved']==lock[path]['resolved'],path
   edge_count+=1;compare(node,path)
 compare(tree)
 emit('npm-ls-lock-comparison.json',{'logical_edges_checked':edge_count,'unexpected_packages':0,'version_or_resolved_mismatches':0,'installed_module_paths_verified':len(actual)})
 print('npm ls edges match lock:',edge_count)
