import subprocess, sys, json, os, pathlib
C = pathlib.Path(__file__).resolve().parents[1]
M = [
 ('P1 profile: operational mode admitted', 'src/profile.ts', "if (env.MODE !== 'test') return false;", "if (env.MODE !== 'test' && env.MODE !== 'operational') return false;"),
 ('P2 profile: RP_ID not pinned to host', 'src/profile.ts', "env.RP_ID === 'mapl-test.' + sub + '.workers.dev' && ", "typeof env.RP_ID === 'string' && "),
 ('P3 profile: ORIGIN scheme not https', 'src/profile.ts', "env.ORIGIN === 'https://' + env.RP_ID", "env.ORIGIN!.endsWith('://' + env.RP_ID)"),
 ('P4 profile: placeholder subdomain admitted', 'src/profile.ts', "/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(sub)", "/^[A-Za-z0-9_-]+$/.test(sub)"),
 ('P5 profile: worker name not pinned (mapl-*)', 'src/profile.ts', "env.RP_ID === 'mapl-test.' + sub + '.workers.dev'", "/^mapl[a-z-]*\\./.test(env.RP_ID!) && env.RP_ID!.endsWith('.' + sub + '.workers.dev')"),
 ('T1 token: malformed/placeholder digest falls back to raw secret', 'src/secrets.ts', "    const valid = typeof hash === 'string' && /^[0-9a-f]{64}$/", "    if (!(typeof hash === 'string' && /^[0-9a-f]{64}$/.test(hash))) return secretEqual(auth, typeof raw === 'string' && raw.length >= 32 ? 'Bearer ' + raw : undefined, 39);\n    const valid = typeof hash === 'string' && /^[0-9a-f]{64}$/"),
 ('T2 token: raw token accepted on deployed profile', 'src/secrets.ts', "if (env.ORIGIN === 'http://localhost:8790' && env.RP_ID === 'localhost' && hash === undefined)", "if (typeof raw === 'string' && raw.length >= 32 && 'Bearer ' + raw === auth)"),
 ('T3 token: runner digest also opens requester', 'src/worker.ts', "['/api/requester/', this.env.REQUESTER_TOKEN_SHA256, this.env.REQUESTER_TOKEN]", "['/api/requester/', this.env.RUNNER_TOKEN_SHA256, this.env.REQUESTER_TOKEN]"),
 ('T4 token: bearer on public routes tolerated', 'src/worker.ts', "} else if (publicRoute) need(!auth, 'token_scope_refused', 403);", "}"),
 ('T5 token: bearer on browser routes falls to cookie check', 'src/worker.ts', "                need(!auth, 'session_required', 401);\n", ""),
 ('T6 token: valid digest of either role opens any role path', 'src/secrets.ts', "const equal = (crypto.subtle as SubtleCrypto & { timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean }).timingSafeEqual(actual, expected);\n    return valid && equal;", "const equal = (crypto.subtle as SubtleCrypto & { timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean }).timingSafeEqual(actual, expected);\n    return valid && (equal || [env.RUNNER_TOKEN_SHA256, env.REQUESTER_TOKEN_SHA256].includes(Array.from(actual, b => b.toString(16).padStart(2, '0')).join('')));"),
 ('C1 configure: hash placeholder admitted', 'scripts/configure.mjs', "for(const key of ['RUNNER_TOKEN_SHA256','REQUESTER_TOKEN_SHA256']) assert.match(p[key], /^[0-9a-f]{64}$/, key+' placeholder must be replaced by reviewed public digest');", ""),
 ('C2 configure: subdomain placeholder admitted', 'scripts/configure.mjs', "assert.match(p.SUBDOMAIN, /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/);", "assert.match(p.SUBDOMAIN, /^[A-Za-z0-9_-]+$/);"),
 ('C3 configure: workers_dev left false / name left local', 'scripts/configure.mjs', ".replace('mapl-local-only','mapl-test')", ""),
 ('C4 verify: public merge second-parent check skipped', 'scripts/verify-deployed.mjs', " assert.equal(head.parents[1].sha,reviewed,'public merge second parent differs');\n", ""),
 ('C5 verify: public merge tree check skipped', 'scripts/verify-deployed.mjs', " assert.equal(head.commit?.tree?.sha,commit.commit.tree.sha,'public merge tree differs');\n", ""),
]
# T5 is the reviewer's authority-equivalent browser-cookie mutant; opt in explicitly.
sel = sys.argv[1:] or [m[0].split()[0] for m in M if not m[0].startswith('T5 ')]
before = {(C / f): (C / f).read_bytes() for _, f, _, _ in M}
env = dict(os.environ, WRANGLER_SEND_METRICS='false', DO_NOT_TRACK='1')
out = []
for name, f, old, new in M:
    if name.split()[0] not in sel: continue
    p = C / f; src = p.read_text()
    assert src.count(old) == 1, (name, src.count(old))
    p.write_text(src.replace(old, new))
    try:
        v = subprocess.run(['node','node_modules/vitest/vitest.mjs','run'], cwd=C, env=env, capture_output=True, text=True, timeout=300)
        t = subprocess.run(['node','--test','tests/deploy-tools.test.mjs'], cwd=C, env=env, capture_output=True, text=True, timeout=300)
        tc = subprocess.run(['node','node_modules/typescript/bin/tsc','--noEmit'], cwd=C, env=env, capture_output=True, text=True, timeout=300)
        failed = [l.strip() for l in (v.stdout+v.stderr).splitlines() if l.strip().startswith(('×','FAIL'))][:6] + [l.strip() for l in t.stdout.splitlines() if l.strip().startswith('✖')][:4]
        r = {'mutant': name, 'vitest_rc': v.returncode, 'tools_rc': t.returncode, 'tsc_rc': tc.returncode, 'killed': v.returncode != 0 or t.returncode != 0, 'failing': failed}
    finally:
        p.write_text(src)
    print(json.dumps(r, ensure_ascii=False), flush=True); out.append(r)
restored = all(p.read_bytes() == data for p, data in before.items())
print('source restored:', restored, flush=True)
sys.exit(0 if restored and all(r['killed'] for r in out) else 1)
