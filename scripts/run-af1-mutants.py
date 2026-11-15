"""Local regression mutants: restore each source byte in finally, no operational calls."""
import json
import os
from pathlib import Path
import subprocess
import sys

PY_TEST = [sys.executable, '-I', '-B', '-c', 'import sys,unittest;sys.path.insert(0,".");unittest.main(module="planning.impl.mapl_cloudflare.tests.test_approval_flow")']
TS_TEST = ['node', 'node_modules/vitest/vitest.mjs', 'run', 'tests/approval-flow.test.ts']
MUTANTS = [
 ('minute-bound', 'planning/impl/mapl_test/request.py', 'seconds % 60 == 0', 'True', PY_TEST),
 ('descriptor-rebuild', 'planning/impl/mapl_test/request.py', "rebuilt['check'] = descriptor(MOCK_K7)", "rebuilt['check'] = request['check']", PY_TEST),
 ('pending-subset', 'planning/impl/mapl_test/flow.py', "all(x in r['check']['scope'] for x in pending)", 'True', PY_TEST),
 ('strict-exit', 'planning/impl/mapl_test/check_contract.py', 'exit_code != 3 or ', '', PY_TEST),
 ('recovery-current', 'planning/impl/mapl_test/runner_sim.py', "digest_pointer(self.root) == rec['only_if_current_sha256']", 'True', PY_TEST),
 ('recovery-start-deadline', 'planning/impl/mapl_test/runner_sim.py', "(now - utc(swap['at'])).total_seconds() <= request['check']['check_and_recover_max_s']", 'True', PY_TEST),
 ('recovery-entry-phase', 'planning/impl/mapl_test/check_contract.py', "phase != 'recovery_intent' or ", '', PY_TEST),
 ('restart-recheck', 'planning/impl/mapl_test/runner_sim.py', "event, evidence = 'check_unknown', copy.deepcopy(swap['evidence'])\n        self._report", "self._check_v2(rid, entry['revision'], entry['claim_id'], request)\n            event, evidence = 'check_unknown', copy.deepcopy(swap['evidence'])\n        self._report", PY_TEST),
 ('session-idle', 'src/store.ts', 's.idle_deadline > this.clock()', 'true', TS_TEST),
 ('session-absolute', 'src/store.ts', 's.absolute_deadline > this.clock()', 'true', TS_TEST),
 ('management-one-use', 'src/store.ts', "n && !n.used && n.session === session && n.action", "n && n.session === session && n.action", TS_TEST),
 ('restart-kit-gap', 'planning/impl/mapl_test/runner_sim.py', "swap = {'evidence': evidence}", 'return False', PY_TEST),
 ('unknown-check-evidence-py', 'planning/impl/mapl_test/flow.py', "or bool(c.get('checking_at'))", 'or True', PY_TEST),
 ('recovery-repeat-py', 'planning/impl/mapl_test/flow.py', "and not c.get('recovery_at') and not c.get('check_reported_unknown')", "and not c.get('check_reported_unknown')", PY_TEST),
 ('recovery-check-unknown-py', 'planning/impl/mapl_test/flow.py', "and not c.get('check_reported_unknown')", '', PY_TEST),
 ('unknown-check-evidence-ts', 'src/flow.ts', "|| Boolean(c.checking_at)", '|| true', TS_TEST),
 ('recovery-repeat-ts', 'src/flow.ts', "&& !c.recovery_at && !c.check_reported_unknown", '&& !c.check_reported_unknown', TS_TEST),
 ('recovery-check-unknown-ts', 'src/flow.ts', "&& !c.check_reported_unknown", '', TS_TEST),
]


def main():
    results=[]
    for label, name, old, new, command in MUTANTS:
        path=Path(name); original=path.read_bytes(); source=original.decode()
        if old not in source:raise RuntimeError('mutation target missing: '+label)
        try:
            path.write_text(source.replace(old,new,1))
            answer=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env={**os.environ,'WRANGLER_SEND_METRICS':'false','DO_NOT_TRACK':'1'},timeout=120)
            row={'mutant':label,'killed':answer.returncode!=0,'exit_code':answer.returncode}
            print(json.dumps(row),flush=True);results.append(row)
        finally:path.write_bytes(original)
    if not all(row['killed'] for row in results):raise SystemExit(1)


if __name__=='__main__':main()
