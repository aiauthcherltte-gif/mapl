"""Child process entry used only by the local restart tests."""
import json
import sys
from datetime import datetime

from ...mapl_test.canonical import digest
from ...mapl_test.errors import Refusal
from ...mapl_test.isolation import TestRoot
from ...mapl_test.mock_kit import MockKit
from ..runner import MacRunner
from ..transport import HTTPSTransport


def main():
    data = json.loads(sys.stdin.readline())
    root = TestRoot.reopen_for_runner_test(data['root'], data['marker'])
    clock = lambda: datetime.fromisoformat(data['now'])
    transport = HTTPSTransport(data['origin'], data['test_token'], test_ca_pem=data['ca'])
    kit = MockKit(root, clock)
    runner = None
    try:
        runner = MacRunner(root, transport, kit, clock, scenario=data.get('scenario', 'normal'),
                           takeover_after_crash=data.get('takeover', False))
        if data.get('hold'):
            print('LOCKED', flush=True)
            sys.stdin.readline()
        else:
            runner.step()
            rid = data['rid']
            path = 'runner/records/' + rid + '.json'
            print(json.dumps({'calls': sum(kit.calls.values()),
                'record_sha256': digest(root.read_bytes(path)) if root.exists(path) else None,
                'journal_sha256': digest(root.read_bytes('runner/journal.json')) if root.exists('runner/journal.json') else None}), flush=True)
            if data.get('hold_after_step'):
                sys.stdin.readline()
    except Refusal as error:
        print(json.dumps({'refusal': error.code}), flush=True)
        return 2
    finally:
        if runner:
            runner.close()
        root.detach_runner_test()
    return 0
