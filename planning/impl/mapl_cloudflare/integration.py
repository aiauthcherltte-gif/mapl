"""W4 single-pass localhost integration; never imports the Python server/store.

Run with the existing MAPLI Python environment and --evidence <new directory>.
The HTTP adapter is deliberately test-only: W2 fixes its origin to HTTP localhost.
MacRunner, its independent signature/key checks, and the mock kit are unchanged.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization

from ..mapl_test.canonical import b64decode, b64encode, canonical_bytes, digest, parse_json
from ..mapl_test.config import SCENARIOS
from ..mapl_test.errors import Refusal
from ..mapl_test.isolation import TestRoot
from ..mapl_test.mock_kit import MockKit
from ..mapl_test.runner_sim import HTTPTransport
from ..mapl_test.seed import seed
from ..mapl_test.tests.soft_authenticator import SoftAuthenticator
from .runner import MacRunner
from .transport import HTTPSTransport, RUNNER_ROUTES

ORIGIN = 'http://localhost:8790'
RUNNER_TOKEN = 'local-w4-runner-fixture-' * 3
REQUESTER_TOKEN = 'local-w4-requester-fixture-' * 3
CODE = 'LOCAL-W4-SETUP-ONLY'
BROWSER_COOKIE = ''
REPO = Path(__file__).resolve().parents[3]
PYTHON_ENTRY = 'import sys;sys.path.insert(0,sys.argv.pop(1));from planning.impl.mapl_cloudflare.integration import main;main()'


def loopback_only():
    """Refuse non-loopback socket destinations before a connection is made."""
    def audit(event, args):
        if event == 'socket.connect' and args[1][0] != '127.0.0.1':
            raise RuntimeError('W4 non-loopback connection refused')
    sys.addaudithook(audit)


def now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def api(method, path, body=None, token=None):
    global BROWSER_COOKIE
    if not (path.startswith('/api/') and '?' not in path):
        raise ValueError('test route refused')
    connection = http.client.HTTPConnection('127.0.0.1', 8790, timeout=10)
    try:
        headers = {'Host': 'localhost:8790', 'Origin': ORIGIN, 'Content-Type': 'application/json'}
        if BROWSER_COOKIE:
            headers['Cookie'] = BROWSER_COOKIE
        if token:
            headers['Authorization'] = 'Bearer ' + token
        connection.request(method, path, headers=headers,
                           body=None if body is None else canonical_bytes(body))
        response = connection.getresponse()
        if response.getheader('Set-Cookie'):
            BROWSER_COOKIE = response.getheader('Set-Cookie').split(';')[0]
        result = parse_json(response.read(2 * 1024 * 1024 + 1))
        if response.status != 200:
            raise Refusal(result.get('error', 'http_refused'), response.status)
        return result
    finally:
        connection.close()


class LocalWorkerTransport(HTTPSTransport):
    """Local equivalent only; inherits W3 poll/envelope and runner protocol checks.

    Reuses the frozen test-version HTTP wire method. No TLS trust setting or
    production HTTPSTransport code is changed, and this adapter accepts one origin.
    """
    def __init__(self):
        self.url = urlsplit('http://127.0.0.1:8790')
        self.origin, self.rp_id, self.token = ORIGIN, 'localhost', RUNNER_TOKEN
        self._envelopes, self.observations = [], []

    def call(self, method, path, body=None):
        if path not in RUNNER_ROUTES:
            raise Refusal('runner_route_refused')
        result = HTTPTransport.call(self, method, path, body)
        if path == '/api/runner/claim':
            record = api('GET', '/api/requests/' + body['request_id'])
            self.observations.append({'execution': record['execution'],
                                      'display_state': record['display_state'],
                                      'claim_id': body['claim_id']})
        return result


class Baseline:
    """Seed sink writes only the runner's immutable local manifest, no server."""
    def __init__(self, root):
        self.root = root

    def create_request(self, request):
        self.root.write_json('runner/manifests/' + request['request_id'] + '/1.json',
                             request, exclusive=True)


EXPECTED = {
    'normal': ('done', 1, '완료 · 시험 대상 포인터가 gen/0006을 가리킴 (모의 실행)'),
    'runner_offline': ('not_started', 0, '아직 실행 안 함 · Mac이 이 요청을 맡지 않았습니다'),
    'window_later': ('not_started', 0, None),
    'claim_response_lost': ('not_run', 0, '실행 안 됨 · 포인터 바뀐 것 없음 (Mac 보고)'),
    'crash_after_start': ('not_run', 0, '실행 안 됨 · 포인터 바뀐 것 없음 (Mac 보고)'),
    'crash_after_marker': ('failed_after_marker', 1, '실패 · 표시 뒤 실패, 포인터 바뀐 것 없음, 다시 실행 불가'),
    'kit_refuses': ('failed_no_change', 1, '실패 · 실행 전 거부, 포인터 바뀐 것 없음 (POINTER_BEFORE_MISMATCH)'),
    'result_unclear': ('unknown', 1, '결과 불명 · 자동으로 다시 실행하지 않습니다 · Core 확인 필요'),
    'double_click': ('done', 1, '완료 · 시험 대상 포인터가 gen/0006을 가리킴 (모의 실행)'),
}


def child():
    global BROWSER_COOKIE
    data = json.loads(sys.stdin.readline())
    BROWSER_COOKIE = data['browser_cookie']
    root = TestRoot.reopen_for_runner_test(data['root'], data['root_id'])
    transport, kit, runner = LocalWorkerTransport(), MockKit(root, now), None
    try:
        runner = MacRunner(root, transport, kit, now, scenario=data['scenario'],
                           takeover_after_crash=data.get('takeover', False))
        runner.step()
        # One request, an additional poll: closed work must never execute twice.
        if runner._active:
            runner.step()
        rid = data['rid']
        path = 'runner/records/' + rid + '.json'
        print(json.dumps({'kit_calls': kit.calls.get(rid, 0), 'swaps': kit.swaps.get(rid, 0),
                          'observations': transport.observations,
                          'record_sha256': digest(root.read_bytes(path)) if root.exists(path) else None,
                          'connection_state': runner.connection_state,
                          'schedule_failures': runner.schedule.failures}), flush=True)
    finally:
        if runner:
            runner.close()
        root.detach_runner_test()


def run_child(root, request, scenario, takeover=False):
    data = {'root': root.path, 'root_id': root.root_id, 'rid': request['request_id'],
            'scenario': scenario, 'takeover': takeover, 'browser_cookie': BROWSER_COOKIE}
    result = subprocess.run([sys.executable, '-I', '-B', '-c', PYTHON_ENTRY, str(REPO), '--child'],
                            input=json.dumps(data) + '\n', text=True, capture_output=True,
                            timeout=45, check=True)
    return json.loads(result.stdout)


def resources():
    pressure = int(subprocess.check_output(['sysctl', '-n', 'kern.memorystatus_vm_pressure_level'], text=True))
    memory = subprocess.check_output(['memory_pressure', '-Q'], text=True)
    free_percent = int(memory.split('free percentage: ')[1].split('%')[0])
    disk = subprocess.check_output(['df', '-k', '/System/Volumes/Data'], text=True)
    free_kib = int(disk.splitlines()[1].split()[3])
    value = {'pressure': pressure, 'memory_free_percent': free_percent, 'data_free_kib': free_kib}
    if pressure >= 3 or free_percent < 20 or free_kib < 12 * 1024 * 1024:
        raise RuntimeError('W4 resource stop: ' + json.dumps(value))
    return value


def listener_absent():
    with socket.socket() as sock:
        sock.settimeout(1)
        return sock.connect_ex(('127.0.0.1', 8790)) != 0


def scenario_run(name, server, evidence):
    global BROWSER_COOKIE
    BROWSER_COOKIE = ''
    root = TestRoot.create()
    started = False
    try:
        request = seed(root, Baseline(root), now(), name)
        server.stdin.write(json.dumps({'action': 'start', 'root_id': root.root_id}) + '\n')
        server.stdin.flush()
        ready = json.loads(server.stdout.readline())
        assert ready['ready'] == 'http://127.0.0.1:8790', ready
        started = True
        api('POST', '/api/requester/requests', {'request': request}, REQUESTER_TOKEN)
        auth = SoftAuthenticator()
        options = api('POST', '/api/register/options', {'code': CODE})
        registered = api('POST', '/api/register/verify', {
            'code': CODE, 'credential': auth.registration(b64decode(options['challenge']))})
        assert registered['credential_count'] == 1
        login = api('POST', '/api/login/options', {})
        api('POST', '/api/login/verify', {
            'challenge': login['challenge'], 'credential': auth.assertion(b64decode(login['challenge']))})
        assert BROWSER_COOKIE.startswith('__Host-mapl_session=')
        # Independently pin the fixture authenticator's PUBLIC key, never the server's key.
        spki = auth.key.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
        root.write_json('runner/pinned-credential.json', {
            'id': b64encode(auth.credential_id), 'spki': b64encode(spki)}, exclusive=True)
        rid, path = request['request_id'], '/api/requests/' + request['request_id']
        record = api('GET', path)
        options = api('POST', path + '/approve/options', {
            'revision': 1, 'content_hash': record['content_hash']})
        assertion = auth.assertion(b64decode(options['challenge']))
        def approve(_):
            try:
                api('POST', path + '/approve/verify', {'revision': 1, 'credential': assertion})
                return 'ok'
            except Refusal as error:
                return error.code
        if name == 'double_click':
            with ThreadPoolExecutor(max_workers=2) as pool:
                approvals = list(pool.map(approve, range(2)))
            assert approvals.count('ok') == 1 and set(approvals) <= {'ok', 'already_approved', 'nonce_used'}, approvals
        else:
            approvals = [approve(0)]
            assert approvals == ['ok'], approvals
        processes, intermediate = [], []
        if name != 'runner_offline':
            processes.append(run_child(root, request, name))
        if name == 'crash_after_start':
            record = api('GET', path)
            assert record['execution'] == 'running', record
            intermediate.append({'execution': record['execution'], 'display_state': record['display_state']})
            processes.append(run_child(root, request, 'normal', takeover=True))
            assert processes[0]['record_sha256'] == processes[1]['record_sha256']
        record = api('GET', path)
        execution, count, wording = EXPECTED[name]
        if name == 'window_later':
            wording = '아직 실행 안 함 · 실행 가능 시간 ' + request['window_utc'][0][11:16] + '부터'
        kit_calls = sum(p['kit_calls'] for p in processes)
        assert record['approval'] == 'approved' and record['execution'] == execution, record
        assert record['display_state'] == wording, (record['display_state'], wording)
        assert record['view']['state'] == wording and wording in record['view']['default_text']
        assert kit_calls == count and kit_calls <= 1, (name, kit_calls)
        history = record['history']
        assert sum(row['event'] == 'approve' for row in history) == 1
        claims = sum(row['event'] == 'claim' for row in history)
        assert claims == (0 if name in ('runner_offline', 'window_later') else 1), history
        assert all(p['connection_state'] == '연결됨' and p['schedule_failures'] == 0 for p in processes)
        if name == 'claim_response_lost':
            observations = processes[0]['observations']
            assert len(observations) == 3 and len({r['claim_id'] for r in observations}) == 1
            assert all(r['execution'] == 'claimed' and '대기' not in r['display_state'] for r in observations)
        result = {'scenario': name, 'runs': 1, 'passed': True, 'request_id': rid,
                  'expected_execution': execution, 'execution': record['execution'],
                  'display_state': record['display_state'], 'kit_calls': kit_calls,
                  'swaps': sum(p['swaps'] for p in processes), 'history': history,
                  'view': record['view'], 'approval_results': approvals,
                  'intermediate': intermediate, 'runner_processes': processes, 'server': ready}
        (evidence / (name + '.json')).write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        return result
    finally:
        if started:
            server.stdin.write('{"action":"stop"}\n')
            server.stdin.flush()
            assert json.loads(server.stdout.readline()) == {'stopped': True}
            assert listener_absent(), 'Worker listener remains after dispose'
        root.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--child', action='store_true')
    args = parser.parse_args()
    loopback_only()
    if args.child:
        return child()
    if not args.evidence or args.evidence.exists():
        parser.error('--evidence must be a new directory; prevents accidental reruns')
    assert tuple(EXPECTED) == SCENARIOS, 'scenario oracle coverage mismatch'
    assert listener_absent(), '127.0.0.1:8790 already occupied'
    args.evidence.mkdir(parents=True)
    summary = {'scenario_runs': [], 'resources': [{'before': 'launcher', **resources()}], 'passed': False}
    with (args.evidence / 'server-stderr.log').open('w') as errors:
        server = subprocess.Popen(['node', 'scripts/integration-server.mjs'], cwd=REPO,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, text=True)
        try:
            for name in SCENARIOS:
                summary['resources'].append({'before': name, **resources()})
                result = scenario_run(name, server, args.evidence)
                summary['scenario_runs'].append({'scenario': name, 'kit_calls': result['kit_calls'],
                                                  'execution': result['execution'], 'passed': True})
                print(name + ': PASS; ' + result['execution'] + '; kit=' + str(result['kit_calls']), flush=True)
            summary['passed'] = len(summary['scenario_runs']) == 9
        finally:
            server.stdin.close()
            try:
                summary['server_exit'] = server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.terminate()
                summary['server_exit'] = server.wait(timeout=10)
            summary['listener_absent'] = listener_absent()
            summary['resources'].append({'after': 'all', **resources()})
            (args.evidence / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    assert summary['passed'] and summary['server_exit'] == 0 and summary['listener_absent'], summary


if __name__ == '__main__':
    main()
