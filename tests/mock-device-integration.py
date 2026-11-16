"""Two device-check requests through the unchanged localhost Worker and MacRunner.

Synthetic local profile only; no role token files, public target, or browser.
"""
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

module = runpy.run_path('scripts/mock-mac.py')
from planning.impl.mapl_cloudflare import integration as wire
from planning.impl.mapl_test.canonical import b64decode, b64encode, digest
from planning.impl.mapl_test.tests.soft_authenticator import SoftAuthenticator
from cryptography.hazmat.primitives import serialization


def main():
    wire.loopback_only()
    wire.resources()
    assert wire.listener_absent()
    root = module['TestRoot'].create()
    server = subprocess.Popen(['node', 'scripts/integration-server.mjs'], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    started = False
    try:
        with tempfile.TemporaryDirectory(prefix='mapl-device-local-') as directory:
            state = Path(directory) / 'state.json'
            baseline = module['seed'](root, module['Baseline'](root), wire.now())
            data = {'mode': 'test', 'root': root.path, 'root_id': root.root_id, 'request': baseline}
            state.write_text(json.dumps(data))
            server.stdin.write(json.dumps({'action': 'start', 'root_id': root.root_id}) + '\n')
            server.stdin.flush()
            assert json.loads(server.stdout.readline())['ready'] == 'http://127.0.0.1:8790'
            started = True
            auth = SoftAuthenticator()
            options = wire.api('POST', '/api/register/options', {'code': wire.CODE})
            wire.api('POST', '/api/register/verify', {'code': wire.CODE, 'credential': auth.registration(b64decode(options['challenge']))})
            login = wire.api('POST', '/api/login/options', {})
            wire.api('POST', '/api/login/verify', {'challenge': login['challenge'], 'credential': auth.assertion(b64decode(login['challenge']))})
            root.write_json('runner/pinned-credential.json', {'id': b64encode(auth.credential_id),
                'spki': b64encode(auth.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))}, exclusive=True)
            # W8 predecessor really completes through this Worker/MacRunner,
            # leaving gen/0006, journal, immutable record and original marker.
            wire.api('POST', '/api/requester/requests', {'request': baseline}, wire.REQUESTER_TOKEN)
            path = '/api/requests/' + baseline['request_id']
            record = wire.api('GET', path)
            options = wire.api('POST', path + '/approve/options', {'revision': 1, 'content_hash': record['content_hash']})
            wire.api('POST', path + '/approve/verify', {'revision': 1, 'credential': auth.assertion(b64decode(options['challenge']))})
            module['mark_submission'](data)
            prior = wire.run_child(root, baseline, 'normal')
            assert prior['swaps'] == prior['kit_calls'] == 1
            assert wire.api('GET', path)['execution'] == 'done'
            assert digest(root.read_bytes(root.pointer())) == baseline['target']['after_sha256']
            protected = {path: root.read_bytes(path) for path in (
                'runner/records/' + baseline['request_id'] + '.json',
                'runner/manifests/' + baseline['request_id'] + '/1.json',
                'kit/used/' + baseline['request_id'] + '.json',
                'kit/results/' + baseline['request_id'] + '.json',
                'runner/submission-attempted.json')}
            prior_record = wire.api('GET', '/api/requests/' + baseline['request_id'])
            data, v2 = module['device_request'](state, data, 'v2', wire.now)
            data, withdraw = module['device_request'](state, data, 'withdraw-target', wire.now)
            for request in (v2, withdraw):
                assert request['target']['from_generation'] == 'gen/0006'
                assert request['target']['to_generation'] == 'gen/0005'
                assert request['target']['before_sha256'] == baseline['target']['after_sha256']
            assert v2['check']['scope'] == ['pointer_bytes', 'pinned_reader', 'collector', 'screen']
            # Run the actual JS submit helper with its fixed HTTPS assertion intact;
            # the injected test fetch delivers those exact bytes to localhost only.
            for purpose in ('v2', 'withdraw-target'):
                module['mark_submission']({**data, 'request': data['device_requests'][purpose]})
                script = """import {submit} from './scripts/submit-request.mjs';
import {readFileSync} from 'node:fs';
import http from 'node:http';
const state=JSON.parse(readFileSync(process.argv[1]));
await submit({state,purpose:process.argv[2],token:'local-w4-requester-fixture-'.repeat(3),
deployment:{SUBDOMAIN:'visibly-fake-fixture',TEST_ROOT_ID:state.root_id},
request:(_url,options)=>new Promise((resolve,reject)=>{
 const req=http.request('http://127.0.0.1:8790/api/requester/requests',
 {method:options.method,headers:{...options.headers,Origin:'http://localhost:8790',Host:'localhost:8790'}},
 res=>{res.resume();res.on('end',()=>resolve({status:res.statusCode}));});
 req.on('error',reject);req.end(options.body);
})});"""
                subprocess.run(['node', '--input-type=module', '-e', script, str(state), purpose], check=True, timeout=20)
            for request in (v2, withdraw):
                path = '/api/requests/' + request['request_id']
                record = wire.api('GET', path)
                options = wire.api('POST', path + '/approve/options', {'revision': 1, 'content_hash': record['content_hash']})
                wire.api('POST', path + '/approve/verify', {'revision': 1, 'credential': auth.assertion(b64decode(options['challenge']))})
                if request is v2:
                    assert record['view']['failure'] == ('교체 전에 멈추면 바뀌는 것이 없습니다. '
                        '교체 뒤 포인터·읽기·수집기·화면 확인이 실패하면, 교체 뒤 10분 안에 한 번만 이전 화면으로 자동 복구를 시작합니다. '
                        '복구 조건이 맞지 않거나 복구가 거부되면 다시 시도하지 않고 멈춥니다. '
                        '이때 어느 화면이 남는지는 보장하지 않으며 확인을 요청합니다. '
                        '결과가 불분명하면(복구 포함) 다시 실행하지 않고 멈춥니다. 그때 화면이 어느 쪽인지는 확인 전까지 알 수 없습니다.')
            path = '/api/requests/' + withdraw['request_id']
            wire.api('POST', path + '/withdraw', {})
            withdrawn_before = wire.api('GET', path)
            result = wire.run_child(root, v2, 'normal')
            record = wire.api('GET', '/api/requests/' + v2['request_id'])
            assert record['execution'] == 'done', record
            assert record['display_state'] == '완료 · 포인터·읽기 확인됨 · 수집기·화면 확인 대기'
            assert record['pending'] == ['collector', 'screen']
            journal = root.read_json('runner/journal.json')[v2['request_id']]
            check_rows = [row['evidence'] for row in journal['rows'] if row['state'] == 'check_result']
            assert check_rows == [{'event': 'check_ok', 'evidence': {'pending': ['collector', 'screen']}}], check_rows
            assert [x for x in v2['check']['scope'] if x not in record['pending']] == ['pointer_bytes', 'pinned_reader']
            assert result['swaps'] == result['kit_calls'] == 1
            assert digest(root.read_bytes(root.pointer())) == v2['target']['after_sha256']
            assert not root.exists('kit/recovery/' + v2['request_id'] + '.json')
            assert not root.exists('kit/used/' + withdraw['request_id'] + '.json')
            assert not root.exists('runner/records/' + withdraw['request_id'] + '.json')
            withdrawn_after = wire.api('GET', path)
            assert {k: v for k, v in withdrawn_before.items() if k not in ('runner_status', 'server_now')} == {k: v for k, v in withdrawn_after.items() if k not in ('runner_status', 'server_now')}, [k for k in withdrawn_before if withdrawn_before[k] != withdrawn_after[k]]
            assert withdrawn_after['approval'] == 'withdrawn' and withdrawn_after['claim_id'] is None
            assert sum(x['event'] == 'claim' for x in record['history']) == 1
            for path, original in protected.items():
                assert root.read_bytes(path) == original, path
            prior_after = wire.api('GET', '/api/requests/' + baseline['request_id'])
            # Recovery may resend the original v1 result; its closed state/history
            # must remain identical, as must its immutable local execution record.
            assert {k: v for k, v in prior_record.items() if k not in ('runner_status', 'server_now')} == {k: v for k, v in prior_after.items() if k not in ('runner_status', 'server_now')}
            print('PASS: executed W8 predecessor preserved, gen/0006 to gen/0005, two submissions, longest recovery line, v2 claim/swap/check/report, exact verified/pending, no recovery, withdrawn request untouched')
    finally:
        if started:
            server.stdin.write('{"action":"stop"}\n'); server.stdin.flush()
            assert json.loads(server.stdout.readline()) == {'stopped': True}
        server.stdin.close()
        try:
            code = server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.terminate(); code = server.wait(timeout=10)
        errors = server.stderr.read()
        if code: print(errors, file=sys.stderr)
        root.cleanup()
        assert code == 0 and wire.listener_absent()

if __name__ == '__main__': main()
