"""Harness-written fixed-template report. Never infer an authenticator source."""
from .errors import Refusal

SENTENCES = frozenset((
    'Local test server code only.',
    'Browser WebAuthn API called in a test harness.',
    'Virtual authenticator signature verified (automated, no person).',
    'Signature verification passed for a test key.',
    'Simulated runner code uses the in-process instance model.',
    'Mock execution on the test target completed.',
    'Test pointer is confined to a fresh temporary test root.',
    'Notice text preview only; Telegram is not connected.',
    'Test RP ID is localhost.',
    'Cross-process restart is outside this test version.',
    'No run was performed under the coordinator hold.',
    'Test group has not run.',
    'Test group passed.',
    'Test group failed.',
))
FORBIDDEN = ('인증 성공', '승인 완료', '실행 완료', '게시 완료', 'published', 'authenticated',
    'approved by the user', 'authentication succeeded', 'passkey authentication succeeded',
    'publication executed', 'device authentication succeeded', 'executed', '실행됨', '게시됨',
    'Face ID', 'iPhone', 'user approved', 'real runner', 'Mac runner', 'notification sent',
    'deployed', 'web app live', 'the user approved a real publication', 'execution completed',
    'gen/0006 live', 'CURRENT', 'screen pointer')

# Each outcome sentence has its own required evidence. Browser and protocol
# evidence remain separate: a protocol PASS never claims a browser API call.
_EVIDENCE = {
    'Virtual authenticator signature verified (automated, no person).': ('BIND', 'REG'),
    'Signature verification passed for a test key.': ('BIND', 'REG'),
    'Mock execution on the test target completed.': ('ST', 'DP', 'BIND', 'REG'),
    'Browser WebAuthn API called in a test harness.': ('E2E',),
}


def _supports(sentence, auth_source, results):
    return auth_source == 'virtual_authenticator' and all(results.get(group) == 'PASS' for group in _EVIDENCE[sentence])


def build_report(auth_source, results):
    if auth_source not in ('virtual_authenticator', 'not_run'):
        raise Refusal('report_source_refused')
    if not isinstance(results, dict) or any(value not in ('PASS', 'FAIL', 'NOT RUN') for value in results.values()):
        raise Refusal('report_results_refused')
    # Results/identifiers are structured data; prose accepts no caller-supplied text.
    sentences = ['Local test server code only.', 'Simulated runner code uses the in-process instance model.',
        'Test pointer is confined to a fresh temporary test root.',
        'Notice text preview only; Telegram is not connected.', 'Test RP ID is localhost.',
        'Cross-process restart is outside this test version.']
    if auth_source == 'not_run':
        sentences.append('No run was performed under the coordinator hold.')
    else:
        sentences.extend(sentence for sentence in _EVIDENCE if _supports(sentence, auth_source, results))
    result = {'format': 'mapl-test-report/1', 'auth_source': auth_source,
              'runner': 'simulated', 'kit': 'mock', 'target': 'isolated_test_target',
              'sentences': sentences, 'results': dict(results)}
    validate_report(result)
    return result


def validate_report(value):
    if (not isinstance(value, dict) or set(value) != {'format', 'auth_source', 'runner', 'kit', 'target', 'sentences', 'results'}
        or value['format'] != 'mapl-test-report/1' or value['auth_source'] not in ('virtual_authenticator', 'not_run')
        or value['runner'] != 'simulated' or value['kit'] != 'mock' or value['target'] != 'isolated_test_target'
        or not isinstance(value['sentences'], list) or any(sentence not in SENTENCES for sentence in value['sentences'])):
        raise Refusal('report_template_refused')
    if (not isinstance(value['results'], dict)
        or any(key not in ('ST', 'DP', 'ISO', 'LBL', 'BIND', 'REG', 'E2E', 'EXTRA') for key in value['results'])
        or any(result not in ('PASS', 'FAIL', 'NOT RUN') for result in value['results'].values())):
        raise Refusal('report_template_refused')
    if (value['auth_source'] == 'not_run' and any(result != 'NOT RUN' for result in value['results'].values())):
        raise Refusal('report_evidence_refused')
    for sentence in value['sentences']:
        if sentence in _EVIDENCE and not _supports(sentence, value['auth_source'], value['results']):
            raise Refusal('report_evidence_refused')
        if sentence == 'No run was performed under the coordinator hold.' and value['auth_source'] != 'not_run':
            raise Refusal('report_evidence_refused')
        if sentence == 'Test group passed.' and 'PASS' not in value['results'].values():
            raise Refusal('report_evidence_refused')
        if sentence == 'Test group failed.' and 'FAIL' not in value['results'].values():
            raise Refusal('report_evidence_refused')
        if sentence == 'Test group has not run.' and 'NOT RUN' not in value['results'].values():
            raise Refusal('report_evidence_refused')
    return True


def write_report(root, auth_source, results):
    value = build_report(auth_source, results)
    root.write_json('reports/run.json', value)
    return value
