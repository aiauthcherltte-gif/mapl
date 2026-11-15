"""W1 oracle: fixture construction and calls to the reviewed test-version functions.

Run with an isolated interpreter via unittest-style explicit workspace bootstrap.
No validation or state-transition rules are reimplemented here. JSON duplicate-key
rejection is deliberately a fixed expectation, independently of the oracle.
MAPLW13F canonical/refusal decisions are handwritten fixed files, never generated.
"""
import copy
import hashlib
import json
import os
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from ..mapl_test import canonical, request, state, ui
from ..mapl_test.errors import Refusal
from ..mapl_test.isolation import NOT_COVERED

DESTINATION = Path(__file__).with_name('reference')
SOURCE_COMMIT = '0bc608b056540f750d8f66a8693f366a3f7cd4db'
CONTRACT_DECISION = 'MAPLW13F: CLOCK_SKEW accepted; safe integers; code-point key ordering'


def fixture():
    return {'format': 'mapl-request/1', 'mode': 'test', 'request_id': '1' * 32,
        'revision': 1, 'action_type': 'screen_publication/1',
        'created_at': '2026-11-14T06:00:00Z', 'expires_at': '2026-11-14T08:00:00Z',
        'window_utc': ['2026-11-14T06:00:00Z', '2026-11-14T08:00:00Z'],
        'target': {'pointer': 'test-screen/CURRENT.json', 'test_root_id': '2' * 32,
            'from_generation': 'gen/0005', 'to_generation': 'gen/0006',
            'before_sha256': '3' * 64, 'after_sha256': '4' * 64},
        'kit': {'name': 'mock-kit/1', 'sha256': '5' * 64},
        'bundle': {'name': 'gen/0006', 'sha256': '6' * 64},
        'not_covered': list(NOT_COVERED), 'recovery': {'included_in_this_approval': False},
        'summary_by_ai': '시험 자료 참고'}


def outcome(function, *args):
    try:
        return {'accepted': True, 'value': function(*args)}
    except Refusal as error:
        return {'accepted': False, 'reason': error.code, 'status': error.status}
    except UnicodeEncodeError:
        return {'accepted': False, 'exception': 'UnicodeEncodeError'}


def write(name, value):
    # Artifact serialization is not an oracle. ASCII transport preserves lone
    # surrogates in the negative input cases without encoding them as UTF-8.
    data = (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode()
    (DESTINATION / name).write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def canonical_cases():
    values = [None, True, False, '', 'plain', '한글', 'é', 'e\u0301', '😀', '\u2028\u2029',
        '\b\f\n\r\t', '"\\/', '\x00\x01\x1f', '</script>', 0, -1, 1,
        2**31-1, -2**31, 2**32, 2**53-1, -(2**53-1), 2**53, -2**53,
        [], {}, [1, True, None, '한글'], {'z': 0, 'a': 1},
        {'Z': 1, '_': 2, 'a': 3, 'A': 4}, {'nested': [{'b': '😀', 'a': '\n'}]},
        {'unicode_value': '서울 🐳'}, {'empty': [], 'object': {}}, 1.25, '\ud800', '\udfff']
    rows = []
    for index, value in enumerate(values):
        result = outcome(canonical.canonical_bytes, value)
        if result['accepted']:
            data = result.pop('value')
            result.update(utf8_hex=data.hex(), sha256=canonical.digest(data))
        rows.append({'id': index, 'input': value, 'expected': result})
    return rows


def request_cases(base):
    mutations = [('', None), ('summary_by_ai', ''), ('summary_by_ai', '😀한글'),
        ('summary_by_ai', 'a'*4096), ('revision', 2), ('revision', 2**53-1),
        ('created_at', '2026-11-14T05:59:59Z'), ('expires_at', '2026-11-14T06:00:01Z'),
        ('window_utc', ['2026-11-14T04:00:00Z', '2026-11-14T08:00:00Z']),
        ('action_type', 'other'), ('mode', 'production'), ('format', 'other'),
        ('revision', 0), ('revision', -1), ('revision', True), ('revision', '1'),
        ('request_id', 'A'*32), ('request_id', '1'*31), ('request_id', None),
        ('target.pointer', 'other'), ('target.test_root_id', '0'*32),
        ('target.from_generation', 'gen/005'), ('target.to_generation', 'gen/00000'),
        ('target.to_generation', '../0006'), ('target.before_sha256', 'a'*63),
        ('target.after_sha256', 'A'*64), ('kit.name', 'real-kit/1'), ('kit.sha256', 'x'*64),
        ('bundle.name', 'gen/0007'), ('bundle.sha256', 10), ('recovery.included_in_this_approval', True),
        ('recovery.included_in_this_approval', 0), ('recovery', {}), ('not_covered', []),
        ('not_covered', list(reversed(NOT_COVERED))), ('summary_by_ai', 'a'*4097),
        ('summary_by_ai', None), ('created_at', '2026-11-14T08:00:00Z'),
        ('expires_at', '2026-11-14T08:00:01Z'), ('expires_at', '2026-11-14T05:59:59Z'),
        ('created_at', '2026-11-14T06:00:00+00:00'), ('created_at', '2026-02-30T00:00:00Z'),
        ('window_utc', ['2026-11-14T08:00:00Z', '2026-11-14T08:00:00Z']),
        ('window_utc', ['2026-11-14T03:59:59Z', '2026-11-14T08:00:00Z']),
        ('window_utc', []), ('extra', 'not allowed')]
    rows = []
    for index, (path, value) in enumerate(mutations):
        candidate = copy.deepcopy(base)
        if path:
            owner = candidate
            keys = path.split('.')
            for key in keys[:-1]:
                owner = owner[key]
            owner[keys[-1]] = value
        result = outcome(request.validate, candidate, SimpleNamespace(root_id='2'*32))
        result.pop('value', None)
        rows.append({'id': index, 'input': candidate, 'expected': result})
    for field in ('format', 'revision', 'kit', 'bundle', 'window_utc', 'target', 'recovery'):
        candidate = copy.deepcopy(base)
        del candidate[field]
        result = outcome(request.validate, candidate, SimpleNamespace(root_id='2'*32))
        result.pop('value', None)
        rows.append({'id': 'missing_' + field, 'input': candidate, 'expected': result})
    return rows


def transitions(base):
    now = state.utc(base['created_at'])
    nodes = []
    interned = {}

    def intern(current, at):
        key = (canonical.canonical_bytes(current), state.stamp(at))
        if key not in interned:
            interned[key] = len(nodes)
            nodes.append({'state': current, 'now': state.stamp(at)})
        return interned[key]

    initial = intern(state.initial(), now)
    rows = [{'sequence': [], 'node': initial, 'reason': None}]
    frontier = [([], state.initial(), now)]
    for depth in range(1, 5):
        next_frontier = []
        for sequence, previous, at in frontier:
            for event_index, event in enumerate(state.PROPERTY_EVENTS):
                later = at + timedelta(seconds=900 if event == 'tick_15m' else 86400 if event == 'tick_24h' else 0)
                result = outcome(state.transition, previous, event, state.property_evidence(event, base), later, base)
                current = result['value'] if result['accepted'] else previous
                path = sequence + [event_index]
                rows.append({'sequence': path, 'node': intern(current, later), 'reason': result.get('reason')})
                next_frontier.append((path, current, later))
        frontier = next_frontier
    return {'events': list(state.PROPERTY_EVENTS), 'max_length': 4, 'nodes': nodes,
            'sequences': rows, 'rejection_semantics': 'state unchanged; event time still advances'}


def wording(base, table):
    rows = []
    # A fixed TZ makes local-time wording reproducible on every generator host.
    for index, node in enumerate(table['nodes']):
        current, now = node['state'], state.utc(node['now'])
        record = {'request': base, 'history': [{'at': base['created_at'], 'event': 'create'}],
            'runner_status': 'Mac 실행기(모의) 연결 기록 없음', 'credential_count': 0,
            'display_state': state.display(current, base, now)}
        rows.append({'node': index, 'display': record['display_state'],
            'view': ui.view(record, now), 'confirmation': ui.confirm(record, 'https://mapl-test.invalid')})
    return {'timezone': 'UTC', 'band': ui.BAND, 'cases': rows}


def main():
    import time
    os.environ['TZ'] = 'UTC'
    time.tzset()
    DESTINATION.mkdir(exist_ok=True)
    base = fixture()
    table = transitions(base)
    hashes = {}
    for name, value in [('canonical.json', canonical_cases()),
        ('challenge.json', [{'request': {**base, 'revision': index+1}, 'nonce': 'nonce-한글-' + str(index),
            'expected_hex': canonical.approval_challenge({**base, 'revision': index+1}, 'nonce-한글-' + str(index)).hex()}
            for index in range(10)]),
        ('request.json', request_cases(base)),
        ('strict-json-fixed.json', [{'raw': '{"revision":1,"revision":2}',
            'expected': {'accepted': False, 'reason': 'json_malformed', 'status': 400},
            'source': 'Fixed expectation required by MAPL-PLAN W1; not generated from json.loads'}]),
        ('state.json', table), ('wording.json', wording(base, table))]:
        hashes[name] = write(name, value)
    for name in ('canonical-fixed.json', 'refusal-fixed.json'):
        hashes[name] = hashlib.sha256((DESTINATION / name).read_bytes()).hexdigest()
    write('manifest.json', {'source_commit': SOURCE_COMMIT, 'contract_decision': CONTRACT_DECISION, 'sha256': hashes,
        'canonical_fixed_cases': 7, 'refusal_fixed_cases': 2,
        'canonical_cases': len(canonical_cases()), 'challenge_cases': 10,
        'request_cases': len(request_cases(base)), 'state_sequences': len(table['sequences']),
        'state_nodes': len(table['nodes']), 'events': len(state.PROPERTY_EVENTS)})
    print(json.dumps(hashes, sort_keys=True))


if __name__ == '__main__':
    main()
