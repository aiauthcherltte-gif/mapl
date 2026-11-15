"""Generate additional AF1 fixtures, never rewrite the v1 reference files."""
import copy
import json
from pathlib import Path
from datetime import timedelta
from .generate_reference import fixture
from ..mapl_test.canonical import canonical_bytes, digest, approval_challenge
from ..mapl_test.request import validate
from ..mapl_test import state
from ..mapl_test.errors import Refusal

DEST = Path(__file__).parent / 'reference'


def request():
    r = fixture()
    r.update(format='mapl-request/2', check={'scope': ['pointer_bytes', 'pinned_reader', 'collector'], 'recovery_eligible_codes': ['READER_INDEX_MISMATCH'], 'check_and_recover_max_s': 600})
    return r


def clause(r):
    r['not_covered'] = r['not_covered'][:3]
    r['recovery'] = {'included_in_this_approval': True, 'kind': 'restore_previous_pointer', 'restore_to_sha256': r['target']['before_sha256'], 'only_if_current_sha256': r['target']['after_sha256'], 'on': ['READER_INDEX_MISMATCH'], 'valid_until': state.stamp(state.utc(r['window_utc'][1]) + timedelta(seconds=600)), 'max_runs': 1}
    return r


def generate():
    base = request()
    cases = []
    def add(name, r, accepted):
        cases.append({'id': name, 'request': r, 'accepted': accepted})
    add('no-clause', copy.deepcopy(base), True)
    add('clause', clause(copy.deepcopy(base)), True)
    for i, scope in enumerate((['pointer_bytes'], ['pinned_reader', 'pointer_bytes'], ['pointer_bytes', 'pointer_bytes'], ['pointer_bytes', 'unknown'], ['screen'], [])):
        r = copy.deepcopy(base); r['check']['scope'] = scope
        add('scope-' + str(i), r, i == 0)
    for n in (0, 60, 61, 119, 120, 600, 601):
        r = copy.deepcopy(base); r['check']['check_and_recover_max_s'] = n
        add('seconds-' + str(n), r, n in (60, 120, 600))
    for label, field, value in (('ineligible', 'on', ['OTHER']), ('empty', 'on', []), ('duplicate', 'on', ['READER_INDEX_MISMATCH']*2), ('time', 'valid_until', base['window_utc'][1]), ('twice', 'max_runs', 2), ('wrong-before', 'restore_to_sha256', 'a'*64), ('wrong-after', 'only_if_current_sha256', 'b'*64)):
        r = clause(copy.deepcopy(base)); r['recovery'][field] = value; add(label, r, False)
    r = copy.deepcopy(base); r['format'] = 'mapl-request/1'; add('v1-with-check', r, False)
    for days, accepted in ((2, True), (7, True), (8, False)):
        r = copy.deepcopy(base); r['window_utc'][1] = r['expires_at'] = state.stamp(state.utc(r['created_at']) + timedelta(days=days)); add('days-' + str(days), r, accepted)
    root = type('Root', (), {'root_id': base['target']['test_root_id']})()
    for case in cases:
        try: validate(case['request'], root); actual = True
        except Refusal: actual = False
        if actual != case['accepted']: raise RuntimeError(case['id'])
    rows = []
    for event, evidence in [('check_ok', {'pending': []}), ('check_ok', {'pending': ['collector']}), ('check_ok', {'pending': ['screen']}), ('check_ok', {'pending': ['pointer_bytes']}), ('check_failed', {'code': 'CURRENT_IS_NOT_APPROVED_AFTER_BYTES'}), ('check_unknown', {}), ('recovery_start', {'code': 'READER_INDEX_MISMATCH'}), ('recovery_start', {'code': 'OTHER'}), ('recovery_done', {'code':'READER_INDEX_MISMATCH','recovery_claim_id':'a'*32,'recovery_status':'restored_pointer_exact','pointer_sha256':base['target']['before_sha256']}), ('recovery_failed', {'code':'READER_INDEX_MISMATCH','exit':'refused','recovery_marker':'absent','pointer_sha256':base['target']['after_sha256']}), ('recovery_unknown', {'code':'READER_INDEX_MISMATCH'}), ('withdraw', {}), ('tick', {})]:
        for rec in (False, True):
            r = clause(copy.deepcopy(base)) if rec else copy.deepcopy(base)
            now = state.utc(r['created_at']); c = state.initial(); c.update(approval='approved', execution='checking', claim_id='a'*32, checking_at=state.stamp(now))
            if event in ('recovery_done','recovery_failed'): c['execution']='recovering'
            if event == 'withdraw': c.update(execution='not_started',claim_id=None)
            e = {'claim_id': 'a'*32, **evidence}
            at = now + timedelta(seconds=900) if event == 'tick' else now
            try:
                next_state = state.transition(c, event, e, at, r); expected = {'state': next_state, 'display': state.display(next_state, r, at)}
            except Refusal as error: expected = {'error': error.code}
            rows.append({'request': r, 'previous': c, 'event': event, 'evidence': e, 'now': state.stamp(at), 'expected': expected})
    # Spec-authored sequences: §4.5 r10/r10F and MAPLAF r4 P2.
    # No transition call computes any expectation in these rows.
    def sequence(label, start, steps, rec=True, **fields):
        r = clause(copy.deepcopy(base)) if rec else copy.deepcopy(base)
        now = r['created_at']
        c = state.initial()
        c.update(approval='approved', execution=start, claim_id='a'*32,
                 claimed_at=now, started_at=now if start == 'running' else None, **fields)
        rows.append({'id': label, 'request': r, 'previous': c, 'steps': [
            {'event': event, 'evidence': {'claim_id': 'a'*32, **e},
             'now': state.stamp(state.utc(now) + timedelta(seconds=seconds)), 'expected': expected}
            for event, e, seconds, expected in steps]})
    swap = {'exit': 'ok', 'marker': 'present_this_claim', 'pointer_sha256': base['target']['after_sha256'], 'output': 'mock_swapped_test_target'}
    code = {'code': 'READER_INDEX_MISMATCH'}
    for start in ('claimed', 'running', 'unknown'):
        for event, evidence in (('check_ok', {'pending': []}), ('check_failed', code)):
            sequence(start+'-no-swap-'+event, start, [
                ('tick', {}, 900, {'execution': 'unknown'}),
                (event, evidence, 901, {'error': 'swap_evidence_required'}),
                ('check_unknown', swap, 902, {'execution': 'check_unknown'}),
                ('recovery_start', code, 903, {'error': 'recovery_started'})])
        sequence(start+'-swap-restart', start, [
            ('check_unknown', swap, 0, {'execution': 'check_unknown'}),
            ('recovery_start', code, 1, {'error': 'recovery_started'}),
            ('tick', {}, 901, {'execution': 'check_unknown'})])
    for event, evidence, final in (('check_ok', {'pending': []}, 'done'), ('check_failed', code, 'check_failed')):
        sequence('late-'+event, 'running', [
            ('result', swap, 0, {'execution': 'checking'}),
            ('tick', {}, 900, {'execution': 'unknown'}),
            (event, evidence, 901, {'execution': final})])
        sequence('evidence-'+event, 'unknown', [
            (event, {**swap, **evidence}, 0, {'execution': final}),
            ('recovery_start', code, 1, {'error': 'not_claimed'}),
            ('tick', {}, 900, {'execution': final})])
    for timeout in ('tick', 'recovery_unknown'):
        sequence('no-second-recovery-'+timeout, 'running', [
            ('result', swap, 0, {'execution': 'checking'}),
            ('recovery_start', code, 1, {'execution': 'recovering'}),
            (timeout, code, 901, {'execution': 'unknown'}),
            ('recovery_start', code, 902, {'error': 'recovery_started'})])
    sequence('late-recovery-from-checking', 'unknown', [
        ('recovery_start', code, 0, {'execution': 'recovering'}),
        ('recovery_unknown', code, 1, {'execution': 'unknown'}),
        ('recovery_start', code, 2, {'error': 'recovery_started'})], checking_at=base['created_at'])
    sequence('runner-check-unknown-is-closed', 'check_unknown', [
        ('recovery_start', code, 0, {'error': 'recovery_started'}),
        ('check_failed', code, 1, {'execution': 'check_failed'}),
        ('tick', {}, 900, {'execution': 'check_failed'})], checking_at=base['created_at'], check_reported_unknown=True)
    sequence('timeout-check-unknown-allows-late-recovery', 'check_unknown', [
        ('recovery_start', code, 0, {'execution': 'recovering'}),
        ('recovery_unknown', code, 1, {'execution': 'unknown'}),
        ('recovery_start', code, 2, {'error': 'recovery_started'})], checking_at=base['created_at'])
    canon = [{'request': r, 'utf8': canonical_bytes(r).decode(), 'content_hash': digest(canonical_bytes(r)), 'nonce': 'a'*64, 'challenge_hex': approval_challenge(r, 'a'*64).hex()} for r in (base, clause(copy.deepcopy(base)))]
    files = {'request-v2.json': cases, 'state-v2.json': rows, 'canonical-v2.json': canon}
    for name, data in files.items(): (DEST / name).write_bytes(canonical_bytes(data) + b'\n')
    (DEST / 'manifest-v2.json').write_bytes(canonical_bytes({name: digest((DEST / name).read_bytes()) for name in files}) + b'\n')


if __name__ == '__main__': generate()
