"""Signed v2 report state machine. Reports narrow the signed scope."""
import re
from .errors import Refusal

EVENTS = ('check_ok', 'check_failed', 'check_unknown', 'recovery_start', 'recovery_done', 'recovery_failed', 'recovery_unknown')
WORDS = dict(zip(('pointer_bytes', 'pinned_reader', 'collector', 'screen'), ('포인터', '읽기', '수집기', '화면')))


def need(value, reason):
    if not value:
        raise Refusal(reason)


def transition(c, event, e, now, r):
    from .request import ordered_scope
    from .state import stamp
    need(r['format'] == 'mapl-request/2', 'event_refused')
    need(c['claim_id'] and e.get('claim_id') == c['claim_id'], 'claim_mismatch')
    need(c['execution'] in ('checking', 'recovering', 'check_unknown', 'unknown'), 'not_claimed')
    need(event not in ('check_ok', 'check_failed', 'recovery_start') or c['execution'] != 'unknown' or bool(c.get('checking_at')), 'swap_evidence_required')
    if event.startswith('recovery_'):
        need(r['recovery']['included_in_this_approval'] is True, 'recovery_refused')
        need(e.get('code') in r['recovery']['on'], 'recovery_code_refused')
    if event == 'recovery_start':
        need(c['execution'] != 'recovering' and not c.get('recovery_at') and not c.get('check_reported_unknown'), 'recovery_started')
        c.update(execution='recovering', recovery_at=stamp(now), result_code=e['code'])
    elif event == 'check_ok':
        need(c['execution'] != 'recovering' and not c.get('recovery_at'), 'check_closed')
        pending = e.get('pending')
        need(ordered_scope(pending) and 'pointer_bytes' not in pending and all(x in r['check']['scope'] for x in pending), 'pending_invalid')
        c.update(execution='done', pending=pending)
    elif event == 'check_failed':
        need(c['execution'] != 'recovering' and not c.get('recovery_at'), 'check_closed')
        need(isinstance(e.get('code'), str) and re.fullmatch('[A-Z_]{1,80}', e['code']), 'refusal_code_invalid')
        c.update(execution='check_failed', result_code=e['code'])
    elif event == 'check_unknown':
        need(c['execution'] != 'recovering' and not c.get('recovery_at'), 'check_closed')
        c['execution'] = 'check_unknown'
        c['check_reported_unknown'] = True
    elif event == 'recovery_unknown':
        c['execution'] = 'unknown'
    else:
        need(c['execution'] in ('checking', 'check_unknown', 'recovering', 'unknown'), 'recovery_not_started')
        if event == 'recovery_done':
            need(e.get('recovery_claim_id') == c['claim_id'] and e.get('recovery_status') == 'restored_pointer_exact' and e.get('pointer_sha256') == r['target']['before_sha256'], 'recovery_evidence_invalid')
            c['execution'] = 'recovered'
        else:
            need(e.get('exit') == 'refused' and e.get('recovery_marker') == 'absent' and e.get('pointer_sha256') == r['target']['after_sha256'], 'recovery_evidence_invalid')
            c['execution'] = 'recovery_refused'
        c['result_code'] = e['code']
    return c


def words(scope):
    return '·'.join(WORDS[x] for x in scope)


def display(c, r):
    if r['format'] != 'mapl-request/2':
        return None
    code = c.get('result_code', 'UNKNOWN')
    if c['execution'] == 'done':
        verified = [x for x in r['check']['scope'] if x not in c.get('pending', [])]
        pending = [x for x in WORDS if x not in verified]
        return '완료 · ' + words(verified) + ' 확인됨' + (' · ' + words(pending) + ' 확인 대기' if pending else '')
    return {'checking': '교체됨 · 확인 중', 'check_failed': f'교체됨 · 확인 실패 ({code}) · 자동 복구 없음 · 확인 요청',
            'recovering': f'확인 실패 ({code}) · 이전 화면으로 복구 중', 'recovered': f'확인 실패 ({code}) · 이전 화면으로 복구됨 · 확인 요청',
            'recovery_refused': f'확인 실패 ({code}) · 복구 전 거부, 교체된 상태 그대로 · 확인 요청',
            'check_unknown': '교체됨 · 확인 안 됨 · 자동 복구 없음 · 확인 요청'}.get(c['execution'])
