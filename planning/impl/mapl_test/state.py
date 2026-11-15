"""Pure evidence-based transitions; elapsed time only reduces certainty."""
import copy
import re
from datetime import datetime, timezone

from .errors import Refusal
from . import flow

FINAL_EXECUTION = frozenset(('done', 'check_failed', 'check_unknown', 'recovered', 'recovery_refused', 'failed_no_change', 'failed_after_marker', 'not_run', 'expired_not_run'))
EXPLICIT_REFUSALS = frozenset(('EXPIRED', 'WINDOW_NOT_OPEN', 'POINTER_BEFORE_MISMATCH', 'KIT_LOCKED', 'REFUSED'))
V1_PROPERTY_EVENTS = ('approve', 'decline', 'cancel', 'revise', 'claim_same', 'claim_other',
    'start_ok', 'start_wrong', 'result_done', 'result_no_change', 'result_after_marker',
    'result_partial', 'result_other', 'not_run_full', 'not_run_empty', 'tick_15m', 'tick_24h')

PROPERTY_EVENTS = V1_PROPERTY_EVENTS + flow.EVENTS + ('withdraw',)

def utc(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value):
        raise Refusal('request_invalid', 400)
    try:
        result = datetime.fromisoformat(value[:-1] + '+00:00')
        if result.utcoffset().total_seconds() != 0:
            raise ValueError('zone')
        return result
    except ValueError as error:
        raise Refusal('request_invalid', 400) from error


def stamp(now):
    return now.astimezone(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def initial():
    return {'approval': 'pending', 'execution': 'not_started', 'claim_id': None,
            'claimed_at': None, 'started_at': None}


def expired(request, now):
    return now >= utc(request['expires_at']) or now > utc(request['window_utc'][1])


def result_state(evidence, request):
    before = evidence.get('pointer_sha256') == request['target']['before_sha256']
    after = evidence.get('pointer_sha256') == request['target']['after_sha256']
    marker = evidence.get('marker')
    if (evidence.get('exit') == 'ok' and marker == 'present_this_claim' and after
            and evidence.get('output') == 'mock_swapped_test_target'):
        return 'done'
    # Core msg_28808b171e89: only the kit's explicit refusal signal certifies
    # this state. A timeout, absent result or arbitrary code never does.
    if (evidence.get('exit') == 'refused' and evidence.get('code') in EXPLICIT_REFUSALS
            and marker == 'absent' and before and evidence.get('lock_other', False) is False):
        return 'failed_no_change'
    if (marker == 'present_this_claim' and before and 'output' in evidence
            and evidence.get('output') != 'mock_swapped_test_target'):
        return 'failed_after_marker'
    return 'unknown'


def no_run_evidence(evidence, request):
    return (evidence.get('marker') == 'absent'
            and evidence.get('pointer_sha256') == request['target']['before_sha256']
            and evidence.get('lock_held') is False and evidence.get('lock_other', False) is False)


def transition(previous, event, evidence, now, request):
    current = copy.deepcopy(previous)
    execution, approval = current['execution'], current['approval']
    if event.startswith('tick'):
        if execution in ('checking', 'recovering'):
            since = current.get('checking_at' if execution == 'checking' else 'recovery_at')
            if since and (now - utc(since)).total_seconds() >= 900:
                current['execution'] = 'check_unknown' if execution == 'checking' and not request['recovery']['included_in_this_approval'] else 'unknown'
            return current
        if execution in ('claimed', 'running'):
            since = current['started_at'] if execution == 'running' else current['claimed_at']
            if since and (now - utc(since)).total_seconds() >= 900:
                current['execution'] = 'unknown'
        elif execution == 'not_started' and approval in ('pending', 'approved') and expired(request, now):
            current['execution'] = 'expired_not_run'
            if approval == 'pending':
                current['approval'] = 'expired'
        return current
    event = {'claim_same': 'claim', 'claim_other': 'claim', 'start_ok': 'start', 'start_wrong': 'start',
             'not_run_full': 'not_run', 'not_run_empty': 'not_run'}.get(event, event)
    if event.startswith('result_'):
        event = 'result'
    if event == 'approve':
        if approval != 'pending':
            raise Refusal('already_' + approval)
        if expired(request, now):
            raise Refusal('expired')
        current['approval'] = 'approved'
    elif event == 'withdraw':
        if approval != 'approved' or execution != 'not_started' or current['claim_id']:
            raise Refusal('withdraw_refused')
        current['approval'] = 'withdrawn'
    elif event in flow.EVENTS:
        if event in ('check_ok', 'check_failed', 'check_unknown') and current['execution'] in ('claimed', 'running', 'unknown') and result_state(evidence, request) == 'done':
            current.update(execution='checking', checking_at=stamp(now))
        return flow.transition(current, event, evidence, now, request)
    elif event == 'decline':
        if approval != 'pending' or current['claim_id']:
            raise Refusal('not_pending')
        current['approval'] = 'declined'
    elif event in ('cancel', 'revise'):
        if current['claim_id']:
            raise Refusal('claimed_revision_in_progress')
        if approval not in ('pending', 'approved'):
            raise Refusal('not_pending')
        current['approval'] = 'cancelled' if event == 'cancel' else 'superseded'
    elif event == 'claim':
        if expired(request, now):
            raise Refusal('not_claimable:expired')
        if approval != 'approved' or execution != 'not_started':
            raise Refusal('not_claimable:' + (approval if approval != 'approved' else execution))
        if now < utc(request['window_utc'][0]):
            raise Refusal('not_claimable:window_not_open')
        current.update(execution='claimed', claim_id=evidence['claim_id'], claimed_at=stamp(now))
    elif event in ('start', 'result', 'not_run'):
        if not current['claim_id'] or evidence.get('claim_id') != current['claim_id']:
            raise Refusal('claim_mismatch')
        if execution in FINAL_EXECUTION:
            raise Refusal('claim_closed:' + execution)
        if execution not in ('claimed', 'running', 'unknown'):
            raise Refusal('not_claimed')
        if event == 'start':
            if execution != 'claimed':
                raise Refusal('start_closed')
            current.update(execution='running', started_at=stamp(now))
        elif event == 'not_run':
            if not no_run_evidence(evidence, request):
                raise Refusal('insufficient_not_run_evidence')
            current['execution'] = 'not_run'
        else:
            current['execution'] = result_state(evidence, request)
            if request['format'] == 'mapl-request/2' and current['execution'] == 'done':
                current.update(execution='checking', checking_at=stamp(now))
    else:
        raise Refusal('event_refused')
    return current


def display(current, request, now):
    approval = current['approval']
    execution = current['execution']
    if approval not in ('approved', 'expired'):
        return {'pending': '승인 대기', 'declined': '거절됨 · 실행하지 않습니다.',
                'superseded': '내용 변경으로 무효', 'withdrawn': '승인 철회 · 실행하지 않습니다', 'cancelled': '요청자 철회'}.get(approval, '만료')
    v2text = flow.display(current, request)
    if v2text:
        return v2text
    if execution == 'not_started':
        if now < utc(request['window_utc'][0]):
            return '아직 실행 안 함 · 실행 가능 시간 ' + utc(request['window_utc'][0]).astimezone().strftime('%H:%M') + '부터'
        return '아직 실행 안 함 · Mac이 이 요청을 맡지 않았습니다'
    if execution == 'running':
        started = utc(current['started_at'])
        minutes = max(0, int((now - started).total_seconds()) // 60)
        return f'실행 중 · 시작 보고 {started.astimezone():%H:%M} ({minutes}분 경과)'
    return {
        'claimed': '실행 여부 확인 안 됨 · Mac이 맡았고 시작 보고는 아직 없습니다',
        'done': f"완료 · 시험 대상 포인터가 {request['target']['to_generation']}을 가리킴 (모의 실행)",
        'failed_no_change': '실패 · 실행 전 거부, 포인터 바뀐 것 없음 (' + current.get('result_code', 'REFUSED') + ')',
        'failed_after_marker': '실패 · 표시 뒤 실패, 포인터 바뀐 것 없음, 다시 실행 불가',
        'not_run': '실행 안 됨 · 포인터 바뀐 것 없음 (Mac 보고)',
        'expired_not_run': '만료 · 실행 안 함 (Mac이 맡기 전에 만료)',
        'unknown': '결과 불명 · 자동으로 다시 실행하지 않습니다 · Core 확인 필요',
    }[execution]


def property_evidence(event, request):
    claim_id = 'a' * 32
    result = {'claim_id': 'b' * 32 if event in ('claim_other', 'start_wrong') else claim_id}
    if event == 'result_done':
        result.update(exit='ok', marker='present_this_claim', pointer_sha256=request['target']['after_sha256'], output='mock_swapped_test_target')
    elif event in ('result_no_change', 'result_after_marker', 'not_run_full'):
        result.update(exit='refused', code='REFUSED', marker='present_this_claim' if event == 'result_after_marker' else 'absent',
                      pointer_sha256=request['target']['before_sha256'], output=None, lock_held=False)
    elif event == 'result_other':
        result.update(marker='present_other', pointer_sha256='f' * 64)
    return result
