"""Fixed Korean view templates; AI/free text belongs only to details."""
import re

from .errors import Refusal
from .state import utc

BAND = '시험판 · 시험용 대상만 바뀜 · 실제 승인·실행과 연결 안 됨'


def confirm(record, origin):
    revision = record['request']['revision']
    return f'이 요청 1건(판본 {revision})만 승인합니다. 기기 확인(Face ID 또는 기기 암호)을 합니다.\n주소: {origin}'


def view(record, now, summary=None):
    request = record['request']
    target = request['target']
    before, after = target['from_generation'], target['to_generation']
    if not all(isinstance(x, str) and re.fullmatch(r'gen/\d{4}', x) for x in (before, after)):
        raise Refusal('request_invalid')
    expiry = utc(request['expires_at'])
    remaining = max(0, int((expiry - now).total_seconds()))
    start, end = map(utc, request['window_utc'])
    title = f'화면 자료 게시  {before} → {after}'
    change = f'시험용 화면 포인터가 {before}에서 {after}로 바뀝니다.'
    deadline = f'{expiry.astimezone():%H:%M}까지 ({remaining // 60}분 남음) · 실행은 {start.astimezone():%H:%M}–{end.astimezone():%H:%M} 사이에만'
    conditions = '원장은 바뀌지 않습니다. 되돌리기는 이 승인에 포함되지 않습니다.'
    history = '\n'.join(event['at'] + ' ' + ('Mac 보고 · ' if event.get('source') == 'simulated_runner_report' else '')
                        + event['event'] + (' · ' + event['text'] if event.get('text') else '') for event in record['history'])
    details = '\n'.join((
        '대상 ' + target['pointer'] + ' (시험 폴더)',
        '이전 해시 ' + target['before_sha256'], '이후 해시 ' + target['after_sha256'],
        '모의 키트 ' + request['kit']['name'] + ' · ' + request['kit']['sha256'],
        '묶음 해시 ' + request['bundle']['sha256'], f"판본 {request['revision']} · 요청 번호 {request['request_id']}",
        '하지 않는 일 ' + ', '.join(request['not_covered']), '이력\n' + history,
        'AI 작성 참고 문구 — 승인 기준이 아닙니다: ' + (request.get('summary_by_ai', '') if summary is None else summary),
        record['runner_status'],
        f"등록된 패스키 {record['credential_count']}개 · 마지막 추가 {record.get('credential_registered_at') or '기록 없음'}",
        f'알림 문구 미리보기 (보내지 않음): [승인 요청] 화면 자료 게시 {before} → {after} · 링크'))
    return {'title': title, 'change': change, 'deadline': deadline, 'conditions': conditions,
            'state': record['display_state'], 'details_text': details,
            'default_text': '\n'.join((BAND, title, '무엇이 바뀌나 ' + change, '승인 기한 ' + deadline,
                                       '중요한 조건 ' + conditions, '현재 상태 ' + record['display_state']))}
