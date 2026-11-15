import { hm, utc } from './state';
import type { Dict } from './types';
export const BAND = '시험판 · 시험용 대상만 바뀜 · 실제 승인·실행과 연결 안 됨';
export const confirm = (record: Dict, origin: string) => `이 요청 1건(판본 ${record.request.revision})만 승인합니다. 기기 확인(Face ID 또는 기기 암호)을 합니다.\n주소: ${origin}`;
export function view(record: Dict, now: number): Dict {
    const r = record.request, t = r.target, before = t.from_generation, after = t.to_generation, expiry = utc(r.expires_at), remaining = Math.max(0, Math.floor((expiry - now) / 1000));
    const title = `화면 자료 게시  ${before} → ${after}`, change = `시험용 화면 포인터가 ${before}에서 ${after}로 바뀝니다.`, deadline = `${hm(r.expires_at)}까지 (${Math.floor(remaining / 60)}분 남음) · 실행은 ${hm(r.window_utc[0])}–${hm(r.window_utc[1])} 사이에만`, conditions = '원장은 바뀌지 않습니다. 되돌리기는 이 승인에 포함되지 않습니다.';
    const history = record.history.map((e: Dict) => e.at + ' ' + (e.source === 'simulated_runner_report' ? 'Mac 보고 · ' : '') + e.event + (e.text ? ' · ' + e.text : '')).join('\n');
    const details_text = [`대상 ${t.pointer} (시험 폴더)`, `이전 해시 ${t.before_sha256}`, `이후 해시 ${t.after_sha256}`, `모의 키트 ${r.kit.name} · ${r.kit.sha256}`, `묶음 해시 ${r.bundle.sha256}`, `판본 ${r.revision} · 요청 번호 ${r.request_id}`, '하지 않는 일 ' + r.not_covered.join(', '), '이력\n' + history, 'AI 작성 참고 문구 — 승인 기준이 아닙니다: ' + (r.summary_by_ai ?? ''), record.runner_status, `등록된 패스키 ${record.credential_count}개 · 마지막 추가 ${record.credential_registered_at ?? '기록 없음'}`, `알림 문구 미리보기 (보내지 않음): [승인 요청] 화면 자료 게시 ${before} → ${after} · 링크`].join('\n');
    return { title, change, deadline, conditions, state: record.display_state, details_text, default_text: [BAND, title, '무엇이 바뀌나 ' + change, '승인 기한 ' + deadline, '중요한 조건 ' + conditions, '현재 상태 ' + record.display_state].join('\n') };
}
