import { words } from './flow';
import { kst, kstRange, utc } from './state';
import type { Dict } from './types';
export const BAND = '시험판 · 시험용 대상만 바뀜 · 실제 승인·실행과 연결 안 됨';
export const confirm = (record: Dict, origin: string) => `이 요청 1건(판본 ${record.request.revision})만 승인합니다. 기기 확인(Face ID 또는 기기 암호)을 합니다.\n주소: ${origin}`;
export function view(record: Dict, now: number): Dict {
    const r = record.request, t = r.target, before = t.from_generation, after = t.to_generation, expiry = utc(r.expires_at), remaining = Math.max(0, Math.floor((expiry - now) / 1000));
    const title = `화면 자료 게시  ${before} → ${after}`, change = `시험용 화면 포인터가 ${before}에서 ${after}로 바뀝니다.`, deadline = `${kst(r.expires_at)}까지 (${Math.floor(remaining / 60)}분 남음)`;
    const target = '시험용 화면 자료 포인터', impact = '시험 화면을 여는 사람에게 새 세대의 자료가 보입니다.', scope = `이 포인터를 한 번 바꿉니다 · 원장·서비스·수집기는 바꾸지 않습니다 · 실행 가능 ${kstRange(r.window_utc[0], r.window_utc[1])}`, failure = failureText(r);
    const history = record.history.map((e: Dict) => kst(e.at, true) + ' ' + (e.source === 'simulated_runner_report' ? 'Mac 보고 · ' : '') + e.event + (e.text ? ' · ' + e.text : '')).join('\n');
    const details_text = [`대상 ${t.pointer} (시험 폴더)`, `이전 해시 ${t.before_sha256}`, `이후 해시 ${t.after_sha256}`, `모의 키트 ${r.kit.name} · ${r.kit.sha256}`, `묶음 해시 ${r.bundle.sha256}`, `판본 ${r.revision} · 요청 번호 ${r.request_id}`, '하지 않는 일 ' + r.not_covered.join(', '), '이력\n' + history, 'AI 작성 참고 문구 — 승인 기준이 아닙니다: ' + (r.summary_by_ai ?? '')].join('\n');
    return { title, change, target, impact, scope, failure, deadline, state: record.display_state, details_text, default_text: [BAND, title, '무엇이 바뀌나 ' + change, '대상 ' + target, '영향 ' + impact, '실행 범위 ' + scope, '실패 시 ' + failure, '승인 기한 ' + deadline, '현재 상태 ' + record.display_state].join('\n') };
}

export function failureText(r: Dict): string {
    if (r.format === 'mapl-request/1') return '이 요청은 교체 뒤 확인을 하지 않습니다. 자동 복구도 없습니다. 실패하면 어느 화면이 남는지 보장하지 않으며 확인을 요청합니다.';
    const middle = r.recovery.included_in_this_approval
        ? `교체 뒤 ${words(r.check.scope)} 확인이 실패하면, 교체 뒤 ${r.check.check_and_recover_max_s / 60}분 안에 한 번만 이전 화면으로 자동 복구를 시작합니다. 복구 조건이 맞지 않거나 복구가 거부되면 다시 시도하지 않고 멈춥니다. 이때 어느 화면이 남는지는 보장하지 않으며 확인을 요청합니다.`
        : '교체 뒤 확인이 실패해도 자동 복구는 없습니다. 이때 어느 화면이 남는지는 보장하지 않으며 확인을 요청합니다.';
    return '교체 전에 멈추면 바뀌는 것이 없습니다. ' + middle + ' 결과가 불분명하면(복구 포함) 다시 실행하지 않고 멈춥니다. 그때 화면이 어느 쪽인지는 확인 전까지 알 수 없습니다.';
}

export function listRow(record: Dict): Dict {
    const r = record.request;
    return { list_title: `화면 자료 게시 ${r.target.from_generation} → ${r.target.to_generation}`, list_meta: `요청 ${kst(r.created_at)} · #${r.request_id.slice(0, 6)}` };
}
