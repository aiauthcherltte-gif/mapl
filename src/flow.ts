import { need, type Dict, type MaplRequest } from './types';
import { orderedScope, SCOPE, WORDS } from './scope';
import { stamp, type State } from './state';
export { FLOW_EVENTS } from './scope';

export const words = (scope: string[]) => scope.map(x => WORDS[x]).join('·');
export function flow(c: State, event: string, e: Dict, now: number, r: MaplRequest): State {
    need(r.format === 'mapl-request/2', 'event_refused');
    need(c.claim_id && e.claim_id === c.claim_id, 'claim_mismatch', 409);
    need(['checking', 'recovering', 'check_unknown', 'unknown'].includes(c.execution), 'not_claimed', 409);
    need(!['check_ok', 'check_failed', 'recovery_start'].includes(event) || c.execution !== 'unknown' || Boolean(c.checking_at), 'swap_evidence_required', 409);
    const recovery = event.startsWith('recovery_');
    if (recovery) {
        need(r.recovery.included_in_this_approval === true, 'recovery_refused', 409);
        need(r.recovery.on.includes(e.code), 'recovery_code_refused', 409);
    }
    if (event === 'recovery_start') {
        need(['checking', 'check_unknown', 'unknown'].includes(c.execution) && !c.recovery_at && !c.check_reported_unknown, 'recovery_started', 409);
        Object.assign(c, {execution: 'recovering', recovery_at: stamp(now), result_code: e.code});
    } else if (event === 'check_ok') {
        need(c.execution !== 'recovering' && !c.recovery_at, 'check_closed', 409);
        need(orderedScope(e.pending) && !e.pending.includes('pointer_bytes') && e.pending.every((x: string) => r.check.scope.includes(x)), 'pending_invalid');
        Object.assign(c, {execution: 'done', pending: e.pending});
    } else if (event === 'check_failed') {
        need(c.execution !== 'recovering' && !c.recovery_at, 'check_closed', 409);
        need(typeof e.code === 'string' && /^[A-Z_]{1,80}$/.test(e.code), 'refusal_code_invalid');
        Object.assign(c, {execution: 'check_failed', result_code: e.code});
    } else if (event === 'check_unknown') {
        need(c.execution !== 'recovering' && !c.recovery_at, 'check_closed', 409);
        c.execution = 'check_unknown';
        c.check_reported_unknown = true;
    } else if (event === 'recovery_unknown') c.execution = 'unknown';
    else {
        need(['checking', 'check_unknown', 'recovering', 'unknown'].includes(c.execution), 'recovery_not_started', 409);
        if (event === 'recovery_done') {
            need(e.recovery_claim_id === c.claim_id && e.recovery_status === 'restored_pointer_exact' && e.pointer_sha256 === r.target.before_sha256, 'recovery_evidence_invalid');
            c.execution = 'recovered';
        } else {
            need(e.exit === 'refused' && e.recovery_marker === 'absent' && e.pointer_sha256 === r.target.after_sha256, 'recovery_evidence_invalid');
            c.execution = 'recovery_refused';
        }
        c.result_code = e.code;
    }
    return c;
}
export function flowText(c: State, r: MaplRequest): string | undefined {
    if (r.format !== 'mapl-request/2') return;
    const code = c.result_code ?? 'UNKNOWN';
    if (c.execution === 'done') {
        const verified = r.check.scope.filter((x: string) => !c.pending?.includes(x)), pending = SCOPE.filter(x => !verified.includes(x));
        return `완료 · ${words(verified)} 확인됨` + (pending.length ? ` · ${words(pending)} 확인 대기` : '');
    }
    return ({checking: '교체됨 · 확인 중', check_failed: `교체됨 · 확인 실패 (${code}) · 자동 복구 없음 · 확인 요청`, recovering: `확인 실패 (${code}) · 이전 화면으로 복구 중`, recovered: `확인 실패 (${code}) · 이전 화면으로 복구됨 · 확인 요청`, recovery_refused: `확인 실패 (${code}) · 복구 전 거부, 교체된 상태 그대로 · 확인 요청`, check_unknown: '교체됨 · 확인 안 됨 · 자동 복구 없음 · 확인 요청'} as Dict)[c.execution];
}
