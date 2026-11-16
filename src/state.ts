import { FLOW_EVENTS } from './scope';
import { flow, flowText } from './flow';
import { clone, need, Refusal, type Dict, type MaplRequest } from './types';
export interface State {
    checking_at?: string;
    check_reported_unknown?: boolean;
    recovery_at?: string;
    pending?: string[];
    approval: string;
    execution: string;
    claim_id: string | null;
    claimed_at: string | null;
    started_at: string | null;
    result_code?: string;
}
export const FINAL_EXECUTION = new Set(['done', 'check_failed', 'check_unknown', 'recovered', 'recovery_refused', 'failed_no_change', 'failed_after_marker', 'not_run', 'expired_not_run']);
const EXPLICIT_REFUSALS = new Set(['EXPIRED', 'WINDOW_NOT_OPEN', 'POINTER_BEFORE_MISMATCH', 'KIT_LOCKED', 'REFUSED']);
export const V1_PROPERTY_EVENTS = ['approve', 'decline', 'cancel', 'revise', 'claim_same', 'claim_other', 'start_ok', 'start_wrong', 'result_done', 'result_no_change', 'result_after_marker', 'result_partial', 'result_other', 'not_run_full', 'not_run_empty', 'tick_15m', 'tick_24h'];
export const PROPERTY_EVENTS = [...V1_PROPERTY_EVENTS, ...FLOW_EVENTS, 'withdraw'];
export function utc(v: unknown): number {
    need(typeof v === 'string', 'request_invalid');
    const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/.exec(v);
    need(m && +m[1] >= 1, 'request_invalid');
    const base = Date.parse(v.slice(0, 19) + 'Z'), d = new Date(base);
    need(Number.isFinite(base) && d.getUTCFullYear() === +m[1] && d.getUTCMonth() + 1 === +m[2] && d.getUTCDate() === +m[3] && d.getUTCHours() === +m[4] && d.getUTCMinutes() === +m[5] && d.getUTCSeconds() === +m[6], 'request_invalid');
    return base + Number('0.' + (m[7] ?? '0')) * 1000;
}
export const stamp = (now: number) => new Date(now).toISOString().replace(/\.\d{3}Z$/, 'Z');
const kstDate = (iso: string) => new Date(utc(iso) + 9 * 3600000);
const kstDay = (d: Date) => `${d.getUTCMonth() + 1}월\u00a0${d.getUTCDate()}일`;
const kstClock = (d: Date, seconds = false) => [d.getUTCHours(), d.getUTCMinutes(), ...(seconds ? [d.getUTCSeconds()] : [])].map(n => String(n).padStart(2, '0')).join(':');
export const kst = (iso: string, seconds = false) => { const d = kstDate(iso); return `${kstDay(d)}\u00a0${kstClock(d, seconds)}\u00a0KST`; };
export function kstRange(a: string, b: string): string {
    const start = kstDate(a), end = kstDate(b);
    return start.getUTCFullYear() === end.getUTCFullYear() && start.getUTCMonth() === end.getUTCMonth() && start.getUTCDate() === end.getUTCDate()
        ? `${kstDay(start)}\u00a0${kstClock(start)}–${kstClock(end)}\u00a0KST`
        : `${kstDay(start)}\u00a0${kstClock(start)} – ${kst(b)}`;
}
export const initial = (): State => ({ approval: 'pending', execution: 'not_started', claim_id: null, claimed_at: null, started_at: null });
export const expired = (r: MaplRequest, now: number) => now >= utc(r.expires_at) || now > utc(r.window_utc[1]);
export function resultState(e: Dict, r: MaplRequest): string {
    const before = e.pointer_sha256 === r.target.before_sha256, after = e.pointer_sha256 === r.target.after_sha256;
    if (e.exit === 'ok' && e.marker === 'present_this_claim' && after && e.output === 'mock_swapped_test_target')
        return 'done';
    if (e.exit === 'refused' && EXPLICIT_REFUSALS.has(e.code) && e.marker === 'absent' && before && (e.lock_other ?? false) === false)
        return 'failed_no_change';
    if (e.marker === 'present_this_claim' && before && Object.hasOwn(e, 'output') && e.output !== 'mock_swapped_test_target')
        return 'failed_after_marker';
    return 'unknown';
}
export const noRunEvidence = (e: Dict, r: MaplRequest) => e.marker === 'absent' && e.pointer_sha256 === r.target.before_sha256 && e.lock_held === false && (e.lock_other ?? false) === false;
export function transition(previous: State, event: string, e: Dict, now: number, r: MaplRequest): State {
    const c = clone(previous), { execution, approval } = c;
    if (event.startsWith('tick')) {
        if (['checking', 'recovering'].includes(execution)) {
            const since = execution === 'checking' ? c.checking_at : c.recovery_at;
            if (since && now - utc(since) >= 900000) c.execution = execution === 'checking' && !r.recovery.included_in_this_approval ? 'check_unknown' : 'unknown';
            return c;
        }
        if (['claimed', 'running'].includes(execution)) {
            const since = execution === 'running' ? c.started_at : c.claimed_at;
            if (since && now - utc(since) >= 900000)
                c.execution = 'unknown';
        }
        else if (execution === 'not_started' && ['pending', 'approved'].includes(approval) && expired(r, now)) {
            c.execution = 'expired_not_run';
            if (approval === 'pending')
                c.approval = 'expired';
        }
        return c;
    }
    event = ({ claim_same: 'claim', claim_other: 'claim', start_ok: 'start', start_wrong: 'start', not_run_full: 'not_run', not_run_empty: 'not_run' } as Dict)[event] ?? event;
    if (event.startsWith('result_'))
        event = 'result';
    if (event === 'approve') {
        need(approval === 'pending', 'already_' + approval, 409);
        need(!expired(r, now), 'expired', 409);
        c.approval = 'approved';
    }
    else if (event === 'withdraw') {
        need(approval === 'approved' && execution === 'not_started' && !c.claim_id, 'withdraw_refused', 409);
        c.approval = 'withdrawn';
    }
    else if (FLOW_EVENTS.includes(event)) {
        if (['check_ok', 'check_failed', 'check_unknown'].includes(event) && ['claimed', 'running', 'unknown'].includes(c.execution) && resultState(e, r) === 'done') { c.execution = 'checking'; c.checking_at = stamp(now); }
        return flow(c, event, e, now, r);
    }
    else if (event === 'decline') {
        need(approval === 'pending' && !c.claim_id, 'not_pending', 409);
        c.approval = 'declined';
    }
    else if (event === 'cancel' || event === 'revise') {
        need(!c.claim_id, 'claimed_revision_in_progress', 409);
        need(['pending', 'approved'].includes(approval), 'not_pending', 409);
        c.approval = event === 'cancel' ? 'cancelled' : 'superseded';
    }
    else if (event === 'claim') {
        need(!expired(r, now), 'not_claimable:expired', 409);
        need(approval === 'approved' && execution === 'not_started', 'not_claimable:' + (approval !== 'approved' ? approval : execution), 409);
        need(now >= utc(r.window_utc[0]), 'not_claimable:window_not_open', 409);
        Object.assign(c, { execution: 'claimed', claim_id: e.claim_id, claimed_at: stamp(now) });
    }
    else if (['start', 'result', 'not_run'].includes(event)) {
        need(c.claim_id && e.claim_id === c.claim_id, 'claim_mismatch', 409);
        need(!FINAL_EXECUTION.has(execution), 'claim_closed:' + execution, 409);
        need(['claimed', 'running', 'unknown'].includes(execution), 'not_claimed', 409);
        if (event === 'start') {
            need(execution === 'claimed', 'start_closed', 409);
            Object.assign(c, { execution: 'running', started_at: stamp(now) });
        }
        else if (event === 'not_run') {
            need(noRunEvidence(e, r), 'insufficient_not_run_evidence', 409);
            c.execution = 'not_run';
        }
        else
            {
            c.execution = resultState(e, r);
            if (r.format === 'mapl-request/2' && c.execution === 'done') { c.execution = 'checking'; c.checking_at = stamp(now); }
        }
    }
    else
        throw new Refusal('event_refused');
    return c;
}
export function display(c: State, r: MaplRequest, now: number): string {
    const a = c.approval, e = c.execution;
    if (!['approved', 'expired'].includes(a))
        return ({ pending: '승인 대기', declined: '거절됨 · 실행하지 않습니다.', superseded: '내용 변경으로 무효', withdrawn: '승인 철회 · 실행하지 않습니다', cancelled: '요청자 철회' } as Dict)[a] ?? '만료';
    const v2text = flowText(c, r);
    if (v2text) return v2text;
    if (e === 'not_started')
        return now < utc(r.window_utc[0]) ? '아직 실행 안 함 · 실행 가능 시간 ' + kst(r.window_utc[0]) + '부터' : '아직 실행 안 함 · Mac이 이 요청을 맡지 않았습니다';
    if (e === 'running')
        return `실행 중 · 시작 보고 ${kst(c.started_at!)} (${Math.max(0, Math.floor((now - utc(c.started_at!)) / 60000))}분 경과)`;
    return ({ claimed: '실행 여부 확인 안 됨 · Mac이 맡았고 시작 보고는 아직 없습니다', done: `완료 · 시험 대상 포인터가 ${r.target.to_generation}을 가리킴 (모의 실행)`, failed_no_change: '실패 · 실행 전 거부, 포인터 바뀐 것 없음 (' + (c.result_code ?? 'REFUSED') + ')', failed_after_marker: '실패 · 표시 뒤 실패, 포인터 바뀐 것 없음, 다시 실행 불가', not_run: '실행 안 됨 · 포인터 바뀐 것 없음 (Mac 보고)', expired_not_run: '만료 · 실행 안 함 (Mac이 맡기 전에 만료)', unknown: '결과 불명 · 자동으로 다시 실행하지 않습니다 · Core 확인 필요' } as Dict)[e];
}
export function propertyEvidence(event: string, r: MaplRequest): Dict {
    const e: Dict = { claim_id: ['claim_other', 'start_wrong'].includes(event) ? 'b'.repeat(32) : 'a'.repeat(32) };
    if (event === 'result_done')
        Object.assign(e, { exit: 'ok', marker: 'present_this_claim', pointer_sha256: r.target.after_sha256, output: 'mock_swapped_test_target' });
    else if (['result_no_change', 'result_after_marker', 'not_run_full'].includes(event))
        Object.assign(e, { exit: 'refused', code: 'REFUSED', marker: event === 'result_after_marker' ? 'present_this_claim' : 'absent', pointer_sha256: r.target.before_sha256, output: null, lock_held: false });
    else if (event === 'result_other')
        Object.assign(e, { marker: 'present_other', pointer_sha256: 'f'.repeat(64) });
    return e;
}
