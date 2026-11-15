import { describe, it, expect } from 'vitest';
import { world, refuses, CID } from './support';
import { initial, transition, propertyEvidence, PROPERTY_EVENTS } from '../src/state';
import { canonical } from '../src/canonical';
import { Refusal } from '../src/types';
describe('ported ST server cases', () => {
    it('ST-1 pending is explicit', () => world(w => { expect(w.record().display_state).toBe('승인 대기'); expect(w.record().approval).toBe('pending'); }));
    it('ST-2 approved has not started', () => world(async (w) => { await w.approve(); expect(w.record().execution).toBe('not_started'); expect(w.record().display_state).toBe('아직 실행 안 함 · Mac이 이 요청을 맡지 않았습니다'); }));
    it('ST-3 claim means uncertain, never waiting', () => world(async (w) => { await w.approve(); w.claim(); expect(w.record().execution).toBe('claimed'); expect(w.record().display_state).toContain('실행 여부 확인 안 됨'); expect(w.record().display_state).not.toContain('대기'); }));
    it('ST-4 wrong claim cannot start', () => world(async (w) => { await w.approve(); w.claim(); await refuses('claim_mismatch', () => w.report('start', {}, 'b'.repeat(32))); expect(w.record().execution).toBe('claimed'); }));
    it('ST-5 every success fact is required', async () => { for (const missing of ['exit', 'marker', 'pointer_sha256', 'output', null])
        await world(async (w) => { await w.approve(); w.claim(); const e = w.evidence(); if (missing)
            delete e[missing]; w.report('result', e); expect(w.record().execution).toBe(missing ? 'unknown' : 'done'); }); });
    it('ST-6 result classification follows evidence', async () => { for (const [marker, pointer, expected] of [['absent', 'before', 'failed_no_change'], ['present_this_claim', 'before', 'failed_after_marker'], ['present_other', 'before', 'unknown'], ['absent', 'third', 'unknown']])
        await world(async (w) => { await w.approve(); w.claim(); w.report('result', { exit: 'refused', code: 'POINTER_BEFORE_MISMATCH', marker, pointer_sha256: pointer === 'before' ? w.request.target.before_sha256 : 'f'.repeat(64), output: null, lock_held: false }); expect(w.record().execution).toBe(expected); }); });
    it('ST-7 not_run requires evidence', () => world(async (w) => { await w.approve(); w.claim(); await refuses('insufficient_not_run_evidence', () => w.report('not_run')); w.advance(900); expect(w.record().execution).toBe('unknown'); }));
    it('ST-8 elapsed time cannot resolve uncertainty', () => world(async (w) => { await w.approve(); w.claim(); w.advance(900); expect(w.record().execution).toBe('unknown'); w.advance(86400); expect(w.record().execution).toBe('unknown'); }));
    it('ST-9 complete event alphabet through depth six never resets execution', () => world(w => {
        expect(PROPERTY_EVENTS).toHaveLength(17);
        let frontier = [{ s: initial(), now: w.clock.now, ever: false }];
        for (let depth = 0; depth < 6; depth++) {
            const next = new Map<string, typeof frontier[0]>();
            for (const p of frontier)
                for (const e of PROPERTY_EVENTS) {
                    const now = p.now + (e === 'tick_15m' ? 900000 : e === 'tick_24h' ? 86400000 : 0);
                    let s = p.s;
                    try {
                        s = transition(p.s, e, propertyEvidence(e, w.request), now, w.request);
                    }
                    catch (err) {
                        if (!(err instanceof Refusal))
                            throw err;
                    }
                    if (p.ever)
                        expect(s.execution).not.toBe('not_started');
                    const ever = p.ever || s.execution !== 'not_started';
                    next.set(canonical([s, now, ever]), { s, now, ever });
                }
            frontier = Array.from(next.values());
        }
    }));
    it('ST-10 running becomes unknown at 15 minutes', () => world(async (w) => { await w.approve(); w.claim(); w.report('start'); w.advance(899); expect(w.record().execution).toBe('running'); w.advance(1); expect(w.record().execution).toBe('unknown'); }));
    it('ST-11 cancel allowed only before claim', async () => { await world(async (w) => { await w.approve(); w.store.cancel(w.rid); expect(w.record().approval).toBe('cancelled'); }); await world(async (w) => { await w.approve(); w.claim(); await refuses('claimed_revision_in_progress', () => w.store.cancel(w.rid)); expect(w.record().execution).toBe('claimed'); }); });
    it('ST-12 expiry prevents claim', () => world(async (w) => { await w.approve(); w.advance(7201); expect(w.record().execution).toBe('expired_not_run'); expect((await refuses('not_claimable:expired', () => w.claim())).status).toBe(409); }));
    it('ST-13 future window blocks claim', () => world(async (w) => { const r = structuredClone(w.request); r.revision = 2; r.window_utc[0] = '2026-11-14T07:00:00Z'; await w.store.create(r); await w.approve(); await refuses('not_claimable:window_not_open', () => w.claim(2)); expect(w.record().display_state).toContain('실행 가능 시간'); expect(w.record().claim_id).toBeNull(); }));
    it('ST-14 cancelled cannot claim', () => world(async (w) => { await w.approve(); w.store.cancel(w.rid); await refuses('not_claimable:cancelled', () => w.claim()); expect(w.record().approval).toBe('cancelled'); }));
});
describe('ported DP server obligations', () => {
    it('DP-1 concurrent approval is one committed history row', () => world(async (w) => { const a = await w.sign(); const r = await Promise.allSettled([w.store.approve(w.rid, a), w.store.approve(w.rid, a)]); expect(r.filter(v => v.status === 'fulfilled')).toHaveLength(1); expect(w.record().history.filter((v: any) => v.event === 'approve')).toHaveLength(1); }));
    it('DP-2 same claim is idempotent while claimed', () => world(async (w) => { await w.approve(); expect(w.claim()).toEqual(w.claim()); expect(w.record().history.filter((v: any) => v.event === 'claim')).toHaveLength(1); }));
    it('DP-3 different claim refused', () => world(async (w) => { await w.approve(); w.claim(); await refuses('already_claimed', () => w.claim(1, 'b'.repeat(32))); }));
    it('DP-7 all closed claim states reject even same claim', async () => { for (const event of ['start', 'result', 'not_run', 'tick'])
        await world(async (w) => { await w.approve(); w.claim(); if (event === 'tick')
            w.advance(900);
        else
            w.report(event, event === 'result' ? w.evidence() : event === 'not_run' ? w.evidence('not_run_full') : {}); const execution = w.record().execution; await refuses('claim_closed:' + execution, () => w.claim()); expect(w.record().claim_id).toBe(CID); }); });
    it('DP-11 claim latest-only and revision guarded after claim', () => world(async (w) => { await w.approve(); await w.revise(); await refuses('not_claimable:superseded', () => w.claim(1)); await w.approve(); w.claim(2); await refuses('claimed_revision_in_progress', () => w.revise()); expect(w.record().claim_id).toBe(CID); }));
    it('report retry is idempotent without new history', () => world(async (w) => { await w.approve(); w.claim(); w.report('result', w.evidence()); const n = w.record().history.length; w.report('result', w.evidence()); expect(w.record().history).toHaveLength(n); await refuses('claim_closed:done', () => w.report('not_run', w.evidence('not_run_full'))); }));
});
