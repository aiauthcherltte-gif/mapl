import { describe, it, expect } from 'vitest';
import { world, refuses } from './support';
import { verifyAssertion } from '../src/webauthn';
function barrier() { let arrivals = 0, release!: () => void, reached!: () => void; const held = new Promise<void>(r => release = r), both = new Promise<void>(r => reached = r); return { both, release: () => release(), verifier: async (...args: Parameters<typeof verifyAssertion>) => { const facts = await verifyAssertion(...args); if (++arrivals === 2)
        reached(); await held; return facts; }, get arrivals() { return arrivals; } }; }
describe('C5 barrier witnesses (same tests must fail on recheck-removed mutant)', () => {
    it('two verified calls on the same nonce commit exactly one approval and one nonce_used', () => world(async (w) => {
        const a = await w.sign(), gate = barrier();
        w.store.verifier = gate.verifier;
        const outcomes = Promise.allSettled([w.store.approve(w.rid, a, 1), w.store.approve(w.rid, a, 1)]);
        await gate.both;
        expect(gate.arrivals).toBe(2);
        expect(w.record().approval).toBe('pending');
        gate.release();
        const answers = await outcomes;
        expect(answers.filter(a => a.status === 'fulfilled')).toHaveLength(1);
        expect(answers.filter(a => a.status === 'rejected').map(a => (a as PromiseRejectedResult).reason.code)).toEqual(['nonce_used']);
        expect(w.record().history.filter((h: any) => h.event === 'approve')).toHaveLength(1);
        expect(w.store.entry(w.rid, 1).options!.used).toBe(true);
    }));
    it('revision interleaves after both phase-1 snapshots; old revision never remains approved or claimable', () => world(async (w) => {
        const a = await w.sign(), gate = barrier();
        w.store.verifier = gate.verifier;
        const outcomes = Promise.allSettled([w.store.approve(w.rid, a, 1), w.store.approve(w.rid, a, 1)]);
        await gate.both;
        expect(gate.arrivals).toBe(2);
        await w.revise();
        expect(w.record(1).approval).toBe('superseded');
        gate.release();
        const answers = await outcomes;
        expect(answers.every(a => a.status === 'rejected' && a.reason.code === 'stale_revision')).toBe(true);
        expect(w.record(1).approval).toBe('superseded');
        expect(w.record().approval).toBe('pending');
        expect(w.store.approved()).toEqual([]);
        await refuses('not_claimable:superseded', () => w.claim(1));
    }));
});
