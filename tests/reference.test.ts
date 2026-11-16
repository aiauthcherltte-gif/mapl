import { describe, it, expect } from 'vitest';
import canonicalRows from '../planning/impl/mapl_cloudflare/reference/canonical.json';
import fixedRows from '../planning/impl/mapl_cloudflare/reference/canonical-fixed.json';
import challenges from '../planning/impl/mapl_cloudflare/reference/challenge.json';
import requests from '../planning/impl/mapl_cloudflare/reference/request.json';
import states from '../planning/impl/mapl_cloudflare/reference/state.json';
import wording from '../planning/impl/mapl_cloudflare/reference/wording.json';
import strictRows from '../planning/impl/mapl_cloudflare/reference/strict-json-fixed.json';
import refusalRows from '../planning/impl/mapl_cloudflare/reference/refusal-fixed.json';
import { canonical, canonicalBytes, hex, digest, approvalChallenge, parseJson } from '../src/canonical';
import { validate } from '../src/request';
import { display, kst, initial, propertyEvidence, transition, utc, type State } from '../src/state';
import { confirm, view, BAND } from '../src/ui';
import { REFUSAL_CODES } from '../src/store';
import { Refusal, type Dict, type MaplRequest } from '../src/types';
const base = requests[0].input as unknown as MaplRequest;
const outcome = (f: () => unknown) => { try {
    f();
    return { accepted: true };
}
catch (e) {
    if (e instanceof Refusal)
        return { accepted: false, reason: e.code, status: e.status };
    throw e;
} };
describe('W1 immutable oracle: all rows', () => {
    it('35 canonical byte and digest rows', async () => { for (const row of canonicalRows) {
        const expected = row.expected as Dict;
        if (expected.accepted) {
            const bytes = canonicalBytes(row.input);
            expect(hex(bytes), String(row.id)).toBe(expected.utf8_hex);
            expect(await digest(bytes)).toBe(expected.sha256);
        }
        else if (expected.exception)
            expect(() => canonical(row.input)).toThrow('json_surrogate_refused');
        else
            expect(outcome(() => canonical(row.input))).toEqual({ accepted: false, reason: expected.reason, status: expected.status });
    } });
    it('7 fixed safe integer and code-point rows', () => { for (const row of fixedRows) {
        const expected = row.expected as Dict;
        if (expected.accepted)
            expect(canonical(row.input)).toBe(expected.utf8);
        else
            expect(outcome(() => canonical(row.input))).toEqual(expected);
    } });
    it('10 content-bound challenge rows', async () => { for (const row of challenges)
        expect(hex(await approvalChallenge(row.request as unknown as MaplRequest, row.nonce))).toBe(row.expected_hex); });
    it('53 request outcomes', () => { for (const row of requests)
        expect(outcome(() => validate(row.input, '2'.repeat(32))), String(row.id)).toEqual(row.expected); });
    it('88741 state sequences and 112 nodes', () => {
        const interned = new Map<string, {
            state: State;
            now: number;
        }>();
        interned.set('', { state: initial(), now: utc(base.created_at) });
        for (const row of states.sequences) {
            if (!row.sequence.length) {
                expect(initial()).toEqual(states.nodes[row.node].state);
                continue;
            }
            const seq = row.sequence, prior = interned.get(seq.slice(0, -1).join(','))!, event = states.events[seq.at(-1)!], now = prior.now + (event === 'tick_15m' ? 900000 : event === 'tick_24h' ? 86400000 : 0);
            let next = prior.state, reason = null;
            try {
                next = transition(prior.state, event, propertyEvidence(event, base), now, base);
            }
            catch (e) {
                if (!(e instanceof Refusal))
                    throw e;
                reason = e.code;
            }
            expect(reason).toBe(row.reason);
            expect(next).toEqual(states.nodes[row.node].state);
            expect(now).toBe(utc(states.nodes[row.node].now));
            interned.set(seq.join(','), { state: next, now });
        }
    });
    it('112 immutable v1 statuses; AF1 supersedes old screen layout', () => { expect(BAND).toBe(wording.band); let mapped = 0, unchanged = 0; for (const row of wording.cases) {
        const node = states.nodes[row.node], now = utc(node.now), text = display(node.state, base, now), record = { request: base, history: [{ at: base.created_at, event: 'create' }], runner_status: 'Mac 실행기(모의) 연결 기록 없음', credential_count: 0, display_state: text };
        const pattern = /시작 보고 (\d\d:\d\d) \(/g;
        const matches = [...row.display.matchAll(pattern)];
        if (matches.length) {
            expect(matches).toHaveLength(1);
            expect(matches[0][1]).toBe(node.state.started_at!.slice(11, 16));
            mapped++;
        } else unchanged++;
        const expected = (value: string) => value.replace(pattern, () => `시작 보고 ${kst(node.state.started_at!)} (`);
        expect(text).toBe(expected(row.display));
        const current = view(record, now);
        for (const field of ['title', 'change']) expect(current[field]).toBe(row.view[field as keyof typeof row.view]);
        expect(current.state).toBe(expected(row.view.state));
        expect(current.failure).toContain('이 요청은 교체 뒤 확인을 하지 않습니다.');
        expect(confirm(record, 'https://mapl-test.invalid')).toBe(row.confirmation);
    } expect(mapped).toBe(4); expect(unchanged).toBe(108); });
    it('strict JSON fixed duplicate row', () => { for (const row of strictRows)
        expect(outcome(() => parseJson(row.raw))).toEqual(row.expected); });
    it('2 fixed refusal-code decisions', () => { for (const row of refusalRows)
        expect(REFUSAL_CODES.has(row.code)).toBe(row.expected.accepted); });
});
