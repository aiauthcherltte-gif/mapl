import { describe, it, expect } from 'vitest';
import { SELF } from 'cloudflare:test';
import { world, refuses, CODE, CID, base } from './support';
import { BAND, view, confirm } from '../src/ui';
import { Store } from '../src/store';
import { parseJson, canonical, b64decode } from '../src/canonical';
import { SoftAuthenticator } from './soft-auth';
import APP from '../public/app.js.txt';
import INDEX from '../public/index.html';
import type { Dict } from '../src/types';
describe('ported LBL server and shared UI obligations', () => {
    it('LBL-1 all page routes show one test band and security headers', () => world(async (w) => { for (const path of ['/register', '/r/' + w.rid]) {
        const r = await w.http('GET', path);
        expect(r.status).toBe(200);
        expect((await r.text()).split(BAND)).toHaveLength(2);
        expect(r.headers.get('Content-Security-Policy')).toContain('frame-ancestors');
        expect(r.headers.get('X-Frame-Options')).toBe('DENY');
        expect(r.headers.get('Cache-Control')).toBe('no-store');
    } }));
    it('LBL-2 success remains simulated test target', () => world(async (w) => { await w.approve(); w.claim(); w.report('result', w.evidence()); expect(w.record().display_state).toContain('모의 실행'); expect(w.record().display_state).toContain('시험 대상'); }));
    it('LBL-3 server record never identifies authenticator kind', () => world(async (w) => { await w.approve(); const s = canonical(w.record()); expect(s).not.toMatch(/auth_source|가상 인증기|Face ID/); }));
    it('LBL-4 contact never asserts online or offline', () => world(w => { expect(w.store.runnerStatus()).toContain('켜짐·꺼짐은 이 정보만으로 알 수 없습니다'); w.store.heartbeat(); expect(w.store.runnerStatus()).toContain('마지막 연결'); w.store.heartbeat(true); expect(w.store.runnerStatus()).toMatch(/^실행기가 꺼진다고 알림 \d\d:\d\d:\d\d$/); }));
    it('LBL-6 hashes, paths and AI prose stay in details', () => world(w => { const r = w.record(); r.request.summary_by_ai = 'reference-secret-text'; const v = view(r, w.clock.now); expect(v.default_text).not.toMatch(/[0-9a-f]{16,}|TEST_ROOT|test-screen|\.json|mock-kit|request_id|reference-secret-text/); for (const text of [w.rid, w.request.target.before_sha256, 'mock-kit/1', 'reference-secret-text'])
        expect(v.details_text).toContain(text); }));
    it('LBL-7 conditions appear once and confirmation does not repeat', () => world(w => { const r = w.record(), v = view(r, w.clock.now); for (const word of ['자동 복구', '원장']) {
        expect(v.default_text.split(word)).toHaveLength(2);
        expect(confirm(r, w.bindings.ORIGIN)).not.toContain(word);
    } }));
    it('LBL-8 no design notes in primary view', () => world(w => { const r = w.record(); for (const t of [view(r, w.clock.now).default_text, confirm(r, w.bindings.ORIGIN)])
        expect(t).not.toMatch(/U-[1-6]|미정|iCloud 키체인/); expect(view(r, w.clock.now).default_text.split('현재 상태')).toHaveLength(2); }));
    it('LBL-9 malicious AI prose stays text-only', () => world(w => { const r = w.record(), malicious = '<img src=x onerror="alert(1)"><script>evil()</script>'; r.request.summary_by_ai = malicious; const v = view(r, w.clock.now); expect(v.default_text).not.toContain(malicious); expect(v.details_text).toContain(malicious); expect(APP).not.toMatch(/innerHTML|insertAdjacentHTML/); expect(APP).toContain('textContent'); }));
    it('DP-2 approval options close after approval', () => world(async (w) => { await w.approve(); await refuses('already_approved', () => w.options()); expect(w.record().history.filter((h: Dict) => h.event === 'approve')).toHaveLength(1); }));
    it('DP-9 no retry or rerun endpoint or button', () => world(async (w) => { for (const path of ['/api/runner/retry', '/api/runner/rerun']) {
        const r = await w.http('POST', path, {}, { Authorization: 'Bearer ' + w.bindings.RUNNER_TOKEN });
        expect(r.status).toBe(404);
    } expect(INDEX).not.toMatch(/(retry|rerun|다시 실행)[^<]*<\/button>/i); }));
    it('DP-11 gave-up report closes same claim', () => world(async (w) => { await w.approve(); w.claim(); w.report('not_run', w.evidence('not_run_full')); await refuses('claim_closed:not_run', () => w.claim()); expect(w.record().display_state).not.toContain('대기'); }));
    it('poll queued approval/claim/running or connection uncertainty at 5 seconds; stop while hidden', () => { expect(APP).toContain("['claimed', 'running', 'checking', 'recovering'].includes(record.execution)"); expect(APP).toContain('!document.hidden && (uncertain || active())'); expect(APP).toContain('}, 5000)'); expect(APP).not.toContain('}, 2000)'); expect(APP).toContain("document.addEventListener('visibilitychange'"); });
});
describe('server-authoritative refusal folding and load', () => {
    it('poll has_pending matches active requests and heartbeat writes at most once per five minutes', () => world(async (w) => {
        const path = '/api/runner/approved', headers = { Authorization: 'Bearer ' + w.bindings.RUNNER_TOKEN };
        const before = w.store.writes;
        let r = await w.http('GET', path, undefined, headers);
        expect((await r.json() as Dict).has_pending).toBe(true);
        const first = w.store.writes;
        expect(first - before).toBe(2); // Initial insert includes the primary-key index; steady updates write one row.
        w.advance(20);
        await w.http('GET', path, undefined, headers);
        expect(w.store.writes).toBe(first);
        w.advance(280);
        await w.http('GET', path, undefined, headers);
        expect(w.store.writes).toBe(first + 1);
        w.store.cancel(w.rid);
        r = await w.http('GET', path, undefined, headers);
        expect((await r.json() as Dict).has_pending).toBe(false);
    }));
    it('restart and stale/malicious client counts never overwrite durable total', () => world(async (w) => { await w.approve(); const before = w.store.writes; w.report('refused_before_claim', { code: 'CLOCK_SKEW', count: 1000, last_at: '2099-01-01T00:00:00Z' }, null); const perUpdate = w.store.writes - before; w.advance(20); w.report('refused_before_claim', { code: 'CLOCK_SKEW', count: 0, last_at: '2000-01-01T00:00:00Z' }, null); w.store = w.instance.store = new Store(w.store.storage, w.bindings, () => w.clock.now); w.advance(20); w.report('refused_before_claim', { code: 'CLOCK_SKEW', count: 1 }, null); const rows = w.record().history.filter((h: Dict) => h.event === 'refused_before_claim'); expect(rows).toHaveLength(1); expect(rows[0]).toMatchObject({ code: 'CLOCK_SKEW', count: 3, last_at: '2026-11-14T06:00:40Z' }); expect(w.record().approval).toBe('approved'); expect(w.record().execution).toBe('not_started'); expect(w.record().claim_id).toBeNull(); console.log('R5.3 refusal SQL rowsWritten per update:', perUpdate, '; 4320 polls/day =>', 4320 * perUpdate, 'additional SQL rowsWritten/day; local counter, not operational metric'); expect(perUpdate).toBeGreaterThan(0); }));
    it('exact accepted/refused refusal codes and no history change on rejection', () => world(async (w) => { for (const code of ['CONTENT_MISMATCH', 'pinned_key_mismatch', 'ASSERTION_REFUSED', 'CLOCK_SKEW'])
        w.report('refused_before_claim', { code }, null); for (const code of ['UNKNOWN_REFUSAL', 'clock_skew', 'CLOCK_SKEW ', null, [], {}]) {
        const n = w.record().history.length;
        expect((await refuses('refusal_code_invalid', () => w.report('refused_before_claim', { code }, null))).status).toBe(400);
        expect(w.record().history).toHaveLength(n);
    } expect(w.record().history.filter((h: Dict) => h.event === 'refused_before_claim')).toHaveLength(4); }));
});
describe('strict HTTP boundaries', () => {
    it('duplicate keys including escaped, nested and prototype names are seen before assignment', () => world(async (w) => { for (const raw of ['{"revision":1,"revision":2}', '{"revision":1,"revis\\u0069on":2}', '{"x":{"a":1,"a":2}}', '{"__proto__":1,"__proto__":2}']) {
        const r = await w.http('POST', '/api/requester/requests', raw, { Authorization: 'Bearer ' + w.bindings.REQUESTER_TOKEN });
        expect(r.status).toBe(400);
        expect(await r.json()).toEqual({ error: 'json_malformed' });
    } expect(parseJson('{"__proto__":{"x":1},"a":2}')).toEqual(JSON.parse('{"__proto__":{"x":1},"a":2}')); expect(({} as Dict).x).toBeUndefined(); }));
    it('safe integer boundaries and forbidden JSON floats/constants', () => { for (const n of ['9007199254740991', '-9007199254740991'])
        expect(parseJson(n)).toBe(Number(n)); for (const raw of ['9007199254740992', '-9007199254740992', '9007199254740993', '{"nested":[9007199254740993]}'])
        expect(() => parseJson(raw)).toThrow('json_integer_out_of_range'); for (const raw of ['1.0', '1e0', 'NaN', 'Infinity', '{"a":1,}', '[1,]', '01', 'truefalse'])
        expect(() => parseJson(raw)).toThrow('json_malformed'); });
    it('host, origin, size and role scope fail closed', () => world(async (w) => { const p = '/api/requests/' + w.rid + '/approve/options'; let r = await w.instance.fetch(new Request('http://evil' + p, { method: 'POST', body: '{}', headers: { Origin: w.bindings.ORIGIN, Cookie: w.cookie } })); expect(await r.json()).toEqual({ error: 'host_mismatch' }); r = await w.http('POST', p, {}, { Origin: 'http://evil' }); expect(await r.json()).toEqual({ error: 'origin_mismatch' }); r = await w.http('POST', '/api/runner/claim', {}, { Authorization: 'Bearer ' + w.bindings.REQUESTER_TOKEN }); expect(await r.json()).toEqual({ error: 'token_scope_refused' }); r = await w.http('POST', '/api/requester/requests', 'x'.repeat(131073), { Authorization: 'Bearer ' + w.bindings.REQUESTER_TOKEN }); expect(r.status).toBe(413); }));
    it('test worker refuses operational request', () => world(async (w) => { const request = { ...w.request, mode: 'production' }; const r = await w.http('POST', '/api/requester/requests', { request }, { Authorization: 'Bearer ' + w.bindings.REQUESTER_TOKEN }); expect(r.status).toBe(400); expect(await r.json()).toEqual({ error: 'request_invalid' }); }));
});
it('real Worker forwarding → SQLite DO → software registration → approval → claim → simulated report', async () => {
    const auth = await new SoftAuthenticator().init(), origin = 'http://localhost:8790';
    let cookie = '';
    const call = async (path: string, body?: Dict, token?: string) => { const response = await SELF.fetch(origin + path, { method: body ? 'POST' : 'GET', headers: { Origin: origin, Cookie: cookie, ...token ? { Authorization: 'Bearer ' + token } : {} }, body: body ? JSON.stringify(body) : undefined }); if (response.headers.has('Set-Cookie')) cookie = response.headers.get('Set-Cookie')!.split(';')[0]; const data = await response.json() as Dict; expect(response.status, canonical(data)).toBe(200); return data; };
    const request = structuredClone(base), now = Date.now();
    request.created_at = new Date(now - 1000).toISOString();
    request.expires_at = new Date(now + 3600000).toISOString();
    request.window_utc = [request.created_at, request.expires_at];
    await call('/api/requester/requests', { request }, 'local-requester-fixture-'.repeat(3));
    const registration = await call('/api/register/options', { code: CODE });
    await call('/api/register/verify', { code: CODE, credential: await auth.registration(b64decode(registration.challenge)) });
    const login = await call('/api/login/options', {});
    await call('/api/login/verify', { challenge: login.challenge, credential: await auth.assertion(b64decode(login.challenge)) });
    const current = await call('/api/requests/' + request.request_id);
    const options = await call('/api/requests/' + request.request_id + '/approve/options', { revision: 1, content_hash: current.content_hash });
    await call('/api/requests/' + request.request_id + '/approve/verify', { revision: 1, credential: await auth.assertion(b64decode(options.challenge)) });
    const approved = await call('/api/runner/approved', undefined, 'local-runner-fixture-'.repeat(3));
    expect(approved.requests).toHaveLength(1);
    expect(approved.has_pending).toBe(true);
    expect(approved.server_now).toBeTypeOf('string');
    expect(approved.requests[0].credential.spki).toBeTypeOf('string');
    await call('/api/runner/claim', { request_id: request.request_id, revision: 1, claim_id: CID }, 'local-runner-fixture-'.repeat(3));
    const result = await call('/api/runner/report', { request_id: request.request_id, revision: 1, claim_id: CID, event: 'result', evidence: { exit: 'ok', marker: 'present_this_claim', pointer_sha256: request.target.after_sha256, output: 'mock_swapped_test_target' } }, 'local-runner-fixture-'.repeat(3));
    expect(result.execution).toBe('done');
    expect(result.display_state).toContain('모의 실행');
});
