import { it, expect, vi } from 'vitest';
import { world, refuses, CODE, type World } from './support';
import { b64decode, b64encode, canonical } from '../src/canonical';
import { Store } from '../src/store';
import { SoftAuthenticator } from './soft-auth';
import { secretEqual } from '../src/secrets';
import type { Dict } from '../src/types';

const routes = (w: World): [string, string, unknown?][] => [
    ['GET', '/'], ['GET', '/r/' + w.rid], ['GET', '/history'], ['GET', '/credential-add'],
    ['GET', '/api/requests'], ['GET', '/api/requests/' + w.rid], ['GET', '/api/requests/' + w.rid + '/history'],
    ['POST', '/api/requests/' + w.rid + '/approve/options', { revision: 1, content_hash: w.record().content_hash }],
    ['POST', '/api/requests/' + w.rid + '/approve/verify', {}], ['POST', '/api/requests/' + w.rid + '/decline', {}],
    ['POST', '/api/credential-add/options', {}], ['POST', '/api/credential-add/prepare', {}], ['POST', '/api/credential-add/verify', {}],
    ['GET', '/api/history'], ['POST', '/api/logout', {}],
];
for (const kind of ['none', 'runner', 'requester', 'expired', 'forged', 'valid'] as const)
    it('W5b every browser route session matrix: ' + kind, () => world(async w => {
        const valid = w.cookie;
        const headers: Record<string, string> = { Cookie: kind === 'none' || kind === 'runner' || kind === 'requester' ? '' : kind === 'forged' ? '__Host-mapl_session=' + 'a'.repeat(43) : valid };
        if (kind === 'runner' || kind === 'requester') headers.Authorization = 'Bearer ' + (kind === 'runner' ? w.bindings.RUNNER_TOKEN : w.bindings.REQUESTER_TOKEN);
        if (kind === 'expired') w.advance(900);
        const observations: { method: string; path: string; status: number; body: unknown; location: string | null }[] = [];
        for (const [method, path, body] of routes(w)) {
            const response = await w.http(method, path, body, headers);
            const text = await response.text();
            let result: unknown = null;
            try { result = JSON.parse(text); } catch { /* public HTML has no request data */ }
            observations.push({ method, path, status: response.status, body: result, location: response.headers.get('Location') });
        }
        console.log('W5b route matrix', kind, JSON.stringify(observations.map(({ method, path, status }) => ({ method, path, status }))));
        for (const response of observations) {
            if (kind !== 'valid') {
                const html = response.method === 'GET' && !response.path.startsWith('/api/');
                expect(response.status, response.path).toBe(html ? 303 : 401);
                if (html) expect(response.location, response.path).toBe('/login');
                else expect(response.body, response.path).toEqual({ error: 'session_required' });
            } else {
                expect(response.status, response.path).not.toBe(401);
                expect(response.status, response.path).not.toBe(404);
                if (response.method === 'GET') expect(response.status, response.path).toBe(200);
            }
        }
    }));
it('W5b missing session wins over forged Origin, token, malformed body and spoofed headers', () => world(async w => {
    for (const [method, path] of routes(w)) {
        const r = await w.http(method, path, method === 'POST' ? '{invalid' : undefined,
            { Cookie: '', Origin: 'http://evil', Host: 'evil', 'X-Authenticated-User': 'owner', Authorization: 'Bearer fake' });
        if (method === 'GET' && !path.startsWith('/api/')) {
            expect(r.status, path).toBe(303); expect(r.headers.get('Location')).toBe('/login');
        } else { expect(r.status, path).toBe(401); expect(await r.json()).toEqual({ error: 'session_required' }); }
    }
}));
it('W5b real UV login sets hardened cookie and persists revocable server session across reconstruction', () => world(async w => {
    const options = await w.http('POST', '/api/login/options', {}), o = await options.json() as Dict;
    expect(o.userVerification).toBe('required'); expect(b64decode(o.challenge)).toHaveLength(32);
    const assertion = await w.auth.assertion(b64decode(o.challenge));
    const r = await w.http('POST', '/api/login/verify', { challenge: o.challenge, credential: assertion });
    expect(r.status).toBe(200);
    const set = r.headers.get('Set-Cookie')!;
    for (const flag of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/', 'Max-Age=900']) expect(set).toContain(flag);
    const cookie = set.split(';')[0], sid = cookie.split('=')[1];
    expect(w.store.meta('session:' + sid)).toMatchObject({ revoked: false, credential_id: w.auth.id });
    w.store = w.instance.store = new Store(w.store.storage, w.bindings, () => w.clock.now);
    expect((await w.http('GET', '/api/requests', undefined, { Cookie: cookie })).status).toBe(200);
    expect((await w.http('POST', '/api/logout', {}, { Cookie: cookie })).status).toBe(200);
    expect((await w.http('GET', '/api/requests', undefined, { Cookie: cookie })).status).toBe(401);
    await refuses('login_challenge_invalid', () => w.store.login(o.challenge, assertion));
}));
it('W5b login challenges are random, single-use, expire and require a real UV signature', () => world(async w => {
    const a = w.store.loginOptions(), b = w.store.loginOptions(); expect(a.challenge).not.toBe(b.challenge);
    await refuses('uv_missing', async () => w.store.login(a.challenge, await w.auth.assertion(b64decode(a.challenge), { flags: 1 })));
    expect(w.store.meta<Dict>('login:' + a.challenge)!.used).toBe(false);
    await refuses('challenge_mismatch', async () => w.store.login(a.challenge, await w.auth.assertion(b64decode(b.challenge))));
    const assertion = await w.auth.assertion(b64decode(a.challenge));
    const answers = await Promise.allSettled([w.store.login(a.challenge, assertion), w.store.login(a.challenge, assertion)]);
    expect(answers.filter(x => x.status === 'fulfilled')).toHaveLength(1);
    w.advance(180); await refuses('login_challenge_invalid', async () => w.store.login(b.challenge, await w.auth.assertion(b64decode(b.challenge))));
}));
it('W5b login assertion and session cannot replace per-action approval or add signatures', () => world(async w => {
    const o = w.store.loginOptions(), assertion = await w.auth.assertion(b64decode(o.challenge));
    await w.store.login(o.challenge, assertion); await w.options();
    await refuses('challenge_mismatch', () => w.store.approve(w.rid, assertion));
    expect((await w.http('POST', '/api/requests/' + w.rid + '/approve/verify', {})).status).toBe(400);
    expect(w.record().approval).toBe('pending');
}));
it('W5b role tokens never yield a session or create credential_add/1', () => world(async w => {
    for (const token of [w.bindings.REQUESTER_TOKEN, w.bindings.RUNNER_TOKEN]) {
        for (const path of ['/api/login/options', '/api/login/verify']) {
            const r = await w.http('POST', path, {}, { Authorization: 'Bearer ' + token });
            expect(r.status).toBe(403); expect(r.headers.get('Set-Cookie')).toBeNull();
        }
    }
    const r = await w.http('POST', '/api/requester/requests', { request: { ...w.request, action_type: 'credential_add/1' } }, { Authorization: 'Bearer ' + w.bindings.REQUESTER_TOKEN });
    expect(r.status).toBe(409); expect(await r.json()).toEqual({ error: 'action_type_refused' });
}));
async function prepare(w: World) {
    const candidate = await new SoftAuthenticator().init(); candidate.id = b64encode(crypto.getRandomValues(new Uint8Array(24))); const o = w.store.credentialAddOptions(w.session);
    const approval = await w.store.credentialAddPrepare(w.session, o.action_id, await candidate.registration(b64decode(o.registration.challenge)));
    return { candidate, o, approval };
}
it('W5b credential_add/1 binds new public key and requires existing passkey UV; new key then logs in and approves', () => world(async w => {
    const { candidate, o, approval } = await prepare(w);
    expect(approval.action_type).toBe('credential_add/1');
    await refuses('existing_passkey_required', async () => w.store.credentialAddVerify(w.session, o.action_id, await candidate.assertion(b64decode(approval.challenge))));
    await refuses('uv_missing', async () => w.store.credentialAddVerify(w.session, o.action_id, await w.auth.assertion(b64decode(approval.challenge), { flags: 1 })));
    const login = w.store.loginOptions();
    await refuses('challenge_mismatch', async () => w.store.credentialAddVerify(w.session, o.action_id, await w.auth.assertion(b64decode(login.challenge))));
    const assertion = await w.auth.assertion(b64decode(approval.challenge));
    const outcomes = await Promise.allSettled([w.store.credentialAddVerify(w.session, o.action_id, assertion), w.store.credentialAddVerify(w.session, o.action_id, assertion)]);
    expect(outcomes.filter(x => x.status === 'fulfilled')).toHaveLength(1);
    expect(w.store.credentialSummary()).toMatchObject({ credential_count: 2, credential_registered_at: w.record().server_now });
    expect(w.store.meta<Dict[]>('auth_history')!.at(-1)).toMatchObject({ event: 'credential_added', signer_id: w.auth.id, credential_id: candidate.id });
    const lo = w.store.loginOptions(); await w.store.login(lo.challenge, await candidate.assertion(b64decode(lo.challenge)));
    const ao = await w.options(); expect(ao.allowCredentials.map((c: Dict) => c.id)).toContain(candidate.id);
    await w.store.approve(w.rid, await candidate.assertion(b64decode(ao.challenge)));
    expect(w.store.approved()[0].credential.id).toBe(candidate.id);
}));
it('W5b credential addition is bound to session and expires, and session is rechecked after verifier await', () => world(async w => {
    const { o, approval } = await prepare(w), other = w.store.loginOptions();
    const sid = await w.store.login(other.challenge, await w.auth.assertion(b64decode(other.challenge)));
    await refuses('credential_add_invalid', async () => w.store.credentialAddVerify(sid, o.action_id, await w.auth.assertion(b64decode(approval.challenge))));
    const a = await w.auth.assertion(b64decode(approval.challenge)), verify = w.store.verifier;
    w.store.verifier = async (...args) => { const facts = await verify(...args); w.store.logout(w.session); return facts; };
    await refuses('session_required', () => w.store.credentialAddVerify(w.session, o.action_id, a));
    expect(w.store.credentialSummary().credential_count).toBe(1);
}));
it('W5b CB-5 only stored+1 revokes once, preserves keys and writes both history rows; re-registration retained', () => world(async w => {
    const before = canonical(w.store.meta('credential')), history = w.store.meta<Dict[]>('auth_history')!.length;
    const reopen = (epoch: string) => new Store(w.store.storage, { ...w.bindings, RECOVERY_EPOCH: epoch }, () => w.clock.now);
    reopen('0'); expect(canonical(w.store.meta('credential'))).toBe(before);
    for (const epoch of ['2', '-1', 'garbage', '01']) await refuses('recovery_epoch_invalid', () => reopen(epoch));
    w.store = w.instance.store = reopen('1');
    expect(w.store.meta<Dict>('credential')).toMatchObject({ id: w.auth.id, revoked: true });
    expect(w.store.meta<Dict[]>('auth_history')!.slice(history).map(h => h.event)).toEqual(['credential_revoked', 'registration_window_reopened']);
    reopen('1'); expect(w.store.meta<Dict[]>('auth_history')).toHaveLength(history + 2);
    await refuses('session_required', () => w.store.requireSession(w.session));
    await refuses('recovery_epoch_invalid', () => reopen('0'));
    const old = w.auth.id; w.auth = await new SoftAuthenticator().init(); w.auth.id = b64encode(crypto.getRandomValues(new Uint8Array(24))); await w.register();
    expect(w.store.credentials()).toHaveLength(2); expect(w.store.credentials().find(c => c.id === old)?.revoked).toBe(true);
    expect(w.store.meta<Dict[]>('auth_history')!.at(-1)?.event).toBe('credential_registered');
    const count = w.store.meta<Dict[]>('auth_history')!.length;
    w.store = w.instance.store = reopen('2');
    expect(w.store.meta<Dict[]>('auth_history')!.slice(count).map(h => h.event)).toEqual(['credential_revoked', 'registration_window_reopened']);
    expect(w.store.credentials().every(c => c.revoked)).toBe(true);
}));
it('W5b L1 digest comparison accepts only exact role tokens and setup code', () => world(async w => {
    expect(await secretEqual(CODE, CODE, 10)).toBe(true);
    for (const value of ['', CODE.slice(1), CODE + 'x', null, {}]) expect(await secretEqual(value, CODE, 10)).toBe(false);
    for (const token of [w.bindings.RUNNER_TOKEN, w.bindings.RUNNER_TOKEN + 'x', w.bindings.RUNNER_TOKEN!.slice(1)]) {
        const r = await w.http('GET', '/api/runner/approved', undefined, { Authorization: 'Bearer ' + token });
        expect(r.status).toBe(token === w.bindings.RUNNER_TOKEN ? 200 : 403);
    }
}));

it('W5b L1 both HTTP role auth and setup gate compare fixed-size hashes with timingSafeEqual', () => world(async w => {
    const subtle = crypto.subtle as SubtleCrypto & { timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean };
    const original = subtle.timingSafeEqual.bind(subtle), lengths: number[][] = [];
    const spy = vi.spyOn(subtle, 'timingSafeEqual').mockImplementation((a, b) => { lengths.push([a.byteLength, b.byteLength]); return original(a, b); });
    try {
        await w.http('GET', '/api/runner/approved', undefined, { Authorization: 'Bearer ' + w.bindings.RUNNER_TOKEN });
        await w.http('POST', '/api/requester/requests', {}, { Authorization: 'Bearer wrong' });
        await w.store.registrationOptions(CODE);
        expect(lengths).toEqual([[32, 32], [32, 32], [32, 32]]);
    } finally { spy.mockRestore(); }
}, false));
it('W5b login rechecks challenge expiry and credential revocation after verification', () => world(async w => {
    for (const change of ['expiry', 'revoke']) {
        const o = w.store.loginOptions(), assertion = await w.auth.assertion(b64decode(o.challenge)), verify = w.store.verifier;
        w.store.verifier = async (...args) => { const facts = await verify(...args); if (change === 'expiry') w.advance(180); else { const c = w.store.meta<Dict>('credential')!; w.store.putMeta('credential', { ...c, revoked: true }); } return facts; };
        await refuses(change === 'expiry' ? 'login_challenge_invalid' : 'credential_revoked', () => w.store.login(o.challenge, assertion));
        w.store.verifier = verify;
        expect(w.store.meta<Dict>('login:' + o.challenge)!.used).toBe(false);
    }
}));
it('W5b expired credential_add and per-action approval after logout commit no new authority', () => world(async w => {
    const { o, approval } = await prepare(w), assertion = await w.auth.assertion(b64decode(approval.challenge));
    w.advance(180); await refuses('credential_add_invalid', () => w.store.credentialAddVerify(w.session, o.action_id, assertion));
    expect(w.store.credentialSummary().credential_count).toBe(1);
    const a = await w.sign(), verify = w.store.verifier;
    w.store.verifier = async (...args) => { const facts = await verify(...args); w.store.logout(w.session); return facts; };
    await refuses('session_required', () => w.store.approve(w.rid, a, 1, w.session));
    expect(w.record().approval).toBe('pending'); expect(w.store.entry(w.rid).options?.used).toBe(false);
}));

it('W5b HTTP credential_add ceremony exposes count and last-added time on first screen', () => world(async w => {
    const candidate = await new SoftAuthenticator().init(); candidate.id = b64encode(crypto.getRandomValues(new Uint8Array(24)));
    const call = async (path: string, body?: Dict): Promise<Dict> => {
        const r = await w.http(body ? 'POST' : 'GET', path, body); expect(r.status).toBe(200); return await r.json() as Dict;
    };
    const action = await call('/api/credential-add/options', {});
    const bound = await call('/api/credential-add/prepare', { action_id: action.action_id, credential: await candidate.registration(b64decode(action.registration.challenge)) });
    const result = await call('/api/credential-add/verify', { action_id: action.action_id, credential: await w.auth.assertion(b64decode(bound.challenge)) });
    expect(result.credential_count).toBe(2);
    const list = await call('/api/requests');
    expect(list.credential_count).toBe(2); expect(list.credential_registered_at).toBe(w.record().server_now);
    expect((await call('/api/history')).history.at(-1).event).toBe('credential_added');
}));
