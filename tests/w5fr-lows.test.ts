import { it, expect } from 'vitest';
import { world, refuses, type World } from './support';
import { b64decode, canonical } from '../src/canonical';
import type { Dict } from '../src/types';

function rows(w: World, prefix: string): { key: string; json: string }[] {
    return w.store.storage.sql.exec<{ key: string; json: string }>('SELECT key,json FROM meta WHERE key GLOB ? ORDER BY key', prefix + ':*').toArray();
}

it('W5FR L1r HTML GET routes redirect invalid sessions to login; APIs keep 401 JSON', () => world(async w => {
    const pages = ['/', '/r/' + w.rid, '/history', '/credential-add'];
    for (const cookie of ['', '__Host-mapl_session=' + 'x'.repeat(43), w.cookie]) {
        if (cookie === w.cookie) w.advance(900);
        for (const path of pages) {
            const r = await w.http('GET', path, undefined, { Cookie: cookie });
            expect(r.status, path).toBe(303);
            expect(r.headers.get('Location')).toBe('/login');
            expect(r.headers.get('Cache-Control')).toBe('no-store');
            expect(await r.text()).not.toContain(w.rid);
        }
        for (const path of ['/api/requests', '/api/requests/' + w.rid, '/api/history']) {
            const r = await w.http('GET', path, undefined, { Cookie: cookie, Accept: 'text/html' });
            expect(r.status, path).toBe(401);
            expect(r.headers.get('Location')).toBeNull();
            expect(await r.json()).toEqual({ error: 'session_required' });
        }
    }
    expect((await w.http('GET', '/login', undefined, { Cookie: '' })).status).toBe(200);
}));

it('W5FR L1r redirect applies only to HTML GET routes', () => world(async w => {
    for (const [method, path] of [['POST', '/history'], ['GET', '/unknown'], ['POST', '/api/logout']]) {
        const r = await w.http(method, path, undefined, { Cookie: '' });
        expect(r.status).toBe(401);
        expect(r.headers.get('Location')).toBeNull();
        expect(await r.json()).toEqual({ error: 'session_required' });
    }
}));

it('W5FR L3r HTTP logout during held approval verification leaves pending and nonce unused', () => world(async w => {
    const assertion = await w.sign(), verify = w.store.verifier;
    const credentialBefore = canonical(w.store.credential(w.auth.id));
    let reached!: () => void, release!: () => void;
    const verified = new Promise<void>(resolve => reached = resolve), held = new Promise<void>(resolve => release = resolve);
    w.store.verifier = async (...args) => { const facts = await verify(...args); reached(); await held; return facts; };
    const approval = w.http('POST', '/api/requests/' + w.rid + '/approve/verify', { revision: 1, credential: assertion });
    try {
        await verified;
        expect(w.record().approval).toBe('pending');
        const logout = await w.http('POST', '/api/logout', {});
        expect(logout.status).toBe(200);
    } finally { release(); w.store.verifier = verify; }
    const response = await approval;
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'session_required' });
    // A post-handler 401 alone hides the reviewer's mutant committing authority.
    expect(w.record().approval).toBe('pending');
    expect(w.store.entry(w.rid).options?.used).toBe(false);
    expect(w.record().history.filter((h: Dict) => h.event === 'approve')).toEqual([]);
    expect(w.store.approved()).toEqual([]);
    expect(canonical(w.store.credential(w.auth.id))).toBe(credentialBefore);
}));

it('W5FR L2r 200 unauthenticated attempts keep at most 32 login challenges and preserve a valid session', () => world(async w => {
    let first = '', last = '';
    for (let i = 0; i < 200; i++) {
        const r = await w.http('POST', '/api/login/options', {}, { Cookie: '' });
        expect(r.status).toBe(200);
        const o = await r.json() as Dict;
        if (i === 0) first = o.challenge;
        last = o.challenge;
    }
    expect(rows(w, 'login').length).toBeLessThanOrEqual(32);
    expect(rows(w, 'login').length).toBeGreaterThan(0);
    expect(w.store.meta('login:' + first)).toBeNull();
    await refuses('login_challenge_invalid', async () => w.store.login(first, await w.auth.assertion(b64decode(first))));
    const r = await w.http('POST', '/api/login/verify', { challenge: last, credential: await w.auth.assertion(b64decode(last)) }, { Cookie: '' });
    expect(r.status).toBe(200);
    expect(w.store.requireSession(w.session)).toBe(w.session);
}));

it('W5FR L2r expired login and session rows drain in bounded batches without deleting live authority or audit', () => world(async w => {
    const history = canonical(w.store.meta('auth_history'));
    // Legacy login rows have issued_at only. Expiry equality must be reclaimable.
    for (let i = 0; i < 100; i++) {
        w.store.putMeta('login:expired-' + i, { issued_at: w.clock.now - 180000, used: false, epoch: '0' });
        w.store.putMeta('session:expired-' + i, { expires_at: w.clock.now, revoked: i % 2 === 0 });
    }
    const live = w.store.loginOptions();
    const remaining = () => [...rows(w, 'login'), ...rows(w, 'session')].filter(r => r.key.includes(':expired-')).length;
    expect(remaining()).toBeLessThan(200);
    expect(200 - remaining()).toBeLessThanOrEqual(32);
    for (let i = 0; i < 10; i++) {
        const before = remaining();
        const r = await w.http('POST', '/api/login/options', {}, { Cookie: '' });
        expect(r.status).toBe(200);
        expect(before - remaining()).toBeLessThanOrEqual(32);
    }
    expect(remaining()).toBe(0);
    expect(w.store.meta('login:' + live.challenge)).not.toBeNull();
    expect(w.store.requireSession(w.session)).toBe(w.session);
    expect(canonical(w.store.meta('auth_history'))).toBe(history);
}));

it('W5FR L2r failed login verification also performs bounded expired-row cleanup', () => world(async w => {
    w.store.putMeta('login:old', { issued_at: w.clock.now - 180001, used: false, epoch: '0' });
    w.store.putMeta('session:old', { expires_at: w.clock.now - 1, revoked: false });
    const r = await w.http('POST', '/api/login/verify', { challenge: 'invalid', credential: {} }, { Cookie: '' });
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: 'login_challenge_invalid' });
    expect(w.store.meta('login:old')).toBeNull();
    expect(w.store.meta('session:old')).toBeNull();
}));

it('W5FR L2r cleanup preserves unexpired rows then reclaims logged-out sessions at expiry', () => world(async w => {
    const o = w.store.loginOptions();
    w.store.logout(w.session);
    w.advance(179);
    w.store.loginOptions();
    expect(w.store.meta('login:' + o.challenge)).not.toBeNull();
    expect(w.store.meta('session:' + w.session)).not.toBeNull();
    w.advance(1);
    w.store.loginOptions();
    expect(w.store.meta('login:' + o.challenge)).toBeNull();
    expect(w.store.meta('session:' + w.session)).not.toBeNull();
    w.advance(720);
    w.store.loginOptions();
    expect(w.store.meta('session:' + w.session)).toBeNull();
    await refuses('session_required', () => w.store.requireSession(w.session));
}));
