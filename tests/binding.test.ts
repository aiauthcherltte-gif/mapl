import { describe, it, expect } from 'vitest';
import { world, refuses, base } from './support';
import { b64decode, b64encode, utf8, approvalChallenge } from '../src/canonical';
import { validate } from '../src/request';
import { verifyAssertion } from '../src/webauthn';
import type { Dict } from '../src/types';
describe('ported BIND server cases', () => {
    it('BIND-1 old revision cannot approve; claimed request cannot revise', () => world(async (w) => { const a = await w.sign(); await w.revise(); await refuses('superseded', () => w.store.approve(w.rid, a, 1)); expect(w.record(1).approval).toBe('superseded'); await w.approve(); w.claim(2); await refuses('claimed_revision_in_progress', () => w.revise()); }));
    it('BIND-4 test root binding', () => world(async (w) => { const r = structuredClone(w.request); r.target.test_root_id = 'f'.repeat(32); await refuses('test_root_id_mismatch', () => w.store.create(r)); }));
    it('BIND-5 expiry blocks approval and claim', () => world(async (w) => { const a = await w.sign(); w.advance(7201); await refuses('expired', () => w.store.approve(w.rid, a)); await refuses('not_claimable:expired', () => w.claim()); }));
    it('BIND-6 nonce replay, other request binding and nonce lifetime', () => world(async (w) => { const a = await w.approve(); await refuses('nonce_used', () => w.store.approve(w.rid, a)); }));
    it('BIND-6 cross-request signature fails and old nonce expires', () => world(async (w) => { const r = structuredClone(w.request); r.request_id = 'b'.repeat(32); await w.store.create(r); const a = await w.sign(); await w.options(r.request_id); await refuses('challenge_mismatch', () => w.store.approve(r.request_id, a)); w.advance(180); await refuses('nonce_expired', () => w.store.approve(w.rid, a)); }));
    const checks: [
        Dict,
        string
    ][] = [[{ kind: 'other' }, 'type_mismatch'], [{ origin: 'http://127.0.0.1:8790' }, 'origin_mismatch'], [{ origin: 'https://localhost:8790' }, 'origin_mismatch'], [{ origin: 'http://localhost:8791' }, 'origin_mismatch'], [{ extra: { crossOrigin: true } }, 'cross_origin_refused'], [{ extra: { topOrigin: 'x' } }, 'cross_origin_refused'], [{ rp: 'other' }, 'rp_id_mismatch'], [{ flags: 4 }, 'up_missing'], [{ flags: 1 }, 'uv_missing'], [{ flags: 0x15 }, 'backup_flags_invalid'], [{ id: 'unknown' }, 'unknown_credential']];
    for (const [params, code] of checks)
        it('BIND-7 ' + code + ' ' + JSON.stringify(params), () => world(async (w) => { await refuses(code, () => w.sign(params).then(a => w.store.approve(w.rid, a))); expect(w.record().approval).toBe('pending'); expect(w.store.entry(w.rid, 1).options!.used).toBe(false); expect(w.record().history.filter((e: Dict) => e.event === 'approve')).toHaveLength(0); }));
    it('BIND-7 wrong challenge, corrupted signature and signed bytes reject specifically', () => world(async (w) => {
        const ch = b64decode((await w.options()).challenge);
        await refuses('challenge_mismatch', async () => w.store.approve(w.rid, await w.auth.assertion(utf8('wrong'))));
        const a = await w.auth.assertion(ch);
        a.response.signature = b64encode(utf8('bad'));
        await refuses('signature_invalid', () => w.store.approve(w.rid, a));
        const b = await w.auth.assertion(ch);
        b.response.clientDataJSON = b64encode(new Uint8Array([...b64decode(b.response.clientDataJSON), 32]));
        await refuses('signature_invalid', () => w.store.approve(w.rid, b));
        const raw = new TextDecoder().decode(w.auth.client(ch, 'webauthn.get', w.bindings.ORIGIN));
        await refuses('client_data_malformed', async () => w.store.approve(w.rid, await w.auth.assertion(ch, { client: utf8(raw.slice(0, -1) + ',"type":"webauthn.get"}') })));
        expect(w.record().approval).toBe('pending');
    }));
    it('BIND-8 cookie, requester/runner tokens and absent assertion never approve', () => world(async (w) => { const path = '/api/requests/' + w.rid + '/approve/verify'; for (const headers of [{ Cookie: 'session=anything' }, { Authorization: 'Bearer ' + w.bindings.RUNNER_TOKEN }, { Authorization: 'Bearer ' + w.bindings.REQUESTER_TOKEN }, {}]) {
        const r = await w.http('POST', path, {}, headers as Record<string, string>);
        expect(r.status).toBeGreaterThanOrEqual(400);
    } expect(w.record().approval).toBe('pending'); expect((await w.http('POST', path, {}, { Origin: 'http://evil' })).status).toBe(403); }));
    it('BIND-10 recovery must be excluded', () => world(async (w) => { const r = structuredClone(w.request); r.recovery.included_in_this_approval = true; await refuses('scope_refused', () => w.store.create(r)); r.recovery.included_in_this_approval = false; r.not_covered = r.not_covered.filter(v => v !== 'recovery'); await refuses('scope_refused', () => w.store.create(r)); }));
    it('BIND-11 action limited to screen_publication/1', () => world(async (w) => { for (const action of ['credential_add/1', 'screen_recovery/1', 'shell/1']) {
        const r = { ...w.request, action_type: action };
        await refuses('action_type_refused', () => w.store.create(r));
    } }));
    it('BIND-12 superseded approval cannot claim', () => world(async (w) => { await w.approve(); await w.revise(); await refuses('not_claimable:superseded', () => w.claim(1)); expect(w.record(1).approval).toBe('superseded'); }));
    it('display pair is mandatory, exact and invalidated by revision', () => world(async (w) => { const path = '/api/requests/' + w.rid + '/approve/options'; const r = w.record(); expect((await w.http('POST', path, {})).status).toBe(400); expect((await w.http('POST', path, { revision: 1, content_hash: r.content_hash })).status).toBe(200); const bad = await w.http('POST', path, { revision: 1, content_hash: '0'.repeat(64) }); expect(await bad.json()).toEqual({ error: 'revision_changed' }); await w.revise(); const stale = await w.http('POST', path, { revision: 1, content_hash: r.content_hash }); expect(await stale.json()).toEqual({ error: 'revision_changed' }); }));
    it('every bound request field changes the signed challenge', async () => { const original = await approvalChallenge(base, 'nonce'); for (const path of ['target.pointer', 'target.before_sha256', 'target.after_sha256', 'bundle.sha256', 'kit.sha256', 'window_utc.0', 'expires_at', 'not_covered.0', 'recovery.included_in_this_approval']) {
        const r = structuredClone(base);
        let owner: Dict = r;
        const parts = path.split('.');
        for (const p of parts.slice(0, -1))
            owner = owner[p];
        owner[parts.at(-1)!] = 'changed';
        expect(b64encode(await approvalChallenge(r, 'nonce')), path).not.toBe(b64encode(original));
    } });
    it('counter decrease is recorded as warning without bypassing signature', () => world(async (w) => { w.store.storage.transactionSync(() => { const c = w.store.meta<Dict>('credential')!; c.sign_count = 999; w.store.putMeta('credential', c); }); await w.approve(); expect(w.store.entry(w.rid, 1).approval_facts!.counter_warning).toBe(true); }));
});
describe('W1 supplemental field-specific rejection rules with independent valid control', () => {
    const rows: [
        string,
        unknown,
        string,
        string
    ][] = [['action_type', 'other', 'action_type_refused', 'action_type'], ['mode', 'production', 'request_invalid', 'mode'], ['recovery.included_in_this_approval', true, 'scope_refused', 'recovery_scope'], ['revision', 0, 'request_invalid', 'revision'], ['revision', true, 'request_invalid', 'revision'], ['target.from_generation', 'gen/005', 'request_invalid', 'target.from_generation'], ['target.to_generation', 'other', 'request_invalid', 'target.to_generation'], ['target.before_sha256', 'a'.repeat(63), 'request_invalid', 'target.before_sha256'], ['target.after_sha256', 'A'.repeat(64), 'request_invalid', 'target.after_sha256'], ['target.pointer', 'real/CURRENT.json', 'request_invalid', 'target.pointer'], ['target.test_root_id', 'f'.repeat(32), 'test_root_id_mismatch', 'target.test_root_id'], ['kit.name', 'real-kit/1', 'request_invalid', 'kit.name'], ['kit.sha256', 'bad', 'request_invalid', 'kit.sha256'], ['bundle.name', 'gen/0007', 'request_invalid', 'bundle.name'], ['bundle.sha256', 10, 'request_invalid', 'bundle.sha256'], ['created_at', '2026-02-30T00:00:00Z', 'request_invalid', 'timestamps'], ['created_at', base.expires_at, 'request_invalid', 'created_before_expiry'], ['expires_at', '2026-11-14T08:00:01Z', 'request_invalid', 'expiry_within_window'], ['window_utc.0', base.window_utc[1], 'request_invalid', 'window_order'], ['window_utc.0', '2026-11-14T03:59:59Z', 'request_invalid', 'window_maximum']];
    for (const [path, value, code, rule] of rows)
        it(path + ' → ' + rule, () => { expect(validate(base, '2'.repeat(32))).toEqual(base); const r = structuredClone(base); let owner: Dict = r; const parts = path.split('.'); for (const p of parts.slice(0, -1))
            owner = owner[p]; owner[parts.at(-1)!] = value; try {
            validate(r, '2'.repeat(32));
            throw Error('expected rejection');
        }
        catch (e) {
            expect(e).toMatchObject({ code, rule });
        } });
    it('new revision must start at 1 and increment exactly', () => world(async (w) => { await refuses('revision_refused', () => w.store.create({ ...w.request, request_id: 'b'.repeat(32), revision: 2 })); await refuses('revision_refused', () => w.store.create({ ...w.request, revision: 3 })); await w.revise(); expect(w.record().request.revision).toBe(2); }));
});
describe('C5 remaining rechecks after a held verifier', () => {
    for (const [name, code] of [['cancel', 'cancelled'], ['expire', 'expired'], ['nonce', 'challenge_mismatch'], ['nonce_expire', 'nonce_expired'], ['revoke', 'credential_revoked'], ['epoch', 'credential_revoked'], ['hash', 'content_changed'], ['request_id', 'content_changed']] as const)
        it(name + ' cannot slip through phase 2', () => world(async (w) => {
            const a = await w.sign();
            let release!: () => void, entered!: () => void;
            const hold = new Promise<void>(r => release = r), ready = new Promise<void>(r => entered = r);
            w.store.verifier = async (...args) => { const f = await verifyAssertion(...args); entered(); await hold; return f; };
            const outcome = w.store.approve(w.rid, a).then(() => null, e => e);
            await ready;
            if (name === 'cancel')
                w.store.cancel(w.rid);
            else if (name === 'expire')
                w.advance(7201);
            else if (name === 'nonce_expire')
                w.advance(180);
            else if (name === 'revoke') {
                const c = w.store.meta<Dict>('credential')!;
                c.revoked = true;
                w.store.putMeta('credential', c);
            }
            else if (name === 'epoch')
                w.store.putMeta('epoch', '1');
            else {
                const e = w.store.entry(w.rid, 1);
                if (name === 'nonce')
                    e.options!.value = 'new';
                else if (name === 'hash')
                    e.content_hash = '0'.repeat(64);
                else
                    e.request.request_id = 'b'.repeat(32);
                if (name === 'request_id')
                    w.store.storage.sql.exec('UPDATE requests SET json=? WHERE key=?', JSON.stringify(e), w.rid + ':1');
                else
                    w.store.save(e);
            }
            release();
            expect(await outcome).toMatchObject({ code });
            expect(w.store.entry(w.rid, 1).options!.used).toBe(false);
            expect(w.store.entry(w.rid, 1).history.filter(h => h.event === 'approve')).toHaveLength(0);
        }));
});
