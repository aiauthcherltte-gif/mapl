import { describe, it, expect } from 'vitest';
import { world, refuses, CODE } from './support';
import { b64decode, b64encode } from '../src/canonical';
import { decode } from '../src/cbor';
import { cbor } from './soft-auth';
describe('ported REG server cases', () => {
    it('REG-1 missing/wrong/expired setup code', () => world(async (w) => { await refuses('setup_code_invalid', () => w.store.registrationOptions('')); await refuses('setup_code_invalid', () => w.store.registrationOptions('WRONG')); w.advance(600); await refuses('setup_code_expired', () => w.store.registrationOptions(CODE)); }, false));
    it('REG-2 registration closes after one credential', () => world(async (w) => { await refuses('registration_closed', () => w.register()); expect(w.store.meta('credential')).not.toBeNull(); }));
    it('REG-3 only none attestation and ES256 are accepted', () => world(async (w) => { const options = (await w.store.registrationOptions(CODE)), ch = b64decode(options.challenge); await refuses('attestation_format_refused', async () => w.store.register(CODE, await w.auth.registration(ch, { fmt: 'packed' }))); const cose = decode(w.auth.cose) as Map<unknown, unknown>; cose.set(3, -257); const original = w.auth.cose; w.auth.cose = cbor(cose); await refuses('cose_algorithm_refused', async () => w.store.register(CODE, await w.auth.registration(ch))); w.auth.cose = original; expect(w.store.meta('credential')).toBeNull(); await w.store.register(CODE, await w.auth.registration(ch)); }, false));
    for (const [name, data] of [['indefinite', [191, 255]], ['tag', [192, 160]], ['duplicate', [162, 1, 1, 1, 2]], ['trailing', [160, 0]], ['nonminimal', [184, 0]], ['depth', [...Array(10).fill(129), 0]]] as const)
        it('REG-3 CBOR ' + name, () => world(async (w) => { const ch = b64decode((await w.store.registrationOptions(CODE)).challenge), r = await w.auth.registration(ch); r.response.attestationObject = b64encode(new Uint8Array(data)); await refuses('cbor_malformed', () => w.store.register(CODE, r)); expect(w.store.meta('credential')).toBeNull(); }, false));
    it('REG-4 role tokens cannot register', () => world(async (w) => { for (const token of [w.bindings.RUNNER_TOKEN, w.bindings.REQUESTER_TOKEN])
        for (const endpoint of ['options', 'verify']) {
            const r = await w.http('POST', '/api/register/' + endpoint, { code: CODE }, { Authorization: 'Bearer ' + token });
            expect(r.status).toBe(403);
            expect(await r.json()).toEqual({ error: 'token_scope_refused' });
        } expect(w.store.meta('credential')).toBeNull(); }, false));
    it('registration challenge expires and is rechecked after verification', () => world(async (w) => { const ch = b64decode((await w.store.registrationOptions(CODE)).challenge), r = await w.auth.registration(ch); w.advance(181); await refuses('registration_challenge_expired', () => w.store.register(CODE, r)); expect(w.store.meta('credential')).toBeNull(); }, false));
    it('registration malformed body is refused', () => world(async (w) => { (await w.store.registrationOptions(CODE)); await refuses('registration_malformed', () => w.store.register(CODE, null as any)); }, false));
});
