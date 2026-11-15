import { env, runInDurableObject } from 'cloudflare:test';
import { expect } from 'vitest';
import requestRows from '../planning/impl/mapl_cloudflare/reference/request.json';
import { b64decode, contentHash } from '../src/canonical';
import { Store } from '../src/store';
import { utc, propertyEvidence } from '../src/state';
import { Refusal, type Dict, type MaplRequest } from '../src/types';
import { SoftAuthenticator } from './soft-auth';
import type { Env } from '../src/platform';
import type { MaplApproval } from '../src/worker';
export const base = requestRows[0].input as unknown as MaplRequest;
export const CODE = 'LOCAL-TEST-SETUP-ONLY';
export const CID = 'a'.repeat(32);
export async function refuses(code: string, action: () => unknown | Promise<unknown>) { try {
    await action();
    throw Error('Expected refusal ' + code);
}
catch (e) {
    expect(e).toBeInstanceOf(Refusal);
    expect((e as Refusal).code).toBe(code);
    return e as Refusal;
} }
// The sole negative control removes the production phase-2 recheck. It is never routed by Worker code.
class UnsafeStore extends Store {
    protected recheckApproval(): void { }
}
export class World {
    auth!: SoftAuthenticator;
    cookie = '';
    session = '';
    request = structuredClone(base);
    rid = base.request_id;
    clock = { now: utc(base.created_at) };
    store!: Store;
    constructor(public instance: MaplApproval, public bindings: Env, public mutant = false) { }
    async init(register = true) { this.store = this.instance.store = new (this.mutant ? UnsafeStore : Store)(this.instance.store.storage, this.bindings, () => this.clock.now); this.store.putMeta('setup_until', this.clock.now + 600000); this.auth = await new SoftAuthenticator().init(); await this.store.create(this.request); if (register)
        await this.register(); if (register) { const o = this.store.loginOptions(); this.session = await this.store.login(o.challenge, await this.auth.assertion(b64decode(o.challenge))); this.cookie = '__Host-mapl_session=' + this.session; } return this; }
    advance(seconds: number) { this.clock.now += seconds * 1000; }
    async register() { const options = await this.store.registrationOptions(CODE); return this.store.register(CODE, await this.auth.registration(b64decode(options.challenge))); }
    record(revision?: number) { return this.store.get(this.rid, revision); }
    async options(rid = this.rid) { const r = this.store.get(rid); return this.store.approvalOptions(rid, r.request.revision, r.content_hash); }
    async sign(o: Dict = {}, rid = this.rid) { return this.auth.assertion(b64decode((await this.options(rid)).challenge), o); }
    async approve() { const a = await this.sign(); await this.store.approve(this.rid, a); return a; }
    claim(revision = 1, cid = CID) { return this.store.claim(this.rid, revision, cid); }
    report(event: string, evidence: Dict = {}, cid: string | null = CID) { return this.store.report(this.rid, 1, cid, event, evidence); }
    evidence(event = 'result_done') { const { claim_id: _, ...e } = propertyEvidence(event, this.request); return e; }
    async revise() { const r = structuredClone(this.request); r.revision = this.store.latest(this.rid)! + 1; return this.store.create(r); }
    async http(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) { return this.instance.fetch(new Request('http://localhost:8790' + path, { method, headers: { Origin: this.bindings.ORIGIN, ...(this.cookie ? { Cookie: this.cookie } : {}), ...headers }, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) })); }
}
export async function world(fn: (w: World) => unknown | Promise<unknown>, register = true) { const bindings = env as unknown as Env & {
    MUTANT: string;
}; const stub = bindings.APPROVAL.get(bindings.APPROVAL.idFromName(crypto.randomUUID())); return runInDurableObject(stub as any, async (instance: MaplApproval) => { const w = await new World(instance, bindings, bindings.MUTANT === '1').init(register); return fn(w); }); }
export async function boundOptions(w: World) { return w.store.approvalOptions(w.rid, 1, await contentHash(w.request)); }
