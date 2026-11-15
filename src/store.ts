import { FLOW_EVENTS } from './flow';
import { approvalChallenge, b64decode, b64encode, canonical, contentHash, digest, sha256, utf8 } from './canonical';
import { validate } from './request';
import { display, expired, initial, stamp, transition, utc, type State } from './state';
import { clone, need, type Dict, type MaplRequest } from './types';
import { verifyAssertion, verifyRegistration, type Credential, type Facts } from './webauthn';
import type { Env, Storage } from './platform';
import { secretEqual } from './secrets';
interface Nonce {
    value: string;
    issued_at: string;
    used: boolean;
}
export interface Entry {
    request: MaplRequest;
    content_hash: string;
    state: State;
    history: Dict[];
    assertion: Dict | null;
    nonce: string | null;
    approval_facts: Facts | null;
    claim_response: Dict | null;
    last_evidence: Dict | null;
    options?: Nonce;
    last_report?: Dict;
}
export interface ApprovalSnapshot {
    entry: Entry;
    credential: Credential;
    epoch: string;
    session?: string;
}
export type Verifier = typeof verifyAssertion;
export const REFUSAL_CODES = new Set(['EXPIRED', 'CONTENT_MISMATCH', 'pinned_key_mismatch', 'ASSERTION_REFUSED', 'CLOCK_SKEW']);
const random = (length: number) => Array.from(crypto.getRandomValues(new Uint8Array(length)), v => v.toString(16).padStart(2, '0')).join('');

const AUTH_ROWS = "(key GLOB 'login:*' OR key GLOB 'session:*')";
// Existing login records have issued_at, while sessions already have expires_at.
const AUTH_EXPIRY = "coalesce(json_extract(json,'$.expires_at'), json_extract(json,'$.issued_at') + 180000)";
const AUTH_CLEANUP_LIMIT = 32, LOGIN_CHALLENGE_LIMIT = 32;
const key = (rid: string, revision: number) => { need(typeof rid === 'string' && /^[0-9a-f]{32}$/.test(rid) && Number.isSafeInteger(revision) && revision >= 1, 'request_not_found', 404); return rid + ':' + revision; };
export class Store {
    public verifier: Verifier = verifyAssertion;
    public writes = 0;
    constructor(public storage: Storage, public env: Env, public clock: () => number = Date.now) {
        storage.sql.exec('CREATE TABLE IF NOT EXISTS requests (key TEXT PRIMARY KEY, json TEXT NOT NULL)');
        storage.sql.exec('CREATE TABLE IF NOT EXISTS latest (rid TEXT PRIMARY KEY, revision INTEGER NOT NULL)');
        storage.sql.exec('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, json TEXT NOT NULL)');
        storage.sql.exec(`CREATE INDEX IF NOT EXISTS auth_expiry ON meta (${AUTH_EXPIRY}, key) WHERE ${AUTH_ROWS}`);
        storage.transactionSync(() => {
            if (this.meta('setup_until') === null)
                this.putMeta('setup_until', clock() + 600000);
            if (this.meta('user_id') === null)
                this.putMeta('user_id', b64encode(crypto.getRandomValues(new Uint8Array(16))));
            const epoch = env.RECOVERY_EPOCH ?? '0', stored = this.meta<string>('epoch');
            need(/^(0|[1-9][0-9]*)$/.test(epoch) && Number.isSafeInteger(Number(epoch)), 'recovery_epoch_invalid', 503);
            if (stored === null) this.putMeta('epoch', epoch);
            else if (epoch !== stored) {
                need(Number(epoch) === Number(stored) + 1, 'recovery_epoch_invalid', 503);
                for (const c of this.activeCredentials()) {
                    c.revoked = true;
                    this.saveCredential(c);
                    this.audit('credential_revoked', { credential_id: c.id, epoch });
                }
                this.putMeta('registration', null);
                this.putMeta('setup_until', clock() + 600000);
                this.putMeta('epoch', epoch);
                this.audit('registration_window_reopened', { epoch, until: stamp(clock() + 600000) });
            }
        });
    }
    meta<T = any>(name: string): T | null { const row = this.storage.sql.exec<{
        json: string;
    }>('SELECT json FROM meta WHERE key=?', name).toArray()[0]; return row ? JSON.parse(row.json) : null; }
    putMeta(name: string, value: unknown) { this.writes += this.storage.sql.exec('INSERT INTO meta(key,json) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET json=excluded.json', name, JSON.stringify(value)).rowsWritten; }
    latest(rid: string): number | undefined { return this.storage.sql.exec<{
        revision: number;
    }>('SELECT revision FROM latest WHERE rid=?', rid).toArray()[0]?.revision; }
    entry(rid: string, revision?: number): Entry { revision = revision ?? this.latest(rid); const k = key(rid, revision as number); const row = this.storage.sql.exec<{
        json: string;
    }>('SELECT json FROM requests WHERE key=?', k).toArray()[0]; need(row, 'request_not_found', 404); return JSON.parse(row.json); }
    save(e: Entry) { this.writes += this.storage.sql.exec('INSERT INTO requests(key,json) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET json=excluded.json', key(e.request.request_id, e.request.revision), JSON.stringify(e)).rowsWritten; }
    history(e: Entry, event: string, extra: Dict = {}) { e.history.push({ at: stamp(this.clock()), event, ...extra }); }
    tick(e: Entry) { const next = transition(e.state, 'tick', {}, this.clock(), e.request); if (canonical(e.state) !== canonical(next)) {
        e.state = next;
        this.history(e, 'tick', { execution: next.execution });
        this.save(e);
    } }
    runnerStatus(): string {
        const stop = this.meta<string>('stopped_at'), contact = this.meta<string>('last_contact'), suffix = '켜짐·꺼짐은 이 정보만으로 알 수 없습니다';
        if (stop)
            return '실행기가 꺼진다고 알림 ' + stop.slice(11, 19);
        if (!contact)
            return 'Mac 실행기(모의) 연결 기록 없음 · ' + suffix;
        return `Mac 실행기(모의) 마지막 연결 ${contact.slice(11, 19)} (${Math.max(0, Math.floor((this.clock() - utc(contact)) / 60000))}분 전) · ${suffix}`;
    }
    record(e: Entry): Dict {
        return { request: clone(e.request), ...clone(e.state), content_hash: e.content_hash, history: clone(e.history), display_state: display(e.state, e.request, this.clock()), server_now: stamp(this.clock()), runner_status: this.runnerStatus(), ...this.credentialSummary() };
    }
    get(rid: string, revision?: number): Dict { return this.storage.transactionSync(() => { const e = this.entry(rid, revision); this.tick(e); return this.record(e); }); }
    async create(input: unknown): Promise<Dict> {
        const r = validate(input, this.env.TEST_ROOT_ID), hash = await contentHash(r);
        return this.storage.transactionSync(() => {
            if (r.format === 'mapl-request/2') need(utc(r.created_at) >= this.clock() - 300000 && utc(r.created_at) <= this.clock() + 60000, 'request_invalid', 400, 'created_at_admission');
            const latest = this.latest(r.request_id);
            if (latest !== undefined) {
                const old = this.entry(r.request_id);
                need(!old.state.claim_id, 'claimed_revision_in_progress', 409);
                need(r.revision === latest + 1, 'revision_refused', 409);
                old.state = transition(old.state, 'revise', {}, this.clock(), old.request);
                this.history(old, 'revise');
                this.save(old);
            }
            else
                need(r.revision === 1, 'revision_refused', 409);
            const e: Entry = { request: r, content_hash: hash, state: initial(), history: [], assertion: null, nonce: null, approval_facts: null, claim_response: null, last_evidence: null };
            this.history(e, 'create');
            this.save(e);
            this.writes += this.storage.sql.exec('INSERT INTO latest(rid,revision) VALUES (?,?) ON CONFLICT(rid) DO UPDATE SET revision=excluded.revision', r.request_id, r.revision).rowsWritten;
            return this.record(e);
        });
    }
    credentials(): Credential[] {
        const primary = this.meta<Credential>('credential');
        return [...(primary ? [primary] : []), ...(this.meta<Credential[]>('additional_credentials') ?? [])];
    }
    activeCredentials(): Credential[] { return this.credentials().filter(c => !c.revoked); }
    credential(id?: string): Credential | null { return this.activeCredentials().find(c => id === undefined || c.id === id) ?? null; }
    saveCredential(c: Credential): void {
        if (this.meta<Credential>('credential')?.id === c.id) this.putMeta('credential', c);
        else this.putMeta('additional_credentials', [...(this.meta<Credential[]>('additional_credentials') ?? []).filter(x => x.id !== c.id), c]);
    }
    credentialSummary(): Dict {
        const cs = this.activeCredentials();
        return { credential_count: cs.length, credential_registered_at: cs.map(c => c.registered_at!).sort().at(-1) ?? null };
    }
    audit(event: string, extra: Dict = {}): void { this.putMeta('auth_history', [...(this.meta<Dict[]>('auth_history') ?? []), { at: stamp(this.clock()), event, ...extra }]); }
    private gate(): void {
        need(this.activeCredentials().length === 0, 'registration_closed', 409);
        need(this.clock() < this.meta<number>('setup_until')!, 'setup_code_expired', 409);
    }
    private async setupCode(code: unknown): Promise<void> {
        need(await secretEqual(code, this.env.SETUP_CODE, 10), 'setup_code_invalid', 403);
    }
    private registrationShape(challenge: string): Dict {
        return { challenge, rp: { id: this.env.RP_ID, name: 'MAPL 시험판' }, user: { id: this.meta('user_id'), name: 'mapl-test', displayName: 'MAPL 시험판' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], attestation: 'none', authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' }, excludeCredentials: this.credentials().map(c => ({ type: 'public-key', id: c.id })), timeout: 180000 };
    }
    async registrationOptions(code: unknown): Promise<Dict> {
        this.gate(); await this.setupCode(code);
        return this.storage.transactionSync(() => {
            this.gate();
            const ch = b64encode(crypto.getRandomValues(new Uint8Array(32)));
            this.putMeta('registration', { value: ch, issued_at: stamp(this.clock()) });
            return this.registrationShape(ch);
        });
    }
    async register(code: unknown, registration: Dict): Promise<Dict> {
        this.gate(); await this.setupCode(code); this.gate();
        const issued = this.meta<Dict>('registration'), epoch = this.meta<string>('epoch');
        need(issued && this.clock() - utc(issued.issued_at) < 180000, 'registration_challenge_expired', 409);
        const c = await verifyRegistration(registration, b64decode(issued.value), this.env.ORIGIN, this.env.RP_ID);
        return this.storage.transactionSync(() => {
            this.gate();
            need(this.meta('epoch') === epoch && canonical(this.meta('registration')) === canonical(issued) && this.clock() - utc(issued.issued_at) < 180000, 'registration_challenge_expired', 409);
            const previous = this.meta<Credential>('credential');
            if (previous) this.putMeta('additional_credentials', [...(this.meta<Credential[]>('additional_credentials') ?? []), previous]);
            need(!this.credentials().some(x => x.id === c.id), 'credential_exists', 409);
            c.registered_at = stamp(this.clock()); this.putMeta('credential', c); this.putMeta('registration', null);
            this.audit('credential_registered', { credential_id: c.id, epoch });
            return { ...this.credentialSummary(), registered_at: c.registered_at };
        });
    }
    private cleanupAuthRows(): void {
        this.storage.transactionSync(() => {
            // Reserve one deletion for challenge eviction: at most 32 rows per attempt.
            this.writes += this.storage.sql.exec(`DELETE FROM meta WHERE key IN (SELECT key FROM meta WHERE ${AUTH_ROWS} AND ${AUTH_EXPIRY} <= ? ORDER BY ${AUTH_EXPIRY}, key LIMIT ?)`, this.clock(), AUTH_CLEANUP_LIMIT - 1).rowsWritten;
        });
    }
    loginOptions(): Dict {
        this.cleanupAuthRows();
        return this.storage.transactionSync(() => {
            need(this.activeCredentials().length, 'registration_required', 409);
            // Bound even a burst within the three-minute lifetime. Oldest outstanding
            // ceremonies may be evicted; callers can request a fresh challenge.
            const oldest = this.storage.sql.exec<{ key: string }>(`SELECT key FROM meta WHERE ${AUTH_ROWS} AND key GLOB 'login:*' ORDER BY ${AUTH_EXPIRY}, rowid LIMIT ?`, LOGIN_CHALLENGE_LIMIT).toArray();
            if (oldest.length === LOGIN_CHALLENGE_LIMIT)
                this.writes += this.storage.sql.exec('DELETE FROM meta WHERE key=?', oldest[0].key).rowsWritten;
            const challenge = b64encode(crypto.getRandomValues(new Uint8Array(32)));
            this.putMeta('login:' + challenge, { issued_at: this.clock(), used: false, epoch: this.meta('epoch') });
            return this.assertionOptions(challenge);
        });
    }
    private assertionOptions(challenge: string): Dict {
        return { challenge, rpId: this.env.RP_ID, userVerification: 'required', timeout: 180000, allowCredentials: this.activeCredentials().map(c => ({ type: 'public-key', id: c.id })) };
    }
    private freshLogin(challenge: string): Dict {
        need(typeof challenge === 'string' && /^[A-Za-z0-9_-]{43}$/.test(challenge), 'login_challenge_invalid', 401);
        const n = this.meta<Dict>('login:' + challenge);
        need(n && !n.used && this.clock() >= n.issued_at && this.clock() - n.issued_at < 180000 && n.epoch === this.meta('epoch'), 'login_challenge_invalid', 401);
        return n;
    }
    async login(challenge: string, assertion: Dict): Promise<string> {
        this.cleanupAuthRows();
        const n = this.freshLogin(challenge), c = this.credential(assertion?.id);
        need(c, 'unknown_credential', 401);
        const facts = await this.verifier(assertion, c, b64decode(challenge), this.env.ORIGIN, this.env.RP_ID);
        return this.storage.transactionSync(() => {
            this.freshLogin(challenge);
            need(canonical(this.credential(c.id)) === canonical(c), 'credential_revoked', 401);
            this.putMeta('login:' + challenge, { ...n, used: true });
            const session = b64encode(crypto.getRandomValues(new Uint8Array(32)));
            this.putMeta('session:' + session, { credential_id: c.id, epoch: this.meta('epoch'), login_at: this.clock(), absolute_deadline: this.clock() + 86400000, last_activity_at: this.clock(), idle_deadline: this.clock() + 28800000, expires_at: this.clock() + 28800000, revoked: false });
            this.saveCredential({ ...c, sign_count: facts.sign_count, be: facts.be, bs: facts.bs });
            return session;
        });
    }
    requireSession(session: unknown): string {
        need(typeof session === 'string' && /^[A-Za-z0-9_-]{43}$/.test(session), 'session_required', 401);
        const s = this.meta<Dict>('session:' + session);
        need(s && !s.revoked && s.idle_deadline > this.clock() && s.absolute_deadline > this.clock() && s.epoch === this.meta('epoch') && this.credential(s.credential_id), 'session_required', 401);
        return session;
    }
    touch(session: string): void {
        this.storage.transactionSync(() => {
            this.requireSession(session);
            const s = this.meta<Dict>('session:' + session)!;
            const deadline = Math.min(this.clock() + 28800000, s.absolute_deadline);
            this.putMeta('session:' + session, {...s, last_activity_at: this.clock(), idle_deadline: deadline, expires_at: deadline});
        });
    }
    cookieAge(session: string): number {
        this.requireSession(session);
        return Math.max(0, Math.floor((this.meta<Dict>('session:' + session)!.absolute_deadline - this.clock()) / 1000));
    }
    async managementOptions(session: string, action: string, target: string): Promise<Dict> {
        this.requireSession(session);
        need(['logout', 'session_revoke'].includes(action), 'action_refused');
        if (action === 'logout') need(target === session, 'action_target_refused');
        const id = random(16), nonce = random(32), epoch = this.meta('epoch');
        const challenge = b64encode(await sha256(utf8(canonical({format: 'mapl-management/1', action, session, target, nonce, epoch}))));
        return this.storage.transactionSync(() => {
            this.requireSession(session); need(this.meta('epoch') === epoch, 'session_required', 401);
            this.putMeta('management:' + id, {session, action, target, challenge, epoch, issued_at: this.clock(), used: false});
            return {action_id: id, ...this.assertionOptions(challenge)};
        });
    }
    async manage(session: string, id: string, action: string, target: string, assertion: Dict): Promise<void> {
        const fresh = () => {
            this.requireSession(session);
            const n = this.meta<Dict>('management:' + id);
            need(n && !n.used && n.session === session && n.action === action && n.target === target && n.epoch === this.meta('epoch') && this.clock() >= n.issued_at && this.clock() - n.issued_at < 180000, 'management_challenge_invalid');
            return n;
        };
        const n = fresh(), c = this.credential(assertion?.id); need(c, 'unknown_credential');
        const facts = await this.verifier(assertion, c, b64decode(n.challenge), this.env.ORIGIN, this.env.RP_ID);
        this.storage.transactionSync(() => {
            need(canonical(fresh()) === canonical(n) && canonical(this.credential(c.id)) === canonical(c), 'management_challenge_invalid');
            const destination = this.meta<Dict>('session:' + target);
            need(destination && destination.credential_id === this.meta<Dict>('session:' + session)!.credential_id, 'action_target_refused');
            this.putMeta('session:' + target, {...destination, revoked: true});
            this.putMeta('management:' + id, {...n, used: true});
            this.saveCredential({...c, sign_count: facts.sign_count, be: facts.be, bs: facts.bs});
            this.audit(action, {target});
        });
    }
    withdraw(rid: string): Dict {
        return this.storage.transactionSync(() => {
            const e = this.entry(rid); this.tick(e);
            e.state = transition(e.state, 'withdraw', {}, this.clock(), e.request);
            this.history(e, 'withdraw'); this.save(e); return this.record(e);
        });
    }
    list(): Dict { return { ...this.credentialSummary(), last_response: this.meta<string>('last_contact')?.slice(11, 16) ?? null, requests: this.storage.sql.exec<{ rid: string }>('SELECT rid FROM latest').toArray().map(({ rid }) => this.get(rid)) }; }
    credentialAddOptions(session: string): Dict {
        return this.storage.transactionSync(() => {
            this.requireSession(session);
            const id = random(16), challenge = b64encode(crypto.getRandomValues(new Uint8Array(32)));
            this.putMeta('credential_add:' + id, { session, challenge, epoch: this.meta('epoch'), issued_at: this.clock(), used: false });
            return { action_type: 'credential_add/1', action_id: id, registration: this.registrationShape(challenge) };
        });
    }
    private freshAdd(session: string, id: string): Dict {
        this.requireSession(session);
        need(typeof id === 'string' && /^[0-9a-f]{32}$/.test(id), 'credential_add_invalid', 409);
        const n = this.meta<Dict>('credential_add:' + id);
        need(n && n.session === session && !n.used && n.epoch === this.meta('epoch') && this.clock() - n.issued_at < 180000, 'credential_add_invalid', 409);
        return n;
    }
    async credentialAddPrepare(session: string, id: string, registration: Dict): Promise<Dict> {
        const n = this.freshAdd(session, id);
        const candidate = await verifyRegistration(registration, b64decode(n.challenge), this.env.ORIGIN, this.env.RP_ID);
        const nonce = random(32);
        const challenge = b64encode(await sha256(utf8(canonical({format: 'mapl-credential-add/2', session, action_id: id, candidate, nonce}))));
        return this.storage.transactionSync(() => {
            need(canonical(this.freshAdd(session, id)) === canonical(n) && !n.candidate, 'credential_add_invalid', 409);
            need(!this.credentials().some(c => c.id === candidate.id), 'credential_exists', 409);
            this.putMeta('credential_add:' + id, { ...n, candidate, nonce, approval_challenge: challenge });
            return { action_type: 'credential_add/1', action_id: id, ...this.assertionOptions(challenge) };
        });
    }
    async credentialAddVerify(session: string, id: string, assertion: Dict): Promise<Dict> {
        const n = this.freshAdd(session, id), signer = this.credential(assertion?.id);
        need(n.candidate && signer && signer.id !== n.candidate.id, 'existing_passkey_required', 403);
        const facts = await this.verifier(assertion, signer, b64decode(n.approval_challenge), this.env.ORIGIN, this.env.RP_ID);
        return this.storage.transactionSync(() => {
            need(canonical(this.freshAdd(session, id)) === canonical(n), 'credential_add_invalid', 409);
            need(canonical(this.credential(signer.id)) === canonical(signer), 'credential_revoked', 409);
            need(!this.credentials().some(c => c.id === n.candidate.id), 'credential_exists', 409);
            const c = { ...n.candidate, registered_at: stamp(this.clock()) };
            this.putMeta('additional_credentials', [...(this.meta<Credential[]>('additional_credentials') ?? []), c]);
            this.saveCredential({ ...signer, sign_count: facts.sign_count, be: facts.be, bs: facts.bs });
            this.putMeta('credential_add:' + id, { ...n, used: true });
            this.audit('credential_added', { action_type: 'credential_add/1', action_id: id, credential_id: c.id, signer_id: signer.id, assertion: clone(assertion), nonce: n.nonce });
            return this.credentialSummary();
        });
    }
    async approvalOptions(rid: string, revision: number, hash: string): Promise<Dict> {
        const snapshot = this.storage.transactionSync(() => {
            const e = this.entry(rid);
            need(revision === e.request.revision && hash === e.content_hash, 'revision_changed', 409);
            this.tick(e);
            need(e.state.approval !== 'approved', 'already_approved', 409);
            need(!expired(e.request, this.clock()), 'expired', 409);
            need(e.state.approval === 'pending', e.state.approval, 409);
            const credential = this.credential();
            need(credential && !credential.revoked, 'registration_required', 409);
            if (!e.options || this.clock() - utc(e.options.issued_at) >= 2000) {
                e.options = { value: random(32), issued_at: stamp(this.clock()), used: false };
                this.save(e);
            }
            return { entry: e, credential };
        });
        return { challenge: b64encode(await approvalChallenge(snapshot.entry.request, snapshot.entry.options!.value)), rpId: this.env.RP_ID, userVerification: 'required', timeout: 180000, allowCredentials: this.activeCredentials().map(c => ({ type: 'public-key', id: c.id })) };
    }
    // All awaits finish before phase2. Each value here is a detached JSON snapshot.
    async approve(rid: string, assertion: Dict, revision?: number, session?: string): Promise<Dict> {
        if (session) this.requireSession(session);
        const e = this.entry(rid, revision);
        need(this.latest(rid) === e.request.revision, 'superseded', 409);
        need(!e.options?.used, 'nonce_used', 409);
        need(e.state.approval !== 'approved', 'already_approved', 409);
        need(!expired(e.request, this.clock()), 'expired', 409);
        need(e.state.approval === 'pending', e.state.approval, 409);
        need(e.options, 'challenge_mismatch');
        need(this.clock() - utc(e.options.issued_at) < 180000, 'nonce_expired', 409);
        need(this.activeCredentials().length, 'registration_required', 409);
        const credential = this.credential(assertion?.id);
        need(credential, 'unknown_credential');
        validate(e.request, this.env.TEST_ROOT_ID);
        const snapshot: ApprovalSnapshot = { entry: clone(e), credential: clone(credential), epoch: this.meta<string>('epoch')!, session };
        const ch = await approvalChallenge(e.request, e.options.value);
        const facts = await this.verifier(assertion, snapshot.credential, ch, this.env.ORIGIN, this.env.RP_ID);
        const assertionHash = await digest(utf8(canonical(assertion)));
        return this.phase2(snapshot, assertion, facts, assertionHash);
    }
    protected recheckApproval(s: ApprovalSnapshot, current: Entry, credential: Credential | null): void {
        const old = s.entry, n = current.options;
        need(this.latest(old.request.request_id) === old.request.revision && current.request.revision === old.request.revision, 'stale_revision', 409);
        need(current.request.request_id === old.request.request_id && current.content_hash === old.content_hash && canonical(current.request) === canonical(old.request), 'content_changed', 409);
        need(n && !n.used, 'nonce_used', 409);
        need(current.state.approval === 'pending', current.state.approval, 409);
        need(!expired(current.request, this.clock()), 'expired', 409);
        need(n.value === old.options!.value && n.issued_at === old.options!.issued_at, 'challenge_mismatch');
        need(this.clock() - utc(n.issued_at) < 180000, 'nonce_expired', 409);
        need(credential && !credential.revoked && credential.id === s.credential.id && credential.spki === s.credential.spki && credential.cose === s.credential.cose && this.meta('epoch') === s.epoch, 'credential_revoked', 409);
    }
    private phase2(snapshot: ApprovalSnapshot, assertion: Dict, facts: Facts, assertionHash: string): Dict {
        return this.storage.transactionSync(() => {
            const e = this.entry(snapshot.entry.request.request_id, snapshot.entry.request.revision), credential = this.credential(snapshot.credential.id);
            if (snapshot.session) this.requireSession(snapshot.session);
            this.recheckApproval(snapshot, e, credential);
            // Recheck pending is performed above; direct state update also makes omission detectable by both negative controls.
            e.state.approval = 'approved';
            e.options!.used = true;
            e.assertion = clone(assertion);
            e.nonce = snapshot.entry.options!.value;
            e.approval_facts = clone(facts);
            Object.assign(credential!, { sign_count: facts.sign_count, be: facts.be, bs: facts.bs });
            this.saveCredential(credential!);
            this.history(e, 'approve', { assertion_sha256: assertionHash, facts });
            this.save(e);
            return this.record(e);
        });
    }
    decline(rid: string): Dict { return this.storage.transactionSync(() => { const e = this.entry(rid); this.tick(e); e.state = transition(e.state, 'decline', {}, this.clock(), e.request); this.history(e, 'decline'); this.save(e); return this.record(e); }); }
    cancel(rid: string): Dict { return this.storage.transactionSync(() => { const e = this.entry(rid); e.state = transition(e.state, 'cancel', {}, this.clock(), e.request); this.history(e, 'cancel'); this.save(e); return this.record(e); }); }
    approved(): Dict[] {
        return this.storage.transactionSync(() => {
            const out: Dict[] = [];
            for (const { rid } of this.storage.sql.exec<{
                rid: string;
            }>('SELECT rid FROM latest')) {
                const e = this.entry(rid);
                this.tick(e);
                if (e.state.approval === 'approved' && e.state.execution === 'not_started')
                    out.push({ request: clone(e.request), assertion: clone(e.assertion), nonce: e.nonce, credential: this.credentials().find(c => c.id === e.assertion?.id), content_hash: e.content_hash });
            }
            return out;
        });
    }
    claim(rid: string, revision: number, claimId: string): Dict {
        return this.storage.transactionSync(() => {
            need(typeof claimId === 'string' && /^[0-9a-f]{32}$/.test(claimId), 'claim_id_invalid');
            const e = this.entry(rid, revision);
            this.tick(e);
            if (e.state.claim_id !== null) {
                need(e.state.claim_id === claimId, 'already_claimed', 409);
                need(e.state.execution === 'claimed', 'claim_closed:' + e.state.execution, 409);
                return clone(e.claim_response!);
            }
            need(this.latest(rid) === revision, 'not_claimable:superseded', 409);
            e.state = transition(e.state, 'claim', { claim_id: claimId }, this.clock(), e.request);
            e.claim_response = { granted: true, request_id: rid, revision, claim_id: claimId };
            this.history(e, 'claim', { claim_id: claimId });
            this.save(e);
            return clone(e.claim_response);
        });
    }
    report(rid: string, revision: number, claimId: string | null, event: string, evidence: Dict): Dict {
        return this.storage.transactionSync(() => {
            const e = this.entry(rid, revision);
            need(evidence && typeof evidence === 'object' && !Array.isArray(evidence), 'evidence_malformed');
            if (event === 'refused_before_claim') {
                need(!e.state.claim_id, 'already_claimed', 409);
                const code = evidence.code;
                need(REFUSAL_CODES.has(code), 'refusal_code_invalid');
                let row = e.history.find(x => x.event === event && x.code === code);
                if (!row) {
                    this.history(e, event, { code, text: code === 'EXPIRED' ? 'Mac 실행기(모의)가 만료로 맡지 않음 (EXPIRED)' : code === 'CONTENT_MISMATCH' ? 'Mac 실행기(모의)가 내용 불일치로 맡지 않음 (CONTENT_MISMATCH)' : `Mac 실행기(모의)가 검증 불일치로 맡지 않음 (${code})`, count: 1, last_at: stamp(this.clock()) });
                }
                else {
                    row.count = (row.count ?? 1) + 1;
                    row.last_at = stamp(this.clock());
                }
                // Client count/last_at never replace the authoritative persisted values.
                this.save(e);
                return this.record(e);
            }
            need(['start', 'result', 'not_run', ...FLOW_EVENTS].includes(event), 'event_refused');
            if (evidence.code)
                need(typeof evidence.code === 'string' && /^[A-Z_]{1,80}$/.test(evidence.code), 'refusal_code_invalid');
            this.tick(e);
            const report = { claim_id: claimId, event, evidence };
            if (e.last_report && canonical(e.last_report) === canonical(report))
                return this.record(e);
            e.state = transition(e.state, event, { ...clone(evidence), claim_id: claimId }, this.clock(), e.request);
            if (event === 'result' && evidence.code)
                e.state.result_code = evidence.code;
            e.last_evidence = clone(evidence);
            e.last_report = clone(report);
            this.history(e, event, { claim_id: claimId, evidence: clone(evidence), source: 'simulated_runner_report' });
            this.save(e);
            return this.record(e);
        });
    }
    hasPending(): boolean {
        for (const { rid } of this.storage.sql.exec<{
            rid: string;
        }>('SELECT rid FROM latest')) {
            const e = this.entry(rid);
            if (['pending', 'approved'].includes(e.state.approval) && e.state.execution === 'not_started')
                return true;
        }
        return false;
    }
    heartbeat(stopping = false): Dict {
        return this.storage.transactionSync(() => {
            const last = this.meta<string>('last_contact'), stop = this.meta<string>('stopped_at');
            if (!stopping && !stop && last && this.clock() - utc(last) < 300000)
                return { recorded: false };
            const now = stamp(this.clock());
            this.putMeta('last_contact', now);
            if (stopping || stop)
                this.putMeta('stopped_at', stopping ? now : null);
            return { recorded: true };
        });
    }
}
