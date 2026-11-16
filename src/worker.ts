import { kst } from './state';
import { canonical, parseJson } from './canonical';
import { type Env, type DOState } from './platform';
import { Store } from './store';
import { roleEqual } from './secrets';
import { validProfile } from './profile';
import { view } from './ui';
import { need, Refusal, type Dict } from './types';
import INDEX from '../public/index.html';
import APP from '../public/app.js.txt';
import CSS from '../public/app.css.txt';
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
export const HEADERS = { 'Content-Security-Policy': CSP, 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Type': 'application/json; charset=utf-8' };
export class MaplApproval {
    store: Store;
    constructor(state: DOState, public env: Env) { this.store = new Store(state.storage, env); }
    async fetch(req: Request): Promise<Response> {
        try {
            need(validProfile(this.env), 'local_profile_required', 503);
            const u = new URL(req.url), path = u.pathname, method = req.method;
            const auth = req.headers.get('Authorization');
            const role = path.startsWith('/api/runner/') || path.startsWith('/api/requester/');
            const publicRoute = ['/version', '/login', '/register', '/static/app.js', '/static/app.css', '/api/login/options', '/api/login/verify', '/api/register/options', '/api/register/verify'].includes(path);
            let session: string | undefined;
            if (!role && !publicRoute) {
                need(!auth, 'session_required', 401);
                const cookies = (req.headers.get('Cookie') ?? '').split(';').map(c => c.trim()).filter(c => c.startsWith('__Host-mapl_session='));
                need(cookies.length === 1, 'session_required', 401);
                session = this.store.requireSession(cookies[0].slice('__Host-mapl_session='.length));
            } else if (publicRoute) need(!auth, 'token_scope_refused', 403);
            for (const [prefix, hash, token] of [['/api/runner/', this.env.RUNNER_TOKEN_SHA256, this.env.RUNNER_TOKEN], ['/api/requester/', this.env.REQUESTER_TOKEN_SHA256, this.env.REQUESTER_TOKEN]])
                if (path.startsWith(prefix!)) need(await roleEqual(auth, hash, token, this.env), 'token_scope_refused', 403);
            need(u.host === new URL(this.env.ORIGIN).host && (!req.headers.has('Host') || req.headers.get('Host') === u.host), 'host_mismatch', 403);
            need(!u.search && !path.includes('%'), 'route_not_found', 404);
            // Authentication precedes all browser input parsing and Origin checks.
            if (!role && method === 'POST') need(req.headers.get('Origin') === this.env.ORIGIN, 'origin_mismatch', 403);
            const length = Number(req.headers.get('Content-Length') ?? 0);
            need(Number.isSafeInteger(length) && length >= 0 && length <= 131072, 'body_too_large', 413);
            let raw = '';
            if (req.body) {
                const reader = req.body.getReader(), chunks: Uint8Array[] = [];
                let size = 0;
                while (true) {
                    const { done, value } = await reader.read();
                    if (done)
                        break;
                    size += value.length;
                    if (size > 131072) {
                        await reader.cancel();
                        throw new Refusal('body_too_large', 413);
                    }
                    chunks.push(value);
                }
                const all = new Uint8Array(size);
                let off = 0;
                for (const v of chunks) {
                    all.set(v, off);
                    off += v.length;
                }
                try {
                    raw = new TextDecoder('utf-8', { fatal: true }).decode(all);
                }
                catch {
                    throw new Refusal('json_malformed', 400);
                }
            }
            if (session) this.store.requireSession(session);
            if (method === 'GET' && (['/login', '/register', '/', '/history', '/credential-add'].includes(path) || /^\/r\/[0-9a-f]{32}$/.test(path))) {
                if (path.startsWith('/r/'))
                    this.store.get(path.slice(3));
                if (session) this.store.touch(session);
                return new Response(INDEX, { headers: { ...HEADERS, 'Content-Type': 'text/html; charset=utf-8' } });
            }
            if (method === 'GET' && ['/static/app.js', '/static/app.css'].includes(path))
                return new Response(path.endsWith('.js') ? APP : CSS, { headers: { ...HEADERS, 'Content-Type': path.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'text/css; charset=utf-8' } });
            if (method === 'GET' && path === '/version') return new Response(canonical({ mode: this.env.MODE, operational: false, test_root_id: this.env.TEST_ROOT_ID, commit: /^[0-9a-f]{40}$/.test(this.env.BUILD_COMMIT ?? '') ? this.env.BUILD_COMMIT : null, registration: this.store.activeCredentials().length ? 'closed' : this.store.clock() < (this.store.meta<number>('setup_until') ?? 0) && typeof this.env.SETUP_CODE === 'string' && this.env.SETUP_CODE.length >= 10 ? 'code_required' : 'closed' }), { headers: HEADERS });
            const body = (raw ? parseJson(raw) : {}) as Dict;
            need(body && typeof body === 'object' && !Array.isArray(body), 'body_malformed');
            const match = /^\/api\/requests\/([0-9a-f]{32})(?:\/(approve\/options|approve\/verify|decline|withdraw|history))?$/.exec(path);
            let result: unknown;
            if (method === 'GET' && match && (!match[2] || match[2] === 'history'))
                result = this.record(match[1]);
            else if (method === 'POST' && match && match[2]) {
                if (match[2] === 'approve/options') {
                    need(Number.isSafeInteger(body.revision) && typeof body.content_hash === 'string', 'display_binding_required');
                    result = await this.store.approvalOptions(match[1], body.revision, body.content_hash);
                }
                else if (match[2] === 'approve/verify') {
                    need(body.credential && typeof body.credential === 'object', 'body_malformed');
                    await this.store.approve(match[1], body.credential, body.revision, session);
                    result = this.record(match[1]);
                }
                else {
                    need(['decline', 'withdraw'].includes(match[2]), 'route_not_found', 404);
                    if (match[2] === 'withdraw') this.store.withdraw(match[1]); else this.store.decline(match[1]);
                    result = this.record(match[1]);
                }
            }
            else if (method === 'POST' && path === '/api/register/options')
                result = await this.store.registrationOptions(body.code);
            else if (method === 'POST' && path === '/api/register/verify')
                result = await this.store.register(body.code, body.credential);
            else if (method === 'POST' && path === '/api/login/options') result = this.store.loginOptions();
            else if (method === 'POST' && path === '/api/login/verify') {
                const value = await this.store.login(body.challenge, body.credential);
                return new Response(canonical({ ...this.store.credentialSummary(), authenticated: true }), { headers: { ...HEADERS, 'Set-Cookie': '__Host-mapl_session=' + value + '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=' + this.store.cookieAge(value) } });
            }
            else if (method === 'POST' && path === '/api/logout/options') result = await this.store.managementOptions(session!, 'logout', session!);
            else if (method === 'POST' && path === '/api/session-revoke/options') result = await this.store.managementOptions(session!, 'session_revoke', body.target);
            else if (method === 'POST' && path === '/api/session-revoke/verify') { await this.store.manage(session!, body.action_id, 'session_revoke', body.target, body.credential); result = {revoked: true}; }
            else if (method === 'POST' && path === '/api/logout') {
                await this.store.manage(session!, body.action_id, 'logout', session!, body.credential);
                return new Response(canonical({ authenticated: false }), { headers: { ...HEADERS, 'Set-Cookie': '__Host-mapl_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0' } });
            }
            else if (method === 'GET' && path === '/api/requests') result = this.store.list();
            else if (method === 'GET' && path === '/api/history') result = { history: (this.store.meta<Dict[]>('auth_history') ?? []).map(e => ({ ...e, at_text: kst(e.at, true) })) };
            else if (method === 'POST' && path === '/api/credential-add/options') result = this.store.credentialAddOptions(session!);
            else if (method === 'POST' && path === '/api/credential-add/prepare') result = await this.store.credentialAddPrepare(session!, body.action_id, body.credential);
            else if (method === 'POST' && path === '/api/credential-add/verify') result = await this.store.credentialAddVerify(session!, body.action_id, body.credential);
            else if (method === 'GET' && path === '/api/runner/approved') {
                this.store.heartbeat();
                result = { requests: this.store.approved(), has_pending: this.store.hasPending(), server_now: new Date(this.store.clock()).toISOString().replace(/\.\d{3}Z$/, 'Z') };
            }
            else if (method === 'POST' && path === '/api/runner/claim')
                result = this.store.claim(body.request_id, body.revision, body.claim_id);
            else if (method === 'POST' && path === '/api/runner/report')
                result = this.store.report(body.request_id, body.revision, body.claim_id ?? null, body.event, body.evidence ?? {});
            else if (method === 'POST' && path === '/api/runner/heartbeat')
                result = this.store.heartbeat();
            else if (method === 'POST' && path === '/api/runner/stopping')
                result = this.store.heartbeat(true);
            else if (method === 'POST' && path === '/api/requester/requests')
                result = await this.store.create(body.request);
            else if (method === 'POST' && path === '/api/requester/cancel')
                result = this.store.cancel(body.request_id);
            else
                throw new Refusal('route_not_found', 404);
            if (session) {
                this.store.requireSession(session);
                if (method === 'POST' || !path.startsWith('/api/')) this.store.touch(session);
            }
            return new Response(canonical(result), { headers: HEADERS });
        }
        catch (e) {
            const path = new URL(req.url).pathname;
            if (e instanceof Refusal && e.code === 'session_required' && req.method === 'GET' &&
                (['/', '/history', '/credential-add'].includes(path) || /^\/r\/[0-9a-f]{32}$/.test(path)))
                return new Response(null, { status: 303, headers: { ...HEADERS, Location: '/login' + (/^\/r\/[0-9a-f]{32}$/.test(path) ? '#' + path : '') } });
            if (e instanceof Refusal)
                return new Response(canonical({ error: e.code }), { status: e.status, headers: HEADERS });
            if (e instanceof TypeError)
                return new Response(canonical({ error: 'body_malformed' }), { status: 400, headers: HEADERS });
            throw e;
        }
    }
    record(rid: string): Dict { const r = this.store.get(rid); return { ...r, view: view(r, this.store.clock()), site_host: new URL(this.env.ORIGIN).host, test_scenario: 'normal' }; }
}
export default { fetch(req: Request, env: Env): Promise<Response> { return env.APPROVAL.get(env.APPROVAL.idFromName('mapl-approval-local-test')).fetch(req); } };
