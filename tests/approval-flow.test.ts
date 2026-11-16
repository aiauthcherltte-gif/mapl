import { it, expect } from 'vitest';
import { base, world, refuses, CID, CODE } from './support';
import { validate } from '../src/request';
import { canonical, contentHash, approvalChallenge, b64decode } from '../src/canonical';
import { transition, display, kst, kstRange, utc, initial, propertyEvidence } from '../src/state';
import { failureText, view } from '../src/ui';
import requests from '../planning/impl/mapl_cloudflare/reference/request-v2.json';
import states from '../planning/impl/mapl_cloudflare/reference/state-v2.json';
import bytes from '../planning/impl/mapl_cloudflare/reference/canonical-v2.json';
import type { Dict, MaplRequest } from '../src/types';
const v2 = () => structuredClone(requests[0].request) as unknown as MaplRequest;
it('AF1 immutable v2 request accept/refuse cases', () => {
    for (const row of requests) { const call = () => validate(row.request, base.target.test_root_id); if (row.accepted) expect(call()).toEqual(row.request); else expect(call).toThrow(); }
});
it('AF1 Python/TS canonical bytes, hash and signed descriptor challenges', async () => {
    for (const row of bytes) {
        expect(canonical(row.request)).toBe(row.utf8); expect(await contentHash(row.request)).toBe(row.content_hash);
        expect(Array.from(await approvalChallenge(row.request as unknown as MaplRequest, row.nonce), n => n.toString(16).padStart(2, '0')).join('')).toBe(row.challenge_hex);
        const changed = structuredClone(row.request); changed.check.scope = ['pointer_bytes'];
        expect(await contentHash(changed)).not.toBe(row.content_hash);
    }
});
it('AF1 cross-language state and conservative wording table', () => {
    for (const row of states as Dict[]) {
        if (row.steps) {
            let c = row.previous;
            for (const step of row.steps) {
                const call = () => transition(c, step.event, step.evidence, utc(step.now), row.request);
                if (step.expected.error) expect(call, row.id).toThrow(step.expected.error);
                else {c = call(); expect(c.execution, row.id).toBe(step.expected.execution);}
            }
            continue;
        }
        const call = () => transition(row.previous as any, row.event, row.evidence, utc(row.now), row.request as unknown as MaplRequest);
        if ('error' in row.expected) expect(call).toThrow(row.expected.error); else { const next = call(); expect(next).toEqual(row.expected.state); expect(display(next, row.request as unknown as MaplRequest, utc(row.now))).toBe(row.expected.display); }
    }
});
it('AF1 report cannot widen signed scope or count pending pointer/screen as verified', () => {
    const r = v2(), c = {...initial(), approval:'approved', execution:'checking', claim_id:CID};
    r.check.scope = ['pointer_bytes'];
    const next = transition(c, 'check_ok', {claim_id:CID, pending:[], scope:['screen']}, utc(r.created_at), r);
    expect(display(next,r,utc(r.created_at))).toBe('완료 · 포인터 확인됨 · 읽기·수집기·화면 확인 대기');
    for(const pending of [['screen'], ['pointer_bytes'], ['collector','collector']]) expect(() => transition(c,'check_ok',{claim_id:CID,pending},utc(r.created_at),r)).toThrow();
});
it('AF1 v2 result is checking, v1 remains done', () => {
    for (const r of [structuredClone(base), v2()]) {
        const c = {...initial(), approval:'approved', execution:'running', claim_id:CID};
        expect(transition(c,'result',propertyEvidence('result_done',r),utc(r.created_at),r).execution).toBe(r.format === 'mapl-request/2' ? 'checking' : 'done');
    }
});
it('AF1 withdrawal wins before claim and is refused after claim', () => world(async w => {
    await w.approve(); w.store.withdraw(w.rid); expect(w.store.approved()).toEqual([]); expect(w.record().display_state).toBe('승인 철회 · 실행하지 않습니다'); await refuses('not_claimable:withdrawn',()=>w.claim());
}));
it('AF1 claim wins withdrawal race', () => world(async w => {await w.approve(); w.claim(); await refuses('withdraw_refused',()=>w.store.withdraw(w.rid));}));
it('AF1 v2 admission anchored at every revision', () => world(async w => {
    const r = {...v2(), request_id:'b'.repeat(32)};
    for(const offset of [-300001,60001]) {r.created_at = new Date(w.clock.now+offset).toISOString(); await refuses('request_invalid',()=>w.store.create(r));}
    r.created_at = base.created_at; await w.store.create(r); r.revision=2; r.created_at=new Date(w.clock.now-300001).toISOString(); await refuses('request_invalid',()=>w.store.create(r));
}));
it('AF1 session idle expiry checked before activity and polling never renews', () => world(async w => {
    const before = w.store.meta<Dict>('session:'+w.session)!;
    expect(before.absolute_deadline-before.login_at).toBe(86400000); expect(before.idle_deadline-before.login_at).toBe(28800000);
    w.advance(28799); await w.http('GET','/api/requests/'+w.rid); expect(w.store.meta<Dict>('session:'+w.session)!.idle_deadline).toBe(before.idle_deadline);
    w.advance(1); await refuses('session_required',()=>w.store.touch(w.session));
}));
it('AF1 activity renews idle only up to absolute 24h, cookie follows server', () => world(async w => {
    for(let i=0;i<3;i++){w.advance(7*3600); w.store.touch(w.session);}
    expect(w.store.cookieAge(w.session)).toBe(3*3600); w.store.putMeta('session:'+w.session,{...w.store.meta<Dict>('session:'+w.session),idle_deadline:w.clock.now+86400000}); w.advance(3*3600); await refuses('session_required',()=>w.store.touch(w.session));
}));
it('AF1 logout and revocation require their own one-use fresh action-bound UV signature', () => world(async w => {
    expect((await w.http('POST','/api/logout',{})).status).not.toBe(200);
    const o=await w.store.managementOptions(w.session,'logout',w.session), other=await w.store.managementOptions(w.session,'session_revoke',w.session);
    const a=await w.auth.assertion(b64decode(o.challenge));
    await refuses('challenge_mismatch',()=>w.store.manage(w.session,other.action_id,'session_revoke',w.session,a));
    await refuses('management_challenge_invalid',()=>w.store.manage(w.session,o.action_id,'session_revoke',w.session,a));
    await w.store.manage(w.session,o.action_id,'logout',w.session,a); await refuses('session_required',()=>w.store.requireSession(w.session));
}));
it('AF1 failure templates preserve the r4 limits and v1 never promises a check',()=>{
    expect(failureText(base)).toBe('이 요청은 교체 뒤 확인을 하지 않습니다. 자동 복구도 없습니다. 실패하면 어느 화면이 남는지 보장하지 않으며 확인을 요청합니다.');
    for(const r of [v2(),requests[1].request]){const text=failureText(r); expect(text).toContain('어느 화면이 남는지는 보장하지 않으며'); expect(text).not.toContain('새 화면이 남'); expect(text).toContain('교체 전에 멈추면 바뀌는 것이 없습니다.');}
});
it('AF1 EXPIRED refusal history is distinct from content mismatch',()=>world(w=>{
    w.store.report(w.rid,1,null,'refused_before_claim',{code:'EXPIRED'});
    expect(w.record().history.at(-1).text).toBe('Mac 실행기(모의)가 만료로 맡지 않음 (EXPIRED)');
}));
it('AF1 management rejects login, approval, expired and non-UV assertions',()=>world(async w=>{
    const o=await w.store.managementOptions(w.session,'logout',w.session), login=w.store.loginOptions();
    for(const challenge of [login.challenge,(await w.options()).challenge]) await refuses('challenge_mismatch',async()=>w.store.manage(w.session,o.action_id,'logout',w.session,await w.auth.assertion(b64decode(challenge))));
    await refuses('uv_missing',async()=>w.store.manage(w.session,o.action_id,'logout',w.session,await w.auth.assertion(b64decode(o.challenge),{flags:1})));
    const a=await w.auth.assertion(b64decode(o.challenge));w.advance(180);await refuses('management_challenge_invalid',()=>w.store.manage(w.session,o.action_id,'logout',w.session,a));
}));
it('AF1 fresh action is rechecked after verification and cannot target another session',()=>world(async w=>{
    const o=await w.store.managementOptions(w.session,'logout',w.session), a=await w.auth.assertion(b64decode(o.challenge)), verify=w.store.verifier;
    w.store.verifier=async(...args)=>{const facts=await verify(...args);w.advance(180);return facts;};
    await refuses('management_challenge_invalid',()=>w.store.manage(w.session,o.action_id,'logout',w.session,a));
    expect(w.store.meta<Dict>('management:'+o.action_id)!.used).toBe(false);
}));
it('AF1 recovery evidence, missing clause and wrong claim remain bounded',()=>{
    const r=structuredClone(requests[1].request) as unknown as MaplRequest, now=utc(r.created_at), c={...initial(),approval:'approved',execution:'recovering',claim_id:CID};
    const e={claim_id:CID,code:'READER_INDEX_MISMATCH',recovery_claim_id:CID,recovery_status:'restored_pointer_exact',pointer_sha256:r.target.before_sha256};
    expect(transition(c,'recovery_done',e,now,r).execution).toBe('recovered');
    expect(()=>transition(c,'recovery_done',{...e,pointer_sha256:r.target.after_sha256},now,r)).toThrow('recovery_evidence_invalid');
    expect(()=>transition(c,'recovery_done',{...e,claim_id:'b'.repeat(32)},now,r)).toThrow('claim_mismatch');
    expect(()=>transition(c,'recovery_done',e,now,v2())).toThrow('recovery_refused');
    const refused=transition(c,'recovery_failed',{claim_id:CID,code:e.code,exit:'refused',recovery_marker:'absent',pointer_sha256:r.target.after_sha256},now,r);
    expect(display(refused,r,now)).toContain('교체된 상태 그대로');
});
it('AF1 no passkey removal route; removal uses the account recovery epoch path',()=>world(async w=>{
    expect((await w.http('POST','/api/credential-remove',{})).status).toBe(404);
}));
it('AF1 revocation challenge is single use while the initiating session stays live',()=>world(async w=>{
    const login=w.store.loginOptions(), target=await w.store.login(login.challenge,await w.auth.assertion(b64decode(login.challenge)));
    const o=await w.store.managementOptions(w.session,'session_revoke',target), a=await w.auth.assertion(b64decode(o.challenge));
    await w.store.manage(w.session,o.action_id,'session_revoke',target,a);
    expect(w.store.requireSession(w.session)).toBe(w.session);
    await refuses('management_challenge_invalid',()=>w.store.manage(w.session,o.action_id,'session_revoke',target,a));
}));
it('AF1 changed descriptor cannot reuse a server approval signature',()=>world(async w=>{
    const r: MaplRequest={...v2(),request_id:w.rid,revision:2};await w.store.create(r);const signed=await w.sign();
    r.revision=3;r.check.scope=['pointer_bytes'];await w.store.create(r);await w.options();
    await refuses('challenge_mismatch',()=>w.store.approve(w.rid,signed));expect(w.record().approval).toBe('pending');
}));
it('AF1 approval screen binds fixed server host and removes the extra panel',()=>world(async w=>{
    const response=await w.http('GET','/api/requests/'+w.rid), record=await response.json() as Dict;
    expect(record.site_host).toBe(new URL(w.bindings.ORIGIN).host);expect(record.confirmation).toBeUndefined();
    for(const field of ['target','impact','scope','failure'])expect(record.view[field]).toBeTruthy();
    expect(record.view.details_text).not.toMatch(/알림 문구|마지막 연결|등록된 패스키/);
}));

it('AF1 date and time formatting and fixed impact wording', () => {
    const r = v2(), v = view({request:r, history:[], display_state:'승인 대기'}, utc(r.created_at));
    expect(v.impact).toBe('시험 화면을 여는 사람에게 새 세대의 자료가 보입니다.');
    expect(v.deadline).toBe('11월\u00a014일\u00a017:00\u00a0KST까지 (120분 남음)');
    expect(v.scope).toBe('이 포인터를 한 번 바꿉니다 · 원장·서비스·수집기는 바꾸지 않습니다 · 실행 가능 11월\u00a014일\u00a015:00–17:00\u00a0KST');
});
it('MAPLTZ fixed KST rollover, fractional seconds and ranges', () => {
    expect(kst('2026-11-16T14:59:00Z')).toBe('11월\u00a016일\u00a023:59\u00a0KST');
    expect(kst('2026-11-16T15:00:00Z')).toBe('11월\u00a017일\u00a000:00\u00a0KST');
    expect(kst('2026-12-31T15:30:00.5Z')).toBe('1월\u00a01일\u00a000:30\u00a0KST');
    expect(kst('2026-11-16T15:00:09Z', true)).toBe('11월\u00a017일\u00a000:00:09\u00a0KST');
    expect(kstRange('2026-11-16T12:30:00Z', '2026-11-16T14:30:00Z')).toBe('11월\u00a016일\u00a021:30–23:30\u00a0KST');
    expect(kstRange('2026-11-16T14:30:00Z', '2026-11-16T16:30:00Z')).toBe('11월\u00a016일\u00a023:30 – 11월\u00a017일\u00a001:30\u00a0KST');
});
it('MAPLTZ midnight deadline and history contain only formatted clock text', () => {
    const r = {...v2(), created_at:'2026-11-16T14:30:00Z', expires_at:'2026-11-16T15:30:00Z', window_utc:['2026-11-16T14:30:00Z','2026-11-16T16:30:00Z']};
    const v = view({request:r, history:[{at:r.created_at,event:'create'}], display_state:'승인 대기'}, utc(r.created_at));
    expect(v.deadline).toBe('11월\u00a017일\u00a000:30\u00a0KST까지 (60분 남음)');
    expect(v.scope).toContain('11월\u00a016일\u00a023:30 – 11월\u00a017일\u00a001:30\u00a0KST');
    expect(v.details_text).toContain('11월\u00a016일\u00a023:30:00\u00a0KST create');
    for (const field of Object.values(v)) expect(field).not.toMatch(/T\d\d:|Z|\d{4}-\d{2}-\d{2}/);
});
it('MAPLTZ list sorts newest first with deterministic id ties and distinct same-minute marks', () => world(async w => {
    const a = {...structuredClone(base), request_id:'a'.repeat(32)}, b = {...structuredClone(base), request_id:'b'.repeat(32)};
    await w.store.create(b); await w.store.create(a);
    const later = {...structuredClone(base), request_id:'c'.repeat(32), created_at:new Date(w.clock.now + 1000).toISOString()};
    await w.store.create(later);
    const rows = w.store.list().requests;
    expect(rows.map((r: Dict) => r.request.request_id)).toEqual([later.request_id, ...[w.rid,a.request_id,b.request_id].sort()]);
    const pair = rows.filter((r: Dict) => [a.request_id,b.request_id].includes(r.request.request_id));
    expect(pair[0].list_title).toBe(`화면 자료 게시 ${a.target.from_generation} → ${a.target.to_generation}`);
    expect(pair[1].list_title).toBe(pair[0].list_title);
    expect(pair.map((r: Dict) => r.list_meta)).toEqual([`요청 ${kst(a.created_at)} · #aaaaaa`, `요청 ${kst(b.created_at)} · #bbbbbb`]);
}));
it('MAPLTZ last response null and contact/stop timestamps retain elapsed wording', () => world(w => {
    expect(w.store.list().last_response).toBeNull();
    w.store.putMeta('last_contact','2026-11-16T15:00:09Z'); w.clock.now=utc('2026-11-16T15:02:09Z');
    expect(w.store.list().last_response).toBe('11월\u00a017일\u00a000:00\u00a0KST');
    expect(w.store.runnerStatus()).toBe('Mac 실행기(모의) 마지막 연결 11월\u00a017일\u00a000:00:09\u00a0KST (2분 전) · 켜짐·꺼짐은 이 정보만으로 알 수 없습니다');
    w.store.putMeta('stopped_at','2026-11-16T15:01:09Z');
    expect(w.store.runnerStatus()).toBe('실행기가 꺼진다고 알림 11월\u00a017일\u00a000:01:09\u00a0KST');
}));
it('MAPLTZ history API adds display text while preserving UTC audit time', () => world(async w => {
    const before = w.store.meta<Dict[]>('auth_history')!;
    const response = await w.http('GET','/api/history'), body = await response.json() as Dict;
    expect(body.history.length).toBeGreaterThan(0);
    expect(body.history).toEqual(before.map(e => ({...e,at_text:kst(e.at,true)})));
    expect(w.store.meta('auth_history')).toEqual(before);
}));
it('MAPLTZ register API adds server time text without changing UTC credential summary', () => world(async w => {
    const options = await w.store.registrationOptions(CODE);
    const credential = await w.auth.registration(b64decode(options.challenge));
    const response = await w.http('POST','/api/register/verify',{code:CODE,credential}), body = await response.json() as Dict;
    expect(response.status).toBe(200);
    expect(body.registered_at).toBe(base.created_at);
    expect(body.credential_registered_at).toBe(base.created_at);
    expect(body.registered_at_text).toBe(kst(base.created_at,true));
}, false));
