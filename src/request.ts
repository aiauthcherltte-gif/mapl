import { orderedScope } from './scope';
import { clone, need, Refusal, type Dict, type MaplRequest } from './types';
import { utc } from './state';
export const NOT_COVERED = ['ledger write', 'service start', 'collector restart', 'recovery'];
const keys = (v: unknown, want: string[]) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join('|') === [...want].sort().join('|');
const match = (v: unknown, re: RegExp) => typeof v === 'string' && re.test(v);
export function validate(input: unknown, rootId: string): MaplRequest {
    let rule = 'structure';
    const v2 = (input as Dict)?.format === 'mapl-request/2';
    const check = (v: unknown, r: string) => { rule = r; need(v, 'request_invalid', 400, r); };
    try {
        const r = input as Dict;
        need(r?.action_type === 'screen_publication/1', 'action_type_refused', 409, 'action_type');
        check(Object.hasOwn(r, 'recovery'), 'fields');
        if (!v2) need(keys(r.recovery, ['included_in_this_approval']) && r.recovery.included_in_this_approval === false && Array.isArray(r.not_covered) && r.not_covered.includes('recovery'), 'scope_refused', 409, 'recovery_scope');
        const t = r.target;
        need(t, 'request_invalid');
        need(t.test_root_id === rootId, 'test_root_id_mismatch', 409, 'target.test_root_id');
        const required = ['format', 'mode', 'request_id', 'revision', 'action_type', 'created_at', 'expires_at', 'window_utc', 'target', 'kit', 'bundle', 'not_covered', 'recovery'];
        if (v2) required.push('check');
        check(required.every(k => Object.hasOwn(r, k)) && Object.keys(r).every(k => required.includes(k) || k === 'summary_by_ai'), 'fields');
        check(r.format === 'mapl-request/1' || v2, 'format');
        check(r.mode === 'test', 'mode');
        check(match(r.request_id, /^[0-9a-f]{32}$/), 'request_id');
        check(Number.isSafeInteger(r.revision) && r.revision >= 1, 'revision');
        check(t.pointer === 'test-screen/CURRENT.json', 'target.pointer');
        check(keys(t, ['pointer', 'test_root_id', 'from_generation', 'to_generation', 'before_sha256', 'after_sha256']), 'target.fields');
        for (const k of ['from_generation', 'to_generation'])
            check(match(t[k], /^gen\/[0-9]{4}$/), 'target.' + k);
        for (const k of ['before_sha256', 'after_sha256'])
            check(match(t[k], /^[0-9a-f]{64}$/), 'target.' + k);
        check(keys(r.kit, ['name', 'sha256']) && r.kit.name === 'mock-kit/1', 'kit.name');
        check(keys(r.bundle, ['name', 'sha256']) && r.bundle.name === t.to_generation, 'bundle.name');
        for (const k of ['kit', 'bundle'])
            check(match(r[k].sha256, /^[0-9a-f]{64}$/), k + '.sha256');
        check(Array.isArray(r.window_utc) && r.window_utc.length === 2, 'window_utc');
        check(JSON.stringify(r.not_covered) === JSON.stringify(v2 && r.recovery.included_in_this_approval === true ? NOT_COVERED.slice(0, 3) : NOT_COVERED), 'not_covered');
        check(typeof (r.summary_by_ai ?? '') === 'string' && r.summary_by_ai !== null && Array.from(r.summary_by_ai ?? '').length <= 4096, 'summary_by_ai');
        rule = 'timestamps';
        const created = utc(r.created_at), expiry = utc(r.expires_at), start = utc(r.window_utc[0]), end = utc(r.window_utc[1]);
        check(created < expiry, 'created_before_expiry');
        check(expiry <= end, 'expiry_within_window');
        check(start < end, 'window_order');
        if (v2) {
            check(end - created <= 604800000, 'window_maximum');
            validateCheck(r, check);
        } else check(end - start <= 14400000, 'window_maximum');
        return clone(r) as MaplRequest;
    }
    catch (e) {
        if (e instanceof Refusal) {
            if (e.code === 'request_invalid' && !e.rule)
                e.rule = rule;
            throw e;
        }
        throw new Refusal('request_invalid', 400, rule);
    }
}

function validateCheck(r: Dict, check: (v: unknown, rule: string) => void): void {
    const c = r.check, rec = r.recovery;
    check(keys(c, ['scope', 'recovery_eligible_codes', 'check_and_recover_max_s']), 'check.fields');
    check(orderedScope(c.scope) && c.scope.includes('pointer_bytes'), 'check.scope');
    check(Array.isArray(c.recovery_eligible_codes) && c.recovery_eligible_codes.every((x: unknown) => match(x, /^[A-Z_]{1,80}$/)) && JSON.stringify(c.recovery_eligible_codes) === JSON.stringify([...new Set(c.recovery_eligible_codes)].sort()), 'check.recovery_eligible_codes');
    check(Number.isInteger(c.check_and_recover_max_s) && c.check_and_recover_max_s >= 60 && c.check_and_recover_max_s <= 600 && c.check_and_recover_max_s % 60 === 0, 'check.check_and_recover_max_s');
    if (rec.included_in_this_approval === false) check(keys(rec, ['included_in_this_approval']), 'recovery.fields');
    else {
        check(rec.included_in_this_approval === true && keys(rec, ['included_in_this_approval', 'kind', 'restore_to_sha256', 'only_if_current_sha256', 'on', 'valid_until', 'max_runs']), 'recovery.fields');
        check(rec.kind === 'restore_previous_pointer' && rec.max_runs === 1 && rec.restore_to_sha256 === r.target.before_sha256 && rec.only_if_current_sha256 === r.target.after_sha256, 'recovery.binding');
        check(Array.isArray(rec.on) && rec.on.length > 0 && new Set(rec.on).size === rec.on.length && rec.on.every((x: unknown) => c.recovery_eligible_codes.includes(x)), 'check.on');
        check(utc(rec.valid_until) === utc(r.window_utc[1]) + c.check_and_recover_max_s * 1000, 'check.valid_until');
    }
}
