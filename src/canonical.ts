import { need, Refusal, type Dict, type MaplRequest } from './types';
const encoder = new TextEncoder();
export const utf8 = (s: string) => encoder.encode(s);
export const hex = (b: Uint8Array) => Array.from(b, n => n.toString(16).padStart(2, '0')).join('');
function string(s: string): string {
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff) {
            need(++i < s.length && s.charCodeAt(i) >= 0xdc00 && s.charCodeAt(i) <= 0xdfff, 'json_surrogate_refused');
        }
        else
            need(c < 0xdc00 || c > 0xdfff, 'json_surrogate_refused');
    }
    return JSON.stringify(s);
}
export function codePointOrder(a: string, b: string): number {
    const aa = Array.from(a, c => c.codePointAt(0)!), bb = Array.from(b, c => c.codePointAt(0)!);
    for (let i = 0; i < Math.min(aa.length, bb.length); i++)
        if (aa[i] !== bb[i])
            return aa[i] - bb[i];
    return aa.length - bb.length;
}
export function canonical(value: unknown): string {
    if (value === null || typeof value === 'boolean')
        return JSON.stringify(value);
    if (typeof value === 'string')
        return string(value);
    if (typeof value === 'number') {
        need(Number.isInteger(value), 'json_type_refused');
        need(Number.isSafeInteger(value), 'json_integer_out_of_range');
        return String(value);
    }
    if (Array.isArray(value))
        return '[' + value.map(canonical).join(',') + ']';
    if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
        const obj = value as Dict;
        return '{' + Object.keys(obj).sort(codePointOrder).map(k => string(k) + ':' + canonical(obj[k])).join(',') + '}';
    }
    throw new Refusal('json_type_refused', 400);
}
export const canonicalBytes = (v: unknown) => utf8(canonical(v));
export const sha256 = async (v: Uint8Array): Promise<Uint8Array> => new Uint8Array(await crypto.subtle.digest('SHA-256', v as BufferSource));
export const digest = async (v: Uint8Array): Promise<string> => hex(await sha256(v));
export const contentHash = (v: unknown) => digest(canonicalBytes(v));
export const approvalChallenge = async (r: MaplRequest, nonce: string) => sha256(canonicalBytes({ format: 'mapl-approve/1', request_id: r.request_id, revision: r.revision, content_hash: await contentHash(r), decision: 'approve', nonce }));
export function b64encode(v: Uint8Array): string { return btoa(Array.from(v, c => String.fromCharCode(c)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
export function b64decode(v: unknown): Uint8Array {
    try {
        need(typeof v === 'string' && /^[A-Za-z0-9_-]*$/.test(v), 'base64_malformed');
        const raw = Uint8Array.from(atob(v.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - v.length % 4) % 4)), c => c.charCodeAt(0));
        need(b64encode(raw) === v, 'base64_malformed');
        return raw;
    }
    catch {
        throw new Refusal('base64_malformed', 400);
    }
}
// Recursive descent sees each key before assignment, including escaped equivalents.
export function parseJson(input: string | Uint8Array): unknown {
    try {
        const s = typeof input === 'string' ? input : new TextDecoder('utf-8', { fatal: true }).decode(input);
        let at = 0;
        const ws = () => { while (/[\x20\t\r\n]/.test(s[at] ?? '!'))
            at++; };
        const str = (): string => {
            const start = at++;
            let escaped = false;
            while (at < s.length) {
                const c = s[at++];
                if (!escaped && c === '"')
                    return JSON.parse(s.slice(start, at));
                if (!escaped && c === '\\')
                    escaped = true;
                else
                    escaped = false;
            }
            throw Error('string');
        };
        const item = (depth: number): unknown => {
            need(depth <= 64, 'json_malformed');
            ws();
            const c = s[at];
            if (c === '"')
                return str();
            if (c === '{' || c === '[') {
                at++;
                ws();
                const object = c === '{';
                const result: Dict | unknown[] = object ? {} : [];
                const keys = new Set<string>();
                const close = object ? '}' : ']';
                if (s[at] === close) {
                    at++;
                    return result;
                }
                while (true) {
                    ws();
                    let k = '';
                    if (object) {
                        need(s[at] === '"', 'json_malformed');
                        k = str();
                        need(!keys.has(k), 'json_malformed');
                        keys.add(k);
                        ws();
                        need(s[at++] === ':', 'json_malformed');
                    }
                    const v = item(depth + 1);
                    if (object)
                        Object.defineProperty(result, k, { value: v, writable: true, enumerable: true, configurable: true });
                    else
                        (result as unknown[]).push(v);
                    ws();
                    if (s[at] === close) {
                        at++;
                        return result;
                    }
                    need(s[at++] === ',', 'json_malformed');
                }
            }
            for (const [word, v] of [['true', true], ['false', false], ['null', null]] as const)
                if (s.startsWith(word, at)) {
                    at += word.length;
                    return v;
                }
            const m = /^-?(?:0|[1-9][0-9]*)/.exec(s.slice(at));
            need(m, 'json_malformed');
            at += m[0].length;
            need(!/[.eE]/.test(s[at] ?? '!'), 'json_malformed');
            const n = Number(m[0]);
            need(Number.isSafeInteger(n), 'json_integer_out_of_range');
            return n;
        };
        const value = item(0);
        ws();
        need(at === s.length, 'json_malformed');
        return value;
    }
    catch (e) {
        if (e instanceof Refusal && e.code === 'json_integer_out_of_range')
            throw e;
        throw new Refusal('json_malformed', 400);
    }
}
