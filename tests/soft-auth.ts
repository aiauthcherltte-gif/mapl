import { b64encode, canonicalBytes, sha256, utf8 } from '../src/canonical';
import type { Dict } from '../src/types';
export function concat(...parts: Uint8Array[]): Uint8Array { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) {
    out.set(p, at);
    at += p.length;
} return out; }
// Test-only canonical CBOR encoder, separate from the production decoder.
export function cbor(v: unknown): Uint8Array {
    const head = (major: number, n: number) => n < 24 ? new Uint8Array([major * 32 + n]) : n < 256 ? new Uint8Array([major * 32 + 24, n]) : new Uint8Array([major * 32 + 25, n >> 8, n & 255]);
    if (v === null)
        return new Uint8Array([246]);
    if (typeof v === 'boolean')
        return new Uint8Array([v ? 245 : 244]);
    if (typeof v === 'number')
        return head(v < 0 ? 1 : 0, v < 0 ? -1 - v : v);
    if (typeof v === 'string') {
        const s = utf8(v);
        return concat(head(3, s.length), s);
    }
    if (v instanceof Uint8Array)
        return concat(head(2, v.length), v);
    if (v instanceof Map) {
        const pairs = Array.from(v, ([k, val]) => [cbor(k), cbor(val)]).sort((a, b) => a[0].length - b[0].length || (() => { for (let i = 0; i < a[0].length; i++)
            if (a[0][i] !== b[0][i])
                return a[0][i] - b[0][i]; return 0; })());
        return concat(head(5, pairs.length), ...pairs.flat());
    }
    throw Error('unsupported test CBOR');
}
const unb64 = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
export class SoftAuthenticator {
    keys!: CryptoKeyPair;
    cose!: Uint8Array;
    id = b64encode(utf8('software-test-credential'));
    count = 0;
    async init() { this.keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair; const jwk = await crypto.subtle.exportKey('jwk', this.keys.publicKey); this.cose = cbor(new Map<unknown, unknown>([[1, 2], [3, -7], [-1, 1], [-2, unb64(jwk.x!)], [-3, unb64(jwk.y!)]])); return this; }
    client(ch: Uint8Array, kind: string, origin: string, extra: Dict = {}) { return canonicalBytes({ type: kind, challenge: b64encode(ch), origin, ...extra }); }
    async auth(flags: number, rp: string) { const n = new Uint8Array(4); new DataView(n.buffer).setUint32(0, ++this.count); return concat(await sha256(utf8(rp)), new Uint8Array([flags]), n); }
    async registration(ch: Uint8Array, o: Dict = {}) {
        const id = unb64(this.id), len = new Uint8Array([id.length >> 8, id.length & 255]);
        const raw = concat(await this.auth(o.flags ?? 0x45, o.rp ?? 'localhost'), new Uint8Array(16), len, id, this.cose);
        return { id: this.id, type: 'public-key', response: { clientDataJSON: b64encode(this.client(ch, 'webauthn.create', o.origin ?? 'http://localhost:8790', o.extra)), attestationObject: b64encode(cbor(new Map<unknown, unknown>([['fmt', o.fmt ?? 'none'], ['attStmt', new Map()], ['authData', raw]]))) } };
    }
    async assertion(ch: Uint8Array, o: Dict = {}) {
        const client = o.client ?? this.client(ch, o.kind ?? 'webauthn.get', o.origin ?? 'http://localhost:8790', o.extra), raw = await this.auth(o.flags ?? 5, o.rp ?? 'localhost');
        const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.keys.privateKey, concat(raw, await sha256(client)) as BufferSource));
        const integer = (v: Uint8Array) => { let at = 0; while (at < v.length - 1 && v[at] === 0)
            at++; v = v.slice(at); if (v[0] & 128)
            v = concat(new Uint8Array([0]), v); return concat(new Uint8Array([2, v.length]), v); };
        const ints = concat(integer(sig.slice(0, 32)), integer(sig.slice(32))), der = concat(new Uint8Array([48, ints.length]), ints);
        return { id: o.id ?? this.id, type: 'public-key', response: { clientDataJSON: b64encode(client), authenticatorData: b64encode(raw), signature: b64encode(der) } };
    }
}
