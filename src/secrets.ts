import { utf8, sha256 } from './canonical';
import { type Env } from './platform';
// Fixed-size digests avoid leaking lengths to the equality primitive.
export async function secretEqual(actual: unknown, expected: unknown, minimum: number): Promise<boolean> {
    const valid = typeof actual === 'string' && typeof expected === 'string' && expected.length >= minimum;
    const [a, b] = await Promise.all([sha256(utf8(typeof actual === 'string' ? actual : '')), sha256(utf8(typeof expected === 'string' ? expected : ''))]);
    const equal = (crypto.subtle as SubtleCrypto & { timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean }).timingSafeEqual(a, b);
    return valid && equal;
}

// Deployed profile uses public digests exclusively; raw fixtures remain local-only.
export async function roleEqual(auth: unknown, hash: unknown, raw: unknown, env: Env): Promise<boolean> {
    if (env.ORIGIN === 'http://localhost:8790' && env.RP_ID === 'localhost' && hash === undefined)
        return secretEqual(auth, typeof raw === 'string' && raw.length >= 32 ? 'Bearer ' + raw : undefined, 39);
    const valid = typeof hash === 'string' && /^[0-9a-f]{64}$/.test(hash) && typeof auth === 'string' && /^Bearer [A-Za-z0-9_-]{32,}$/.test(auth);
    const actual = await sha256(utf8(typeof auth === 'string' ? auth.slice(7) : ''));
    const expected = Uint8Array.from({ length: 32 }, (_, i) => valid ? parseInt((hash as string).slice(i * 2, i * 2 + 2), 16) : 0);
    const equal = (crypto.subtle as SubtleCrypto & { timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean }).timingSafeEqual(actual, expected);
    return valid && equal;
}
