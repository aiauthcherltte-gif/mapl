import { need, Refusal } from './types';
export function decodePrefix(data: Uint8Array): [
    unknown,
    number
] {
    let at = 0;
    const item = (depth: number): unknown => {
        need(depth <= 8 && at < data.length, 'cbor_malformed');
        const first = data[at++], major = first >> 5, ai = first & 31;
        if (major === 7) {
            need([20, 21, 22].includes(ai), 'cbor_malformed');
            return ai === 22 ? null : ai === 21;
        }
        need(major <= 5 && ai <= 27, 'cbor_malformed');
        let n = ai;
        if (ai >= 24) {
            const size = 2 ** (ai - 24);
            need(at + size <= data.length, 'cbor_malformed');
            n = 0;
            for (let i = 0; i < size; i++)
                n = n * 256 + data[at++];
            need(Number.isSafeInteger(n) && n >= (size === 1 ? 24 : 2 ** (8 * (size / 2))), 'cbor_malformed');
        }
        if (major === 0)
            return n;
        if (major === 1)
            return -1 - n;
        need(n <= 65536, 'cbor_malformed');
        if (major === 2 || major === 3) {
            need(at + n <= data.length, 'cbor_malformed');
            const v = data.slice(at, at + n);
            at += n;
            return major === 2 ? v : new TextDecoder('utf-8', { fatal: true }).decode(v);
        }
        if (major === 4)
            return Array.from({ length: n }, () => item(depth + 1));
        const result = new Map<unknown, unknown>();
        let previous: Uint8Array | undefined;
        for (let i = 0; i < n; i++) {
            const start = at, key = item(depth + 1), encoded = data.slice(start, at);
            if (previous) {
                const order = encoded.length - previous.length || (() => { for (let j = 0; j < encoded.length; j++)
                    if (encoded[j] !== previous![j])
                        return encoded[j] - previous![j]; return 0; })();
                need(order > 0, 'cbor_malformed');
            }
            need(typeof key === 'string' || typeof key === 'number' || key instanceof Uint8Array, 'cbor_malformed');
            need(!result.has(key), 'cbor_malformed');
            previous = encoded;
            result.set(key, item(depth + 1));
        }
        return result;
    };
    try {
        need(data.length <= 65536, 'cbor_malformed');
        return [item(0), at];
    }
    catch {
        throw new Refusal('cbor_malformed', 400);
    }
}
export function decode(data: Uint8Array): unknown { const [v, n] = decodePrefix(data); need(n === data.length, 'cbor_malformed'); return v; }
