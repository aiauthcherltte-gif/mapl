import { verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { b64decode, b64encode, parseJson, sha256 } from './canonical';
import { decode, decodePrefix } from './cbor';
import { need, Refusal, type Dict } from './types';
export interface Credential {
    id: string;
    spki: string;
    cose: string;
    sign_count: number;
    be: boolean;
    bs: boolean;
    registered_at?: string;
    revoked?: boolean;
}
export interface Facts {
    up: boolean;
    uv: boolean;
    be: boolean;
    bs: boolean;
    sign_count: number;
    counter_warning?: boolean;
}
export function clientData(encoded: unknown, challenge: Uint8Array, kind: string, origin: string): Uint8Array {
    let raw: Uint8Array, data: Dict;
    try {
        raw = b64decode(encoded);
        data = parseJson(raw) as Dict;
        need(data && typeof data === 'object' && !Array.isArray(data), 'client_data_malformed');
    }
    catch {
        throw new Refusal('client_data_malformed', 400);
    }
    need(data.type === kind, 'type_mismatch');
    need(data.challenge === b64encode(challenge), 'challenge_mismatch');
    need(data.origin === origin, 'origin_mismatch');
    need((data.crossOrigin === undefined || data.crossOrigin === false) && !Object.hasOwn(data, 'topOrigin'), 'cross_origin_refused');
    return raw;
}
export async function authData(raw: Uint8Array, rp: string): Promise<Facts & {
    flags: number;
}> {
    need(raw.length >= 37, 'auth_data_malformed');
    const hash = await sha256(new TextEncoder().encode(rp));
    need(raw.slice(0, 32).every((b, i) => b === hash[i]), 'rp_id_mismatch');
    const flags = raw[32];
    need(flags & 1, 'up_missing');
    need(flags & 4, 'uv_missing');
    need(!(flags & 16) || Boolean(flags & 8), 'backup_flags_invalid');
    return { up: true, uv: true, be: Boolean(flags & 8), bs: Boolean(flags & 16), sign_count: new DataView(raw.buffer, raw.byteOffset).getUint32(33), flags };
}
export async function verifyAssertion(a: Dict, c: Credential, ch: Uint8Array, origin: string, rp: string): Promise<Facts> {
    need(a && a.type === 'public-key' && a.response, 'assertion_malformed');
    clientData(a.response.clientDataJSON, ch, 'webauthn.get', origin);
    const raw = b64decode(a.response.authenticatorData), facts = await authData(raw, rp);
    need(raw.length === 37 && !(facts.flags & 0xc0), 'auth_data_malformed');
    need(a.id === c.id, 'unknown_credential');
    b64decode(a.response.signature);
    try {
        const result = await verifyAuthenticationResponse({ response: { ...a, rawId: a.id, clientExtensionResults: {} } as AuthenticationResponseJSON, expectedChallenge: b64encode(ch), expectedOrigin: origin, expectedRPID: rp, requireUserVerification: true, credential: { id: c.id, publicKey: new Uint8Array(b64decode(c.cose)), counter: 0 } });
        need(result.verified, 'signature_invalid');
    }
    catch {
        throw new Refusal('signature_invalid', 400);
    }
    const { flags: _, ...out } = facts;
    return { ...out, counter_warning: Boolean(facts.sign_count && facts.sign_count <= c.sign_count) };
}
export async function verifyRegistration(a: Dict, ch: Uint8Array, origin: string, rp: string): Promise<Credential> {
    need(a && a.type === 'public-key' && a.response, 'registration_malformed');
    clientData(a.response.clientDataJSON, ch, 'webauthn.create', origin);
    const att = decode(b64decode(a.response.attestationObject));
    need(att instanceof Map && att.size === 3 && ['fmt', 'authData', 'attStmt'].every(k => att.has(k)), 'attestation_malformed');
    need(att.get('fmt') === 'none' && att.get('attStmt') instanceof Map && att.get('attStmt').size === 0, 'attestation_format_refused');
    const raw = att.get('authData');
    need(raw instanceof Uint8Array, 'auth_data_malformed');
    const facts = await authData(raw, rp);
    need((facts.flags & 64) && !(facts.flags & 128) && raw.length >= 55, 'attested_data_missing');
    const length = (raw[53] << 8) | raw[54];
    need(length >= 1 && length <= 1024 && raw.length > 55 + length, 'credential_malformed');
    const id = raw.slice(55, 55 + length);
    need(a.id === b64encode(id), 'credential_malformed');
    const encoded = raw.slice(55 + length), [cose, consumed] = decodePrefix(encoded);
    need(consumed === encoded.length, 'cbor_malformed');
    need(cose instanceof Map && cose.size === 5 && [1, 3, -1, -2, -3].every(k => cose.has(k)), 'cose_malformed');
    need(cose.get(1) === 2 && cose.get(3) === -7 && cose.get(-1) === 1, 'cose_algorithm_refused');
    const x = cose.get(-2), y = cose.get(-3);
    need(x instanceof Uint8Array && y instanceof Uint8Array && x.length === 32 && y.length === 32, 'cose_point_invalid');
    let key: CryptoKey;
    try {
        key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: b64encode(x), y: b64encode(y), ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    }
    catch {
        throw new Refusal('cose_point_invalid', 400);
    }
    try {
        const result = await verifyRegistrationResponse({ response: { ...a, rawId: a.id, clientExtensionResults: {} } as RegistrationResponseJSON, expectedChallenge: b64encode(ch), expectedOrigin: origin, expectedRPID: rp, requireUserVerification: true, supportedAlgorithmIDs: [-7] });
        need(result.verified, 'registration_malformed');
    }
    catch {
        throw new Refusal('registration_malformed', 400);
    }
    return { id: b64encode(id), spki: b64encode(new Uint8Array(await crypto.subtle.exportKey('spki', key))), cose: b64encode(encoded), sign_count: facts.sign_count, be: facts.be, bs: facts.bs };
}
