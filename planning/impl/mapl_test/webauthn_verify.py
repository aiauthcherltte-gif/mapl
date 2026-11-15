"""Pure WebAuthn ES256 verification, used independently by server and runner."""
import hashlib
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .canonical import b64decode, b64encode, parse_json
from .cbor_min import decode, decode_prefix
from .errors import Refusal


def need(condition, code):
    if not condition:
        raise Refusal(code, 400)


def client_data(encoded, challenge, kind, origin):
    try:
        raw = b64decode(encoded)
        data = parse_json(raw)
        need(isinstance(data, dict), 'client_data_malformed')
    except Refusal as error:
        raise Refusal('client_data_malformed', 400) from error
    need(data.get('type') == kind, 'type_mismatch')
    need(data.get('challenge') == b64encode(challenge), 'challenge_mismatch')
    need(data.get('origin') == origin, 'origin_mismatch')
    need(data.get('crossOrigin', False) is False and 'topOrigin' not in data, 'cross_origin_refused')
    return raw


def auth_data(raw, rp_id):
    need(len(raw) >= 37, 'auth_data_malformed')
    need(hmac.compare_digest(raw[:32], hashlib.sha256(rp_id.encode()).digest()), 'rp_id_mismatch')
    flags = raw[32]
    need(bool(flags & 1), 'up_missing')
    need(bool(flags & 4), 'uv_missing')
    need(not (flags & 16) or bool(flags & 8), 'backup_flags_invalid')
    return {'up': True, 'uv': True, 'be': bool(flags & 8), 'bs': bool(flags & 16),
            'sign_count': int.from_bytes(raw[33:37], 'big'), 'flags': flags}


def verify_assertion(assertion, credential, challenge, origin, rp_id):
    try:
        need(isinstance(assertion, dict) and assertion.get('type') == 'public-key', 'assertion_malformed')
        response = assertion['response']
        client = client_data(response['clientDataJSON'], challenge, 'webauthn.get', origin)
        auth = b64decode(response['authenticatorData'])
        facts = auth_data(auth, rp_id)
        # Assertions have no attested credential data. Extensions are not used here.
        need(len(auth) == 37 and not facts['flags'] & 0xc0, 'auth_data_malformed')
        need(assertion.get('id') == credential['id'], 'unknown_credential')
        signature = b64decode(response['signature'])
        try:
            r, s = utils.decode_dss_signature(signature)
            need(utils.encode_dss_signature(r, s) == signature, 'signature_invalid')
            key = serialization.load_der_public_key(b64decode(credential['spki']))
            need(isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1), 'signature_invalid')
            key.verify(signature, auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError, TypeError) as error:
            raise Refusal('signature_invalid', 400) from error
        facts['counter_warning'] = bool(facts['sign_count'] and facts['sign_count'] <= credential.get('sign_count', 0))
        del facts['flags']
        return facts
    except (KeyError, TypeError, AttributeError) as error:
        raise Refusal('assertion_malformed', 400) from error


def verify_registration(registration, challenge, origin, rp_id):
    try:
        need(isinstance(registration, dict) and registration.get('type') == 'public-key', 'registration_malformed')
        response = registration['response']
        client_data(response['clientDataJSON'], challenge, 'webauthn.create', origin)
        attestation = decode(b64decode(response['attestationObject']))
        need(isinstance(attestation, dict) and set(attestation) == {'fmt', 'authData', 'attStmt'}, 'attestation_malformed')
        need(attestation['fmt'] == 'none' and attestation['attStmt'] == {}, 'attestation_format_refused')
        raw = attestation['authData']
        need(isinstance(raw, bytes), 'auth_data_malformed')
        facts = auth_data(raw, rp_id)
        need(bool(facts['flags'] & 64) and not facts['flags'] & 128 and len(raw) >= 55, 'attested_data_missing')
        length = int.from_bytes(raw[53:55], 'big')
        need(1 <= length <= 1024 and len(raw) > 55 + length, 'credential_malformed')
        credential_id = raw[55:55 + length]
        need(registration.get('id') == b64encode(credential_id), 'credential_malformed')
        cose, consumed = decode_prefix(raw[55 + length:])
        need(consumed == len(raw) - 55 - length, 'cbor_malformed')
        need(isinstance(cose, dict) and set(cose) == {1, 3, -1, -2, -3}, 'cose_malformed')
        need(cose[1] == 2 and cose[3] == -7 and cose[-1] == 1, 'cose_algorithm_refused')
        need(isinstance(cose[-2], bytes) and isinstance(cose[-3], bytes)
             and len(cose[-2]) == len(cose[-3]) == 32, 'cose_point_invalid')
        try:
            key = ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2], 'big'),
                int.from_bytes(cose[-3], 'big'), ec.SECP256R1()).public_key()
        except ValueError as error:
            raise Refusal('cose_point_invalid', 400) from error
        spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return {'id': b64encode(credential_id), 'spki': b64encode(spki), 'sign_count': facts['sign_count'],
                'be': facts['be'], 'bs': facts['bs']}
    except (KeyError, TypeError, AttributeError) as error:
        raise Refusal('registration_malformed', 400) from error
