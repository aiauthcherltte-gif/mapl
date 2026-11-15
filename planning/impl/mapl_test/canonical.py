"""Small canonical JSON and base64url rules; no external package imports."""
import base64
import binascii
import hashlib
import json
import re

from .errors import Refusal


def _check(value):
    if type(value) is int:
        # MAPLW13F coordinator decision: exact cross-language safe integers.
        if abs(value) > 2**53 - 1:
            raise Refusal('json_integer_out_of_range', 400)
        return
    if value is None or type(value) in (str, bool):
        return
    if isinstance(value, list):
        for item in value:
            _check(item)
        return
    if isinstance(value, dict) and all(isinstance(k, str) for k in value):
        for item in value.values():
            _check(item)
        return
    raise Refusal('json_type_refused', 400)


def canonical_bytes(value):
    _check(value)
    # Python string ordering is Unicode code-point order, including astral keys.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def parse_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate')
            result[key] = value
        return result
    try:
        result = json.loads(data, object_pairs_hook=pairs,
                            parse_float=lambda _: (_ for _ in ()).throw(ValueError('float')),
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))
        _check(result)
        return result
    except (ValueError, UnicodeError, TypeError, RecursionError) as error:
        raise Refusal('json_malformed', 400) from error


def digest(data):
    return hashlib.sha256(data).hexdigest()


def b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def b64decode(value):
    try:
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]*', value):
            raise ValueError('alphabet')
        data = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
        if b64encode(data) != value:
            raise ValueError('noncanonical')
        return data
    except (ValueError, binascii.Error) as error:
        raise Refusal('base64_malformed', 400) from error


def approval_challenge(request, nonce):
    return hashlib.sha256(canonical_bytes({'format': 'mapl-approve/1',
        'request_id': request['request_id'], 'revision': request['revision'],
        'content_hash': digest(canonical_bytes(request)), 'decision': 'approve', 'nonce': nonce})).digest()
