"""Strict bounded, definite-length CBOR subset used by WebAuthn."""
from .errors import Refusal


def decode_prefix(data):
    if not isinstance(data, bytes) or len(data) > 65536:
        raise Refusal('cbor_malformed', 400)
    position = 0

    def item(depth):
        nonlocal position
        if depth > 8 or position >= len(data):
            raise ValueError('depth_or_truncated')
        initial = data[position]
        position += 1
        major, ai = initial >> 5, initial & 31
        if major == 7:
            if ai in (20, 21, 22):
                return {20: False, 21: True, 22: None}[ai]
            raise ValueError('simple')
        if major > 5 or ai > 27:
            raise ValueError('tag_or_indefinite')
        if ai < 24:
            n = ai
        else:
            size = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
            if position + size > len(data):
                raise ValueError('truncated')
            n = int.from_bytes(data[position:position + size], 'big')
            position += size
            if n < (24 if size == 1 else 1 << (8 * (size // 2))):
                raise ValueError('nonminimal')
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if n > 65536:
            raise ValueError('length')
        if major in (2, 3):
            if position + n > len(data):
                raise ValueError('truncated')
            value = data[position:position + n]
            position += n
            return value if major == 2 else value.decode('utf-8')
        if major == 4:
            return [item(depth + 1) for _ in range(n)]
        result = {}
        previous_key = None
        for _ in range(n):
            start = position
            key = item(depth + 1)
            encoded_key = data[start:position]
            order = (len(encoded_key), encoded_key)
            if previous_key is not None and order <= previous_key:
                raise ValueError('noncanonical_map_order')
            previous_key = order
            if type(key) not in (str, int, bytes) or key in result:
                raise ValueError('map_key')
            result[key] = item(depth + 1)
        return result
    try:
        value = item(0)
        return value, position
    except (ValueError, UnicodeError, OverflowError, RecursionError) as error:
        raise Refusal('cbor_malformed', 400) from error


def decode(data):
    value, position = decode_prefix(data)
    if position != len(data):
        raise Refusal('cbor_malformed', 400)
    return value
