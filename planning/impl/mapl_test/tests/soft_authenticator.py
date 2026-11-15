"""Software authenticator fixture: real P-256 signatures, no person or device."""
import hashlib
import json
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ..canonical import b64encode


def cbor(value):
    def head(major, n):
        if n < 24:
            return bytes([major * 32 + n])
        for size, tag in ((1, 24), (2, 25), (4, 26), (8, 27)):
            if n < 1 << (size * 8):
                return bytes([major * 32 + tag]) + n.to_bytes(size, 'big')
        raise ValueError('too_large')
    if isinstance(value, bool):
        return b'\xf5' if value else b'\xf4'
    if value is None:
        return b'\xf6'
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode()
        return head(3, len(data)) + data
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(cbor(x) for x in value)
    pairs = sorted(((cbor(k), cbor(v)) for k, v in value.items()), key=lambda p: (len(p[0]), p[0]))
    return head(5, len(pairs)) + b''.join(k + v for k, v in pairs)


class SoftAuthenticator:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(24)
        self.count = 0

    def client(self, challenge, kind, origin, extra=None):
        data = {'type': kind, 'challenge': b64encode(challenge), 'origin': origin, 'crossOrigin': False}
        data.update(extra or {})
        return json.dumps(data, separators=(',', ':')).encode()

    def assertion(self, challenge, origin='http://localhost:8790', rp='localhost', flags=0x1d,
                  kind='webauthn.get', extra=None, client_raw=None, credential_id=None):
        self.count += 1
        client = client_raw if client_raw is not None else self.client(challenge, kind, origin, extra)
        auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + self.count.to_bytes(4, 'big')
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {'id': b64encode(credential_id or self.credential_id), 'type': 'public-key',
                'response': {'clientDataJSON': b64encode(client), 'authenticatorData': b64encode(auth),
                             'signature': b64encode(sig)}}

    def registration(self, challenge, origin='http://localhost:8790', fmt='none', alg=-7, flags=0x5d):
        numbers = self.key.public_key().public_numbers()
        cose = {1: 2, 3: alg, -1: 1, -2: numbers.x.to_bytes(32, 'big'), -3: numbers.y.to_bytes(32, 'big')}
        auth = (hashlib.sha256(b'localhost').digest() + bytes([flags]) + bytes(4) + bytes(16)
                + len(self.credential_id).to_bytes(2, 'big') + self.credential_id + cbor(cose))
        return {'id': b64encode(self.credential_id), 'type': 'public-key', 'response': {
            'clientDataJSON': b64encode(self.client(challenge, 'webauthn.create', origin)),
            'attestationObject': b64encode(cbor({'fmt': fmt, 'authData': auth, 'attStmt': {}}))}}
