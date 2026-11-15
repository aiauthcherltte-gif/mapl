"""Loopback TLS/Worker protocol stand-in. NOT a Cloudflare/DO implementation.

The ephemeral key/CA are generated only for this isolated fixture. No system
trust store, existing certificate/key, account, or external endpoint is used.
History aggregation and five-minute liveness writes model the W2 wire contract.
"""
import ipaddress
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ...mapl_test.canonical import b64decode, canonical_bytes, parse_json
from ...mapl_test.server import Application
from ...mapl_test.state import stamp
from ...mapl_test.tests.support import World
from ..transport import HTTPSTransport


class TLSStub:
    def __init__(self, scenario='normal'):
        self.world = World(scenario=scenario, register=False)
        self.calls, self.responses, self.aggregates = [], [], {}
        self.server_offset, self.last_contact, self.contact_writes = 0, None, 0
        self.claim_calls, self.report_failures = 0, 0
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.server.stub = self
        self.origin = 'https://127.0.0.1:' + str(self.server.server_port)
        self.world.store.profile = SimpleNamespace(origin=self.origin, rp_id='localhost',
            host='127.0.0.1:' + str(self.server.server_port))
        self.app = Application(self.world.store, scenario)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'MAPLW13 ephemeral loopback test CA')])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .sign(key, hashes.SHA256()))
        self.ca = cert.public_bytes(serialization.Encoding.PEM).decode()
        root = self.world.root
        root.write_atomic('stub-cert.pem', self.ca.encode())
        root.write_atomic('stub-key.pem', key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root.path + '/stub-cert.pem', root.path + '/stub-key.pem')
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        self.thread.start()
        options = self.world.store.registration_options(self.world.store.setup_code)
        self.world.store.register(self.world.store.setup_code,
            self.world.auth.registration(b64decode(options['challenge']), origin=self.origin))

    def approve(self, **kwargs):
        options = self.world.options()
        assertion = self.world.auth.assertion(b64decode(options['challenge']), origin=self.origin, **kwargs)
        self.world.store.approve(self.world.rid, assertion)
        return assertion

    def transport(self):
        return HTTPSTransport(self.origin, self.world.store.runner_token, test_ca_pem=self.ca)

    def handle(self, method, path, headers, raw):
        self.calls.append((method, path))
        if self.responses:
            return self.responses.pop(0)
        if method == 'GET' and path == '/api/runner/approved':
            self.app._auth('runner', {key.lower(): value for key, value in headers.items()})
            w = self.world
            if self.last_contact is None or (w.clock() - self.last_contact).total_seconds() >= 300:
                w.store.heartbeat()
                self.last_contact = w.clock()
                self.contact_writes += 1
            pending = any(w.store._entry(rid)['state']['approval'] in ('pending', 'approved')
                          and w.store._entry(rid)['state']['execution'] == 'not_started'
                          for rid in w.store._data['latest'])
            return 200, {}, canonical_bytes({'requests': w.store.approved(), 'has_pending': pending,
                'server_now': stamp(w.clock() + timedelta(seconds=self.server_offset))})
        if path == '/api/runner/claim':
            self.claim_calls += 1
        if path == '/api/runner/report':
            if self.report_failures:
                self.report_failures -= 1
                return 503, {}, b'<html>local injected report failure</html>'
            body = parse_json(raw)
            if body.get('event') == 'refused_before_claim':
                # Every refusal must pass the real Application/Store contract first.
                status, response_headers, payload = self.app.handle(method, path, headers, raw)
                if status != 200:
                    return status, response_headers, payload
                evidence, rid = body['evidence'], body['request_id']
                entry = self.world.store._entry(rid, body['revision'])
                key = (rid, evidence['code'])
                accepted_row = entry['history'].pop()
                # Only folding is simulated; acceptance above is never widened.
                if key not in self.aggregates:
                    row = {**accepted_row, 'count': 0, 'last_at': stamp(self.world.clock())}
                    self.aggregates[key] = row
                    entry['history'].append(row)
                row = self.aggregates[key]
                row.update(count=row['count'] + 1, last_at=stamp(self.world.clock()))
                self.world.store._save()
                return status, response_headers, canonical_bytes(self.world.record())
        return self.app.handle(method, path, headers, raw)

    def close(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.world.close()


class Handler(BaseHTTPRequestHandler):
    def dispatch(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        status, headers, payload = self.server.stub.handle(self.command, self.path, dict(self.headers), raw)
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = dispatch

    def log_message(self, *_args):
        return None
