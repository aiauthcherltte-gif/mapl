"""Loopback HTTP server and explicit routes. No filesystem-serving base handler."""
import hmac
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .canonical import canonical_bytes, parse_json
from .config import BIND_HOST
from .errors import Refusal
from .isolation import package_bytes
from .state import utc
from . import ui

CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
ROUTES = (
    'GET /register', 'GET /r/<id>', 'GET /static/app.js', 'GET /static/app.css',
    'GET /api/requests/<id>', 'POST /api/register/options', 'POST /api/register/verify',
    'POST /api/requests/<id>/approve/options', 'POST /api/requests/<id>/approve/verify',
    'POST /api/requests/<id>/decline', 'POST /api/runner/heartbeat', 'POST /api/runner/stopping',
    'GET /api/runner/approved', 'POST /api/runner/claim',
    'POST /api/runner/report', 'POST /api/requester/requests', 'POST /api/requester/cancel')


class Application:
    def __init__(self, store, scenario='normal'):
        self.store = store
        self.profile = store.profile
        self.scenario = scenario

    def _auth(self, role, headers):
        expected = self.store.runner_token if role == 'runner' else self.store.requester_token
        if not hmac.compare_digest(headers.get('authorization', ''), 'Bearer ' + expected):
            raise Refusal('token_scope_refused', 403)

    def _record(self, rid):
        record = self.store.get(rid)
        record['view'] = ui.view(record, utc(record['server_now']))
        record['confirmation'] = ui.confirm(record, self.profile.origin)
        record['test_scenario'] = self.scenario
        return record

    def handle(self, method, path, headers, raw):
        headers = {key.lower(): value for key, value in headers.items()}
        common = {'Content-Security-Policy': CSP, 'X-Frame-Options': 'DENY',
                  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                  'Content-Type': 'application/json; charset=utf-8'}
        try:
            if headers.get('host') != self.profile.host:
                raise Refusal('host_mismatch', 403)
            if headers.get('authorization') and not path.startswith(('/api/runner/', '/api/requester/')):
                raise Refusal('token_scope_refused', 403)
            if len(raw) > 131072:
                raise Refusal('body_too_large', 413)
            if '?' in path or '#' in path or '%' in path:
                raise Refusal('route_not_found', 404)
            if method == 'GET' and (path == '/register' or re.fullmatch(r'/r/[0-9a-f]{32}', path)):
                if path.startswith('/r/'):
                    self.store.get(path[3:])
                return 200, {**common, 'Content-Type': 'text/html; charset=utf-8'}, package_bytes('static/index.html')
            if method == 'GET' and path in ('/static/app.js', '/static/app.css'):
                mime = 'text/javascript' if path.endswith('.js') else 'text/css'
                return 200, {**common, 'Content-Type': mime + '; charset=utf-8'}, package_bytes(path[1:])
            browser = path.startswith('/api/register/') or re.fullmatch(r'/api/requests/[0-9a-f]{32}(/approve/(options|verify)|/decline)?', path)
            if browser and method == 'POST':
                if headers.get('origin') != self.profile.origin:
                    raise Refusal('origin_mismatch', 403)
                if headers.get('authorization'):
                    raise Refusal('token_scope_refused', 403)
            if path.startswith('/api/runner/'):
                self._auth('runner', headers)
            elif path.startswith('/api/requester/'):
                self._auth('requester', headers)
            body = parse_json(raw) if raw else {}
            if not isinstance(body, dict):
                raise Refusal('body_malformed', 400)
            match = re.fullmatch(r'/api/requests/([0-9a-f]{32})(?:/(approve/options|approve/verify|decline))?', path)
            if method == 'GET' and match and match[2] is None:
                result = self._record(match[1])
            elif method == 'POST' and match and match[2] is not None:
                rid, action = match[1], match[2]
                if action == 'approve/options':
                    if type(body.get('revision')) is not int or not isinstance(body.get('content_hash'), str):
                        raise Refusal('display_binding_required', 400)
                    result = self.store.approval_options(rid, body['revision'], body['content_hash'])
                elif action == 'approve/verify':
                    self.store.approve(rid, body['credential'], body.get('revision'))
                    result = self._record(rid)
                else:
                    self.store.decline(rid)
                    result = self._record(rid)
            elif method == 'POST' and path == '/api/register/options':
                result = self.store.registration_options(body.get('code', ''))
            elif method == 'POST' and path == '/api/register/verify':
                result = self.store.register(body.get('code', ''), body['credential'])
            elif method == 'GET' and path == '/api/runner/approved':
                result = {'requests': self.store.approved()}
            elif method == 'POST' and path == '/api/runner/claim':
                result = self.store.claim(body['request_id'], body['revision'], body['claim_id'])
            elif method == 'POST' and path == '/api/runner/report':
                result = self.store.runner_report(body['request_id'], body['revision'], body.get('claim_id'), body['event'], body.get('evidence', {}))
            elif method == 'POST' and path == '/api/runner/heartbeat':
                result = self.store.heartbeat()
            elif method == 'POST' and path == '/api/runner/stopping':
                result = self.store.stopping()
            elif method == 'POST' and path == '/api/requester/requests':
                result = self.store.create_request(body['request'])
            elif method == 'POST' and path == '/api/requester/cancel':
                result = self.store.cancel(body['request_id'])
            else:
                raise Refusal('route_not_found', 404)
            return 200, common, canonical_bytes(result)
        except Refusal as error:
            return error.status, common, canonical_bytes({'error': error.code})
        except (KeyError, TypeError, ValueError):
            return 400, common, canonical_bytes({'error': 'body_malformed'})


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, application):
        self.application = application
        super().__init__((BIND_HOST, application.profile.port), Handler)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _dispatch(self):
        # No chunked request bodies, no ambiguous duplicated security headers.
        duplicates = any(len(self.headers.get_all(name, [])) > 1 for name in
                         ('Host', 'Origin', 'Authorization', 'Content-Length', 'Transfer-Encoding'))
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            length = -1
        self.connection.settimeout(5)
        if duplicates or 'Transfer-Encoding' in self.headers or not 0 <= length <= 131072:
            self.close_connection = True
            status, headers, body = 400, {'Content-Type': 'application/json', 'Content-Security-Policy': CSP,
                'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store'}, canonical_bytes({'error': 'body_malformed'})
        else:
            raw = self.rfile.read(length)
            status, headers, body = self.server.application.handle(self.command, self.path, dict(self.headers), raw)
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_DELETE = _dispatch
    do_HEAD = _dispatch
    do_OPTIONS = _dispatch
    do_PATCH = _dispatch
    do_TRACE = _dispatch
    do_CONNECT = _dispatch

    def send_error(self, code, message=None, explain=None):
        # Parser-level errors also return JSON and the same security headers;
        # BaseHTTPRequestHandler's free-form HTML error pages are never served.
        self.close_connection = True
        body = canonical_bytes({'error': 'http_request_refused'})
        self.send_response(code)
        for key, value in {'Content-Type': 'application/json; charset=utf-8',
            'Content-Security-Policy': CSP, 'X-Frame-Options': 'DENY',
            'Cache-Control': 'no-store', 'Content-Length': str(len(body))}.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def log_message(self, *_args):
        # No raw request fields or assertions in logs; reports use fixed templates.
        return
