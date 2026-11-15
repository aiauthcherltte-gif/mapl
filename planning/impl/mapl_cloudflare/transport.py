"""Pinned HTTPS transport. TLS verification stays enabled, including in tests."""
import http.client
import random
import re
import ssl
from urllib.parse import urlsplit

from ..mapl_test.canonical import canonical_bytes, parse_json
from ..mapl_test.errors import Refusal
from ..mapl_test.state import utc

RUNNER_ROUTES = frozenset(('/api/runner/approved', '/api/runner/claim', '/api/runner/report', '/api/runner/stopping'))


def fixed_origin(value):
    try:
        url = urlsplit(value)
        if (url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None
                or url.path or url.query or url.fragment or url.hostname.endswith('.')
                or not re.fullmatch(r'[a-z0-9.-]+', url.hostname)
                or value != 'https://' + url.hostname + (':' + str(url.port) if url.port is not None else '')):
            raise ValueError('origin')
        return url
    except (ValueError, TypeError, AttributeError) as error:
        raise Refusal('runner_base_refused') from error


class HTTPSTransport:
    def __init__(self, origin, token, *, test_ca_pem=None):
        self.url = fixed_origin(origin)
        self.origin, self.rp_id, self.token = origin, self.url.hostname, token
        self.context = ssl.create_default_context()
        if test_ca_pem is not None:
            # Only a loopback fixture may add an ephemeral test CA. Verification
            # and host checks remain mandatory; no insecure-context option exists.
            if self.url.hostname != '127.0.0.1':
                raise Refusal('test_ca_nonlocal_refused')
            self.context.load_verify_locations(cadata=test_ca_pem)
            self.rp_id = 'localhost'
        self._envelopes = []

    def call(self, method, path, body=None):
        if path not in RUNNER_ROUTES:
            raise Refusal('runner_route_refused')
        connection = http.client.HTTPSConnection(self.url.hostname, self.url.port or 443,
                                               timeout=5, context=self.context)
        try:
            connection.request(method, path, body=None if body is None else canonical_bytes(body),
                headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
            response = connection.getresponse()
            payload = response.read(2 * 1024 * 1024 + 1)
            if len(payload) > 2 * 1024 * 1024:
                raise Refusal('runner_response_too_large', 502)
            # Check status BEFORE JSON: Cloudflare limit/redirect pages can be HTML.
            if 300 <= response.status < 400:
                raise Refusal('runner_redirect_refused', response.status)
            if response.status in (429, 1027) or re.search(rb'\b1027\b', payload) and response.status != 200:
                raise Refusal('runner_rate_limited', 429)
            if response.status != 200:
                if response.status >= 500:
                    raise Refusal('runner_server_error', response.status)
                try:
                    code = parse_json(payload).get('error', 'runner_http_refused')
                except (Refusal, AttributeError):
                    code = 'runner_http_refused'
                raise Refusal(code, response.status)
            result = parse_json(payload)
            if not isinstance(result, dict):
                raise Refusal('runner_response_malformed', 502)
            return result
        finally:
            connection.close()

    def poll(self):
        self._envelopes = []
        result = self.call('GET', '/api/runner/approved')
        if (not isinstance(result.get('requests'), list) or type(result.get('has_pending')) is not bool
                or not isinstance(result.get('server_now'), str)):
            raise Refusal('runner_response_malformed', 502)
        try:
            utc(result['server_now'])
            for envelope in result['requests']:
                if (not isinstance(envelope, dict) or not isinstance(envelope.get('request'), dict)
                        or not isinstance(envelope.get('credential'), dict)
                        or not isinstance(envelope.get('assertion'), dict)
                        or not isinstance(envelope.get('nonce'), str)):
                    raise Refusal('runner_response_malformed', 502)
        except (ValueError, TypeError) as error:
            raise Refusal('runner_response_malformed', 502) from error
        self._envelopes = result['requests']
        return result

    def approved(self):
        return self._envelopes

    def heartbeat(self):
        # The authenticated poll carries liveness; no extra HTTP request.
        return None

    def claim(self, rid, revision, claim_id):
        return self.call('POST', '/api/runner/claim', {'request_id': rid, 'revision': revision, 'claim_id': claim_id})

    def report(self, rid, revision, claim_id, event, evidence):
        return self.call('POST', '/api/runner/report', {'request_id': rid, 'revision': revision,
            'claim_id': claim_id, 'event': event, 'evidence': evidence})

    def stopping(self):
        return self.call('POST', '/api/runner/stopping', {})

    def claim_backoff(self):
        return None


class PollSchedule:
    def __init__(self, uniform=random.uniform):
        self.failures, self.uniform = 0, uniform

    def success(self, has_pending):
        self.failures = 0
        return 20 if has_pending else 120

    def failure(self, error):
        self.failures += 1
        if isinstance(error, Refusal) and error.status == 429:
            return 300
        base = (20, 40, 80, 160, 300)[min(self.failures - 1, 4)]
        return min(300, self.uniform(base * .8, base * 1.2))
