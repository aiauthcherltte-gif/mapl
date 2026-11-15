"""In-process simulated runner. HTTP transport is loopback only, never redirects."""
import copy
import http.client
import secrets
import threading
from urllib.parse import urlsplit

from .canonical import approval_challenge, canonical_bytes, parse_json
from .config import Profile
from .errors import Refusal
from .request import local_request, validate
from .state import expired, no_run_evidence, utc
from .webauthn_verify import verify_assertion


def validate_base_url(base_url):
    try:
        url = urlsplit(base_url)
        if (url.scheme != 'http' or url.hostname not in ('localhost', '127.0.0.1')
            or url.username is not None or url.password is not None or url.path not in ('', '/')
            or url.query or url.fragment or url.port is None):
            raise ValueError('loopback_only')
        Profile('local', url.port)
        return url
    except (ValueError, Refusal) as error:
        raise Refusal('runner_base_refused') from error


class HTTPTransport:
    def __init__(self, base_url, token):
        self.url = validate_base_url(base_url)
        self.token = token
        self.origin = f'http://localhost:{self.url.port}'
        self.rp_id = 'localhost'

    def call(self, method, path, body=None):
        if not path.startswith('/api/runner/'):
            raise Refusal('runner_route_refused')
        connection = http.client.HTTPConnection(self.url.hostname, self.url.port, timeout=5)
        try:
            connection.request(method, path, body=None if body is None else canonical_bytes(body),
                headers={'Host': f'localhost:{self.url.port}', 'Authorization': 'Bearer ' + self.token,
                         'Content-Type': 'application/json'})
            response = connection.getresponse()
            payload = response.read(2 * 1024 * 1024 + 1)
            if len(payload) > 2 * 1024 * 1024:
                raise Refusal('runner_response_too_large')
            result = parse_json(payload)
            if response.status != 200:
                raise Refusal(result.get('error', 'runner_http_refused'), response.status)
            return result
        finally:
            connection.close()

    def approved(self):
        return self.call('GET', '/api/runner/approved')['requests']

    def claim(self, rid, revision, claim_id):
        return self.call('POST', '/api/runner/claim', {'request_id': rid, 'revision': revision, 'claim_id': claim_id})

    def report(self, rid, revision, claim_id, event, evidence):
        return self.call('POST', '/api/runner/report', {'request_id': rid, 'revision': revision,
            'claim_id': claim_id, 'event': event, 'evidence': evidence})

    def heartbeat(self):
        return self.call('POST', '/api/runner/heartbeat', {})

    def stopping(self):
        return self.call('POST', '/api/runner/stopping', {})

    def claim_backoff(self):
        # The injected lost-response scenario remains visible to the UI's 2 s
        # polling. Direct protocol tests use an injected clock and no real wait.
        threading.Event().wait(2.1)


class DirectTransport:
    """Tests-only in-process protocol adapter; production entry point uses HTTP."""
    def __init__(self, store):
        self.store = store
        self.origin = store.profile.origin
        self.rp_id = store.profile.rp_id

    def approved(self):
        return self.store.approved()

    def claim(self, rid, revision, claim_id):
        return self.store.claim(rid, revision, claim_id)

    def report(self, rid, revision, claim_id, event, evidence):
        return self.store.runner_report(rid, revision, claim_id, event, evidence)

    def heartbeat(self):
        return self.store.heartbeat()

    def stopping(self):
        return self.store.stopping()

    def claim_backoff(self):
        return


class RunnerInstance:
    def __init__(self, root, transport, kit, clock, scenario='normal', takeover_after_crash=False):
        self.root, self.transport, self.kit, self.clock = root, transport, kit, clock
        self.scenario = scenario
        self.instance_id = secrets.token_hex(16)
        self._active = True
        self.before_kit = None
        self.last_evidence = None
        self.root.acquire_runner_lock(self.instance_id, takeover_after_crash)
        self.journal = root.read_json('runner/journal.json') if root.exists('runner/journal.json') else {}
        self._recovered = set()

    def _journal(self, rid, revision, claim_id, status, evidence=None):
        entry = self.journal.get(rid, {})
        entry.update(revision=revision, claim_id=claim_id, state=status,
                     instance_id=entry.get('instance_id', self.instance_id))
        if evidence is not None:
            entry['evidence'] = copy.deepcopy(evidence)
        self.journal[rid] = entry
        self.root.write_json('runner/journal.json', self.journal)

    def _report(self, rid, revision, claim_id, event, evidence):
        # Only reports are retried. A pending journal result survives this instance.
        for _ in range(3):
            try:
                return self.transport.report(rid, revision, claim_id, event, evidence)
            except (OSError, http.client.HTTPException):
                continue
        return None

    def _refuse(self, request, code):
        self._report(request['request_id'], request['revision'], None, 'refused_before_claim', {'code': code})

    def _claim_refusal(self, error):
        # HTTPS runner may propagate transient HTTP failures to its scheduler.
        return None

    def _has_execution_record(self, rid):
        return rid in self.journal

    def _verify(self, envelope):
        request = envelope['request']
        validate(request, self.root)
        baseline = self.root.read_json('runner/manifests/' + request['request_id'] + '/' + str(request['revision']) + '.json')
        if canonical_bytes(request) != canonical_bytes(baseline):
            raise Refusal('CONTENT_MISMATCH')
        rebuilt = local_request(self.root, baseline)
        if canonical_bytes(rebuilt) != canonical_bytes(baseline):
            raise Refusal('CONTENT_MISMATCH')
        pinned = self.root.read_json('runner/pinned-credential.json')
        credential = envelope.get('credential')
        if not credential or any(pinned.get(key) != credential.get(key) for key in ('id', 'spki')):
            raise Refusal('pinned_key_mismatch')
        # A stored approved flag never substitutes for this independent call.
        assertion = envelope.get('assertion')
        nonce = envelope.get('nonce')
        if assertion is None or not isinstance(nonce, str):
            raise Refusal('ASSERTION_REFUSED')
        verify_assertion(assertion, pinned, approval_challenge(rebuilt, nonce), self.transport.origin, self.transport.rp_id)
        if expired(rebuilt, self.clock()):
            raise Refusal('CONTENT_MISMATCH')
        return rebuilt

    def _recover(self, rid, entry):
        # ANY journal entry is a permanent execution prohibition, even intent.
        # The verified request was durably journaled before the first claim.
        # Recovery needs no new server endpoint and never substitutes a later
        # server revision for the originally checked evidence definitions.
        request = entry['request']
        evidence = self.kit.inspect(request, entry['claim_id'], entry['instance_id'])
        self.last_evidence = evidence
        if entry['state'] == 'claim_intent':
            self._journal(rid, entry['revision'], entry['claim_id'], 'gave_up', evidence)
            # No claim may have been granted. A full report is attempted, never
            # a new claim. If there was none, claim_mismatch preserves not_started.
        if no_run_evidence(evidence, request):
            self._journal(rid, entry['revision'], entry['claim_id'], 'gave_up', evidence)
            event = 'not_run'
        else:
            event = 'result'
        try:
            self._report(rid, entry['revision'], entry['claim_id'], event, evidence)
        except Refusal as error:
            if error.code != 'claim_mismatch' and not error.code.startswith('claim_closed:'):
                raise
        self._recovered.add(rid)

    def step(self):
        if not self._active:
            return
        self.transport.heartbeat()
        for rid, entry in list(self.journal.items()):
            if rid not in self._recovered:
                self._recover(rid, copy.deepcopy(entry))
        for envelope in self.transport.approved():
            request = envelope['request']
            rid, revision = request['request_id'], request['revision']
            if self._has_execution_record(rid):
                continue
            try:
                request = self._verify(envelope)
            except (Refusal, FileNotFoundError) as error:
                code = error.code if isinstance(error, Refusal) else 'CONTENT_MISMATCH'
                if code not in ('CONTENT_MISMATCH', 'pinned_key_mismatch'):
                    code = 'ASSERTION_REFUSED' if code in ('uv_missing', 'origin_mismatch', 'challenge_mismatch', 'ASSERTION_REFUSED',
                        'signature_invalid', 'up_missing', 'rp_id_mismatch', 'unknown_credential', 'assertion_malformed',
                        'cross_origin_refused', 'type_mismatch', 'backup_flags_invalid', 'client_data_malformed') else 'CONTENT_MISMATCH'
                self._refuse(request, code)
                continue
            if self.clock() < utc(request['window_utc'][0]):
                continue
            claim_id = secrets.token_hex(16)
            self.journal[rid] = {'request': copy.deepcopy(request)}
            self._journal(rid, revision, claim_id, 'claim_intent')
            if self.scenario == 'crash_at_claim_intent':
                self.crash()
                return
            granted = False
            for _ in range(3):
                try:
                    answer = self.transport.claim(rid, revision, claim_id)
                    if self.scenario == 'claim_response_lost':
                        self.transport.claim_backoff()
                        raise ConnectionError('injected_claim_response_lost')
                    granted = answer.get('granted') is True and answer.get('claim_id') == claim_id
                    if granted:
                        break
                except (OSError, http.client.HTTPException):
                    continue
                except Refusal as error:
                    self._claim_refusal(error)
                    break
            if not granted:
                evidence = self.kit.inspect(request, claim_id, self.instance_id)
                self.last_evidence = evidence
                self._journal(rid, revision, claim_id, 'gave_up', evidence)
                if no_run_evidence(evidence, request):
                    try:
                        self._report(rid, revision, claim_id, 'not_run', evidence)
                    except Refusal as error:
                        if error.code != 'claim_mismatch' and not error.code.startswith('claim_closed:'):
                            raise
                continue
            self._journal(rid, revision, claim_id, 'claimed')
            try:
                self._report(rid, revision, claim_id, 'start', {})
            except Refusal as error:
                self._claim_refusal(error)
                # Server has closed or invalidated the claim. Never run late.
                evidence = self.kit.inspect(request, claim_id, self.instance_id)
                self._journal(rid, revision, claim_id, 'gave_up', evidence)
                continue
            self._journal(rid, revision, claim_id, 'running')
            if self.scenario == 'crash_after_start':
                self.crash()
                return
            if self.before_kit:
                self.before_kit()
            evidence = self.kit.run(request, self.root.pointer(), claim_id, self.instance_id, self.scenario)
            self.last_evidence = evidence
            self._journal(rid, revision, claim_id, 'result', evidence)
            self._report(rid, revision, claim_id, 'result', evidence)
            self._recovered.add(rid)

    def crash(self):
        if self._active:
            self.root.mark_runner_crash(self.instance_id)
            self._active = False

    def close(self):
        if self._active:
            self.transport.stopping()
            self.root.release_runner_lock(self.instance_id)
            self._active = False
