"""W3 HTTPS Mac runner, exclusively for marked test roots and the mock kit.

The approval verification/claim/execution algorithm is inherited from the reviewed
runner. Intent records are immutable, durable, O_EXCL, and prohibit execution even
if the mutable report journal is missing. Restart recovery can only inspect/report.
An operational kit adapter and account/token provisioning are outside W3.
"""
import copy
import http.client
import re
import secrets

from ..mapl_test.errors import Refusal
from ..mapl_test.isolation import TestRoot
from ..mapl_test.mock_kit import MockKit
from ..mapl_test.runner_sim import RunnerInstance
from ..mapl_test.state import no_run_evidence, utc
from .transport import PollSchedule


class MacRunner(RunnerInstance):
    def __init__(self, root, transport, kit, clock, scenario='normal', takeover_after_crash=False):
        if not isinstance(root, TestRoot) or type(kit) is not MockKit:
            raise Refusal('test_adapter_required')
        self.root, self.transport, self.kit, self.clock = root, transport, kit, clock
        self.scenario, self.instance_id = scenario, secrets.token_hex(16)
        self._active, self.before_kit, self.last_evidence = True, None, None
        root.acquire_process_runner_lock(self.instance_id, takeover_after_crash)
        try:
            self.journal = root.read_json('runner/journal.json') if root.exists('runner/journal.json') else {}
            if not isinstance(self.journal, dict):
                raise Refusal('runner_journal_invalid')
        except BaseException:
            root.release_process_runner_lock(self.instance_id)
            raise
        self._recovered, self._refusals = set(), {}
        self.schedule = PollSchedule()
        self.connection_state = '연결 기록 없음'

    def _record_path(self, rid):
        if not isinstance(rid, str) or not re.fullmatch('[0-9a-f]{32}', rid):
            raise Refusal('request_invalid')
        return 'runner/records/' + rid + '.json'

    def _has_execution_record(self, rid):
        return rid in self.journal or self.root.exists(self._record_path(rid))

    def _journal(self, rid, revision, claim_id, status, evidence=None):
        if status == 'claim_intent':
            self.root.write_json(self._record_path(rid), {'request': copy.deepcopy(self.journal[rid]['request']),
                'revision': revision, 'claim_id': claim_id, 'state': status, 'instance_id': self.instance_id}, exclusive=True)
        super()._journal(rid, revision, claim_id, status, evidence)

    def _report(self, rid, revision, claim_id, event, evidence):
        # Transport rate/5xx refusals escape to the outer polling schedule;
        # network failures get at most the existing three REPORT-only retries.
        answer = super()._report(rid, revision, claim_id, event, evidence)
        if answer is None:
            raise ConnectionError('report_delivery_unconfirmed')
        return answer

    def _claim_refusal(self, error):
        if error.status >= 400:
            raise error

    def _refuse(self, request, code):
        key = (request['request_id'], code)
        now = self.clock().isoformat()
        previous = self._refusals.get(key)
        count = previous['count'] + 1 if previous else 1
        self._refusals[key] = {'count': count, 'last_at': now}
        # Aggregate counters let the server update ONE history row (W2). Send
        # no claim and create no execution record, so a later match may proceed.
        return self._report(request['request_id'], request['revision'], None, 'refused_before_claim',
                            {'code': code, 'count': count, 'last_at': now})

    def _recover(self, rid, entry):
        # Takeover leaves records intact; recovery updates only the mutable journal.
        request = entry['request']
        if self._restart_v2(rid, entry):
            return
        evidence = self.kit.inspect(request, entry['claim_id'], entry['instance_id'])
        self.last_evidence = evidence
        if entry['state'] == 'claim_intent' or no_run_evidence(evidence, request):
            # H2: durable gave_up must precede any not_run report.
            self._journal(rid, entry['revision'], entry['claim_id'], 'gave_up', evidence)
        event = 'not_run' if no_run_evidence(evidence, request) else 'result'
        try:
            self._report(rid, entry['revision'], entry['claim_id'], event, evidence)
        except Refusal as error:
            if error.code != 'claim_mismatch' and not error.code.startswith('claim_closed:'):
                raise
        self._recovered.add(rid)

    def step(self):
        if not self._active:
            return None
        try:
            poll = self.transport.poll()
            # Only require the routing fields needed by _record_path/_refuse.
            # Semantic failures belong to _verify's per-request C6 report path.
            for envelope in poll['requests']:
                request = envelope['request']
                if (not isinstance(request, dict) or not isinstance(request.get('request_id'), str)
                        or not re.fullmatch('[0-9a-f]{32}', request['request_id'])
                        or type(request.get('revision')) is not int or request['revision'] < 1):
                    raise Refusal('runner_response_malformed', 502)
            if abs((utc(poll['server_now']) - self.clock()).total_seconds()) > 60:
                for envelope in poll['requests']:
                    self._refuse(envelope['request'], 'CLOCK_SKEW')
            else:
                super().step()
            self.connection_state = '연결됨'
            return self.schedule.success(poll['has_pending'])
        except Refusal as error:
            if error.status >= 400:
                self.connection_state = '연결 문제'
                return self.schedule.failure(error)
            raise
        except (OSError, http.client.HTTPException) as error:
            self.connection_state = '연결 문제'
            return self.schedule.failure(error)

    def run(self, stop):
        """Foreground loop; clean exit releases ownership, SIGKILL leaves the lock."""
        try:
            while self._active and not stop.is_set():
                delay = self.step()
                if delay is None or stop.wait(delay):
                    break
        finally:
            self.close()

    def crash(self):
        # Tests terminate the process. Leave the durable lock for explicit takeover.
        self._active = False

    def close(self):
        if self._active:
            try:
                self.transport.stopping()
            finally:
                self.root.release_process_runner_lock(self.instance_id)
                self._active = False
