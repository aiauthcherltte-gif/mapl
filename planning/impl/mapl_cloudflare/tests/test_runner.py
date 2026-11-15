import copy
import json
import ssl
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ...mapl_test.canonical import b64decode
from ...mapl_test.errors import Refusal
from ...mapl_test.isolation import TestRoot
from ..runner import MacRunner
from ..generate_reference import DESTINATION
from ..transport import HTTPSTransport, PollSchedule
from .tls_stub import TLSStub

WORKSPACE = str(Path(__file__).resolve().parents[4])
PROBE = [sys.executable, '-I', '-B', '-c',
         'import sys; sys.path.insert(0,sys.argv[1]); from planning.impl.mapl_cloudflare.tests.process_probe import main; sys.exit(main())', WORKSPACE]


class ScheduleTests(unittest.TestCase):
    def test_busy_idle_reset_and_backoff(self):
        schedule = PollSchedule(uniform=lambda low, high: (low+high)/2)
        self.assertEqual(schedule.success(True), 20)
        self.assertEqual(schedule.success(False), 120)
        self.assertEqual([schedule.failure(ConnectionError()) for _ in range(7)], [20,40,80,160,300,300,300])
        self.assertEqual(schedule.success(True), 20)
        self.assertEqual(schedule.failure(Refusal('5xx', 503)), 20)
        self.assertEqual(schedule.failure(Refusal('limit', 429)), 300)

    def test_jitter_bounds_and_hard_cap(self):
        for fraction in (0, .5, 1):
            schedule = PollSchedule(uniform=lambda low, high: low + fraction*(high-low))
            for base in (20,40,80,160,300,300):
                self.assertGreaterEqual(value := schedule.failure(OSError()), base*.8)
                self.assertLessEqual(value, min(300,base*1.2))


class TLSTests(unittest.TestCase):
    def setUp(self):
        self.stub = TLSStub()
        self.addCleanup(self.stub.close)

    def test_fixed_origin_and_route_refusals(self):
        t = self.stub.transport()
        for origin in ('http://example.invalid', 'https://other.invalid/path', 'https://a.invalid/',
                       'https://user@a.invalid', 'https://a.invalid?x=1', 'https://a.invalid#x',
                       'https://a.invalid:bad', 'https://a.invalid.', 'HTTPS://a.invalid'):
            with self.subTest(origin=origin), self.assertRaises(Refusal):
                HTTPSTransport(origin, 'fixture')
        for path in ('https://other.invalid/api/runner/approved', '//other.invalid/api/runner/approved',
                     '/api/runner/../other', '/api/runner/approved?host=other', '/api/runner/approved#fragment'):
            with self.subTest(path=path), self.assertRaises(Refusal):
                t.call('GET', path)
        self.assertEqual(self.stub.calls, [])
        with self.assertRaises(Refusal):
            HTTPSTransport('https://other.invalid', 'fixture', test_ca_pem=self.stub.ca)

    def test_tls_verification_default_and_explicit_local_ca(self):
        t = HTTPSTransport(self.stub.origin, self.stub.world.store.runner_token)
        self.assertEqual(t.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(t.context.check_hostname)
        with self.assertRaises(ssl.SSLCertVerificationError):
            t.poll()
        t = self.stub.transport()
        self.assertEqual(t.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(t.context.check_hostname)
        self.assertIn('server_now', t.poll())

    def test_redirect_refused_without_following(self):
        for code in (301,302,303,307,308):
            self.stub.responses.append((code, {'Location': 'https://forbidden.invalid/'}, b'not JSON'))
            with self.assertRaises(Refusal) as caught:
                self.stub.transport().poll()
            self.assertEqual(caught.exception.code, 'runner_redirect_refused')
        self.assertEqual(len(self.stub.calls), 5)

    def test_cloudflare_1027_and_429_html(self):
        t = self.stub.transport()
        for status, payload in ((429,b'too many requests'), (503,b'<html>Error 1027: free limit</html>')):
            self.stub.responses.append((status, {}, payload))
            with self.assertRaises(Refusal) as caught:
                t.poll()
            self.assertEqual((caught.exception.code,caught.exception.status), ('runner_rate_limited',429))

    def test_auth_and_malformed_envelope(self):
        t = self.stub.transport()
        t.token = 'wrong-fixture-token'
        # Use a real route for the existing server's authenticated rejection.
        with self.assertRaises(Refusal) as caught:
            t.stopping()
        self.assertEqual(caught.exception.code, 'token_scope_refused')
        for payload in (b'[]', b'{}', b'{"requests":[],"has_pending":1,"server_now":"x"}'):
            self.stub.responses.append((200,{},payload))
            with self.assertRaises(Refusal):
                self.stub.transport().poll()

    def test_fixed_refusal_codes_pass_through_real_application(self):
        w = self.stub.world
        for case in json.loads((DESTINATION / 'refusal-fixed.json').read_bytes()):
            with self.subTest(case=case['id']):
                before = copy.deepcopy(w.record()['history'])
                with patch.object(self.stub.app, 'handle', wraps=self.stub.app.handle) as app_call, \
                     patch.object(w.store, 'runner_report', wraps=w.store.runner_report) as rule:
                    if case['expected']['accepted']:
                        self.stub.transport().report(w.rid, 1, None, case['event'], {'code': case['code']})
                        self.assertEqual(w.record()['history'][-1]['code'], case['code'])
                    else:
                        with self.assertRaises(Refusal) as caught:
                            self.stub.transport().report(w.rid, 1, None, case['event'], {'code': case['code']})
                        self.assertEqual((caught.exception.code, caught.exception.status),
                                         (case['expected']['reason'], case['expected']['status']))
                        self.assertEqual(w.record()['history'], before)
                    app_call.assert_called_once()
                    rule.assert_called_once_with(w.rid, 1, None, case['event'], {'code': case['code']})
        for unknown in ('', 'CLOCK_SKEW_EXTRA', None, ['CLOCK_SKEW']):
            with self.assertRaises(Refusal) as caught:
                self.stub.transport().report(w.rid, 1, None, 'refused_before_claim', {'code': unknown})
            self.assertEqual((caught.exception.code, caught.exception.status), ('refusal_code_invalid', 400))


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.stub = TLSStub()
        self.w = self.stub.world
        self.addCleanup(self.stub.close)
        self.runners = []
        self.addCleanup(self.close_runners)

    def close_runners(self):
        for runner in self.runners:
            runner.close()

    def runner(self):
        runner = MacRunner(self.w.root, self.stub.transport(), self.w.kit, self.w.clock)
        self.runners.append(runner)
        return runner

    def test_https_verified_mock_execution_once_and_immutable_record(self):
        self.stub.approve()
        runner = self.runner()
        self.assertEqual(runner.step(), 20)
        record = self.w.root.read_bytes('runner/records/'+self.w.rid+'.json')
        self.assertEqual(runner.step(), 120)
        self.assertEqual(self.w.kit.calls[self.w.rid], 1)
        self.assertEqual(self.w.record()['execution'], 'done')
        self.assertEqual(record, self.w.root.read_bytes('runner/records/'+self.w.rid+'.json'))
        self.assertFalse(any('heartbeat' in path for _,path in self.stub.calls))

    def test_poll_pending_idle_and_liveness_throttled_in_stub(self):
        runner = self.runner()
        for _ in range(4):
            self.assertEqual(runner.step(), 20)
            self.w.clock.advance(20)
        self.assertEqual(self.stub.contact_writes, 1)
        self.w.clock.advance(300)
        runner.step()
        self.assertEqual(self.stub.contact_writes, 2)
        self.w.store.decline(self.w.rid)
        self.assertEqual(runner.step(), 120)

    def test_clock_skew_refuses_claim_and_sixty_seconds_allowed(self):
        self.stub.approve()
        runner = self.runner()
        for offset in (61,-61):
            self.stub.server_offset = offset
            runner.step()
        self.assertEqual(self.stub.claim_calls, 0)
        self.assertEqual(self.w.kit.calls, {})
        self.assertTrue(runner._active)
        self.assertTrue(self.w.root.exists('runner/process-lock'))
        self.assertFalse(self.w.root.exists('runner/records/'+self.w.rid+'.json'))
        row = self.stub.aggregates[(self.w.rid,'CLOCK_SKEW')]
        self.assertEqual(row['count'], 2)
        self.stub.server_offset = 60
        runner.step()
        self.assertEqual(self.w.kit.calls[self.w.rid], 1)

    def test_future_window_no_claim(self):
        later = TLSStub('window_later')
        self.addCleanup(later.close)
        later.approve()
        runner = MacRunner(later.world.root,later.transport(),later.world.kit,later.world.clock)
        try:
            runner.step()
            self.assertEqual(later.claim_calls, 0)
            later.world.clock.advance(600)
            runner.step()
            self.assertEqual(later.world.kit.calls[later.world.rid], 1)
        finally:
            runner.close()

    def test_poll_errors_backoff_then_success_reset(self):
        runner = self.runner()
        runner.schedule = PollSchedule(uniform=lambda lo,hi: (lo+hi)/2)
        for status,payload,expected in ((500,b'broken',20),(503,b'broken',40),
                                       (503,b'Error 1027',300),(429,b'limit',300)):
            self.stub.responses.append((status,{},payload))
            self.assertEqual(runner.step(), expected)
        self.assertEqual(runner.step(), 20)
        with patch.object(runner.transport, 'poll', side_effect=OSError('local fault')):
            self.assertEqual(runner.step(), 20)
        self.assertEqual(self.stub.claim_calls, 0)

    def test_refusals_fold_into_one_row_then_later_matching_state_runs(self):
        self.stub.approve()
        original = self.w.root.read_bytes(self.w.root.pointer())
        self.w.root.write_atomic(self.w.root.pointer(), b'{"fixture":"mismatch"}')
        runner = self.runner()
        for _ in range(3):
            runner.step()
            self.w.clock.advance(20)
        rows = [row for row in self.w.record()['history'] if row['event']=='refused_before_claim']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['count'], 3)
        self.assertNotEqual(rows[0]['at'], rows[0]['last_at'])
        self.assertEqual(self.stub.claim_calls, 0)
        self.w.root.write_atomic(self.w.root.pointer(), original)
        runner.step()
        self.assertEqual(self.w.kit.calls[self.w.rid], 1)

    def test_report_failure_recovery_does_not_execute_again(self):
        self.stub.approve()
        runner = self.runner()
        # Reject the final result only, after the mock kit has run.
        runner.before_kit = lambda: setattr(self.stub, 'report_failures', 1)
        self.assertGreaterEqual(runner.step(), 16)
        self.assertEqual(self.w.kit.calls[self.w.rid], 1)
        runner.step()
        self.assertEqual(self.w.kit.calls[self.w.rid], 1)
        self.assertEqual(self.w.record()['execution'], 'done')

    def test_report_network_loss_remains_retryable_without_execution(self):
        self.stub.approve()
        runner = self.runner()
        real_report = runner.transport.report
        lost = []

        def report(*args):
            if args[3] == 'result' and len(lost) < 3:
                lost.append(True)
                raise ConnectionError('injected_local_report_loss')
            return real_report(*args)

        with patch.object(runner.transport, 'report', side_effect=report):
            self.assertGreaterEqual(runner.step(), 16)
        self.assertEqual(len(lost), 3)
        self.assertEqual(self.w.kit.calls[self.w.rid], 1)
        runner.step()
        self.assertEqual(self.w.kit.calls[self.w.rid], 1)
        self.assertEqual(self.w.record()['execution'], 'done')

    def test_rate_limit_on_claim_backs_off_and_never_reclaims(self):
        self.stub.approve()
        runner = self.runner()
        real_claim = runner.transport.claim
        with patch.object(runner.transport, 'claim', side_effect=Refusal('runner_rate_limited',429)) as claim:
            self.assertEqual(runner.step(), 300)
            self.assertEqual(claim.call_count, 1)
        runner.step()
        self.assertEqual(self.stub.claim_calls, 0)
        self.assertEqual(self.w.kit.calls, {})

    def test_foreground_loop_uses_returned_intervals(self):
        runner = self.runner()
        stop = Mock()
        stop.is_set.return_value = False
        stop.wait.side_effect = [False, False, True]
        with patch.object(runner, 'step', side_effect=[20,120,300]):
            runner.run(stop)
        self.assertEqual([call.args[0] for call in stop.wait.call_args_list], [20,120,300])
        self.assertFalse(self.w.root.exists('runner/process-lock'))

    def test_record_check_alone_skips_before_verify_without_backoff(self):
        self.stub.approve()
        path = 'runner/records/'+self.w.rid+'.json'
        self.w.root.write_json(path, {'sentinel': 'immutable'}, exclusive=True)
        record = self.w.root.read_bytes(path)
        runner = self.runner()
        runner.schedule = PollSchedule(uniform=lambda lo, hi: (lo+hi)/2)
        self.assertEqual(runner.journal, {})
        with patch.object(runner, '_verify', wraps=runner._verify) as verify:
            self.assertEqual(runner.step(), 20)
            verify.assert_not_called()
        self.assertEqual(runner.schedule.failures, 0)
        self.assertEqual(self.stub.claim_calls, 0)
        self.assertEqual(self.w.kit.calls, {})
        self.assertEqual(self.w.root.read_bytes(path), record)

    def test_exclusive_record_write_alone_refuses_second_intent(self):
        runner = self.runner()
        rid = self.w.rid
        runner.journal[rid] = {'request': self.w.record()['request']}
        runner._journal(rid, 1, '1'*32, 'claim_intent')
        path = 'runner/records/'+rid+'.json'
        record = self.w.root.read_bytes(path)
        # Direct writer call bypasses the record check, isolating O_EXCL.
        with self.assertRaises(FileExistsError):
            runner._journal(rid, 2, '2'*32, 'claim_intent')
        self.assertEqual(self.w.root.read_bytes(path), record)
        self.assertEqual(self.stub.claim_calls, 0)
        self.assertEqual(self.w.kit.calls, {})

    def test_4xx_poll_backoff_loop_continues_and_lock_releases(self):
        self.stub.approve()
        runner = self.runner()
        runner.schedule = PollSchedule(uniform=lambda lo, hi: (lo+hi)/2)
        for status in (400, 403, 404, 409, 422):
            self.stub.responses.append((status, {}, b'<html>refused</html>'))
        stop = Mock()
        stop.is_set.return_value = False
        observations = []

        def wait(delay):
            observations.append((delay, runner.connection_state))
            self.assertEqual(self.stub.claim_calls, 0)
            self.assertEqual(self.w.kit.calls, {})
            self.assertTrue(self.w.root.exists('runner/process-lock'))
            return len(observations) == 5

        stop.wait.side_effect = wait
        runner.run(stop)
        self.assertEqual(observations, [(delay, '연결 문제') for delay in (20, 40, 80, 160, 300)])
        self.assertFalse(self.w.root.exists('runner/process-lock'))

    def test_4xx_claim_and_refusal_report_backoff_without_execution(self):
        self.stub.approve()
        runner = self.runner()
        runner.schedule = PollSchedule(uniform=lambda lo, hi: (lo+hi)/2)
        self.stub.server_offset = 61
        with patch.object(runner.transport, 'report', side_effect=Refusal('forbidden', 403)):
            self.assertEqual(runner.step(), 20)
        self.assertEqual(runner.connection_state, '연결 문제')
        self.stub.server_offset = 0
        with patch.object(runner.transport, 'claim', side_effect=Refusal('not_found', 404)) as claim:
            self.assertEqual(runner.step(), 40)
            claim.assert_called_once()
        self.assertEqual(self.w.kit.calls, {})
        self.assertEqual(self.stub.claim_calls, 0)
        self.assertEqual(runner.step(), 20)
        self.assertEqual(runner.connection_state, '연결됨')
        self.assertEqual(self.w.kit.calls, {})

    def test_malformed_envelopes_backoff_before_any_execution_then_reset(self):
        self.stub.approve()
        runner = self.runner()
        runner.schedule = PollSchedule(uniform=lambda lo, hi: (lo+hi)/2)
        valid = self.w.store.approved()[0]
        malformed = [{}, None, {'request': None}, {**valid, 'request': {}},
                     {**valid, 'credential': []}, {**valid, 'assertion': []}]
        for field, values in (('request_id', (None, 1, 'bad', 'A' * 32)),
                              ('revision', (None, True, '1', 0, -1))):
            for value in values:
                malformed.append({**valid, 'request': {**valid['request'], field: value}})
        malformed.append({**valid, 'request': {'request_id': self.w.rid}})
        for bad in malformed:
            # A valid first row must not run if a later row is malformed.
            payload = json.dumps({'requests': [valid, bad], 'has_pending': True,
                                  'server_now': self.w.clock().isoformat().replace('+00:00', 'Z')}).encode()
            self.stub.responses.append((200, {}, payload))
            self.assertGreaterEqual(runner.step(), 20)
            self.assertEqual(runner.connection_state, '연결 문제')
            self.assertEqual(self.stub.claim_calls, 0)
            self.assertEqual(self.w.kit.calls, {})
        self.assertEqual(runner.step(), 20)
        self.assertEqual(runner.connection_state, '연결됨')
        self.assertEqual(self.w.kit.calls[self.w.rid], 1)

    def approve_sibling(self, rid):
        request = copy.deepcopy(self.w.request)
        request['request_id'] = rid
        self.w.store.create_request(request)
        options = self.w.options(rid)
        assertion = self.w.auth.assertion(b64decode(options['challenge']), origin=self.stub.origin)
        self.w.store.approve(rid, assertion)
        return next(row for row in self.w.store.approved() if row['request']['request_id'] == rid)

    def poll_payload(self, envelopes):
        return json.dumps({'requests': envelopes, 'has_pending': True,
                           'server_now': self.w.clock().isoformat().replace('+00:00', 'Z')}).encode()

    def test_semantic_refusals_report_content_mismatch_without_blocking_valid_sibling(self):
        self.stub.approve()
        valid = self.w.store.approved()[0]
        bad = [self.approve_sibling(char * 32) for char in '123']
        bad[0]['request']['recovery']['included_in_this_approval'] = True
        bad[1]['request']['target']['test_root_id'] = '0' * 32
        bad[2]['request']['extra_field'] = 'unapproved'
        runner = self.runner()
        # Refused requests precede the valid one; keep the same tampered batch
        # on the second poll to check refusal folding and one execution only.
        payload = self.poll_payload(bad + [valid])
        with patch.object(runner.transport, 'claim', wraps=runner.transport.claim) as claim:
            for count in (1, 2):
                self.stub.responses.append((200, {}, payload))
                delay = runner.step()
                for envelope in bad:
                    rid = envelope['request']['request_id']
                    rows = [row for row in self.w.store.get(rid)['history']
                            if row['event'] == 'refused_before_claim']
                    self.assertEqual([(row['code'], row['count']) for row in rows],
                                     [('CONTENT_MISMATCH', count)])
                    self.assertFalse(self.w.root.exists('runner/records/' + rid + '.json'))
                self.assertEqual(delay, 20)
                self.assertEqual(self.w.kit.calls, {self.w.rid: 1})
                self.assertEqual(self.w.record()['execution'], 'done')
                self.assertEqual(runner.connection_state, '연결됨')
                self.assertEqual(runner.schedule.failures, 0)
            claim.assert_called_once()
            self.assertEqual(claim.call_args.args[:2], (self.w.rid, 1))
        self.assertEqual(self.stub.claim_calls, 1)

    def assert_semantic_refusal_preserves_recovery(self, event):
        self.stub.approve()
        runner = self.runner()
        runner.schedule = PollSchedule(uniform=lambda lo, hi: (lo+hi)/2)
        real_report = runner.transport.report

        def fail_report(*args):
            if args[3] == ('start' if event == 'not_run' else 'result'):
                raise Refusal('injected_report_failure', 503)
            return real_report(*args)

        with patch.object(runner.transport, 'report', side_effect=fail_report):
            self.assertEqual(runner.step(), 20)
        self.assertEqual(runner.schedule.failures, 1)
        self.assertEqual(runner.journal[self.w.rid]['state'], 'claimed' if event == 'not_run' else 'result')
        record = self.w.root.read_bytes('runner/records/' + self.w.rid + '.json')
        kit_calls = dict(self.w.kit.calls)
        bad = self.approve_sibling('4' * 32)
        bad['request']['extra_field'] = 'unapproved'
        self.stub.responses.append((200, {}, self.poll_payload([bad])))
        with patch.object(runner.transport, 'report', wraps=real_report) as report:
            delay = runner.step()
        self.assertEqual([(call.args[0], call.args[3]) for call in report.call_args_list],
                         [(self.w.rid, event), ('4' * 32, 'refused_before_claim')])
        self.assertEqual(delay, 20)
        self.assertEqual(report.call_args.args[4]['code'], 'CONTENT_MISMATCH')
        self.assertEqual(self.w.record()['execution'], 'not_run' if event == 'not_run' else 'done')
        self.assertEqual(self.w.root.read_bytes('runner/records/' + self.w.rid + '.json'), record)
        self.assertEqual(self.w.kit.calls, kit_calls)
        self.assertEqual(self.stub.claim_calls, 1)
        self.assertIn(self.w.rid, runner._recovered)
        self.assertFalse(self.w.root.exists('runner/records/' + '4' * 32 + '.json'))
        self.assertEqual(runner.connection_state, '연결됨')
        self.assertEqual(runner.schedule.failures, 0)

    def test_semantic_refusal_does_not_block_not_run_recovery_in_same_step(self):
        self.assert_semantic_refusal_preserves_recovery('not_run')

    def test_semantic_refusal_does_not_block_result_recovery_in_same_step(self):
        self.assert_semantic_refusal_preserves_recovery('result')

    def test_clean_exception_exit_releases_lock(self):
        runner = self.runner()
        stop = Mock()
        stop.is_set.return_value = False
        with patch.object(runner, 'step', side_effect=RuntimeError('injected clean exit')):
            with self.assertRaisesRegex(RuntimeError, 'injected clean exit'):
                runner.run(stop)
        self.assertFalse(self.w.root.exists('runner/process-lock'))
        replacement = self.runner()  # No takeover option is needed after clean exit.
        self.assertTrue(replacement._active)


class ProcessRestartTests(unittest.TestCase):
    def setUp(self):
        self.stub = TLSStub()
        self.w = self.stub.world
        self.stub.approve()
        self.addCleanup(self.stub.close)

    def data(self, **changes):
        return {'root': self.w.root.path, 'marker': self.w.root.root_id, 'now': self.w.clock().isoformat(),
            'origin': self.stub.origin, 'test_token': self.w.store.runner_token, 'ca': self.stub.ca,
            'rid': self.w.rid, **changes}

    def probe(self, **changes):
        result = subprocess.run(PROBE,input=json.dumps(self.data(**changes))+'\n',text=True,
                                capture_output=True,timeout=15,cwd=WORKSPACE)
        self.assertIn(result.returncode,(0,2),result.stderr)
        return result.returncode,json.loads(result.stdout)

    def test_record_crash_explicit_takeover_zero_reexecutions(self):
        rc,first = self.probe(scenario='crash_at_claim_intent')
        self.assertEqual(rc,0)
        self.assertEqual(first['calls'],0)
        self.assertEqual(self.probe(), (2,{'refusal':'runner_locked'}))
        rc,second = self.probe(takeover=True)
        self.assertEqual((rc,second['calls']),(0,0))
        self.assertEqual(first['record_sha256'],second['record_sha256'])
        self.assertNotEqual(first['journal_sha256'],second['journal_sha256'])
        self.assertEqual(self.w.root.read_json('runner/journal.json')[self.w.rid]['state'], 'gave_up')
        self.assertEqual(self.stub.claim_calls,0)

    def test_crash_after_start_takeover_reports_only(self):
        _,first = self.probe(scenario='crash_after_start')
        self.assertEqual(self.w.record()['execution'],'running')
        _,second = self.probe(takeover=True)
        self.assertEqual(second['calls'],0)
        self.assertEqual(self.w.record()['execution'],'not_run')
        self.assertEqual(first['record_sha256'],second['record_sha256'])
        self.assertNotEqual(first['journal_sha256'],second['journal_sha256'])
        self.assertEqual(self.w.root.read_json('runner/journal.json')[self.w.rid]['state'], 'gave_up')

    def test_killed_process_takeover_preserves_record_and_never_executes(self):
        child = subprocess.Popen(PROBE,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                 text=True,cwd=WORKSPACE)
        try:
            child.stdin.write(json.dumps(self.data(scenario='crash_at_claim_intent',hold_after_step=True))+'\n')
            child.stdin.flush()
            first = json.loads(child.stdout.readline())
            child.kill()  # Only this test's own child, after durable intent fsync.
            child.communicate(timeout=5)
            self.assertEqual(child.returncode,-9)
            self.assertEqual(self.probe(),(2,{'refusal':'runner_locked'}))
            rc,second = self.probe(takeover=True)
            self.assertEqual((rc,second['calls']),(0,0))
            self.assertEqual(first['record_sha256'],second['record_sha256'])
            self.assertNotEqual(first['journal_sha256'],second['journal_sha256'])
            self.assertEqual(self.w.root.read_json('runner/journal.json')[self.w.rid]['state'], 'gave_up')
            self.assertEqual(self.stub.claim_calls,0)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)

    def test_successful_process_restart_zero_reexecutions(self):
        _,first = self.probe()
        self.assertEqual(first['calls'],1)
        _,second = self.probe()
        self.assertEqual(second['calls'],0)
        self.assertEqual(first['record_sha256'],second['record_sha256'])
        self.assertEqual(self.stub.claim_calls,1)

    def test_recovery_persists_gave_up_before_not_run_report(self):
        _, first = self.probe(scenario='crash_after_start')
        self.assertEqual(self.w.root.read_json('runner/journal.json')[self.w.rid]['state'], 'running')
        runner = MacRunner(self.w.root, self.stub.transport(), self.w.kit, self.w.clock, takeover_after_crash=True)
        real_report = runner.transport.report
        observed = []

        def report(*args):
            if args[3] == 'not_run':
                observed.append(True)
                journal = self.w.root.read_json('runner/journal.json')[self.w.rid]
                self.assertEqual(journal['state'], 'gave_up')
                self.assertEqual(journal, runner.journal[self.w.rid])
                self.assertEqual(self.w.record()['execution'], 'running')
            return real_report(*args)

        try:
            with patch.object(runner.transport, 'report', side_effect=report):
                runner.step()
            self.assertEqual(observed, [True])
            self.assertEqual(self.w.record()['execution'], 'not_run')
            from ...mapl_test.canonical import digest
            self.assertEqual(digest(self.w.root.read_bytes('runner/records/'+self.w.rid+'.json')), first['record_sha256'])
            self.assertEqual(self.w.kit.calls, {})
        finally:
            runner.close()

    def test_record_without_journal_still_prohibits_execution(self):
        _,first = self.probe(scenario='crash_at_claim_intent')
        self.w.root.remove('runner/journal.json')
        _,second = self.probe(takeover=True)
        self.assertEqual(second['calls'],0)
        self.assertEqual(first['record_sha256'],second['record_sha256'])
        self.assertEqual(self.stub.claim_calls,0)

    def test_live_owner_cannot_be_taken_over(self):
        child = subprocess.Popen(PROBE,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                 text=True,cwd=WORKSPACE)
        try:
            child.stdin.write(json.dumps(self.data(hold=True))+'\n')
            child.stdin.flush()
            self.assertEqual(child.stdout.readline().strip(),'LOCKED')
            self.assertEqual(self.probe(takeover=True),(2,{'refusal':'runner_locked'}))
            child.stdin.write('release\n')
            child.stdin.flush()
            child.communicate(timeout=15)
            self.assertEqual(child.returncode,0)
        finally:
            if child.poll() is None:
                child.terminate()
                child.communicate(timeout=5)

    def test_reopen_refuses_unmarked_or_non_test_root(self):
        for path,marker in (('/private/tmp/not-mapl','0'*32), (self.w.root.path,'0'*32)):
            with self.assertRaises(Refusal):
                TestRoot.reopen_for_runner_test(path,marker)
