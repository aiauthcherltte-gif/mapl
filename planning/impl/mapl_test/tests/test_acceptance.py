"""65 binding acceptance cases (3 browser cases live in e2e.mjs), plus 2 approved boundaries.

Fixed before implementation: SPEC 47460a02, PLAN 77a49a3c, REVIEW d8455c38 §A.
Coordinator msg_cb8b39c9e6f2 permits ONLY pointer()'s fixed uppercase name and
isolation's tests-only, confined source audit; runtime package reads stay four files.
No test has been run when this suite is committed.
"""
import ast
import copy
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch

from .. import config, isolation, report, state, ui
from ..canonical import b64decode, b64encode, canonical_bytes, digest
from ..cbor_min import decode
from ..errors import Refusal
from ..runner_sim import validate_base_url
from ..server import Application, ROUTES
from ..webauthn_verify import verify_assertion
from .support import Acceptance, World


class States(Acceptance):
    def test_ST_1(self):
        record = self.w.record()
        self.assertEqual(record['display_state'], '승인 대기')
        self.assertIsInstance(record['display_state'], str)
        self.assertEqual(record['approval'], 'pending')

    def test_ST_2(self):
        self.w.approve()
        record = self.w.record()
        self.assertEqual(record['execution'], 'not_started')
        self.assertEqual(record['display_state'], '아직 실행 안 함 · Mac이 이 요청을 맡지 않았습니다')
        self.assertNotIn('시작했을 수도', record['display_state'])

    def test_ST_3(self):
        self.w.approve()
        self.w.claim()
        self.assertEqual(self.w.record()['execution'], 'claimed')
        self.assertIn('실행 여부 확인 안 됨', self.w.record()['display_state'])
        self.assertNotIn('대기', self.w.record()['display_state'])

    def test_ST_4(self):
        self.w.approve()
        self.w.claim()
        self.refuses('claim_mismatch', self.w.report, 'start', cid='b' * 32)
        self.assertEqual(self.w.record()['execution'], 'claimed')

    def test_ST_5(self):
        for missing in ('exit', 'marker', 'pointer_sha256', 'output', None):
            with self.subTest(missing=missing):
                w = self.world()
                w.approve()
                w.claim()
                evidence = w.evidence()
                if missing:
                    del evidence[missing]
                w.report('result', evidence)
                self.assertEqual(w.record()['execution'], 'unknown' if missing else 'done')

    def test_ST_6(self):
        for marker, pointer, expected in (
                ('absent', 'before', 'failed_no_change'),
                ('present_this_claim', 'before', 'failed_after_marker'),
                ('present_other', 'before', 'unknown'), ('absent', 'third', 'unknown')):
            w = self.world()
            w.approve()
            w.claim()
            sha = w.request['target']['before_sha256'] if pointer == 'before' else 'f' * 64
            w.report('result', {'exit': 'refused', 'code': 'POINTER_BEFORE_MISMATCH',
                               'marker': marker, 'pointer_sha256': sha, 'output': None, 'lock_held': False})
            self.assertEqual(w.record()['execution'], expected)

    def test_ST_7(self):
        self.w.approve()
        self.w.claim()
        self.refuses('insufficient_not_run_evidence', self.w.report, 'not_run')
        self.assertEqual(self.w.record()['execution'], 'claimed')
        self.w.clock.advance(900)
        self.assertEqual(self.w.record()['execution'], 'unknown')

    def test_ST_8(self):
        self.w.approve()
        self.w.claim()
        self.w.clock.advance(900)
        self.assertEqual(self.w.record()['execution'], 'unknown')
        self.w.clock.advance(86400)
        self.assertEqual(self.w.record()['execution'], 'unknown')

    def test_ST_9(self):
        # Enumerate the complete named event alphabet through length six, merging
        # equivalent states at each depth. This covers all sequences without 20^6 copies.
        events = state.V1_PROPERTY_EVENTS
        required = {'approve', 'decline', 'cancel', 'revise', 'claim_same', 'claim_other',
                    'start_ok', 'start_wrong', 'result_done', 'result_no_change',
                    'result_after_marker', 'result_partial', 'result_other',
                    'not_run_full', 'not_run_empty', 'tick_15m', 'tick_24h'}
        self.assertEqual(set(events), required)
        frontier = [(state.initial(), self.w.clock(), False)]
        for depth in range(6):
            next_frontier = {}
            for previous, now, ever_claimed in frontier:
                for event in events:
                    later = now + timedelta(seconds=900 if event == 'tick_15m' else 86400 if event == 'tick_24h' else 0)
                    evidence = state.property_evidence(event, self.w.request)
                    try:
                        current = state.transition(previous, event, evidence, later, self.w.request)
                    except Refusal:
                        current = previous
                    claimed = ever_claimed or current['execution'] != 'not_started'
                    if ever_claimed:
                        self.assertNotEqual(current['execution'], 'not_started', (depth, event, previous))
                    key = (canonical_bytes(current), later.isoformat(), claimed)
                    next_frontier[key] = (current, later, claimed)
            frontier = list(next_frontier.values())

    def test_ST_10(self):
        self.w.approve()
        self.w.claim()
        self.w.report('start')
        self.w.clock.advance(899)
        self.assertEqual(self.w.record()['execution'], 'running')
        self.w.clock.advance(1)
        self.assertEqual(self.w.record()['execution'], 'unknown')

    def test_ST_11(self):
        self.w.approve()
        self.w.store.cancel(self.w.rid)
        self.assertEqual(self.w.record()['approval'], 'cancelled')
        w = self.world()
        w.approve()
        w.claim()
        self.refuses('claimed_revision_in_progress', w.store.cancel, w.rid)
        self.assertEqual(w.record()['execution'], 'claimed')

    def test_ST_12(self):
        self.w.approve()
        self.w.clock.advance(7201)
        self.assertEqual(self.w.record()['execution'], 'expired_not_run')
        error = self.refuses('not_claimable:expired', self.w.claim)
        self.assertEqual(error.status, 409)

    def test_ST_13(self):
        w = self.world(scenario='window_later')
        w.approve()
        self.refuses('not_claimable:window_not_open', w.claim)
        self.assertIn('실행 가능 시간', w.record()['display_state'])
        w.runner().step()
        self.assertIsNone(w.record()['claim_id'])
        self.assertEqual(w.kit.calls, {})

    def test_ST_14(self):
        self.w.approve()
        self.w.store.cancel(self.w.rid)
        self.refuses('not_claimable:cancelled', self.w.claim)
        self.assertEqual(self.w.record()['approval'], 'cancelled')
        self.assertEqual(self.w.kit.calls, {})


class Duplicates(Acceptance):
    def test_DP_1(self):
        assertion = self.w.sign()
        def approve():
            try:
                self.w.store.approve(self.w.rid, assertion)
                return 'ok'
            except Refusal as error:
                return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: approve(), range(2)))
        self.assertEqual(results.count('ok'), 1)
        self.assertTrue(set(results) <= {'ok', 'already_approved', 'nonce_used'})
        self.assertEqual(sum(e['event'] == 'approve' for e in self.w.record()['history']), 1)

    def test_DP_2(self):
        self.w.approve()
        self.refuses('already_approved', self.w.options)
        self.assertEqual(sum(e['event'] == 'approve' for e in self.w.record()['history']), 1)

    def test_DP_3(self):
        self.w.approve()
        first = self.w.claim()
        self.assertEqual(first, self.w.claim())
        self.refuses('already_claimed', self.w.claim, 'b' * 32)
        self.w.report('start')
        self.refuses('claim_closed:running', self.w.claim)

    def test_DP_4(self):
        self.w.approve()
        self.w.runner(scenario='claim_response_lost').step()
        self.assertEqual(self.w.kit.calls, {})
        self.assertEqual(self.w.record()['execution'], 'not_run')
        journal = self.w.root.read_json('runner/journal.json')
        self.assertEqual(journal[self.w.rid]['state'], 'gave_up')

    def test_DP_5(self):
        self.w.approve()
        runner = self.w.runner(scenario='crash_after_marker')
        runner.step()
        runner.crash()
        self.w.runner(takeover=True).step()
        self.assertEqual(self.w.kit.calls[self.w.rid], 1)
        self.assertEqual(self.w.record()['execution'], 'failed_after_marker')

    def test_DP_6(self):
        self.w.approve()
        runner = self.w.runner(scenario='crash_after_start')
        runner.step()
        self.assertEqual(self.w.root.read_json('runner/journal.json')[self.w.rid]['state'], 'running')
        self.w.clock.advance(900)
        self.assertEqual(self.w.record()['execution'], 'unknown')
        self.w.runner(takeover=True).step()
        self.assertEqual(self.w.kit.calls, {})
        self.assertTrue(any(e['event'] == 'not_run' for e in self.w.record()['history']))

    def test_DP_7(self):
        for held in (False, True):
            w = self.world()
            w.approve()
            runner = w.runner(scenario='crash_after_start')
            runner.step()
            if held:
                w.root.write_atomic('kit/lock', runner.instance_id.encode())
            w.clock.advance(900)
            w.record()
            w.runner(takeover=True).step()
            self.assertEqual(w.kit.calls, {})
            self.assertEqual(w.record()['execution'], 'unknown' if held else 'not_run')

    def test_DP_8(self):
        first = self.w.runner()
        self.refuses('runner_locked', self.w.runner)
        self.w.approve()
        first.step()
        self.assertEqual(sum(e['event'] == 'claim' for e in self.w.record()['history']), 1)

    def test_DP_9(self):
        self.assertFalse(any(re.search(r'retry|rerun', route, re.I) for route in ROUTES))
        sources = isolation.audit_sources_for_tests()
        self.assertNotRegex(sources['static/index.html'], r'(?i)(retry|rerun|다시 실행)[^<]*</button>')
        self.assertNotRegex(sources['server.py'], r'add_argument\([\'"]--(?:retry|rerun)')

    def test_DP_10(self):
        self.w.approve()
        runner = self.w.runner()
        for _ in range(4):
            runner.step()
        self.assertEqual(self.w.kit.swaps[self.w.rid], 1)
        self.assertTrue(all(n <= 1 for w in self.worlds for n in w.kit.swaps.values()))

    def test_DP_11(self):
        self.w.approve()
        runner = self.w.runner(scenario='claim_response_lost')
        runner.step()
        entry = self.w.root.read_json('runner/journal.json')[self.w.rid]
        self.assertEqual(entry['state'], 'gave_up')
        runner.crash()
        self.w.runner(takeover=True).step()
        self.refuses('claim_closed:not_run', self.w.claim, entry['claim_id'])
        self.assertEqual(self.w.kit.calls, {})
        w = self.world()
        w.approve()
        runner = w.runner(scenario='crash_at_claim_intent')
        runner.step()
        self.assertEqual(w.root.read_json('runner/journal.json')[w.rid]['state'], 'claim_intent')
        w.runner(takeover=True).step()
        self.assertEqual(w.kit.calls, {})
        self.assertIsNone(w.record()['claim_id'])


class Isolation(Acceptance):
    def test_ISO_1(self):
        self.refuses('root_base_refused', isolation.validate_base, '/outside-mapl-temp')
        sources = isolation.audit_sources_for_tests()
        self.assertNotIn('--root', sources['server.py'])
        for name, text in sources.items():
            if name.endswith('.py') and not name.startswith('tests/') and name != 'isolation.py':
                self.assertNotIn('environ', text, name)
        self.assertTrue(str(self.w.root.path).startswith('/private/'))

    def test_ISO_1b(self):
        with patch.dict('os.environ', {'TMPDIR': '/outside-mapl-temp'}):
            self.refuses('tmpdir_mismatch', isolation.TestRoot.create)

    def test_ISO_2(self):
        # Fault injection stays in isolation.py, and never touches anything real.
        for mode in ('changed', 'missing'):
            w = self.world()
            w.root.inject_marker_fault_for_tests(mode)
            for operation in (lambda: w.root.resolve('safe'), lambda: w.root.read_bytes('safe'),
                              lambda: w.root.write_atomic('safe', b'no'), lambda: w.root.pointer(),
                              lambda: w.root.remove('safe'), lambda: w.root.cleanup()):
                self.refuses('test_root_marker_mismatch', operation)
            w.root.restore_marker_for_tests()

    def test_ISO_3(self):
        for rel in ('../x', '/abs', 'a//b', 'A', 'x/../../y', '', 'a b', 'a/..', 'x\\y'):
            self.refuses('path_refused', self.w.root.resolve, rel)

    def test_ISO_4(self):
        outside = self.world()
        outside.root.write_atomic('safe', b'unchanged')
        self.w.root.inject_symlink_for_tests('escape', outside.root.resolve('safe'))
        for op in (self.w.root.resolve, self.w.root.read_bytes):
            self.refuses('symlink_refused', op, 'escape')
        self.refuses('symlink_refused', self.w.root.write_atomic, 'escape', b'no')
        self.assertEqual(outside.root.read_bytes('safe'), b'unchanged')

    def test_ISO_5(self):
        for word in ('screen-current', 'ledger', 'x.sqlite', 'x.db', 'x-wal', 'x-shm',
                     *(part + '/x' for part in isolation.FORBIDDEN_PATHS)):
            self.refuses('path_refused', self.w.root.resolve, word)

    def test_ISO_6(self):
        violations = isolation.audit_ast_for_tests()
        self.assertEqual(violations['filesystem'], [])
        # Mutation controls show aliased read/write calls are detected, not just spelling.
        for source in ('from pathlib import Path as P\nP("x").read_text()',
                       'import os as o\no.open("x", 0)', 'from io import open as f\nf("x")',
                       'from tempfile import mkdtemp as t\nt()', 'import os\nos.chmod("x", 0)'):
            self.assertTrue(isolation.audit_text_for_tests(source)['filesystem'], source)

    def test_ISO_7(self):
        self.assertEqual(isolation.audit_ast_for_tests()['forbidden'], [])
        for source in ('import subprocess as s', 'import importlib', 'eval("1")',
                       'import os\ngetattr(os, "open")("x")', 'import http.client',
                       'from planning.impl.write_service import server', 'import ssl',
                       'import sys\nsys.path.append("x")'):
            self.assertTrue(isolation.audit_text_for_tests(source)['forbidden'], source)

    def test_ISO_8(self):
        self.assertEqual(config.BIND_HOST, '127.0.0.1')
        for url in ('https://example.com', 'http://localhost.evil:8790', 'http://user@localhost:8790',
                    'http://127.0.0.1:8790/escape', 'https://localhost:8790', 'http://[::1]:8790'):
            self.refuses('runner_base_refused', validate_base_url, url)
        for url in ('http://localhost:8790', 'http://127.0.0.1:8790'):
            validate_base_url(url)
        self.refuses('profile_not_authorized', config.Profile, 'iphone-tailscale')
        self.refuses('port_refused', config.Profile, 'local', 8771)

    def test_ISO_9(self):
        sources = isolation.audit_sources_for_tests()
        for name, source in sources.items():
            if name == 'isolation.py' or name.startswith('tests/'):
                continue
            # Only literals, not identifiers; §5 requires the canonical not_covered
            # value, kept centrally in isolation alongside the second-layer denylist.
            if name.endswith('.py'):
                literals = [n.value for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
                for literal in literals:
                    for prohibited in ('screen-current', *isolation.FORBIDDEN_PATHS, 'ledger'):
                        self.assertNotIn(prohibited, literal, name)
        self.assertIn(b'gen/0005', self.w.root.read_bytes(self.w.root.pointer()))

    def test_EXTRA_fixed_pointer_capability(self):
        # Coordinator msg_cb8b39c9e6f2: the ONLY uppercase exception is pointer().
        pointer = self.w.root.pointer()
        self.assertEqual(pointer.relative, 'test-screen/CURRENT.json')
        for name in ('test-screen/CURRENT.json', 'test-screen/CURRENT.JSON', '../CURRENT.json',
                     'other/current.json', 'CURRENT.json'):
            if name == 'other/current.json':
                self.refuses('pointer_target_refused', self.w.kit.run, self.w.request, name, 'a' * 32, 'i')
            else:
                self.refuses('path_refused', self.w.root.resolve, name)

    def test_EXTRA_source_audit_boundary(self):
        # Coordinator msg_cb8b39c9e6f2: audit is tests-only, runtime reads remain 4 files.
        sources = isolation.audit_sources_for_tests()
        for name in ('server.py', 'runner_sim.py', '__main__.py'):
            self.assertNotIn('audit_sources_for_tests', sources[name])
            self.assertNotIn('audit_ast_for_tests', sources[name])
        for rel in ('../outside.py', '/outside.py', 'server.py', 'tests/test_acceptance.py'):
            self.refuses('package_read_refused', isolation.package_bytes, rel)
        self.assertEqual(set(isolation.RUNTIME_READS), {'mock_kit.py', 'check_contract.py', 'static/index.html', 'static/app.js', 'static/app.css'})
        self.refuses('package_read_refused', isolation.audit_file_for_tests, '../outside.py')
        self.refuses('package_read_refused', isolation.audit_file_for_tests, 'anything.json')


class Labels(Acceptance):
    def test_LBL_1(self):
        app = Application(self.w.store)
        for path in ('/register', '/r/' + self.w.rid):
            status, headers, body = app.handle('GET', path, {'Host': 'localhost:8790'}, b'')
            self.assertEqual(status, 200)
            self.assertEqual(body.decode().count(ui.BAND), 1)
            self.assertIn('frame-ancestors', headers['Content-Security-Policy'])
            self.assertEqual(headers['X-Frame-Options'], 'DENY')
            self.assertEqual(headers['Cache-Control'], 'no-store')

    def test_LBL_2(self):
        self.w.approve()
        self.w.claim()
        self.w.report('result', self.w.evidence())
        self.assertIn('모의 실행', self.w.record()['display_state'])
        self.assertIn('시험 대상', self.w.record()['display_state'])

    def test_LBL_3(self):
        self.w.approve()
        self.w.runner().step()
        record = canonical_bytes(self.w.record()).decode()
        self.assertNotIn('auth_source', record)
        self.assertNotIn('가상 인증기', record)
        self.assertNotIn('Face ID', record)
        self.assertEqual(report.build_report('virtual_authenticator', {})['auth_source'], 'virtual_authenticator')

    def test_LBL_4(self):
        self.w.store.heartbeat()
        for stopped in (False, True):
            if stopped:
                self.w.store.stopping()
            line = self.w.store.runner_status()
            cleaned = re.sub(r'실행기가 꺼진다고 알림 \d\d:\d\d:\d\d', '', line)
            cleaned = cleaned.replace('켜짐·꺼짐은 이 정보만으로 알 수 없습니다', '')
            self.assertNotRegex(cleaned, r'켜짐|꺼짐|켜져|꺼져|online|offline|온라인|오프라인')
            if not stopped:
                self.assertIn('켜짐·꺼짐은 이 정보만으로 알 수 없습니다', line)

    def test_LBL_5(self):
        result = report.build_report('virtual_authenticator', {})
        self.assertTrue(all(sentence in report.SENTENCES for sentence in result['sentences']))
        self.assertTrue(report.validate_report(result))
        for forbidden in report.FORBIDDEN:
            tampered = copy.deepcopy(result)
            tampered['sentences'].append(forbidden + ' (mock 아님)')
            self.refuses('report_template_refused', report.validate_report, tampered)
        required = ('authentication succeeded', 'executed', '실행됨', '게시됨', 'Face ID', 'iPhone',
                    'passkey authentication succeeded', 'publication executed', 'device authentication succeeded',
                    'user approved', 'real runner', 'notification sent', 'deployed', 'published', 'authenticated')
        self.assertTrue(all(word.lower() in [s.lower() for s in report.FORBIDDEN] for word in required))

    def test_LBL_6(self):
        self.w.request['summary_by_ai'] = 'reference-secret-text'
        model = ui.view(self.w.record(), self.w.clock(), 'reference-secret-text')
        default = model['default_text']
        self.assertNotRegex(default, r'[0-9a-f]{16,}|TEST_ROOT|test-screen|\.json|mock-kit|request_id|reference-secret-text')
        self.assertNotIn('/', re.sub(r'gen/\d{4}', '', default))
        for detail in (self.w.rid, self.w.request['target']['before_sha256'], 'mock-kit/1', 'reference-secret-text'):
            self.assertIn(detail, model['details_text'])

    def test_LBL_7(self):
        model = ui.view(self.w.record(), self.w.clock())
        self.assertEqual(model['default_text'].count('되돌리기'), 1)
        self.assertEqual(model['default_text'].count('원장'), 1)
        for condition in ('되돌리기', '원장'):
            self.assertNotIn(condition, ui.confirm(self.w.record(), 'http://localhost:8790'))

    def test_LBL_8(self):
        model = ui.view(self.w.record(), self.w.clock())
        for text in (model['default_text'], ui.confirm(self.w.record(), 'http://localhost:8790')):
            self.assertNotRegex(text, r'U-[1-6]|미정|iCloud 키체인')
        self.assertEqual(model['default_text'].count('현재 상태'), 1)

    def test_LBL_9(self):
        malicious = '<img src=x onerror="alert(1)"><script>evil()</script>'
        model = ui.view(self.w.record(), self.w.clock(), malicious)
        self.assertNotIn(malicious, model['default_text'])
        self.assertIn(malicious, model['details_text'])
        js = isolation.package_bytes('static/app.js').decode()
        self.assertNotIn('innerHTML', js)
        self.assertNotIn('insertAdjacentHTML', js)
        self.assertIn('textContent', js)


class Binding(Acceptance):
    def test_BIND_1(self):
        assertion = self.w.sign()
        self.w.revision()
        self.refuses('superseded', self.w.store.approve, self.w.rid, assertion, 1)
        self.assertEqual(self.w.record(1)['approval'], 'superseded')
        w = self.world()
        w.approve()
        w.claim()
        self.refuses('claimed_revision_in_progress', w.revision)

    def test_BIND_2(self):
        mutations = (
            lambda r: r['target'].update(pointer='other/pointer.json'),
            lambda r: r['target'].update(before_sha256='f' * 64),
            lambda r: r['target'].update(after_sha256='f' * 64),
            lambda r: r['bundle'].update(sha256='f' * 64),
            lambda r: r['kit'].update(sha256='f' * 64),
            lambda r: r['window_utc'].__setitem__(0, '2026-11-14T05:00:00Z'),
            lambda r: r.update(expires_at='2026-11-14T06:30:00Z'),
            lambda r: r['not_covered'].append('extra'),
            lambda r: r['recovery'].update(included_in_this_approval=True))
        for change in mutations:
            w = self.world()
            w.approve()
            w.store.inject_request_for_tests(w.rid, 1, change)
            w.runner().step()
            self.assertEqual(w.kit.calls, {})
            self.assertIsNone(w.record()['claim_id'])
            self.assertEqual(w.record()['execution'], 'not_started')
            self.assertTrue(any(e.get('code') == 'CONTENT_MISMATCH' for e in w.record()['history']))

    def test_BIND_3(self):
        self.w.approve()
        runner = self.w.runner()
        def changed_after_claim():
            self.w.root.write_atomic(self.w.root.pointer(), b'changed-test-pointer')
        runner.before_kit = changed_after_claim
        runner.step()
        self.assertEqual(self.w.root.read_bytes(self.w.root.pointer()), b'changed-test-pointer')
        self.assertEqual(runner.last_evidence['code'], 'POINTER_BEFORE_MISMATCH')
        self.assertEqual(self.w.kit.swaps, {})

    def test_BIND_4(self):
        req = copy.deepcopy(self.w.request)
        req['request_id'] = 'b' * 32
        req['target']['test_root_id'] = 'f' * 32
        self.refuses('test_root_id_mismatch', self.w.store.create_request, req)

    def test_BIND_5(self):
        assertion = self.w.sign()
        self.w.clock.advance(7201)
        self.refuses('expired', self.w.store.approve, self.w.rid, assertion)
        self.refuses('not_claimable:expired', self.w.claim)

    def test_BIND_6(self):
        assertion = self.w.approve()
        self.refuses('nonce_used', self.w.store.approve, self.w.rid, assertion)
        w = self.world()
        fresh = copy.deepcopy(w.request)
        fresh['request_id'] = 'b' * 32
        w.store.create_request(fresh)
        a = w.sign()
        w.options('b' * 32)
        self.refuses('challenge_mismatch', w.store.approve, 'b' * 32, a)
        w.clock.advance(181)
        self.refuses('nonce_expired', w.store.approve, w.rid, a)

    def test_BIND_7(self):
        cases = [({'kind': 'other'}, 'type_mismatch'),
                 ({'origin': 'http://127.0.0.1:8790'}, 'origin_mismatch'),
                 ({'origin': 'https://localhost:8790'}, 'origin_mismatch'),
                 ({'origin': 'http://localhost:8791'}, 'origin_mismatch'),
                 ({'extra': {'crossOrigin': True}}, 'cross_origin_refused'),
                 ({'extra': {'topOrigin': 'x'}}, 'cross_origin_refused'),
                 ({'rp': 'other'}, 'rp_id_mismatch'), ({'flags': 4}, 'up_missing'),
                 ({'flags': 1}, 'uv_missing'), ({'flags': 0x15}, 'backup_flags_invalid'),
                 ({'credential_id': b'unknown'}, 'unknown_credential')]
        for params, expected in cases:
            w = self.world()
            self.refuses(expected, w.store.approve, w.rid, w.sign(**params))
            self.assertEqual(w.record()['approval'], 'pending')
        for mutation, expected in (('challenge', 'challenge_mismatch'), ('signature', 'signature_invalid'),
                                   ('client', 'signature_invalid'), ('duplicate', 'client_data_malformed')):
            w = self.world()
            options = w.options()
            challenge = b64decode(options['challenge'])
            assertion = w.auth.assertion(challenge)
            if mutation == 'challenge':
                assertion = w.auth.assertion(b'wrong')
            elif mutation == 'signature':
                assertion['response']['signature'] = b64encode(b'invalid')
            elif mutation == 'client':
                client = b64decode(assertion['response']['clientDataJSON']) + b' '
                assertion['response']['clientDataJSON'] = b64encode(client)
            else:
                raw = w.auth.client(challenge, 'webauthn.get', 'http://localhost:8790')
                raw = raw[:-1] + b',"type":"webauthn.get"}'
                assertion = w.auth.assertion(challenge, client_raw=raw)
            self.refuses(expected, w.store.approve, w.rid, assertion)
            self.assertEqual(w.record()['approval'], 'pending')

    def test_BIND_8(self):
        app = Application(self.w.store)
        path = '/api/requests/' + self.w.rid + '/approve/verify'
        for headers in ({'Cookie': 'session=anything'}, {'Authorization': 'Bearer ' + self.w.store.runner_token},
                        {'Authorization': 'Bearer ' + self.w.store.requester_token}, {}):
            headers.update(Host='localhost:8790', Origin='http://localhost:8790')
            status, _, _ = app.handle('POST', path, headers, b'{}')
            self.assertGreaterEqual(status, 400)
        self.assertEqual(self.w.record()['approval'], 'pending')
        status, _, _ = app.handle('POST', path, {'Host': 'localhost:8790', 'Origin': 'http://evil'}, b'{}')
        self.assertEqual(status, 403)
        status, _, _ = app.handle('GET', '/r/' + self.w.rid, {'Host': 'evil:8790'}, b'')
        self.assertEqual(status, 403)

    def test_BIND_9(self):
        self.w.approve()
        pinned = self.w.root.read_json('runner/pinned-credential.json')
        pinned['spki'] = 'not-the-server-key'
        self.w.root.write_json('runner/pinned-credential.json', pinned)
        self.w.runner().step()
        self.assertEqual(self.w.kit.calls, {})
        self.assertIsNone(self.w.record()['claim_id'])
        self.assertTrue(any(e.get('code') == 'pinned_key_mismatch' for e in self.w.record()['history']))

    def test_BIND_10(self):
        for which in ('recovery', 'not_covered'):
            request = copy.deepcopy(self.w.request)
            request['request_id'] = 'b' * 32
            if which == 'recovery':
                request['recovery']['included_in_this_approval'] = True
            else:
                request['not_covered'].remove('recovery')
            self.refuses('scope_refused', self.w.store.create_request, request)
        self.w.approve()
        self.w.store.inject_request_for_tests(self.w.rid, 1, lambda r: r['recovery'].update(included_in_this_approval=True))
        self.w.runner().step()
        self.assertEqual(self.w.kit.calls, {})

    def test_BIND_11(self):
        for action in ('credential_add/1', 'screen_recovery/1', 'shell/1'):
            request = copy.deepcopy(self.w.request)
            request.update(action_type=action, request_id='b' * 32)
            self.refuses('action_type_refused', self.w.store.create_request, request)

    def test_BIND_12(self):
        self.w.approve()
        self.w.revision()
        self.refuses('not_claimable:superseded', self.w.claim)
        self.assertEqual(self.w.kit.calls, {})
        self.assertEqual(self.w.record(1)['approval'], 'superseded')

    def test_BIND_13(self):
        for forgery in ('missing', 'uv', 'origin', 'another_request'):
            w = self.world()
            challenge = b64decode(w.options()['challenge'])
            assertion = None
            if forgery == 'uv':
                assertion = w.auth.assertion(challenge, flags=1)
            elif forgery == 'origin':
                assertion = w.auth.assertion(challenge, origin='http://evil')
            elif forgery == 'another_request':
                assertion = w.auth.assertion(b'another-request-challenge')
            w.store.inject_approval_for_tests(w.rid, assertion)
            w.runner().step()
            self.assertEqual(w.kit.calls, {})
            self.assertIsNone(w.record()['claim_id'])
            self.assertTrue(any(e['event'] == 'refused_before_claim' for e in w.record()['history']))

    def test_BIND_14(self):
        mutations = (lambda r: r['target'].update(from_generation='gen/0005 (actual)'),
                     lambda r: r['target'].update(to_generation='other'),
                     lambda r: r.update(expires_at='2026-11-14T09:00:00Z'),
                     lambda r: r['window_utc'].__setitem__(0, r['window_utc'][1]),
                     lambda r: r['window_utc'].__setitem__(0, '2026-11-14T01:00:00Z'),
                     lambda r: r.update(created_at=r['expires_at']))
        for change in mutations:
            request = copy.deepcopy(self.w.request)
            request['request_id'] = 'b' * 32
            change(request)
            self.refuses('request_invalid', self.w.store.create_request, request)
        self.w.approve()
        runner = self.w.runner()
        runner.before_kit = lambda: self.w.clock.advance(7201)
        runner.step()
        self.assertEqual(self.w.kit.swaps, {})
        self.assertEqual(runner.last_evidence['code'], 'EXPIRED')


class Registration(Acceptance):
    def test_REG_1(self):
        w = self.world(register=False)
        self.refuses('setup_code_invalid', w.store.registration_options, '')
        self.refuses('setup_code_invalid', w.store.registration_options, 'WRONG')
        w.clock.advance(601)
        self.refuses('setup_code_expired', w.store.registration_options, w.store.setup_code)

    def test_REG_2(self):
        self.refuses('registration_closed', self.w.register)
        self.assertEqual(self.w.store.credential_count(), 1)

    def test_REG_3(self):
        for bad in ('fmt', 'alg', 'indefinite', 'tag', 'duplicate', 'trailing', 'nonminimal', 'depth'):
            w = self.world(register=False)
            options = w.store.registration_options(w.store.setup_code)
            registration = w.auth.registration(b64decode(options['challenge']),
                                                fmt='packed' if bad == 'fmt' else 'none',
                                                alg=-257 if bad == 'alg' else -7)
            malformed = {'indefinite': b'\xbf\xff', 'tag': b'\xc0\xa0',
                         'duplicate': b'\xa2\x01\x01\x01\x02', 'trailing': b'\xa0\x00',
                         'nonminimal': b'\xb8\x00', 'depth': b'\x81' * 10 + b'\x00'}
            if bad in malformed:
                registration['response']['attestationObject'] = b64encode(malformed[bad])
            with self.assertRaises(Refusal):
                w.store.register(w.store.setup_code, registration)
            self.assertEqual(w.store.credential_count(), 0)

    def test_REG_4(self):
        w = self.world(register=False)
        app = Application(w.store)
        for token in (w.store.runner_token, w.store.requester_token):
            for endpoint in ('options', 'verify'):
                status, _, _ = app.handle('POST', '/api/register/' + endpoint,
                    {'Host': 'localhost:8790', 'Origin': 'http://localhost:8790', 'Authorization': 'Bearer ' + token},
                    canonical_bytes({'code': w.store.setup_code}))
                self.assertEqual(status, 403)
        self.assertEqual(w.store.credential_count(), 0)


class KitRefusalCondition(Acceptance):
    def test_EXTRA_kit_refuses_explicit_no_change(self):
        # Core msg_28808b171e89 adds this condition before any run; the fixed
        # 65 acceptance verdicts and earlier two boundary cases stay unchanged.
        self.w.approve()
        before = self.w.root.read_bytes(self.w.root.pointer())
        runner = self.w.runner(scenario='kit_refuses')
        runner.step()
        self.assertEqual(self.w.root.read_bytes(self.w.root.pointer()), before)
        self.assertEqual(runner.last_evidence['exit'], 'refused')
        self.assertEqual(runner.last_evidence['code'], 'POINTER_BEFORE_MISMATCH')
        self.assertEqual(runner.last_evidence['marker'], 'absent')
        self.assertFalse(self.w.root.exists('kit/used/' + self.w.rid + '.json'))
        self.assertFalse(self.w.root.exists('kit/lock'))
        self.assertEqual(self.w.kit.swaps, {})
        self.assertEqual(self.w.record()['execution'], 'failed_no_change')
        # An actual changed pointer is never certified unchanged, even if an
        # explicit refusal code accompanies that observation (BIND-3 / ST-6).
        changed = self.world()
        changed.approve()
        changed_runner = changed.runner()
        changed_runner.before_kit = lambda: changed.root.write_atomic(changed.root.pointer(), b'changed-test-pointer')
        changed_runner.step()
        self.assertEqual(changed.record()['execution'], 'unknown')
        for code in ('TIMEOUT', 'MISSING_RESULT', None):
            unclear = self.world()
            unclear.approve()
            unclear.claim()
            unclear.report('result', {'exit': 'refused' if code else None, 'code': code,
                'marker': 'absent', 'pointer_sha256': unclear.request['target']['before_sha256'],
                'output': None, 'lock_held': False})
            self.assertEqual(unclear.record()['execution'], 'unknown')
