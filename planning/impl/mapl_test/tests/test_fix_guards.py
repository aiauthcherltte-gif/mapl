"""Additional controls for the fixed regressions, separate from frozen cases."""
import unittest
from unittest.mock import call, patch

from .. import isolation, report
from ..canonical import canonical_bytes, digest, parse_json
from ..errors import Refusal
from ..server import Application
from .support import World


class FixGuards(unittest.TestCase):
    def test_iso1_prose_is_not_a_settings_read(self):
        self.assertEqual(isolation.audit_text_for_tests('"""No environment settings."""')['forbidden'], [])
        for source in ('import os\nos.environ["TMPDIR"]', 'import os as o\nx = o.environ',
                       'from os import getenv as g\ng("TMPDIR")'):
            with self.subTest(source=source):
                self.assertTrue(isolation.audit_text_for_tests(source)['forbidden'])

    def test_path_and_function_provenance(self):
        for source in (
            'from pathlib import Path as P\nconstructor = P\np = constructor("x") / "y"\nf = p.read_text\nf()',
            'from pathlib import Path\np: object = Path("x")\nf = p.write_bytes\nf(b"x")',
            'from pathlib import PosixPath\np = PosixPath("x")\np.touch()',
            'f, g = open, int\nf("x")', 'import builtins as b\nf = b.open\nf("x")',
            'import os as o\nf = o.open\ng = f\ng("x", 0)'):
            with self.subTest(source=source):
                self.assertTrue(isolation.audit_text_for_tests(source)['filesystem'])

    def test_member_imports_and_relative_escape(self):
        for source in ('from urllib import request', 'from .. import write_service',
                       'from planning.impl.mapl_test_evil import app', 'from pathlib import *',
                       'import builtins\nf = builtins.eval\nf("1")'):
            with self.subTest(source=source):
                self.assertTrue(isolation.audit_text_for_tests(source)['forbidden'])
        self.assertEqual(isolation.audit_text_for_tests('from http import client', 'runner_sim.py')['forbidden'], [])
        self.assertEqual(isolation.audit_text_for_tests('from . import ui')['forbidden'], [])

    def test_native_confstr_id_when_python_key_is_missing(self):
        def confstr(key):
            if key == 'CS_DARWIN_USER_TEMP_DIR':
                raise ValueError('unrecognized configuration name')
            self.assertEqual(key, 65537)
            return '/private/tmp/'
        with patch.object(isolation.os, 'confstr', side_effect=confstr) as queried:
            with patch.dict('os.environ', {'TMPDIR': '/private/tmp/', 'TEMP': '/outside-mapl-temp', 'TMP': '/outside-mapl-temp'}):
                root = isolation.TestRoot.create()
                try:
                    self.assertTrue(root.path.startswith('/private/tmp/mapl3-test-'))
                finally:
                    root.cleanup()
        self.assertEqual(queried.call_args_list, [call('CS_DARWIN_USER_TEMP_DIR'), call(65537)])

    def test_complete_protocol_evidence_does_not_claim_browser(self):
        results = {group: 'PASS' for group in ('ST', 'DP', 'ISO', 'LBL', 'BIND', 'REG', 'EXTRA')}
        results['E2E'] = 'NOT RUN'
        value = report.build_report('virtual_authenticator', results)
        self.assertIn('Virtual authenticator signature verified (automated, no person).', value['sentences'])
        self.assertIn('Mock execution on the test target completed.', value['sentences'])
        self.assertNotIn('Browser WebAuthn API called in a test harness.', value['sentences'])
        value['sentences'].append('Browser WebAuthn API called in a test harness.')
        with self.assertRaises(Refusal):
            report.validate_report(value)

    def test_not_run_rejects_run_results_and_generic_success(self):
        with self.assertRaises(Refusal):
            report.build_report('not_run', {'ISO': 'PASS'})
        value = report.build_report('not_run', {'ISO': 'NOT RUN'})
        value['sentences'].append('Test group passed.')
        with self.assertRaises(Refusal):
            report.validate_report(value)

    def test_http_options_require_and_accept_display_pair(self):
        w = World()
        try:
            app = Application(w.store)
            path = '/api/requests/' + w.rid + '/approve/options'
            headers = {'Host': app.profile.host, 'Origin': app.profile.origin}
            status, _, _ = app.handle('POST', path, headers, b'{}')
            self.assertEqual(status, 400)
            shown = w.record()
            self.assertEqual(shown['content_hash'], digest(canonical_bytes(shown['request'])))
            pair = {'revision': shown['request']['revision'], 'content_hash': shown['content_hash']}
            status, _, body = app.handle('POST', path, headers, canonical_bytes(pair))
            self.assertEqual(status, 200)
            self.assertIn('challenge', parse_json(body))
        finally:
            w.close()
