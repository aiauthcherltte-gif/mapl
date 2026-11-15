"""MAPLIF regression witnesses; frozen acceptance assertions remain untouched."""
import copy
import unittest
from unittest.mock import patch

from .. import isolation, report
from ..canonical import canonical_bytes, digest, parse_json
from ..errors import Refusal
from ..server import Application
from .support import World


class RootWitness(unittest.TestCase):
    def test_default_macos_python313_root(self):
        root = isolation.TestRoot.create()
        try:
            root.write_atomic('witness', b'isolated')
            self.assertEqual(root.read_bytes('witness'), b'isolated')
        finally:
            root.cleanup()


class AuditWitness(unittest.TestCase):
    def test_assigned_path_read(self):
        self.assertTrue(isolation.audit_text_for_tests('from pathlib import Path\np = Path("x")\np.read_text()')['filesystem'])

    def test_assigned_path_write(self):
        self.assertTrue(isolation.audit_text_for_tests('from pathlib import Path\np = Path("x")\np.write_text("x")')['filesystem'])

    def test_assigned_open_alias(self):
        self.assertTrue(isolation.audit_text_for_tests('f = open\nf("x")')['filesystem'])

    def test_http_member_import(self):
        self.assertTrue(isolation.audit_text_for_tests('from http import client')['forbidden'])

    def test_other_package_member_import(self):
        self.assertTrue(isolation.audit_text_for_tests('from planning.impl import write_service')['forbidden'])


class ProtocolWitness(unittest.TestCase):
    def setUp(self):
        # Pin the existing allowed base so the tmpdir bug cannot mask these witnesses.
        self.base = patch('planning.impl.mapl_test.isolation.os.confstr', return_value='/private/tmp/')
        self.tmp = patch.dict('os.environ', {'TMPDIR': '/private/tmp/'})
        self.base.start()
        self.tmp.start()
        self.addCleanup(self.base.stop)
        self.addCleanup(self.tmp.stop)
        self.w = World()
        self.addCleanup(self.w.close)

    def options(self, revision, content_hash):
        app = Application(self.w.store)
        status, _, body = app.handle('POST', '/api/requests/' + self.w.rid + '/approve/options',
            {'Host': app.profile.host, 'Origin': app.profile.origin},
            canonical_bytes({'revision': revision, 'content_hash': content_hash}))
        return status, parse_json(body)

    def test_options_refuse_unseen_revision(self):
        shown = self.w.request
        self.w.revision()
        status, body = self.options(shown['revision'], digest(canonical_bytes(shown)))
        self.assertEqual(status, 409)
        self.assertEqual(body['error'], 'revision_changed')
        self.assertEqual(self.w.record()['approval'], 'pending')

    def test_options_refuse_wrong_display_hash(self):
        status, body = self.options(1, '0' * 64)
        self.assertEqual(status, 409)
        self.assertEqual(body['error'], 'revision_changed')


class ReportWitness(unittest.TestCase):
    def test_partial_results_make_no_success_claim(self):
        value = report.build_report('virtual_authenticator', {'ISO': 'PASS'})
        self.assertNotIn('Virtual authenticator signature verified (automated, no person).', value['sentences'])
        self.assertNotIn('Mock execution on the test target completed.', value['sentences'])

    def test_not_run_cannot_claim_verification(self):
        value = report.build_report('not_run', {'BIND': 'NOT RUN'})
        value['sentences'].append('Virtual authenticator signature verified (automated, no person).')
        with self.assertRaises(Refusal):
            report.validate_report(value)

    def test_success_claim_requires_relevant_results(self):
        value = report.build_report('virtual_authenticator', {'ISO': 'PASS'})
        value['sentences'] = ['Mock execution on the test target completed.']
        with self.assertRaises(Refusal):
            report.validate_report(value)
