"""Offline adapter tests: only self-owned marked roots and synthetic files."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

module = runpy.run_path('scripts/mock-mac.py')
main = module['main']
g = main.__globals__
TestRoot = module['TestRoot']
from planning.impl.mapl_test.state import utc
NOW = datetime(2020, 1, 1, tzinfo=timezone.utc)


class MockAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mapl-mock-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.root = TestRoot.create()
        self.addCleanup(self.cleanup_root)
        self.request = module['seed'](self.root, module['Baseline'](self.root), NOW)
        self.data = {'mode': 'test', 'root': self.root.path, 'root_id': self.root.root_id, 'request': self.request}
        self.state = self.repo / 'state.json'
        self.state.write_text(json.dumps(self.data))
        self.original = self.state.read_bytes()
        self.profile = self.repo / 'deploy-profile.json'
        self.profile.write_text(json.dumps({'SUBDOMAIN': 'visibly-fake-fixture', 'TEST_ROOT_ID': self.root.root_id}))

    def cleanup_root(self):
        if not self.root._closed:
            self.root.cleanup()

    def invoke(self, action='reseed', **patches):
        stdout = io.StringIO()
        with patch.dict(g, REPO=self.repo, **patches), patch('sys.argv', ['mock-mac.py', action, '--state', str(self.state), '--token-dir', str(self.repo)]), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            main()
        return stdout.getvalue()

    def refuse(self):
        with self.assertRaises((Exception, SystemExit)):
            self.invoke()
        self.assertEqual(self.state.read_bytes(), self.original)
        self.assertEqual(list(self.repo.glob('state.json.previous-*')), [])
        self.assertEqual(self.root.read_bytes(self.root.pointer()), self.root.read_bytes('bundles/gen/0005/pointer.json'))

    def test_expired_reseed_same_root_fresh_two_hours_and_backup(self):
        # Old seed expired long before the actual clock; no token exists here.
        start = datetime.now(timezone.utc).replace(microsecond=0)
        self.assertLess(utc(self.request['expires_at']), start)
        output = json.loads(self.invoke())
        data = json.loads(self.state.read_bytes())
        request = data['request']
        self.assertEqual(set(output), {'request_id', 'expires_at'})
        self.assertEqual(output, {k: request[k] for k in output})
        self.assertEqual((data['root'], data['root_id']), (self.data['root'], self.data['root_id']))
        self.assertNotEqual(request['request_id'], self.request['request_id'])
        self.assertGreaterEqual(utc(request['created_at']), start)
        self.assertEqual(utc(request['expires_at']) - utc(request['created_at']), timedelta(hours=2))
        self.assertEqual(request['window_utc'], [request['created_at'], request['expires_at']])
        self.assertEqual(request['target'], self.request['target'])
        self.assertEqual(self.root.read_json('runner/manifests/' + request['request_id'] + '/1.json'), request)
        backups = list(self.repo.glob('state.json.previous-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.original)
        second = json.loads(self.invoke())
        self.assertNotEqual(second['request_id'], request['request_id'])
        self.assertEqual(len(list(self.repo.glob('state.json.previous-*'))), 2)

    def test_profile_root_mismatch(self):
        self.profile.write_text(json.dumps({'TEST_ROOT_ID': '0' * 32}))
        self.refuse()

    def test_marker_root_mismatch(self):
        self.data['root_id'] = '0' * 32
        self.profile.write_text(json.dumps({'TEST_ROOT_ID': '0' * 32}))
        self.state.write_text(json.dumps(self.data))
        self.original = self.state.read_bytes()
        self.refuse()

    def test_request_root_mismatch(self):
        self.data['request']['target']['test_root_id'] = '0' * 32
        self.state.write_text(json.dumps(self.data))
        self.original = self.state.read_bytes()
        self.refuse()

    def test_missing_root(self):
        self.root.cleanup()
        with self.assertRaises(FileNotFoundError): self.invoke()
        self.assertFalse(Path(self.data['root']).exists())
        self.assertEqual(self.state.read_bytes(), self.original)

    def test_changed_pointer(self):
        after = self.root.read_bytes('bundles/gen/0006/pointer.json')
        self.root.write_atomic(self.root.pointer(), after)
        with self.assertRaises(ValueError): self.invoke()
        self.assertEqual(self.root.read_bytes(self.root.pointer()), after)
        self.assertEqual(self.state.read_bytes(), self.original)

    def test_approved_request_in_server_store(self):
        self.root.write_json('server/state.json', {'requests': {'old': {'state': {'approval': 'approved'}}}})
        self.refuse()

    def test_execution_record_for_another_request(self):
        self.root.write_json('runner/records/' + 'e' * 32 + '.json', {'state': 'claim_intent'})
        self.refuse()

    def test_used_marker_even_without_pointer_swap(self):
        self.root.write_json('kit/used/' + 'e' * 32 + '.json', {'claim_id': 'synthetic'})
        self.refuse()

    def test_running_runner(self):
        self.root.acquire_process_runner_lock('synthetic')
        try: self.refuse()
        finally: self.root.release_process_runner_lock('synthetic')

    def test_manifest_mismatch(self):
        self.root.write_json('runner/manifests/' + self.request['request_id'] + '/1.json', {**self.request, 'approval': 'approved'})
        self.refuse()

    def test_atomic_replace_failure_retains_old_public_state_and_backup(self):
        replace = os.replace
        def fail_state(src, dst, *args, **kwargs):
            if dst == self.state: raise OSError('synthetic failure')
            return replace(src, dst, *args, **kwargs)
        with patch('os.replace', fail_state), self.assertRaises(OSError): self.invoke()
        self.assertEqual(self.state.read_bytes(), self.original)
        self.assertEqual(list(self.repo.glob('state.json.previous-*'))[0].read_bytes(), self.original)
        self.assertEqual(list(self.repo.glob('state.json.tmp-*')), [])

    def test_submit_stdin_only_permissions_and_reseed_refusal(self):
        token = self.repo / 'requester.token'
        token.write_text('visibly-fake-requester-fixture-0000000\n')
        token.chmod(0o600)
        seen = []
        def submit(argv, **options):
            self.assertNotIn(token.read_text().strip(), ' '.join(argv))
            self.assertEqual(options['input'], token.read_text().strip())
            seen.append(argv)
            return SimpleNamespace(returncode=0)
        with patch('subprocess.run', submit): output = self.invoke('submit')
        self.assertEqual(len(seen), 1)
        self.assertNotIn(token.read_text().strip(), output)
        self.refuse()
        token.chmod(0o644)
        with self.assertRaises(SystemExit): self.invoke('submit')

    def test_failed_submission_also_blocks_offline_reseed(self):
        token = self.repo / 'requester.token'
        token.write_text('visibly-fake-requester-fixture-0000000\n')
        token.chmod(0o600)
        with patch('subprocess.run', return_value=SimpleNamespace(returncode=1)), self.assertRaises(ValueError): self.invoke('submit')
        self.refuse()


if __name__ == '__main__': unittest.main()
