"""Test world; all fixture filesystem access uses isolation capabilities."""
import copy
import unittest
from datetime import datetime, timedelta, timezone

from ..canonical import b64decode
from ..errors import Refusal
from ..isolation import TestRoot
from ..mock_kit import MockKit
from ..seed import seed
from ..store import Store as RuntimeStore, setup_code
from ..runner_sim import RunnerInstance, DirectTransport
from .soft_authenticator import SoftAuthenticator


class Store(RuntimeStore):
    """Fixture retains bootstrap code outside the runtime store implementation."""
    def __init__(self, root, clock):
        self.setup_code = setup_code()
        super().__init__(root, clock, setup_code=self.setup_code)


class Clock:
    def __init__(self):
        self.value = datetime(2026, 11, 14, 6, tzinfo=timezone.utc)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += timedelta(seconds=seconds)


class World:
    def __init__(self, scenario='normal', register=True):
        self.clock = Clock()
        self.root = TestRoot.create()
        self.store = Store(self.root, self.clock)
        self.request = seed(self.root, self.store, self.clock(), scenario)
        self.rid = self.request['request_id']
        self.auth = SoftAuthenticator()
        self.kit = MockKit(self.root, self.clock)
        self.runners = []
        if register:
            self.register()

    def register(self):
        options = self.store.registration_options(self.store.setup_code)
        credential = self.auth.registration(b64decode(options['challenge']))
        return self.store.register(self.store.setup_code, credential)

    def options(self, rid=None):
        return self.store.approval_options(rid or self.rid)

    def sign(self, rid=None, **kwargs):
        options = self.options(rid)
        return self.auth.assertion(b64decode(options['challenge']), **kwargs)

    def approve(self):
        assertion = self.sign()
        self.store.approve(self.rid, assertion)
        return assertion

    def record(self, revision=None):
        return self.store.get(self.rid, revision)

    def claim(self, cid='a' * 32, revision=1):
        return self.store.claim(self.rid, revision, cid)

    def report(self, event, evidence=None, cid='a' * 32):
        return self.store.runner_report(self.rid, 1, cid, event, evidence or {})

    def evidence(self, **changes):
        result = {'exit': 'ok', 'marker': 'present_this_claim',
                  'pointer_sha256': self.request['target']['after_sha256'],
                  'output': 'mock_swapped_test_target', 'lock_held': False}
        result.update(changes)
        return result

    def runner(self, scenario='normal', takeover=False):
        runner = RunnerInstance(self.root, DirectTransport(self.store), self.kit,
                                self.clock, scenario=scenario, takeover_after_crash=takeover)
        self.runners.append(runner)
        return runner

    def revision(self):
        revised = copy.deepcopy(self.request)
        revised['revision'] += 1
        revised['summary_by_ai'] = 'Revised reference only'
        self.store.create_request(revised)
        return revised

    def close(self):
        for runner in self.runners:
            runner.close()
        assert all(n <= 1 for n in self.kit.swaps.values()), self.kit.swaps
        self.root.cleanup()


class Acceptance(unittest.TestCase):
    def setUp(self):
        self.worlds = []
        self.w = self.world()

    def world(self, **kwargs):
        world = World(**kwargs)
        self.worlds.append(world)
        return world

    def tearDown(self):
        for world in self.worlds:
            world.close()

    def refuses(self, code, callback, *args, **kwargs):
        with self.assertRaises(Refusal) as caught:
            callback(*args, **kwargs)
        self.assertTrue(caught.exception.code.startswith(code), caught.exception.code)
        return caught.exception
