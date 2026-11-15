"""Generate fake bytes rather than reading/copying any operational artifact."""
import secrets
from datetime import timedelta

from .canonical import canonical_bytes, digest
from .isolation import NOT_COVERED, package_bytes
from .state import stamp


def seed(root, store, now, scenario='normal'):
    pointers = {}
    for generation in ('gen/0005', 'gen/0006'):
        data = canonical_bytes({'fixture': 'mapl-test-only', 'generation': generation,
                                'rows': [{'label': '시험 자료', 'value': generation[-1]}]})
        root.write_atomic('bundles/' + generation + '/data.json', data)
        pointers[generation] = canonical_bytes({'format': 'mapl-test-pointer/1', 'generation': generation,
                                               'bundle_sha256': digest(data)})
        root.write_atomic('bundles/' + generation + '/pointer.json', pointers[generation])
    root.write_atomic(root.pointer(), pointers['gen/0005'])
    start = now + timedelta(minutes=10) if scenario == 'window_later' else now
    request = {'format': 'mapl-request/1', 'mode': 'test', 'request_id': secrets.token_hex(16),
        'revision': 1, 'action_type': 'screen_publication/1', 'created_at': stamp(now),
        'expires_at': stamp(now + timedelta(hours=2)),
        'window_utc': [stamp(start), stamp(now + timedelta(hours=2))],
        'target': {'pointer': 'test-screen/CURRENT.json', 'test_root_id': root.root_id,
            'from_generation': 'gen/0005', 'to_generation': 'gen/0006',
            'before_sha256': digest(pointers['gen/0005']), 'after_sha256': digest(pointers['gen/0006'])},
        'kit': {'name': 'mock-kit/1', 'sha256': digest(package_bytes('mock_kit.py'))},
        'bundle': {'name': 'gen/0006', 'sha256': digest(root.read_bytes('bundles/gen/0006/data.json'))},
        'not_covered': list(NOT_COVERED), 'recovery': {'included_in_this_approval': False},
        'summary_by_ai': '시험 자료에 대한 참고 문구입니다.'}
    store.create_request(request)
    # create_request freezes a local baseline, including time and scope, for
    # independent runner reconstruction. It is not rewritten after approval.
    return request
