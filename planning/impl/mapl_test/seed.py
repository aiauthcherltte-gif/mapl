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
    return seed_existing(root, store, now, scenario)


def seed_existing(root, store, now, scenario='normal', v2=False):
    """Build another immutable request without resetting any prepared bytes."""
    from .check_contract import MOCK_K7, descriptor, kit_hash
    from .request import validate
    pointers = {}
    for generation in ('gen/0005', 'gen/0006'):
        data = canonical_bytes({'fixture': 'mapl-test-only', 'generation': generation,
                                'rows': [{'label': '시험 자료', 'value': generation[-1]}]})
        pointer = canonical_bytes({'format': 'mapl-test-pointer/1', 'generation': generation,
                                   'bundle_sha256': digest(data)})
        if (root.read_bytes('bundles/' + generation + '/data.json') != data
                or root.read_bytes('bundles/' + generation + '/pointer.json') != pointer):
            raise ValueError('prepared mock bundle changed')
        pointers[generation] = pointer
    current = root.read_bytes(root.pointer())
    matches = [generation for generation, pointer in pointers.items() if pointer == current]
    if len(matches) != 1:
        raise ValueError('current pointer is not a prepared mock generation')
    before = matches[0]
    after = next(generation for generation in pointers if generation != before)
    start = now + timedelta(minutes=10) if scenario == 'window_later' else now
    request = {'format': 'mapl-request/1', 'mode': 'test', 'request_id': secrets.token_hex(16),
        'revision': 1, 'action_type': 'screen_publication/1', 'created_at': stamp(now),
        'expires_at': stamp(now + timedelta(hours=2)),
        'window_utc': [stamp(start), stamp(now + timedelta(hours=2))],
        'target': {'pointer': 'test-screen/CURRENT.json', 'test_root_id': root.root_id,
            'from_generation': before, 'to_generation': after,
            'before_sha256': digest(pointers[before]), 'after_sha256': digest(pointers[after])},
        'kit': {'name': 'mock-kit/1', 'sha256': digest(package_bytes('mock_kit.py'))},
        'bundle': {'name': after, 'sha256': digest(root.read_bytes('bundles/' + after + '/data.json'))},
        'not_covered': list(NOT_COVERED), 'recovery': {'included_in_this_approval': False},
        'summary_by_ai': '시험 자료에 대한 참고 문구입니다.'}
    if v2:
        request['format'] = 'mapl-request/2'
        request['check'] = descriptor(MOCK_K7)
        request['kit']['sha256'] = kit_hash()
        request['not_covered'] = list(NOT_COVERED[:3])
        request['recovery'] = {'included_in_this_approval': True,
            'kind': 'restore_previous_pointer',
            'restore_to_sha256': request['target']['before_sha256'],
            'only_if_current_sha256': request['target']['after_sha256'],
            'on': list(request['check']['recovery_eligible_codes']),
            'valid_until': stamp(now + timedelta(hours=2, seconds=request['check']['check_and_recover_max_s'])),
            'max_runs': 1}
    validate(request, root)
    store.create_request(request)
    # create_request freezes a local baseline, including time and scope, for
    # independent runner reconstruction. It is not rewritten after approval.
    return request
