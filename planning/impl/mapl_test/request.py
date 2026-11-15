"""Strict request validation and local binding reconstruction."""
import copy
import re

from .canonical import digest
from .errors import Refusal
from .isolation import NOT_COVERED, package_bytes
from .state import utc


def validate(request, root):
    try:
        if request.get('action_type') != 'screen_publication/1':
            raise Refusal('action_type_refused')
        if (not isinstance(request['recovery'], dict)
                or set(request['recovery']) != {'included_in_this_approval'}
                or request['recovery']['included_in_this_approval'] is not False
                or not isinstance(request['not_covered'], list)
                or 'recovery' not in request['not_covered']):
            raise Refusal('scope_refused')
        target = request['target']
        if target['test_root_id'] != root.root_id:
            raise Refusal('test_root_id_mismatch')
        required = {'format', 'mode', 'request_id', 'revision', 'action_type', 'created_at',
                    'expires_at', 'window_utc', 'target', 'kit', 'bundle', 'not_covered', 'recovery'}
        if not required <= set(request) or set(request) - required - {'summary_by_ai'}:
            raise Refusal('request_invalid', 400)
        valid = (request['format'] == 'mapl-request/1' and request['mode'] == 'test'
            and isinstance(request['request_id'], str) and re.fullmatch(r'[0-9a-f]{32}', request['request_id'])
            and type(request['revision']) is int and request['revision'] >= 1
            and target['pointer'] == 'test-screen/CURRENT.json'
            and set(target) == {'pointer', 'test_root_id', 'from_generation', 'to_generation', 'before_sha256', 'after_sha256'}
            and all(isinstance(target[key], str) and re.fullmatch(r'gen/\d{4}', target[key]) for key in ('from_generation', 'to_generation'))
            and all(isinstance(target[key], str) and re.fullmatch(r'[0-9a-f]{64}', target[key]) for key in ('before_sha256', 'after_sha256'))
            and set(request['kit']) == {'name', 'sha256'} and request['kit']['name'] == 'mock-kit/1'
            and set(request['bundle']) == {'name', 'sha256'} and request['bundle']['name'] == target['to_generation']
            and all(isinstance(request[key]['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', request[key]['sha256']) for key in ('kit', 'bundle'))
            and isinstance(request['window_utc'], list) and len(request['window_utc']) == 2
            and request['not_covered'] == list(NOT_COVERED)
            and isinstance(request.get('summary_by_ai', ''), str) and len(request.get('summary_by_ai', '')) <= 4096)
        if not valid:
            raise Refusal('request_invalid', 400)
        created, expiry = utc(request['created_at']), utc(request['expires_at'])
        start, end = map(utc, request['window_utc'])
        if not (created < expiry <= end and start < end and (end - start).total_seconds() <= 14400):
            raise Refusal('request_invalid', 400)
    except (KeyError, TypeError, AttributeError) as error:
        raise Refusal('request_invalid', 400) from error
    return copy.deepcopy(request)


def local_request(root, request):
    rebuilt = validate(request, root)
    rebuilt['target']['before_sha256'] = digest(root.read_bytes(root.pointer()))
    after = root.read_bytes('bundles/' + request['target']['to_generation'] + '/pointer.json')
    rebuilt['target']['after_sha256'] = digest(after)
    rebuilt['bundle']['sha256'] = digest(root.read_bytes('bundles/' + request['bundle']['name'] + '/data.json'))
    rebuilt['kit']['sha256'] = digest(package_bytes('mock_kit.py'))
    return rebuilt
