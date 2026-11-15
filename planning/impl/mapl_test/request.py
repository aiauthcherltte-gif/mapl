"""Strict request validation and local binding reconstruction."""
import copy
import re

from .canonical import digest
from .errors import Refusal
from .isolation import NOT_COVERED, package_bytes
from .state import utc


def validate(request, root):
    v2 = isinstance(request, dict) and request.get("format") == "mapl-request/2"
    try:
        if request.get('action_type') != 'screen_publication/1':
            raise Refusal('action_type_refused')
        if not v2 and (not isinstance(request['recovery'], dict)
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
        if v2:
            required.add('check')
        if not required <= set(request) or set(request) - required - {'summary_by_ai'}:
            raise Refusal('request_invalid', 400)
        valid = ((request['format'] == 'mapl-request/1' or v2) and request['mode'] == 'test'
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
            and request['not_covered'] == list(NOT_COVERED[:3] if v2 and request['recovery'].get('included_in_this_approval') is True else NOT_COVERED)
            and isinstance(request.get('summary_by_ai', ''), str) and len(request.get('summary_by_ai', '')) <= 4096)
        if not valid:
            raise Refusal('request_invalid', 400)
        created, expiry = utc(request['created_at']), utc(request['expires_at'])
        start, end = map(utc, request['window_utc'])
        if not (created < expiry <= end and start < end and ((end - created).total_seconds() <= 604800 if v2 else (end - start).total_seconds() <= 14400)):
            raise Refusal('request_invalid', 400)
    except (KeyError, TypeError, AttributeError) as error:
        raise Refusal('request_invalid', 400) from error
    if v2:
        validate_check(request)
    return copy.deepcopy(request)


def local_request(root, request):
    rebuilt = validate(request, root)
    rebuilt['target']['before_sha256'] = digest(root.read_bytes(root.pointer()))
    after = root.read_bytes('bundles/' + request['target']['to_generation'] + '/pointer.json')
    rebuilt['target']['after_sha256'] = digest(after)
    rebuilt['bundle']['sha256'] = digest(root.read_bytes('bundles/' + request['bundle']['name'] + '/data.json'))
    rebuilt['kit']['sha256'] = digest(package_bytes('mock_kit.py'))
    if request['format'] == 'mapl-request/2':
        from .check_contract import descriptor, MOCK_K7, kit_hash
        rebuilt['check'] = descriptor(MOCK_K7)
        rebuilt['kit']['sha256'] = kit_hash()
    return rebuilt

SCOPE = ('pointer_bytes', 'pinned_reader', 'collector', 'screen')


def ordered_scope(value):
    return isinstance(value, list) and value == [x for x in SCOPE if x in value]


def validate_check(r):
    def require(value):
        if not value:
            raise Refusal('request_invalid', 400)
    try:
        c, rec = r['check'], r['recovery']
        require(set(c) == {'scope', 'recovery_eligible_codes', 'check_and_recover_max_s'})
        require(ordered_scope(c['scope']) and 'pointer_bytes' in c['scope'])
        codes, seconds = c['recovery_eligible_codes'], c['check_and_recover_max_s']
        require(isinstance(codes, list) and all(isinstance(x, str) and re.fullmatch('[A-Z_]{1,80}', x) for x in codes))
        require(codes == sorted(set(codes)))
        require(type(seconds) is int and 60 <= seconds <= 600 and seconds % 60 == 0)
        if rec['included_in_this_approval'] is False:
            require(set(rec) == {'included_in_this_approval'})
        else:
            require(rec['included_in_this_approval'] is True)
            require(set(rec) == {'included_in_this_approval', 'kind', 'restore_to_sha256', 'only_if_current_sha256', 'on', 'valid_until', 'max_runs'})
            require(rec['kind'] == 'restore_previous_pointer' and type(rec['max_runs']) is int and rec['max_runs'] == 1)
            require(rec['restore_to_sha256'] == r['target']['before_sha256'] and rec['only_if_current_sha256'] == r['target']['after_sha256'])
            require(isinstance(rec['on'], list) and rec['on'] and len(set(rec['on'])) == len(rec['on']) and all(x in codes for x in rec['on']))
            require((utc(rec['valid_until']) - utc(r['window_utc'][1])).total_seconds() == seconds)
    except (AssertionError, KeyError, TypeError, ValueError, AttributeError) as error:
        raise Refusal('request_invalid', 400) from error
