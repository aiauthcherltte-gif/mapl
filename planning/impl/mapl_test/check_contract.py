"""Local mock v2 check/recovery adapter. No executable or operational paths."""
import re
from .canonical import canonical_bytes, digest
from .errors import Refusal
from .isolation import package_bytes
from .state import utc

# Synthetic swap-only kit declaration; this does not describe an operational kit.
MOCK_K7 = {'scope': ['pointer_bytes', 'pinned_reader'], 'codes': {
    'CURRENT_IS_NOT_APPROVED_AFTER_BYTES': {'current_is_after': False, 'definite': True},
    'READER_INDEX_MISMATCH': {'current_is_after': True, 'definite': True},
    'INPUT_CHANGED': {'current_is_after': True, 'definite': False}}, 'check_and_recover_max_s': 600}


def descriptor(k7):
    return {'scope': list(k7['scope']), 'recovery_eligible_codes': sorted(code for code, facts in k7['codes'].items()
            if facts['current_is_after'] is True and facts['definite'] is True),
            'check_and_recover_max_s': k7['check_and_recover_max_s']}


def kit_hash():
    return digest(package_bytes('mock_kit.py') + package_bytes('check_contract.py'))


def parse_check(exit_code, stderr, k7):
    lines = stderr.splitlines() if isinstance(stderr, str) else []
    if exit_code != 3 or len(lines) != 1 or not re.fullmatch(r'STOP [A-Z_]{1,80}(?::[^\r\n]*)?', lines[0]):
        return None
    code = lines[0][5:].split(':', 1)[0]
    return code if code in k7['codes'] else None


def check(root, request):
    # Reading exact synthetic pointer and bundle only. This entry never writes.
    if digest(root.read_bytes(root.pointer())) != request['target']['after_sha256']:
        return 3, 'STOP CURRENT_IS_NOT_APPROVED_AFTER_BYTES'
    data = root.read_bytes('bundles/' + request['target']['to_generation'] + '/data.json')
    if digest(data) != request['bundle']['sha256'] or kit_hash() != request['kit']['sha256']:
        return 3, 'STOP INPUT_CHANGED'
    return 0, ''


def recover(root, request, claim_id, clock, phase):
    # A capability for this step is required in addition to the signed clause.
    if phase != 'recovery_intent' or request['format'] != 'mapl-request/2' or request['recovery']['included_in_this_approval'] is not True:
        raise Refusal('recovery_entry_refused')
    rid = request['request_id']
    if not root.exists('runner/recovery-intents/' + rid + '.json') or not root.exists('runner/journal.json'):
        raise Refusal('recovery_entry_refused')
    intent = root.read_json('runner/recovery-intents/' + rid + '.json')
    journal = root.read_json('runner/journal.json').get(rid, {})
    rows = journal.get('rows', [])
    recovery_row = next((x for x in rows if x['state'] == 'recovery_intent'), None)
    swap = next((x for x in rows if x['state'] == 'result'), None)
    if (not recovery_row or not swap or intent.get('claim_id') != claim_id or journal.get('claim_id') != claim_id
            or intent.get('instance_id') != journal.get('instance_id')
            or recovery_row['instance_id'] != intent.get('instance_id')
            or canonical_bytes(journal.get('request')) != canonical_bytes(request)
            or recovery_row['evidence'].get('code') not in request['recovery']['on']
            or (utc(recovery_row['at']) - utc(swap['at'])).total_seconds() > request['check']['check_and_recover_max_s']):
        raise Refusal('recovery_entry_refused')
    rec = request['recovery']
    if clock() > utc(rec['valid_until']) or digest(root.read_bytes(root.pointer())) != rec['only_if_current_sha256']:
        return {'exit': 'refused', 'recovery_marker': 'absent', 'pointer_sha256': digest(root.read_bytes(root.pointer()))}
    before = root.read_bytes('bundles/' + request['target']['from_generation'] + '/pointer.json')
    if digest(before) != rec['restore_to_sha256'] or request['kit']['sha256'] != kit_hash():
        raise Refusal('CONTENT_MISMATCH')
    root.write_json('kit/recovery/' + request['request_id'] + '.json', {'claim_id': claim_id}, exclusive=True)
    if clock() > utc(rec['valid_until']) or digest(root.read_bytes(root.pointer())) != rec['only_if_current_sha256']:
        raise Refusal('EXPIRED')
    root.write_atomic(root.pointer(), before)
    evidence = {'recovery_claim_id': claim_id, 'recovery_status': 'restored_pointer_exact', 'pointer_sha256': digest(root.read_bytes(root.pointer()))}
    root.write_json('kit/recovery-results/' + request['request_id'] + '.json', evidence, exclusive=True)
    return evidence
