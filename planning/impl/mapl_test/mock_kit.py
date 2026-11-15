"""Mock kit only: fake pointer, per-request O_EXCL marker, no command execution."""
from .canonical import digest
from .errors import Refusal
from .isolation import Resolved
from .state import expired, utc


class MockKit:
    def __init__(self, root, clock):
        self.root, self.clock = root, clock
        self.calls = {}
        self.swaps = {}

    def inspect(self, request, claim_id, instance_id):
        used = 'kit/used/' + request['request_id'] + '.json'
        marker = 'absent'
        if self.root.exists(used):
            try:
                stored = self.root.read_json(used)
                marker = 'present_this_claim' if isinstance(stored, dict) and stored.get('claim_id') == claim_id else 'present_other'
            except Refusal as error:
                if error.code != 'json_malformed':
                    raise
                marker = 'present_other'
        owner = self.root.read_bytes('kit/lock').decode() if self.root.exists('kit/lock') else None
        result = {'marker': marker, 'pointer_sha256': digest(self.root.read_bytes(self.root.pointer())),
                  'lock_held': owner == instance_id, 'lock_other': owner is not None and owner != instance_id,
                  'exit': None, 'output': None}
        output = 'kit/results/' + request['request_id'] + '.json'
        if self.root.exists(output):
            try:
                stored = self.root.read_json(output)
                if isinstance(stored, dict) and stored.get('claim_id') == claim_id:
                    result.update(exit=stored.get('exit'), output=stored.get('output'), code=stored.get('code'))
            except Refusal as error:
                if error.code != 'json_malformed':
                    raise
        return result

    def run(self, request, target, claim_id, instance_id, scenario='normal'):
        if not isinstance(target, Resolved) or target != self.root.pointer():
            raise Refusal('pointer_target_refused')
        rid = request['request_id']
        self.calls[rid] = self.calls.get(rid, 0) + 1
        result = {'exit': 'refused', 'output': None}
        held = False
        try:
            if scenario == 'kit_refuses':
                # Core msg_28808b171e89, pre-run §6.5 interpretation: this is
                # the kit's own explicit check refusal, raised before ANY write
                # (including lock/marker). Its result is persisted only afterward.
                raise Refusal('POINTER_BEFORE_MISMATCH')
            try:
                self.root.write_atomic('kit/lock', instance_id.encode(), exclusive=True)
                held = True
            except FileExistsError:
                result['code'] = 'KIT_LOCKED'
                return {**self.inspect(request, claim_id, instance_id), **result}
            if expired(request, self.clock()):
                raise Refusal('EXPIRED')
            if self.clock() < utc(request['window_utc'][0]):
                raise Refusal('WINDOW_NOT_OPEN')
            if digest(self.root.read_bytes(target)) != request['target']['before_sha256']:
                raise Refusal('POINTER_BEFORE_MISMATCH')
            marker = 'kit/used/' + rid + '.json'
            try:
                self.root.write_json(marker, {'claim_id': claim_id}, exclusive=True)
            except FileExistsError as error:
                raise Refusal('SINGLE_USE_MARKER_PRESENT_NO_RETRY') from error
            if scenario == 'crash_after_marker':
                raise Refusal('INJECTED_AFTER_MARKER')
            # Re-check immediately before swap as well as before the marker.
            if expired(request, self.clock()):
                raise Refusal('EXPIRED')
            if self.clock() < utc(request['window_utc'][0]):
                raise Refusal('WINDOW_NOT_OPEN')
            if digest(self.root.read_bytes(target)) != request['target']['before_sha256']:
                raise Refusal('POINTER_BEFORE_MISMATCH')
            after = self.root.read_bytes('bundles/' + request['target']['to_generation'] + '/pointer.json')
            if digest(after) != request['target']['after_sha256']:
                raise Refusal('POINTER_AFTER_MISMATCH')
            self.root.write_atomic(target, b'unclear-test-target' if scenario == 'result_unclear' else after)
            self.swaps[rid] = self.swaps.get(rid, 0) + 1
            if self.swaps[rid] > 1:
                raise Refusal('SECOND_SWAP_REFUSED')
            result = {'exit': 'ok', 'output': 'mock_swapped_test_target'}
        except Refusal as error:
            result = {'exit': 'refused', 'output': None, 'code': error.code}
        finally:
            if held:
                self.root.remove('kit/lock')
        self.root.write_json('kit/results/' + rid + '.json', {'claim_id': claim_id, **result})
        return {**self.inspect(request, claim_id, instance_id), **result}
