"""W3 adapter. Prepare marked mock state offline; start only after human review.

Never accepts operational kits, ledger targets, setup/recovery codes or accounts.
"""
import argparse
from datetime import datetime, timezone
import json
import os
import secrets
import tempfile
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from planning.impl.mapl_test.isolation import TestRoot
from planning.impl.mapl_test.mock_kit import MockKit
from planning.impl.mapl_test.canonical import canonical_bytes, digest
from planning.impl.mapl_test.seed import seed, seed_existing
from planning.impl.mapl_cloudflare.runner import MacRunner
from planning.impl.mapl_cloudflare.transport import HTTPSTransport


def configured_origin():
    profile = json.loads((REPO / 'deploy-profile.json').read_text())
    sub = profile['SUBDOMAIN']
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', sub):
        raise ValueError('subdomain placeholder must be reviewed first')
    return 'https://mapl-test.' + sub + '.workers.dev'


def outside_sync(path):
    from planning.impl.mapl_test.isolation import FORBIDDEN_PATHS
    return not any(part.lower() in str(path).lower() for part in FORBIDDEN_PATHS)


class Baseline:
    def __init__(self, root): self.root = root
    def create_request(self, request):
        self.root.write_json('runner/manifests/' + request['request_id'] + '/1.json', request, exclusive=True)


def pristine(root, data):
    """Accept only seed output, never read server credentials or token files.

    Any submission attempt permanently ends offline reseeding, since approval
    on the remote Worker cannot be observed without credentials/network.
    Enumeration uses only the reopened, marker-checked test-root descriptor.
    """
    request = data['request']
    if set(data) != {'mode', 'root', 'root_id', 'request'}:
        raise ValueError('unexpected state')
    request_keys = {'format', 'mode', 'request_id', 'revision', 'action_type', 'created_at',
                    'expires_at', 'window_utc', 'target', 'kit', 'bundle', 'not_covered',
                    'recovery', 'summary_by_ai'}
    if set(request) != request_keys:
        raise ValueError('unexpected request state')
    target = request['target']
    if (request['mode'] != 'test' or target['test_root_id'] != root.root_id
            or target['pointer'] != 'test-screen/CURRENT.json'
            or target['from_generation'] != 'gen/0005' or target['to_generation'] != 'gen/0006'):
        raise ValueError('request root mismatch')
    allowed = {'.mapl3-test-root', 'test-screen/CURRENT.json',
               'runner/process-guard', 'runner/process-lock'}
    for generation in ('gen/0005', 'gen/0006'):
        prefix = 'bundles/' + generation + '/'
        bundle = canonical_bytes({'fixture': 'mapl-test-only', 'generation': generation,
                                  'rows': [{'label': '시험 자료', 'value': generation[-1]}]})
        pointer = canonical_bytes({'format': 'mapl-test-pointer/1', 'generation': generation,
                                   'bundle_sha256': digest(bundle)})
        if root.read_bytes(prefix + 'data.json') != bundle or root.read_bytes(prefix + 'pointer.json') != pointer:
            raise ValueError('seed bundle changed')
        if generation == 'gen/0005':
            if root.read_bytes(root.pointer()) != pointer or target['before_sha256'] != digest(pointer):
                raise ValueError('original generation required')
        allowed.update({prefix + 'data.json', prefix + 'pointer.json'})
    # Explicit allow-list: an approval store, kit marker/result, runner journal,
    # claim intent, submission marker, unexpected file or symlink all refuse.
    def walk(fd, prefix=''):
        root._check()
        for name in os.listdir(fd):
            relative = prefix + name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                if not (relative in ('bundles', 'bundles/gen', 'bundles/gen/0005',
                                     'bundles/gen/0006', 'test-screen', 'runner', 'runner/manifests')
                        or re.fullmatch(r'runner/manifests/[0-9a-f]{32}', relative)):
                    raise ValueError('non-pristine root')
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try: walk(child, relative + '/')
                finally: os.close(child)
            elif (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                  or (relative not in allowed and not re.fullmatch(r'runner/manifests/[0-9a-f]{32}/1.json', relative))):
                raise ValueError('non-pristine root')
            elif relative.startswith('runner/manifests/'):
                manifest = root.read_json(relative)
                if (set(manifest) != set(request) or manifest['target'] != target
                        or manifest['mode'] != 'test' or manifest['revision'] != 1
                        or manifest['request_id'] != relative.split('/')[2]):
                    raise ValueError('manifest mismatch')
    walk(root._fd)
    if root.read_json('runner/manifests/' + request['request_id'] + '/1.json') != request:
        raise ValueError('state manifest mismatch')


def replace_public_state(path, original, data):
    # Keep a unique, exclusive backup alongside the atomically replaced state.
    backup = path.with_name(path.name + '.previous-' + secrets.token_hex(16) + '.json')
    with backup.open('xb') as f:
        f.write(original)
        f.flush()
        os.fsync(f.fileno())
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.tmp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        if path.read_bytes() != original:
            raise ValueError('state changed')
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def reseed(state, data, clock):
    original = state.read_bytes()
    if json.loads(original) != data:
        raise ValueError('state changed')
    root = TestRoot.reopen_for_runner_test(data['root'], data['root_id'])
    instance = secrets.token_hex(16)
    held = False
    try:
        root.acquire_process_runner_lock(instance)
        held = True
        pristine(root, data)
        request = seed(root, Baseline(root), clock())
        if request['request_id'] == data['request']['request_id']:
            raise ValueError('fresh request required')
        replace_public_state(state, original, {**data, 'request': request})
    finally:
        if held: root.release_process_runner_lock(instance)
        root.detach_runner_test()
    print(json.dumps({'request_id': request['request_id'], 'expires_at': request['expires_at']}))


def device_request(state, data, purpose, clock):
    """Keep each device-check request stable across submission retries.

    Does not reseed or overwrite target bytes, prior manifests, or approval state.
    Both requests bind the actual current generation before the next runner swap.
    """
    original = state.read_bytes()
    if json.loads(original) != data:
        raise ValueError('state changed')
    root = TestRoot.reopen_for_runner_test(data['root'], data['root_id'])
    instance, held = secrets.token_hex(16), False
    try:
        root.acquire_process_runner_lock(instance)
        held = True
        from planning.impl.mapl_test.request import validate, local_request
        baseline = data['request']
        validate(baseline, root)
        if root.read_json('runner/manifests/' + baseline['request_id'] + '/1.json') != baseline:
            raise ValueError('state manifest mismatch')
        requests = dict(data.get('device_requests', {}))
        if set(requests) - {'v2', 'withdraw-target'}:
            raise ValueError('unexpected device requests')
        if purpose not in requests:
            requests[purpose] = seed_existing(root, Baseline(root), clock(), v2=purpose == 'v2')
            data = {**data, 'device_requests': requests}
            replace_public_state(state, original, data)
        request = requests[purpose]
        validate(request, root)
        if (root.read_json('runner/manifests/' + request['request_id'] + '/1.json') != request
                or canonical_bytes(local_request(root, request)) != canonical_bytes(request)):
            raise ValueError('device request mismatch')
        return data, request
    finally:
        if held: root.release_process_runner_lock(instance)
        root.detach_runner_test()


def mark_submission(data):
    root = TestRoot.reopen_for_runner_test(data['root'], data['root_id'])
    instance = secrets.token_hex(16)
    held = False
    try:
        root.acquire_process_runner_lock(instance)
        held = True
        marker = {'request_id': data['request']['request_id']}
        # Preserve the original submission guard byte-for-byte; retain each new
        # request in its own exclusive marker, including failed/uncertain sends.
        if not root.exists('runner/submission-attempted.json'):
            root.write_json('runner/submission-attempted.json', marker, exclusive=True)
        path = 'runner/submission-attempts/' + marker['request_id'] + '.json'
        if root.exists(path):
            if root.read_json(path) != marker:
                raise ValueError('submission marker mismatch')
        else:
            root.write_json(path, marker, exclusive=True)
    finally:
        if held: root.release_process_runner_lock(instance)
        root.detach_runner_test()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'reseed', 'submit', 'submit-v2', 'submit-withdraw-target', 'start'])
    parser.add_argument('--state', type=Path, required=True, help='public mock state metadata, outside sync')
    parser.add_argument('--token-dir', type=Path, default=Path(os.environ['MAPL_TOKEN_DIR']) if os.environ.get('MAPL_TOKEN_DIR') else None, help='private role token directory (0600 files)')
    parser.add_argument('--public-pin', type=Path, help='user-reviewed public credential JSON: id and spki only')
    args = parser.parse_args()
    if not outside_sync(args.state.resolve()): parser.error('state must be outside sync')
    clock = lambda: datetime.now(timezone.utc).replace(microsecond=0)
    if args.action == 'prepare':
        root = TestRoot.create()
        try:
            request = seed(root, Baseline(root), clock())
            data = {'mode':'test', 'root':root.path, 'root_id':root.root_id, 'request':request}
            with args.state.open('x') as f: json.dump(data,f,indent=2)
        finally: root.detach_runner_test()
        print('Offline mock root prepared; review root_id and use it as TEST_ROOT_ID before deployment.')
        return
    if args.state.is_symlink() or not args.state.is_file() or args.state.stat().st_nlink != 1:
        parser.error('regular public state file required')
    data = json.loads(args.state.read_text())
    profile = json.loads((REPO / 'deploy-profile.json').read_text())
    if data['mode'] != 'test' or profile.get('TEST_ROOT_ID') != data['root_id']:
        parser.error('reviewed deployment TEST_ROOT_ID must match prepared mock root')
    if args.action == 'reseed':
        reseed(args.state, data, clock)
        return
    origin = configured_origin()
    if args.token_dir is None: parser.error('set MAPL_TOKEN_DIR or pass --token-dir')
    submitting = args.action in ('submit', 'submit-v2', 'submit-withdraw-target')
    role = 'requester' if submitting else 'runner'
    token_path = (args.token_dir / (role + '.token')).resolve()
    if not outside_sync(token_path) or stat.S_IMODE(token_path.stat().st_mode) != 0o600:
        parser.error('token file must be outside sync with mode 0600')
    if submitting:
        purpose = {'submit-v2': 'v2', 'submit-withdraw-target': 'withdraw-target'}.get(args.action)
        if purpose:
            data, request = device_request(args.state, data, purpose, clock)
        else:
            request = data['request']
        mark_submission({**data, 'request': request})
        result = subprocess.run(['node', str(REPO / 'scripts/submit-request.mjs'), str(args.state)] + ([purpose] if purpose else []), input=token_path.read_text().strip(), text=True, capture_output=True, cwd=REPO)
        if result.returncode: raise ValueError('Test requester submission refused')
        print(json.dumps({'request_id': request['request_id'], 'format': request['format'], 'purpose': purpose or 'original', 'expires_at': request['expires_at']}))
        print('Test request submitted; approval and withdrawal require the user on iPhone.')
        return
    if not args.public_pin: parser.error('reviewed public key pin required')
    pin = json.loads(args.public_pin.read_text())
    if set(pin) != {'id','spki'}: parser.error('public pin must contain id and spki only')
    root = TestRoot.reopen_for_runner_test(data['root'], data['root_id'])
    runner = None
    try:
        if not root.exists('runner/pinned-credential.json'):
            root.write_json('runner/pinned-credential.json',pin,exclusive=True)
        elif root.read_json('runner/pinned-credential.json') != pin:
            parser.error('pin change refused')
        transport = HTTPSTransport(origin,token_path.read_text().strip())
        runner = MacRunner(root,transport,MockKit(root,clock),clock)
        stop = threading.Event()
        for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,lambda *_: stop.set())
        runner.run(stop)
    finally:
        if runner: runner.close()
        root.detach_runner_test()

if __name__ == '__main__':
    try: main()
    except Exception:
        print('Mock Mac refused; check private file permissions, reviewed state and public pin.', file=sys.stderr)
        sys.exit(1)
