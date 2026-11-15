# Coordinator msg_cb8b39c9e6f2 (recorded before the acceptance-tests commit):
# External resolve keeps the lowercase grammar. Only pointer() will mint the
# fixed test-screen/CURRENT.json capability after confinement/symlink checks.
# The tests-only source audit will read .py/.html/.js/.css inside this package,
# refuse symlinks and remain unreachable from server/runner entry points.
# Runtime package reads stay restricted to the exact four-file allow-list.
"""Exclusive filesystem capability boundary, including reads and fault injection."""
import ast
import fcntl
import hmac
import os
import re
import secrets
import shutil
import stat
import tempfile
import threading
import weakref
from dataclasses import dataclass

from .canonical import canonical_bytes, parse_json
from .errors import Refusal

DENY = ('/Drives/SYNC/WORK/', '/.worktrees/', 'screen-current', 'ledger', '.sqlite', '.db', '-wal', '-shm')
NOT_COVERED = ('ledger write', 'service start', 'collector restart', 'recovery')
RUNTIME_READS = frozenset(('mock_kit.py', 'static/index.html', 'static/app.js', 'static/app.css'))
_PACKAGE = os.path.realpath(os.path.dirname(__file__))
_MINT = object()
_PATH = re.compile(r'[a-z0-9][a-z0-9_.-]*(/[a-z0-9][a-z0-9_.-]*)*\Z')
_PACKAGE_PATH = re.compile(r'[a-z0-9_][a-z0-9_.-]*(/[a-z0-9_][a-z0-9_.-]*)*\Z')
# Used only by the two-root symlink fault helper, never runtime resolution.
_TEST_CAPABILITIES = weakref.WeakValueDictionary()


def validate_base(base):
    resolved = os.path.realpath(base)
    if not (resolved.startswith('/private/var/folders/') or resolved == '/private/tmp'
            or resolved.startswith('/private/tmp/')) or any(word in resolved for word in DENY):
        raise Refusal('root_base_refused')
    return resolved


@dataclass(frozen=True)
class Resolved:
    relative: str
    _owner: object
    _mint: object


class TestRoot:
    __test__ = False

    def __init__(self, mint, path, marker):
        if mint is not _MINT:
            raise Refusal('root_creation_refused')
        self.path = path
        self.root_id = marker
        self._owner = object()
        self._lock = threading.RLock()
        self._closed = False
        self._fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._identity = os.fstat(self._fd)
        fd = os.open('.mapl3-test-root', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self._fd)
        try:
            os.write(fd, marker.encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self._fd)
        self._crashed_runners = set()
        _TEST_CAPABILITIES[self._owner] = self

    @classmethod
    def create(cls):
        # M1: never let tempfile select a parent from environment variables.
        try:
            base = os.confstr('CS_DARWIN_USER_TEMP_DIR')
        except (ValueError, OSError):
            # Darwin unistd.h: _CS_DARWIN_USER_TEMP_DIR = 65537. CPython
            # 3.13 omits the string key, but accepts this native confstr id.
            # The OS still chooses the base, never tempfile or shell settings.
            try:
                base = os.confstr(65537)
            except (ValueError, OSError):
                base = '/private/tmp/'
        if not base:
            raise Refusal('root_base_refused')
        base = validate_base(base)
        configured = os.environ.get('TMPDIR')
        if configured and os.path.realpath(configured) != base:
            raise Refusal('tmpdir_mismatch')
        path = os.path.realpath(tempfile.mkdtemp(prefix='mapl3-test-', dir=base))
        if not path.startswith(base.rstrip('/') + '/') or any(word in path for word in DENY):
            raise Refusal('root_base_refused')
        return cls(_MINT, path, secrets.token_hex(16))

    def _check(self):
        try:
            if self._closed:
                raise OSError('closed')
            info = os.lstat(self.path)
            if stat.S_ISLNK(info.st_mode) or (info.st_dev, info.st_ino) != (self._identity.st_dev, self._identity.st_ino):
                raise OSError('root_changed')
            fd = os.open('.mapl3-test-root', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._fd)
            try:
                actual = os.read(fd, 129)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise OSError('marker_kind')
            finally:
                os.close(fd)
            if not hmac.compare_digest(actual, self.root_id.encode()):
                raise OSError('marker_changed')
        except OSError as error:
            raise Refusal('test_root_marker_mismatch') from error

    def _relative(self, value):
        if isinstance(value, Resolved):
            if value._mint is not _MINT or value._owner is not self._owner:
                raise Refusal('path_refused')
            return value.relative
        if not isinstance(value, str) or not _PATH.fullmatch(value) or '..' in value:
            raise Refusal('path_refused')
        if value.split('/')[-1] == 'current.json':
            raise Refusal('path_refused')
        if any(word in '/' + value for word in DENY):
            raise Refusal('path_refused')
        return value

    def _walk_check(self, relative):
        target = os.path.join(self.path, relative)
        current = self.path
        for part in relative.split('/'):
            current = os.path.join(current, part)
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode):
                raise Refusal('symlink_refused')
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise Refusal('hardlink_refused')
        if not os.path.realpath(target).startswith(self.path + '/') or any(word in target for word in DENY):
            raise Refusal('path_refused')
        return target

    def resolve(self, relative):
        with self._lock:
            self._check()
            relative = self._relative(relative)
            self._walk_check(relative)
            return Resolved(relative, self._owner, _MINT)

    def pointer(self):
        # Coordinator msg_cb8b39c9e6f2: this exact fixed uppercase name only.
        with self._lock:
            self._check()
            relative = 'test-screen/CURRENT.json'
            self._walk_check(relative)
            return Resolved(relative, self._owner, _MINT)

    def _parent(self, relative, create=False):
        fd = os.dup(self._fd)
        try:
            parts = relative.split('/')
            for component in parts[:-1]:
                if create:
                    self._check()
                    try:
                        os.mkdir(component, 0o700, dir_fd=fd)
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                try:
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except OSError as error:
                    raise Refusal('symlink_refused') from error
                os.close(fd)
                fd = child
            return fd, parts[-1]
        except BaseException:
            os.close(fd)
            raise

    def read_bytes(self, value):
        with self._lock:
            capability = self.resolve(value)
            fd, name = self._parent(capability.relative)
            try:
                self._check()
                file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    info = os.fstat(file_fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 8 * 1024 * 1024:
                        raise Refusal('file_kind_refused')
                    chunks = []
                    while True:
                        data = os.read(file_fd, 65536)
                        if not data:
                            break
                        chunks.append(data)
                    return b''.join(chunks)
                finally:
                    os.close(file_fd)
            finally:
                os.close(fd)

    def exists(self, value):
        with self._lock:
            capability = self.resolve(value)
            # resolve checks the marker and every existing component first.
            return os.path.lexists(os.path.join(self.path, capability.relative))

    def write_atomic(self, value, data, exclusive=False):
        if not isinstance(data, bytes):
            raise Refusal('bytes_required')
        with self._lock:
            capability = self.resolve(value)
            fd, name = self._parent(capability.relative, create=True)
            temporary = None
            try:
                self._check()
                if exclusive:
                    # Markers/locks must be O_EXCL at their final name. The root
                    # lock serializes in-process writers; fsync completes before return.
                    output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                else:
                    temporary = 'tmp-' + secrets.token_hex(16)
                    output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                try:
                    offset = 0
                    while offset < len(data):
                        offset += os.write(output, data[offset:])
                    os.fsync(output)
                finally:
                    os.close(output)
                self._check()
                self._walk_check(capability.relative)
                if temporary:
                    os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
                    temporary = None
                os.fsync(fd)
            finally:
                if temporary:
                    self._check()
                    os.unlink(temporary, dir_fd=fd)
                os.close(fd)

    def read_json(self, value):
        return parse_json(self.read_bytes(value))

    def write_json(self, value, data, exclusive=False):
        self.write_atomic(value, canonical_bytes(data), exclusive=exclusive)

    def remove(self, value):
        with self._lock:
            capability = self.resolve(value)
            fd, name = self._parent(capability.relative)
            try:
                self._check()
                os.unlink(name, dir_fd=fd)
                os.fsync(fd)
            finally:
                os.close(fd)

    def cleanup(self):
        with self._lock:
            self._check()
            if not shutil.rmtree.avoids_symlink_attacks:
                raise Refusal('cleanup_not_symlink_safe')
            shutil.rmtree(self.path)
            os.close(self._fd)
            self._closed = True

    def acquire_runner_lock(self, instance_id, takeover_after_crash=False):
        with self._lock:
            self._check()
            if self.exists('runner/lock'):
                previous = self.read_bytes('runner/lock').decode('ascii')
                if not takeover_after_crash or previous not in self._crashed_runners:
                    raise Refusal('runner_locked')
                self.remove('runner/lock')
                self._crashed_runners.remove(previous)
            self.write_atomic('runner/lock', instance_id.encode(), exclusive=True)

    def mark_runner_crash(self, instance_id):
        with self._lock:
            self._check()
            if self.read_bytes('runner/lock') != instance_id.encode():
                raise Refusal('runner_lock_mismatch')
            self._crashed_runners.add(instance_id)

    def release_runner_lock(self, instance_id):
        with self._lock:
            self._check()
            if self.exists('runner/lock') and self.read_bytes('runner/lock') == instance_id.encode():
                self.remove('runner/lock')

    @classmethod
    def reopen_for_runner_test(cls, path, root_id):
        """Reattach only a marked, OS-temp test root for process restart tests.

        No marker is created/replaced, and no operational directory is accepted.
        The creator retains ownership of cleanup; children must only detach.
        """
        parent, name = os.path.split(path)
        if (validate_base(parent) != parent or not re.fullmatch(r'mapl3-test-[a-z0-9_]+', name)
                or not re.fullmatch(r'[0-9a-f]{32}', root_id)):
            raise Refusal('root_base_refused')
        root = object.__new__(cls)
        root.path, root.root_id, root._owner = path, root_id, object()
        root._lock, root._closed, root._crashed_runners = threading.RLock(), False, set()
        root._fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root._identity = os.fstat(root._fd)
        try:
            root._check()
        except BaseException:
            os.close(root._fd)
            raise
        _TEST_CAPABILITIES[root._owner] = root
        return root

    def detach_runner_test(self):
        with self._lock:
            self._check()
            os.close(self._fd)
            self._closed = True

    def _process_lock_guard(self):
        """Kernel-released guard serializes takeover against acquire/release."""
        self._check()
        fd, name = self._parent('runner/process-guard', create=True)
        try:
            guard = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        finally:
            os.close(fd)
        try:
            info = os.fstat(guard)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise Refusal('file_kind_refused')
            fcntl.flock(guard, fcntl.LOCK_EX)
            self._check()
            return guard
        except BaseException:
            os.close(guard)
            raise

    def acquire_process_runner_lock(self, instance_id, takeover_after_crash=False):
        with self._lock:
            guard = self._process_lock_guard()
            try:
                if self.exists('runner/process-lock'):
                    previous = self.read_json('runner/process-lock')
                    if not takeover_after_crash:
                        raise Refusal('runner_locked')
                    pid = previous.get('pid')
                    if type(pid) is not int or pid < 1:
                        raise Refusal('runner_lock_invalid')
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        pass
                    except PermissionError as error:
                        raise Refusal('runner_locked') from error
                    else:
                        raise Refusal('runner_locked')
                    # Explicit takeover removes ONLY the lock. In particular,
                    # request records and the journal remain byte-for-byte intact.
                    self.remove('runner/process-lock')
                self.write_json('runner/process-lock', {'pid': os.getpid(), 'instance_id': instance_id}, exclusive=True)
            finally:
                os.close(guard)

    def release_process_runner_lock(self, instance_id):
        with self._lock:
            guard = self._process_lock_guard()
            try:
                if (self.exists('runner/process-lock')
                        and self.read_json('runner/process-lock').get('instance_id') == instance_id):
                    self.remove('runner/process-lock')
            finally:
                os.close(guard)

    # Fault helpers are never called by the app. They only act on minted roots.
    def inject_marker_fault_for_tests(self, mode):
        with self._lock:
            self._check()
            if mode == 'missing':
                os.unlink('.mapl3-test-root', dir_fd=self._fd)
            elif mode == 'changed':
                fd = os.open('.mapl3-test-root', os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, dir_fd=self._fd)
                try:
                    os.write(fd, b'wrong-test-marker')
                    os.fsync(fd)
                finally:
                    os.close(fd)
            else:
                raise Refusal('fault_refused')
            os.fsync(self._fd)

    def restore_marker_for_tests(self):
        # Special repair capability for a marker deliberately damaged by this
        # object's test helper; cannot choose a path or attach an existing root.
        with self._lock:
            info = os.lstat(self.path)
            if (info.st_dev, info.st_ino) != (self._identity.st_dev, self._identity.st_ino):
                raise Refusal('test_root_marker_mismatch')
            fd = os.open('.mapl3-test-root', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600, dir_fd=self._fd)
            try:
                os.write(fd, self.root_id.encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(self._fd)

    def inject_symlink_for_tests(self, relative, other):
        with self._lock:
            capability = self.resolve(relative)
            if not isinstance(other, Resolved) or other._mint is not _MINT:
                raise Refusal('fault_refused')
            # Link only to another minted test root, never an arbitrary host path.
            # The mapping is supplied by the fixture through a private registry.
            other_root = _TEST_CAPABILITIES.get(other._owner)
            if other_root is None:
                raise Refusal('fault_refused')
            other_root._check()
            target = other_root._walk_check(other.relative)
            fd, name = self._parent(capability.relative, create=True)
            try:
                os.symlink(target, name, dir_fd=fd)
                os.fsync(fd)
            finally:
                os.close(fd)


def _package_file(relative, allowed):
    if relative not in allowed or not isinstance(relative, str) or not _PACKAGE_PATH.fullmatch(relative) or '..' in relative:
        raise Refusal('package_read_refused')
    target = os.path.join(_PACKAGE, relative)
    if not os.path.realpath(target).startswith(_PACKAGE + '/'):
        raise Refusal('package_read_refused')
    current = _PACKAGE
    for part in relative.split('/'):
        current = os.path.join(current, part)
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise Refusal('package_read_refused')
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 2 * 1024 * 1024:
            raise Refusal('package_read_refused')
        chunks = []
        while True:
            data = os.read(fd, 65536)
            if not data:
                return b''.join(chunks)
            chunks.append(data)
    finally:
        os.close(fd)


def package_bytes(relative):
    """Runtime read-only resolver: exactly four immutable package assets."""
    return _package_file(relative, RUNTIME_READS)


def audit_file_for_tests(relative):
    # Coordinator msg_cb8b39c9e6f2: tests-only package-confined read exception.
    # No runtime module calls this helper or the source-audit entry points.
    if not isinstance(relative, str) or not relative.endswith(('.py', '.html', '.js', '.css')):
        raise Refusal('package_read_refused')
    return _package_file(relative, {relative}).decode('utf-8')


def audit_sources_for_tests():
    result = {}
    for folder, directories, files in os.walk(_PACKAGE, followlinks=False):
        directories[:] = [name for name in directories if name != '__pycache__']
        for name in directories:
            if stat.S_ISLNK(os.lstat(os.path.join(folder, name)).st_mode):
                raise Refusal('package_read_refused')
        for name in files:
            if name.endswith(('.py', '.html', '.js', '.css')):
                relative = os.path.relpath(os.path.join(folder, name), _PACKAGE).replace(os.sep, '/')
                result[relative] = audit_file_for_tests(relative)
    return result


_FS_CALLS = frozenset(('open', 'io.open', 'os.open', 'os.write', 'os.read', 'os.fdopen', 'os.truncate',
    'os.chmod', 'os.fchmod', 'os.replace', 'os.rename', 'os.remove', 'os.unlink', 'os.mkdir', 'os.makedirs',
    'os.rmdir', 'os.symlink', 'os.link', 'tempfile.mkstemp', 'tempfile.NamedTemporaryFile', 'tempfile.mkdtemp',
    'os.listdir', 'os.scandir', 'os.walk', 'os.lstat', 'os.stat'))
_PATH_CALLS = frozenset(('open', 'read_text', 'read_bytes', 'write_text', 'write_bytes', 'unlink',
    'mkdir', 'touch', 'rename', 'replace', 'rmdir', 'chmod', 'symlink_to', 'hardlink_to', 'iterdir', 'glob', 'rglob'))
_BANNED_IMPORTS = ('sqlite3', 'subprocess', 'multiprocessing', 'ctypes', 'socket', 'urllib.request',
    'importlib', 'runpy', 'pickle', 'marshal', 'ssl', 'glob', 'alert', 'write_service', 'approval_client')


def audit_text_for_tests(source, module='candidate.py'):
    """Conservative provenance guard; strings/comments never count as I/O."""
    tree = ast.parse(source)
    aliases = {}
    bindings = {}
    imports = []
    result = {'filesystem': [], 'forbidden': []}

    def raw_name(node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return raw_name(node.value) + '.' + node.attr
        return '?'

    def bind(target, value):
        if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)):
            for child, item in zip(target.elts, value.elts):
                bind(child, item)
        elif isinstance(target, (ast.Name, ast.Attribute)):
            bindings.setdefault(raw_name(target), []).append(value)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
                imports.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            prefix = node.module or ''
            if node.level:
                package = ('planning.impl.mapl_test.' + module.removesuffix('.py').replace('/', '.')).split('.')[:-1]
                package = package[:len(package) - node.level + 1]
                prefix = '.'.join(package + ([prefix] if prefix else []))
            for alias in node.names:
                aliases[alias.asname or alias.name] = prefix + '.' + alias.name
                imports.append((node.lineno, prefix + '.' + alias.name))
                if alias.name == '*':
                    result['forbidden'].append((node.lineno, 'wildcard import'))
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, node.value)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
            bind(node.target, node.value)

    def qualified(node, seen=frozenset()):
        key = raw_name(node)
        names = set()
        if isinstance(node, ast.Name):
            names.add(aliases.get(node.id, node.id))
        elif isinstance(node, ast.Attribute):
            names.update(name + '.' + node.attr for name in qualified(node.value, seen))
        elif isinstance(node, ast.Call):
            names.update(name + '()' for name in qualified(node.func, seen))
        elif isinstance(node, ast.BinOp):
            # Path / component keeps the Path capability.
            names.update(qualified(node.left, seen))
        if key != '?' and key not in seen:
            for value in bindings.get(key, ()):
                names.update(qualified(value, seen | {key}))
        return names or {'?'}

    for line, imported in imports:
        if any(imported == name or imported.startswith(name + '.') for name in _BANNED_IMPORTS):
            result['forbidden'].append((line, imported))
        if (imported.startswith('planning.impl.')
            and imported != 'planning.impl.mapl_test' and not imported.startswith('planning.impl.mapl_test.')):
            result['forbidden'].append((line, imported))
        if imported.startswith('http.client') and module != 'runner_sim.py':
            result['forbidden'].append((line, imported))
        if imported.startswith('cryptography') and module not in ('webauthn_verify.py', 'tests/soft_authenticator.py'):
            result['forbidden'].append((line, imported))

    for node in ast.walk(tree):
        # ISO-1's executable-code check: prose mentioning settings is harmless.
        if isinstance(node, (ast.Name, ast.Attribute)) and 'os.environ' in qualified(node):
            result['forbidden'].append((node.lineno, 'os.environ'))
        if isinstance(node, ast.Call):
            for name in sorted(qualified(node.func)):
                if name.startswith('builtins.'):
                    name = name[len('builtins.'):]
                is_path = name.startswith(('pathlib.Path', 'pathlib.PosixPath', 'pathlib.WindowsPath', 'Path')) and name.rsplit('.', 1)[-1] in _PATH_CALLS
                if name in _FS_CALLS or name.startswith('shutil.') or is_path:
                    result['filesystem'].append((node.lineno, name))
                if (name in ('__import__', 'exec', 'eval', 'compile', 'getattr', 'setattr', 'delattr', 'os.getenv')
                    or name.startswith(('os.exec', 'os.spawn', 'sys.path.', 'pickle.', 'marshal.'))
                    or name in ('os.system', 'os.popen', 'os.listdir', 'os.scandir', 'os.walk',
                                'pathlib.Path.home', 'os.path.expanduser')):
                    result['forbidden'].append((node.lineno, name))
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(name.startswith('sys.path') for target in targets for name in qualified(target)):
                result['forbidden'].append((node.lineno, 'sys.path mutation'))
    return result


def audit_ast_for_tests():
    result = {'filesystem': [], 'forbidden': []}
    for relative, source in audit_sources_for_tests().items():
        if not relative.endswith('.py') or relative == 'isolation.py':
            continue
        found = audit_text_for_tests(source, relative)
        for kind in result:
            result[kind].extend((relative, line, call) for line, call in found[kind])
    return result
