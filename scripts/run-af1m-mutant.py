"""Descriptor-rebuild regression witness, local synthetic roots only."""
from pathlib import Path
import subprocess
import sys

path = Path('planning/impl/mapl_test/request.py')
original = path.read_bytes()
old = "rebuilt['check'] = descriptor(MOCK_K7)"
new = "rebuilt['check'] = request['check']"
assert original.decode().count(old) == 1
try:
    path.write_text(original.decode().replace(old, new))
    result = subprocess.run([sys.executable, '-I', '-B', 'tests/mock-mac-fixture.py',
        'MockAdapterTests.test_device_requests_preserve_root_and_retry_identity'],
        capture_output=True, text=True, timeout=30)
    assert result.returncode != 0 and 'ValueError not raised' in result.stderr, result.stderr
    print('PASS: descriptor-rebuild mutant killed by device request test (missing refusal)')
finally:
    path.write_bytes(original)
