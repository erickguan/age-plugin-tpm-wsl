"""Hardware-free cleanup regressions for the RSA validation driver."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'validate_rsa_backend', Path(__file__).with_name('validate-rsa-backend.py'))
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class CleanupTests(unittest.TestCase):
    def test_partial_identity_write_still_deletes_and_verifies_using_creation_response(self):
        identity = b'complete successful creation response\n'
        calls = []
        original_write = Path.write_bytes

        def partial_write(path, data):
            if path.name == 'identity.txt':
                original_write(path, data[:7])
                raise OSError('injected partial write')
            return original_write(path, data)

        def command(argv, **kwargs):
            calls.append((argv, kwargs))
            if '--algorithm' in argv and 'keygen' not in argv:
                return subprocess.CompletedProcess(argv, 0, b'{}', b'')
            if 'keygen' in argv:
                return subprocess.CompletedProcess(
                    argv, 0, identity,
                    b'creating rsa2048 key age-tpm-wsl-00000000000000000000000000000000\n')
            if 'delete' in argv:
                return subprocess.CompletedProcess(argv, 0, b'', b'')
            if 'inspect' in argv:
                return subprocess.CompletedProcess(argv, 1, b'', b'helper error 0x80090016')
            self.fail('Unexpected command')

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'reports'
            with patch.object(sys, 'argv', ['driver', '--helper', '/unused/helper.exe',
                                            '--output-dir', str(output)]), \
                    patch.object(Path, 'read_bytes', return_value=b'fake executable'), \
                    patch.object(Path, 'write_bytes', new=partial_write), \
                    patch.object(DRIVER.subprocess, 'run', side_effect=command):
                with self.assertRaisesRegex(OSError, 'injected partial write'):
                    DRIVER.main()
            report = json.loads((output / 'summary.json').read_text())
            self.assertTrue(report['cleanup'].startswith('pass;'))
            self.assertNotEqual(report['result'], 'pass')
        self.assertEqual([str(call[0][1]) for call in calls[-2:]], ['delete', 'inspect'])
        for argv, kwargs in calls[-2:]:
            self.assertEqual(str(argv[2]), '/dev/stdin')
            self.assertEqual(kwargs['input'], identity)

    def test_cleanup_failure_is_recorded_and_propagated(self):
        report = {'owned_key_name': 'disposable-owned-name'}
        saved = []

        def failed_delete(*args, **kwargs):
            raise RuntimeError('injected delete failure')

        with patch.object(DRIVER.subprocess, 'run') as inspect:
            with self.assertRaisesRegex(RuntimeError, 'injected delete failure'):
                DRIVER.cleanup_owned('plugin', b'valid identity', {}, failed_delete,
                                     report, lambda: saved.append(dict(report)))
            inspect.assert_not_called()
        self.assertEqual(report['cleanup'], 'failed; stop and inspect owned key')
        self.assertEqual(saved[-1]['owned_key_name'], 'disposable-owned-name')


if __name__ == '__main__':
    unittest.main()
