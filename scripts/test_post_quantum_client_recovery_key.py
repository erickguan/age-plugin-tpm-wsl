"""Real temporary software PQ keys; no Windows probe or native enrollment."""
from dataclasses import replace
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_post_quantum_client_clients as support
from post_quantum_client.authority import Stop
from post_quantum_client.durable import Storage
from post_quantum_client.process import BinaryPin, BoundedProcess, digest
from post_quantum_client.recovery_key import RecoveryKey


class RecoveryKeyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = support.ClientEnvironmentTests()
        self.fixture.setUp()
        self.run = self.fixture.run
        source = Path(shutil.which('age-keygen')).resolve()
        pin = BinaryPin.stage(source, digest(source), self.run.path,
                              self.fixture.staged.helper.source_hashes, 'age-keygen')
        version = BoundedProcess()([pin.path, '--version'], b'', os.environ.copy(), 10)
        self.assertEqual(version.exit_code, 0)
        staged = replace(self.fixture.staged, keygen=pin, keygen_version=version.stdout.decode().strip())
        self.clients = support.ClientEnvironment(self.run, staged, inherited={'PATH': os.environ['PATH']})
        self.path = self.run.path / 'recovery-key/recovery.key'

    def tearDown(self):
        self.fixture.tearDown()  # No native resource exists; test-only private key.

    def generate(self):
        return RecoveryKey.generate(self.run, self.clients.inputs, self.clients.environment(True))

    def test_real_native_pq_key_is_private_metadata_bound_and_removed_exactly_once(self):
        key = self.generate()
        recipient = key.recipient()
        self.assertTrue(recipient.startswith('age1pq1'))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(key.metadata[0] > 50)
        key.verify(); key.retire(); key.verify()
        self.assertFalse(self.path.exists())
        with self.assertRaises(Stop): key.retire()

    def test_python_never_reads_or_hashes_private_file_and_stdout_is_direct_descriptor(self):
        original_read = Path.read_bytes
        def read(path):
            if path == self.path: raise AssertionError('private bytes may not enter Python')
            return original_read(path)
        original_spawn = subprocess.Popen
        calls = []
        def spawn(command, **options):
            if '-pq' in command:
                calls.append(options)
                self.assertIsInstance(options['stdout'], int)
                self.assertNotEqual(options['stdout'], subprocess.PIPE)
                self.assertEqual(options['stderr'], subprocess.DEVNULL)
            return original_spawn(command, **options)
        with patch.object(Path, 'read_bytes', new=read), patch('subprocess.Popen', side_effect=spawn):
            key = self.generate(); key.verify(); key.recipient(); key.retire()
        self.assertEqual(len(calls), 1)

    def test_in_place_file_change_is_rejected_without_hashing_private_bytes(self):
        key = self.generate()
        with self.path.open('ab') as stream: stream.write(b'\n')
        with self.assertRaises(Stop): key.verify()

    def test_replaced_or_linked_key_path_is_not_deleted(self):
        key = self.generate()
        original = self.path.with_name('original.key')
        self.path.rename(original)
        self.path.symlink_to(original)
        with self.assertRaises(OSError): key.retire()
        self.assertTrue(original.exists() and self.path.is_symlink())

    def test_extra_hardlink_or_changed_mode_blocks_retirement(self):
        key = self.generate()
        linked = self.path.with_name('linked.key'); os.link(self.path, linked)
        with self.assertRaises(Stop): key.retire()
        linked.unlink(); self.path.chmod(0o644)
        with self.assertRaises(Stop): key.retire()
        self.assertTrue(self.path.exists())

    def test_failed_retirement_retains_owned_file_and_does_not_claim_absence(self):
        key = self.generate()
        with patch.object(Storage, 'retire', side_effect=OSError('simulated unlink failure')):
            with self.assertRaises(OSError): key.retire()
        self.assertFalse(key.retired)
        self.assertTrue(self.path.exists())
        key.verify()

    def test_recreated_retired_path_is_not_silently_accepted(self):
        key = self.generate(); key.retire()
        self.path.touch(mode=0o600)
        with self.assertRaises(Stop): key.verify()
        self.assertTrue(self.path.exists())

    def test_keygen_failure_retains_the_exclusive_partial_file(self):
        original_spawn = subprocess.Popen
        def spawn(command, **options):
            if '-pq' in command:
                return SimpleNamespace(returncode=1, wait=lambda timeout: 1, poll=lambda: 1)
            return original_spawn(command, **options)
        with patch('subprocess.Popen', side_effect=spawn):
            with self.assertRaises(Stop): self.generate()
        self.assertTrue(self.path.exists())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_key_generator_pin_and_version_required_before_private_file_creation(self):
        self.clients.inputs = replace(self.clients.inputs, keygen_version='wrong-version')
        with self.assertRaises(Stop): self.generate()
        self.assertFalse(self.path.exists())


if __name__ == '__main__':
    unittest.main()
