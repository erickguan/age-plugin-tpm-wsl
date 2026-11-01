"""Local journal/pipe tests only: uses temporary files and ordinary Python children."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from post_quantum_client.authority import Namespace, PREFIX, Stop
from post_quantum_client.journal import Journal
from post_quantum_client.process import BinaryPin, BoundedProcess, digest


class DurableAndProcessTests(unittest.TestCase):
    def setUp(self):
        self.directory_context = tempfile.TemporaryDirectory()
        self.directory = Path(self.directory_context.name)
        self.directory.chmod(0o700)
        self.source = self.directory / 'source'
        self.source.write_bytes(b'approved source')
        original = self.directory / 'original'
        original.write_bytes(b'approved executable')
        self.pin = BinaryPin.stage(original, digest(original), self.directory, {str(self.source): digest(self.source)})
        self.journal = Journal.create(self.directory / 'journal', Namespace(PREFIX + '0' * 32),
                                      'S-1-5-21-1001', self.pin.record())

    def tearDown(self):
        self.directory_context.cleanup()

    def test_journal_and_stage_are_exclusive_and_permission_checked(self):
        self.assertEqual(Path(self.pin.path).stat().st_mode & 0o777, 0o500)
        with self.assertRaises(FileExistsError):
            Journal.create(self.journal.path, Namespace(PREFIX + '0' * 32), 'S-1-5-21-1001', self.pin.record())
        self.journal.path.chmod(0o644)
        with self.assertRaises(Stop):
            with self.journal.locked():
                self.fail('insecure journal accepted')

    def test_journal_lock_prevents_concurrent_operation(self):
        with self.journal.locked():
            with self.assertRaises(Stop):
                with self.journal.locked():
                    self.fail('concurrent operation permitted')

    def test_parent_private_mode_is_rechecked_on_resume_and_each_lock(self):
        self.directory.chmod(0o777)
        with self.assertRaises(Stop):
            Journal(self.journal.path)
        with self.assertRaises(Stop):
            with self.journal.locked():
                self.fail('unsafe parent accepted')
        self.directory.chmod(0o700)
        self.assertTrue(self.journal.failed)
        with self.journal.locked() as session:
            self.assertTrue(session.state.fatal)

    def test_active_marker_survives_an_interrupted_or_unflushed_result(self):
        with self.journal.locked() as session:
            session.append({'kind': 'intent', 'operation': 'prepare'})
        marker = self.journal.path.with_name(self.journal.path.name + '.active')
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        reopened = Journal(self.journal.path)
        with reopened.locked() as session:
            self.assertTrue(session.state.fatal)
        self.assertTrue(marker.exists())

    def test_partial_or_invalid_json_never_establishes_authority(self):
        for content in [b'{', b'{}\n', b'[]\n', b'null\n']:
            self.journal.path.write_bytes(content)
            with self.assertRaises(Stop):
                with self.journal.locked():
                    self.fail('bad journal accepted')

    def test_replaced_binary_inode_rejected_even_with_same_bytes(self):
        path = Path(self.pin.path)
        data = path.read_bytes()
        moved = path.with_suffix('.retained')
        path.rename(moved)
        path.write_bytes(data)
        path.chmod(0o500)
        with self.assertRaises(Stop):
            self.pin.verify()

    def test_replaced_journal_inode_rejected(self):
        saved = self.journal.path.read_bytes()
        self.journal.path.rename(self.directory / 'old-journal')
        self.journal.path.write_bytes(saved)
        self.journal.path.chmod(0o600)
        with self.assertRaises(Stop):
            with self.journal.locked():
                self.fail('replacement journal accepted')

    def test_stage_and_journal_reject_symlinks(self):
        self.journal.path.rename(self.directory / 'real-journal')
        self.journal.path.symlink_to(self.directory / 'real-journal')
        with self.assertRaises(OSError):
            with self.journal.locked():
                self.fail('symlink journal accepted')
        path = Path(self.pin.path)
        path.rename(self.directory / 'real-fixture')
        path.symlink_to(self.directory / 'real-fixture')
        with self.assertRaises(Stop):
            self.pin.verify()

    def test_bounded_process_transfers_only_its_stdout(self):
        process = BoundedProcess()
        result = process([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())'],
                         b'public disposable bytes', os.environ.copy(), 5)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, b'public disposable bytes')

    def test_excessive_stdout_and_deadline_fail_without_a_response(self):
        process = BoundedProcess()
        with self.assertRaises(Stop):
            process([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(b"x"*9000)'],
                    b'', os.environ.copy(), 5)
        with self.assertRaises(Stop):
            process([sys.executable, '-c', 'import time; time.sleep(1)'],
                    b'', os.environ.copy(), 0.05)


if __name__ == '__main__':
    unittest.main()
