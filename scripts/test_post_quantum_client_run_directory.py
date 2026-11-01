"""Retained directory, modes, exclusive paths and identity; no native execution."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from post_quantum_client.authority import Stop
from post_quantum_client.run_directory import RunDirectory


class RunDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.parent = Path(self.temporary.name)
        self.parent.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def test_fresh_private_run_retains_public_artifacts_without_automatic_cleanup(self):
        run = RunDirectory.create(self.parent)
        self.assertEqual(run.path.stat().st_mode & 0o777, 0o700)
        public = run.write_public('identity.txt', b'public reference\n')
        public.verify()
        self.assertEqual(public.path.stat().st_mode & 0o777, 0o600)
        launcher = run.write_public('frontend', b'#!/bin/sh\nexit 1\n', 0o700)
        launcher.verify()
        self.assertEqual(launcher.path.stat().st_mode & 0o777, 0o700)
        home = run.subdirectory('home')
        self.assertEqual(home.stat().st_mode & 0o777, 0o700)
        path = run.path
        del run
        self.assertTrue(path.exists())
        self.assertTrue(public.path.exists())

    def test_exclusive_creation_never_replaces_existing_public_file(self):
        run = RunDirectory.create(self.parent)
        run.write_public('frontend', b'original', 0o700)
        with self.assertRaises(FileExistsError):
            run.write_public('frontend', b'replacement', 0o700)
        self.assertEqual((run.path / 'frontend').read_bytes(), b'original')

    def test_insecure_parent_and_bad_leaf_names_are_rejected_before_creation(self):
        self.parent.chmod(0o777)
        with self.assertRaises(Stop):
            RunDirectory.create(self.parent)
        self.assertEqual(list(self.parent.iterdir()), [])
        self.parent.chmod(0o700)
        run = RunDirectory.create(self.parent)
        for name in ('../outside', '/absolute', 'sub/file', '.hidden', ''):
            with self.assertRaises(Stop):
                run.write_public(name, b'public')
        self.assertEqual(list(run.path.iterdir()), [])

    def test_changed_directory_mode_or_forked_pid_cannot_write(self):
        run = RunDirectory.create(self.parent)
        run.path.chmod(0o755)
        with self.assertRaises(Stop):
            run.write_public('frontend', b'public')
        run.path.chmod(0o700)
        with patch('post_quantum_client.run_directory.os.getpid', return_value=os.getpid() + 1):
            with self.assertRaises(Stop):
                run.write_public('frontend', b'public')
        self.assertFalse((run.path / 'frontend').exists())

    def test_replaced_directory_or_symlink_does_not_gain_run_authority(self):
        run = RunDirectory.create(self.parent)
        retained = self.parent / 'retained'
        run.path.rename(retained)
        run.path.mkdir(mode=0o700)
        with self.assertRaises(Stop):
            run.verify()
        run.path.rmdir()
        run.path.symlink_to(retained, target_is_directory=True)
        with self.assertRaises(OSError):
            run.verify()
        self.assertFalse((retained / 'frontend').exists())


if __name__ == '__main__':
    unittest.main()
