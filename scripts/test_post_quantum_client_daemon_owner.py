"""Real Linux daemon owner checks with plain disposable data; no Windows/TPM."""
import os
from pathlib import Path
import shutil
import struct
import unittest
from unittest.mock import patch

import test_post_quantum_client_fnox as fnox_support
from post_quantum_client.authority import Stop
from post_quantum_client.cases import PAYLOAD
from post_quantum_client.fnox_daemon_owner import OwnedFnoxDaemon
from post_quantum_client.process import BoundedProcess, ProcessResult


class FnoxDaemonOwnerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fnox_support.FnoxTests(); self.fixture.setUp()
        self.run, self.clients = self.fixture.run, self.fixture.clients
        self.clients._write('fnox.toml', b'[daemon]\nenabled = true\n[providers.plain]\ntype = "plain"\n'
                            b'[secrets.OWNER_PROBE]\nprovider = "plain"\nvalue = "' + PAYLOAD + b'"\n')
        self.owners = []

    def tearDown(self):
        for owner in self.owners:
            owner.abandon()  # Stop only a test's own foreground child.
            if owner.path.exists(): shutil.rmtree(owner.path)
            self.assertFalse(os.path.lexists(owner.path))
        self.fixture.tearDown()  # Only software/fake state, never a native key.

    def owner(self, environment=None):
        value = OwnedFnoxDaemon(self.run, self.clients.inputs.fnox, self.clients.project,
                                environment or self.clients.environment(False))
        self.owners.append(value)
        return value

    def get(self, owner, bypass=False):
        result = BoundedProcess()(owner.command(['get', 'OWNER_PROBE'], bypass=bypass), b'',
                                  owner.environment(), 10, cwd=self.clients.project)
        self.assertTrue(result.exit_code == 0 and result.stdout == PAYLOAD + b'\n')

    def test_actual_foreground_peer_cache_states_bypass_and_exact_runtime_retirement(self):
        owner = self.owner()
        self.assertEqual(owner.start().entries, 0)
        self.get(owner)
        cold = owner.status()
        self.assertEqual(cold.entries, 1)
        self.get(owner)
        self.assertEqual(owner.status(), cold)
        self.get(owner, bypass=True)
        self.assertEqual(owner.status(), cold)
        receipt = owner.stop()
        receipt.verify()
        self.assertFalse(os.path.lexists(owner.path))
        self.assertEqual(receipt.pid, cold.pid)
        with self.assertRaises(Stop): owner.start()
        with self.assertRaises(Stop): owner.stop()

    def test_config_change_refuses_admin_action_and_abandon_keeps_private_state(self):
        owner = self.owner(); owner.start()
        self.clients._write('fnox.toml', b'# replaced own public test configuration\n')
        with self.assertRaises(Stop): owner.status()
        owner.abandon()
        self.assertIsNotNone(owner.child.returncode)
        self.assertTrue(owner.path.exists())
        self.assertFalse(owner.retired)

    def test_socket_replacement_is_not_adopted_or_deleted_by_stop(self):
        owner = self.owner(); owner.start()
        moved = owner.socket_path.with_name('retained-owned-socket')
        owner.socket_path.rename(moved)
        with self.assertRaises(Stop): owner.stop()
        owner.abandon()
        self.assertTrue(moved.exists())
        self.assertFalse(owner.retired)

    def test_socket_peer_pid_or_uid_substitution_blocks_admin_command(self):
        owner = self.owner(); owner.start()
        for pid, uid in ((owner.child.pid + 1, os.getuid()), (owner.child.pid, os.getuid() + 1)):
            with self.subTest(pid=pid, uid=uid):
                with patch('post_quantum_client.fnox_daemon_owner.socket.socket') as connection:
                    connection.return_value.__enter__.return_value.getsockopt.return_value = struct.pack('3i', pid, uid, 0)
                    with patch.object(owner, '_invoke') as invoke:
                        with self.assertRaises(Stop): owner.status()
                        invoke.assert_not_called()
        owner.abandon()
        self.assertTrue(owner.path.exists())

    def test_identical_configuration_replacement_is_not_the_original_private_file(self):
        owner = self.owner(); owner.start()
        path = self.clients.project / 'fnox.toml'
        replacement = path.with_name('replacement.toml')
        replacement.write_bytes(path.read_bytes()); replacement.chmod(0o600)
        replacement.replace(path)
        with self.assertRaises(Stop): owner.status()
        owner.abandon()
        self.assertTrue(owner.path.exists())

    def test_retirement_receipt_rejects_recreated_runtime_path(self):
        owner = self.owner(); owner.start()
        receipt = owner.stop()
        owner.path.mkdir(mode=0o700)
        with self.assertRaises(Stop): receipt.verify()

    def failed_action(self, operation):
        owner = self.owner(); owner.start()
        original = owner.process
        def failed(command, payload, environment, seconds, **options):
            if command[-2:] == ['daemon', operation]: return ProcessResult(1, b'')
            return original(command, payload, environment, seconds, **options)
        owner.process = failed
        with self.assertRaises(Stop): getattr(owner, operation)()
        owner.abandon()
        self.assertTrue(owner.path.exists())
        self.assertFalse(owner.retired)
        owner.process = original

    def test_wrong_status_does_not_claim_retirement(self):
        self.failed_action('status')

    def test_failed_stop_does_not_claim_retirement(self):
        self.failed_action('stop')

    def test_environment_is_private_and_drift_stops_before_socket_adoption(self):
        inherited = dict(self.clients.environment(False), AWS_SECRET_ACCESS_KEY='synthetic-not-forwarded',
                         FNOX_CONFIG_FILE='/production/not-read', FNOX_AGE_KEY='synthetic-not-forwarded',
                         WSL_INTEROP='/fixed-test-interop-context')
        owner = self.owner(inherited)
        environment = owner.environment()
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', environment)
        self.assertNotIn('FNOX_CONFIG_FILE', environment)
        self.assertNotIn('FNOX_AGE_KEY', environment)
        self.assertEqual(environment['WSL_INTEROP'], '/fixed-test-interop-context')
        self.assertTrue(Path(environment['XDG_RUNTIME_DIR']).is_relative_to(owner.path))
        self.assertTrue(Path(environment['FNOX_CONFIG_DIR']).is_relative_to(owner.path))
        owner._environment['FNOX_DAEMON'] = 'off'
        with self.assertRaises(Stop): owner.start()
        self.assertIsNone(owner.child)


if __name__ == '__main__':
    unittest.main()
