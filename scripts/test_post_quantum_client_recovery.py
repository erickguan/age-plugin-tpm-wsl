"""Real software PQ recovery with fake native unwraps and actual local IPC."""
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

import test_post_quantum_client_clients as client_support
from test_post_quantum_client_campaign import NativeDouble
from post_quantum_client.authority import Namespace, Observation, PREFIX, Stop
from post_quantum_client.cases import PAYLOAD
from post_quantum_client.controller import frame, response
from post_quantum_client.durable import Storage
from post_quantum_client.process import BinaryPin, BoundedProcess, ProcessResult, digest
from post_quantum_client.recovery_campaign import RecoveryCampaign
from post_quantum_client.recovery_clients import RecoveryEnvironment
from post_quantum_client.report import CampaignReport
from post_quantum_client.wrapper import forward_stdio


class RoutedProcess:
    def __init__(self, run, native):
        self.run, self.native = run, native
        self.skip_native = self.extra_native = self.wrong_recovery = False
        self.software_calls = 0

    def rpc(self):
        request = frame(9, b'\x05\x14' + self.native.inner.identity + b'\x01' * 1153 + b'\x02' * 32)
        output = io.BytesIO()
        forward_stdio(self.run.path / 's', os.getpid(), io.BytesIO(request), output)
        status, _ = response(output.getvalue(), 9)
        if status: raise Stop('fake native request failed')

    def __call__(self, command, payload, environment, seconds, **options):
        if '--decrypt' in command:
            identity = str(command[command.index('--identity') + 1])
            if identity.endswith('/identity.txt'):
                if not self.skip_native: self.rpc()
                # Fixed mock plaintext; no actual TPM key/file key is captured.
                return ProcessResult(0, PAYLOAD)
            if identity.endswith('/recovery-key/recovery.key'):
                self.software_calls += 1
                if environment['AGE_TPM_WSL_HELPER'] != '/nonexistent/offline-only.exe':
                    raise Stop('software recovery must disable helper')
                if self.extra_native: self.rpc()
                if self.wrong_recovery: return ProcessResult(0, b'wrong disposable output')
        return BoundedProcess()(command, payload, environment, seconds, **options)


class RecoveryCampaignTests(unittest.TestCase):
    def setUp(self):
        self.fixture = client_support.ClientEnvironmentTests(); self.fixture.setUp()
        self.run = self.fixture.run
        self.namespace = Namespace(PREFIX + '0' * 32)
        self.report = CampaignReport.create(self.run.path / 'report', self.namespace, '1' * 64)
        self.native = NativeDouble(self.namespace, self.run, self.report)
        source = Path(shutil.which('age-keygen')).resolve()
        pin = BinaryPin.stage(source, digest(source), self.run.path,
                              self.fixture.staged.helper.source_hashes, 'age-keygen')
        version = BoundedProcess()([pin.path, '--version'], b'', os.environ.copy(), 10)
        staged = replace(self.fixture.staged, keygen=pin, keygen_version=version.stdout.decode().strip())
        self.process = RoutedProcess(self.run, self.native)
        self.clients = RecoveryEnvironment(self.run, staged, self.process, {'PATH': os.environ['PATH']})
        def controller(journal, environment, observe):
            self.assertIsNotNone(self.clients.key)
            self.clients.key.verify()  # Generated before simulated enrollment.
            return self.native.controller(journal, environment, observe)
        self.campaign = RecoveryCampaign(self.run, self.namespace, self.report, self.clients,
                                          self.native.observe, controller)

    def tearDown(self):
        self.fixture.tearDown()  # Real software key only; native state is fake.

    def assert_native_retained(self):
        self.assertTrue(self.clients.key.file.path.exists())
        self.assertTrue(self.native.inner.key and self.native.inner.root)
        self.assertTrue((self.run.path / 'journal').exists())
        self.assertTrue(self.campaign.controller.journal.failed)
        self.assertNotIn('delete', self.native.inner.calls)

    def test_real_public_duplicates_and_pq_recovery_share_lifecycle_then_remove_exact_key(self):
        def before_delete():
            self.assertFalse(self.campaign.service.thread.is_alive())
            self.assertTrue(self.clients.key.file.path.exists())
        self.native.cleanup_probe = before_delete
        self.campaign.execute()
        events = [json.loads(line) for line in self.report.path.read_text().splitlines()]
        self.assertEqual(len([row for row in events if row['kind'] == 'client']), 5)
        recovery = [row for row in events if row['kind'] == 'recovery']
        self.assertEqual(len(recovery), 1)
        self.assertFalse(recovery[0]['native'])
        self.assertEqual(events[-2]['successful_reads'], 3)
        self.assertEqual(self.process.software_calls, 1)
        self.assertEqual(self.native.inner.calls.count('unwrap'), 3)
        self.assertEqual(self.native.inner.calls.count('delete'), 1)
        self.assertTrue(self.clients.key.retired and not self.clients.key.file.path.exists())
        self.assertTrue(any(row['kind'] == 'recovery_key_retired' for row in events))
        self.assertTrue(events[-1]['authority_retired'])
        self.assertFalse((self.run.path / 'journal').exists())

    def test_missing_native_call_cannot_be_replaced_by_software_plaintext(self):
        self.process.skip_native = True
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_native_retained()

    def test_software_recovery_cannot_make_an_extra_native_request(self):
        self.process.extra_native = True
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_native_retained()
        self.assertEqual(self.native.inner.calls.count('unwrap'), 4)

    def test_wrong_software_output_stops_and_retains_recovery_key(self):
        self.process.wrong_recovery = True
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_native_retained()

    def final_observer(self, transform):
        original = self.campaign.observe
        def observed(namespace):
            value = original(namespace)
            if self.native.inner is not None:
                latest = json.loads((self.run.path / 'journal').read_text().splitlines()[-1])
                if latest['kind'] == 'success' and latest.get('operation') == 'absence':
                    return transform(value)
            return value
        self.campaign.observe = observed

    def assert_key_and_journal_retained_after_cleanup_stop(self):
        self.assertTrue(self.clients.key.file.path.exists())
        self.assertFalse(self.clients.key.retired)
        self.assertTrue((self.run.path / 'journal').exists())
        self.assertTrue(self.campaign.controller.journal.failed)
        self.assertNotEqual(self.report.phase, 'complete')

    def test_negative_final_native_absence_receipt_retains_private_key_even_when_observer_agrees(self):
        original = self.native.invoke
        def present_root(command, payload, environment, seconds):
            latest = json.loads((self.run.path / 'journal').read_text().splitlines()[-1])
            if latest['operation'] == 'absence':
                self.native.inner.root = True
            return original(command, payload, environment, seconds)
        with patch.object(self.native, 'invoke', side_effect=present_root):
            with self.assertRaises(Stop): self.campaign.execute()
        self.assert_key_and_journal_retained_after_cleanup_stop()
        self.assertTrue(self.native.inner.root)

    def test_negative_final_independent_absence_observation_precedes_private_key_unlink(self):
        self.final_observer(lambda value: Observation(value.sid, False, True))
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_key_and_journal_retained_after_cleanup_stop()

    def test_changed_final_independent_sid_precedes_private_key_unlink(self):
        self.final_observer(lambda value: Observation('S-1-5-21-9999', True, True))
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_key_and_journal_retained_after_cleanup_stop()

    def test_changed_shared_ciphertext_cannot_replace_the_native_control_input(self):
        original = self.clients.recover
        def substituted():
            self.clients._ciphertexts['or_shared'] = b'replaced public ciphertext'
            return original()
        with patch.object(self.clients, 'recover', side_effect=substituted):
            with self.assertRaises(Stop): self.campaign.execute()
        self.assert_native_retained()
        self.assertEqual(self.process.software_calls, 0)

    def test_missing_private_key_stops_without_recreation_or_native_cleanup(self):
        original = self.clients.recover
        moved = self.run.path / 'recovery-key/retained.key'
        def missing():
            self.clients.key.file.path.rename(moved)
            return original()
        with patch.object(self.clients, 'recover', side_effect=missing):
            with self.assertRaises(Stop): self.campaign.execute()
        self.assertTrue(moved.exists())
        self.assertFalse(self.clients.key.file.path.exists())
        self.assertTrue(self.native.inner.key and self.native.inner.root)
        self.assertTrue(self.campaign.controller.journal.failed)
        self.assertTrue((self.run.path / 'journal').exists())
        self.assertNotIn('delete', self.native.inner.calls)
        self.assertEqual(self.process.software_calls, 0)

    def test_missing_staged_helper_stops_before_key_generation_or_native_enrollment(self):
        Path(self.clients.inputs.helper.path).unlink()
        with self.assertRaises(Stop): self.campaign.execute()
        self.assertIsNone(self.clients.key)
        self.assertIsNone(self.native.inner)
        self.assertFalse((self.run.path / 'journal').exists())
        self.assertFalse((self.run.path / 'recovery-key').exists())

    def test_failed_key_absence_publication_retains_journal_after_native_and_private_absence(self):
        original = self.report._append
        def failed(value):
            if value['kind'] == 'recovery_key_retired': raise OSError('fake key absence evidence failure')
            return original(value)
        with patch.object(self.report, '_append', side_effect=failed):
            with self.assertRaises(Stop): self.campaign.execute()
        self.assertFalse(self.native.inner.key or self.native.inner.root)
        self.assertTrue(self.clients.key.retired)
        self.assertFalse(self.clients.key.file.path.exists())
        self.assertTrue((self.run.path / 'journal').exists())
        self.assertNotEqual(self.report.phase, 'complete')

    def test_key_retirement_failure_keeps_journal_after_native_absence(self):
        original = Storage.retire
        def failed(storage):
            if storage.name == 'recovery.key': raise OSError('fake private file unlink failure')
            return original(storage)
        with patch.object(Storage, 'retire', new=failed):
            with self.assertRaises(Stop): self.campaign.execute()
        self.assertFalse(self.native.inner.key or self.native.inner.root)
        self.assertTrue(self.clients.key.file.path.exists())
        self.assertTrue((self.run.path / 'journal').exists())
        self.assertNotEqual(self.report.phase, 'complete')

    def test_recovery_report_failure_stops_before_any_native_cleanup_or_private_unlink(self):
        original = self.report._append
        def failed(value):
            if value['kind'] == 'recovery': raise OSError('fake recovery evidence failure')
            return original(value)
        with patch.object(self.report, '_append', side_effect=failed):
            with self.assertRaises(Stop): self.campaign.execute()
        self.assert_native_retained()


if __name__ == '__main__':
    unittest.main()
