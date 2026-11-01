"""Complete coordinator order through real local IPC and fake native operations."""
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from post_quantum_client.authority import Namespace, Observation, PREFIX, Stop
from post_quantum_client.campaign import MinimalCampaign
from post_quantum_client.cases import positive_cases
from post_quantum_client.fnox import fnox_cases
from post_quantum_client.clients import ClientOutcome, PAYLOAD
from post_quantum_client.controller import Controller, frame, response
from post_quantum_client.durable import Storage
from post_quantum_client.process import BinaryPin, digest
from post_quantum_client.report import CampaignReport, ClientMeasurement
from post_quantum_client.run_directory import RunDirectory
from post_quantum_client.service import ClientService
from post_quantum_client.wrapper import forward_stdio
from test_post_quantum_client_controller import FakeWindows


class NativeDouble:
    def __init__(self, namespace, run, report):
        self.namespace, self.run, self.report = namespace, run, report
        self.inner = None
        self.preexisting = False
        self.interrupt_create = False
        self.unwrap_error = False
        self.cleanup_probe = lambda: None

    def observe(self, namespace):
        if self.inner is None:
            return Observation('S-1-5-21-1001', not self.preexisting, True)
        return self.inner.observe(namespace)

    def controller(self, journal, environment, observe):
        self.inner = FakeWindows(self.namespace, journal)
        return Controller(journal, environment, observe, self.invoke)

    def invoke(self, command, payload, environment, seconds):
        self.report.file.path.stat()  # Evidence must already be reserved.
        operation = json.loads(self.inner.journal.path.read_text().splitlines()[-1])['operation']
        if operation == 'delete':
            self.cleanup_probe()
        if operation == 'unwrap' and self.unwrap_error:
            raise KeyboardInterrupt('simulated native interruption')
        result = self.inner.run(command, payload, environment, seconds)
        if operation == 'create' and self.interrupt_create:
            raise TimeoutError('simulated unknown completion after creation')
        return result


class FakeClients:
    def __init__(self, run, pin, native):
        self.run, self.native = run, native
        self.inputs = SimpleNamespace(helper=pin)
        self.env = {'HOME': str(run.path)}
        self.mismatch = self.no_rpc = self.prepare_failure = False
        self.decryptions = 0
        self.skip_rpc_at = self.mismatch_at = None

    def preflight(self):
        self.inputs.helper.verify()

    def prepare(self, reference):
        if self.prepare_failure:
            raise OSError('simulated public reference write failure')
        self.reference = reference

    def encrypt(self, payload=PAYLOAD, client='age', case=None):
        return ClientOutcome(ClientMeasurement(client, 'encrypt', len(payload), 1, 0, True), b'fixed mock ciphertext')

    def decrypt(self, ciphertext, expected=PAYLOAD, client='age', case=None):
        self.decryptions += 1
        if not self.no_rpc and self.decryptions != self.skip_rpc_at:
            request = frame(9, b'\x05\x14' + self.native.inner.identity + b'\x01' * 1153 + b'\x02' * 32)
            output = io.BytesIO()
            forward_stdio(self.run.path / 's', os.getpid(), io.BytesIO(request), output)
            status, key = response(output.getvalue(), 9)
            if status or key != b'\x5a' * 16:
                return ClientOutcome(ClientMeasurement(client, 'decrypt', len(expected), 1, 1, False), b'')
        return ClientOutcome(ClientMeasurement(client, 'decrypt', len(expected), 1, 0, True),
                             b'wrong plaintext' if self.mismatch or self.decryptions == self.mismatch_at else expected)


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        parent = Path(self.temporary.name)
        parent.chmod(0o700)
        self.run = RunDirectory.create(parent)
        self.namespace = Namespace(PREFIX + '0' * 32)
        self.report = CampaignReport.create(self.run.path / 'report', self.namespace, '1' * 64)
        self.source = parent / 'source'
        self.source.write_bytes(b'fixed approved mock source')
        original = parent / 'image'
        original.write_bytes(b'never executed mock helper')
        pin = BinaryPin.stage(original, digest(original), self.run.path, {str(self.source): digest(self.source)})
        self.native = NativeDouble(self.namespace, self.run, self.report)
        self.clients = FakeClients(self.run, pin, self.native)
        self.campaign = MinimalCampaign(self.run, self.namespace, self.report, self.clients,
                                        self.native.observe, self.native.controller)

    def tearDown(self):
        self.temporary.cleanup()  # Mock state only: never an actual native resource.

    def assert_retained_without_cleanup(self):
        self.assertTrue((self.run.path / 'journal').exists())
        self.assertTrue(self.report.path.exists())
        self.assertTrue(self.campaign.controller.summary()['cleanup_stopped'])
        self.assertNotIn('delete', self.native.inner.calls)
        self.assertNotIn('remove-root', self.native.inner.calls)

    def test_full_minimal_flow_quiesces_before_cleanup_and_retires_only_after_checkpoint(self):
        def quiesced():
            self.assertFalse((self.run.path / 's').exists())
            self.assertFalse(self.campaign.service.thread.is_alive())
        self.native.cleanup_probe = quiesced
        self.assertEqual(self.campaign.execute(), self.report.path)
        self.assertEqual(self.native.inner.calls, ['prepare', 'create', 'unwrap', 'delete', 'remove-root', 'absence'])
        self.assertFalse(self.native.inner.root or self.native.inner.key)
        self.assertFalse((self.run.path / 'journal').exists())
        self.assertTrue(Path(self.clients.inputs.helper.path).exists())
        events = [json.loads(line) for line in self.report.path.read_text().splitlines()]
        self.assertEqual(events[-2]['kind'], 'verified_absence')
        self.assertEqual(events[-1], {'kind': 'complete', 'result': 'pass', 'authority_retired': True})

    def test_full_positive_matrix_records_both_directions_and_all_boundaries_then_cleans_once(self):
        self.campaign.cases = positive_cases()
        self.campaign.execute()
        self.assertEqual(self.native.inner.calls.count('create'), 1)
        self.assertEqual(self.native.inner.calls.count('unwrap'), 56)
        self.assertEqual(self.native.inner.calls.count('delete'), 1)
        events = [json.loads(line) for line in self.report.path.read_text().splitlines()]
        clients = [event for event in events if event['kind'] == 'client']
        self.assertEqual(len(clients), 84)
        decryptions = [event for event in clients if event['operation'] == 'decrypt']
        self.assertEqual({(event['encryptor'], event['client']) for event in decryptions},
                         {('age', 'age'), ('age', 'rage'), ('rage', 'age'), ('rage', 'rage')})
        self.assertEqual({event['payload_bytes'] for event in decryptions},
                         {0, 4, 32, 256, 1024, 2048, 4096, 8192, 65535, 65536, 65537, 1048576, 4194304})
        self.assertTrue(all(event['matched'] and event['result'] == 'pass' for event in clients))
        self.assertFalse((self.run.path / 'journal').exists())
        self.assertEqual(events[-1]['kind'], 'complete')

    def test_one_skipped_matrix_helper_call_is_not_accepted_even_with_matching_plaintext(self):
        self.campaign.cases = positive_cases()
        self.clients.skip_rpc_at = 7
        with self.assertRaises(Stop):
            self.campaign.execute()
        self.assert_retained_without_cleanup()
        self.assertEqual(self.native.inner.calls.count('unwrap'), 55)
        self.assertEqual(self.report.decryptions, 0)

    def test_late_matrix_mismatch_stops_without_cleanup_or_retry(self):
        self.campaign.cases = positive_cases()
        self.clients.mismatch_at = 45
        with self.assertRaises(Stop):
            self.campaign.execute()
        self.assert_retained_without_cleanup()
        self.assertEqual(self.clients.decryptions, 45)

    def test_fnox_direct_and_cache_share_one_native_lifecycle_and_retirement(self):
        self.campaign.cases = fnox_cases()
        self.campaign.execute()
        self.assertEqual(self.native.inner.calls,
                         ['prepare', 'create', 'unwrap', 'unwrap', 'delete', 'remove-root', 'absence'])
        events = [json.loads(line) for line in self.report.path.read_text().splitlines()]
        clients = [event for event in events if event['kind'] == 'client']
        self.assertEqual(len(clients), 4)
        self.assertEqual({event['case'] for event in clients}, {'fnox_direct', 'fnox_cache'})
        self.assertTrue(all(event['client'] == 'fnox' and event['encryptor'] == 'fnox' for event in clients))
        self.assertEqual(events[-2]['successful_reads'], 2)
        self.assertFalse((self.run.path / 'journal').exists())

    def test_fnox_cache_without_its_native_traversal_never_grants_cleanup(self):
        self.campaign.cases = fnox_cases()
        self.clients.skip_rpc_at = 2
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained_without_cleanup()
        self.assertEqual(self.native.inner.calls.count('unwrap'), 1)
        self.assertEqual(self.report.decryptions, 0)

    def test_preexisting_namespace_stops_before_journal_or_enrollment(self):
        self.native.preexisting = True
        with self.assertRaises(Stop):
            self.campaign.execute()
        self.assertIsNone(self.native.inner)
        self.assertFalse((self.run.path / 'journal').exists())

    def test_changed_input_stops_before_observer_controller_or_enrollment(self):
        self.source.write_bytes(b'changed source')
        with self.assertRaises(Stop):
            self.campaign.execute()
        self.assertIsNone(self.native.inner)
        self.assertFalse((self.run.path / 'journal').exists())

    def test_unknown_creation_keeps_namespace_and_never_uses_name_only_cleanup(self):
        self.native.interrupt_create = True
        with self.assertRaises(Stop):
            self.campaign.execute()
        self.assertTrue(self.native.inner.key)
        self.assert_retained_without_cleanup()
        self.assertIsNone(self.campaign.controller.summary()['identity_sha256'])

    def test_mismatch_stops_authority_before_even_broken_failure_reporting(self):
        self.clients.mismatch = True
        observed = []
        def broken_failure(category):
            observed.append(self.campaign.controller.summary()['cleanup_stopped'])
            raise OSError('simulated failed evidence')
        with patch.object(self.report, 'failure', broken_failure):
            with self.assertRaises(Stop):
                self.campaign.execute()
        self.assertEqual(observed, [True])
        self.assert_retained_without_cleanup()

    def test_correct_plaintext_without_helper_traversal_is_not_native_acceptance(self):
        self.clients.no_rpc = True
        with self.assertRaises(Stop):
            self.campaign.execute()
        self.assert_retained_without_cleanup()
        self.assertNotIn('unwrap', self.native.inner.calls)

    def test_reference_file_failure_after_create_preserves_full_canonical_reference(self):
        self.clients.prepare_failure = True
        with self.assertRaises(Stop):
            self.campaign.execute()
        self.assert_retained_without_cleanup()
        self.assertIsNotNone(self.campaign.controller.summary()['identity_sha256'])
        self.assertIn(self.native.inner.identity.hex(), (self.run.path / 'journal').read_text())

    def test_service_native_interruption_stops_and_preserves_owned_state(self):
        self.native.unwrap_error = True
        with self.assertRaises(Stop):
            self.campaign.execute()
        self.assert_retained_without_cleanup()
        self.assertFalse(self.campaign.service.thread.is_alive())

    def test_quiesce_failure_never_allows_native_cleanup(self):
        class FailedQuiesce(ClientService):
            def quiesce(self):
                raise Stop('simulated service shutdown failure')
        self.campaign.service_factory = FailedQuiesce
        with self.assertRaises(Stop):
            self.campaign.execute()
        self.assert_retained_without_cleanup()
        self.assertFalse(self.campaign.service.thread.is_alive())

    def test_retirement_failure_preserves_report_and_journal_without_repeated_native_cleanup(self):
        with patch.object(Storage, 'retire', side_effect=PermissionError('simulated retirement error')):
            with self.assertRaises(Stop):
                self.campaign.execute()
        self.assertTrue((self.run.path / 'journal').exists())
        self.assertFalse(self.native.inner.root or self.native.inner.key)
        self.assertEqual(self.native.inner.calls.count('delete'), 1)
        self.assertEqual(json.loads(self.report.path.read_text().splitlines()[-1]),
                         {'kind': 'retirement_failure', 'result': 'fail'})


if __name__ == '__main__':
    unittest.main()
