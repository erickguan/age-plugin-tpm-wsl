"""Finite refusal lifecycle with actual local CLI refusals and fake native IPC."""
import io
from dataclasses import replace
import json
import os
import unittest
from unittest.mock import patch

import test_post_quantum_client_clients as support
from test_post_quantum_client_campaign import NativeDouble
from post_quantum_client.authority import Namespace, PREFIX, PublicIdentity, Stop
from post_quantum_client.cases import PAYLOAD
from post_quantum_client.controller import frame, response
from post_quantum_client.diagnostics import Diagnostic
from post_quantum_client.journal import AUTHENTICATION_FAILED
from post_quantum_client.process import BoundedProcess, ProcessResult
from post_quantum_client.refusal_campaign import RefusalCampaign
from post_quantum_client.refusal_cases import LOCAL_REFUSALS, REFUSAL_PLAN, Refusal
from post_quantum_client.refusal_clients import RefusalEnvironment
from post_quantum_client.report import CampaignReport
from post_quantum_client.refusals import PreparedRefusals
from post_quantum_client.references import ClientReferences
from test_post_quantum_client_controller import FakeWindows
from post_quantum_client.wrapper import forward_stdio


class RoutedProcess:
    def __init__(self, run, native):
        self.run, self.native = run, native
        self.clients = None
        self.skip_control = self.skip_payload = self.extra_local = self.unknown_local = False
        self.wrong_payload_diagnostic = self.reject_payload_native = False

    def rpc(self):
        request = frame(9, b'\x05\x14' + self.native.inner.identity + b'\x01' * 1153 + b'\x02' * 32)
        output = io.BytesIO()
        forward_stdio(self.run.path / 's', os.getpid(), io.BytesIO(request), output)
        status, _ = response(output.getvalue(), 9)
        return status == 0  # Only a fixed fake-native file key traverses this pipe.

    def __call__(self, command, payload, environment, seconds, **options):
        if '--decrypt' in command and self.clients._prepared is not None:
            case, _ = REFUSAL_PLAN[self.clients._index]
            if case is Refusal.CONTROL:
                if not self.skip_control: self.rpc()
                return ProcessResult(0, PAYLOAD)
            if case is Refusal.PAYLOAD_AUTH:
                if self.reject_payload_native:
                    self.native.inner.override = lambda operation: ProcessResult(0, frame(9, status=AUTHENTICATION_FAILED))
                if not self.skip_payload: self.rpc()
                diagnostic = Diagnostic.NO_MATCH if self.wrong_payload_diagnostic else Diagnostic.PAYLOAD_AUTH
                return ProcessResult(1, b'', diagnostic)
            if case in LOCAL_REFUSALS:
                if self.extra_local: self.rpc()
                if self.unknown_local: return ProcessResult(1, b'', Diagnostic.UNKNOWN)
        return BoundedProcess()(command, payload, environment, seconds, **options)


class RefusalCampaignTests(unittest.TestCase):
    def setUp(self):
        self.fixture = support.ClientEnvironmentTests(); self.fixture.setUp()
        self.run = self.fixture.run
        self.namespace = Namespace(PREFIX + '0' * 32)
        self.report = CampaignReport.create(self.run.path / 'report', self.namespace, '1' * 64)
        self.native = NativeDouble(self.namespace, self.run, self.report)
        self.process = RoutedProcess(self.run, self.native)
        self.clients = RefusalEnvironment(self.run, self.fixture.staged, self.process, {'PATH': os.environ['PATH']})
        self.process.clients = self.clients
        self.campaign = RefusalCampaign(self.run, self.namespace, self.report, self.clients,
                                        self.native.observe, self.native.controller)

    def tearDown(self):
        self.fixture.tearDown()  # Only simulated native state, no actual TPM key.

    def assert_retained(self):
        self.assertTrue(self.native.inner.key and self.native.inner.root)
        self.assertTrue((self.run.path / 'journal').exists())
        self.assertTrue(self.campaign.controller.journal.failed)
        self.assertNotIn('delete', self.native.inner.calls)

    def test_full_plan_has_real_local_refusals_four_native_acks_and_distinct_public_evidence(self):
        self.campaign.execute()
        events = [json.loads(line) for line in self.report.path.read_text().splitlines()]
        self.assertEqual(len([row for row in events if row['kind'] == 'client']), 4)
        rejected = [row for row in events if row['kind'] == 'rejection']
        self.assertEqual(len(rejected), 12)
        self.assertEqual(sum(row['native_unwrap_successes'] for row in rejected), 2)
        self.assertEqual(len([row for row in rejected if row['evidence'] == 'client-local-refusal']), 10)
        self.assertTrue(all(row['exit_code'] == 1 and row['plaintext_bytes'] == 0 and not row['matched'] for row in rejected))
        self.assertEqual(events[-2]['successful_reads'], 2)
        self.assertTrue(events[-1]['authority_retired'])
        self.assertEqual(self.native.inner.calls.count('unwrap'), 4)
        self.assertEqual(self.native.inner.calls.count('delete'), 1)
        self.assertFalse(self.native.inner.key or self.native.inner.root)
        self.assertFalse((self.run.path / 'journal').exists())

    def test_matching_plaintext_control_without_native_call_cannot_authorize_rejections(self):
        self.process.skip_control = True
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()

    def test_unclassified_client_exit_and_no_calls_are_not_a_local_refusal(self):
        self.process.unknown_local = True
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()

    def test_local_refusal_with_extra_successful_native_request_is_uncertain(self):
        self.process.extra_local = True
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()

    def test_payload_diagnostic_without_native_success_is_not_payload_rejection(self):
        self.process.skip_payload = True
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()

    def test_payload_helper_authentication_rejection_is_not_payload_aead_failure(self):
        self.process.reject_payload_native = True
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()

    def test_payload_with_wrong_diagnostic_does_not_pass_on_native_success_alone(self):
        self.process.wrong_payload_diagnostic = True
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()

    def test_original_ciphertext_substitution_stops_before_local_input_invocation(self):
        original = self.clients.execute
        def substituted(controller, case, reader):
            if case is Refusal.WRONG_IDENTITY:
                self.clients._hybrid = b'replaced public ciphertext'
            return original(controller, case, reader)
        with patch.object(self.clients, 'execute', side_effect=substituted):
            with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()

    def test_public_identity_artifact_change_stops_before_local_read(self):
        original = self.clients.execute
        def changed(controller, case, reader):
            if case is Refusal.WRONG_IDENTITY:
                self.clients._identities[case].path.write_bytes(b'changed public identity')
            return original(controller, case, reader)
        with patch.object(self.clients, 'execute', side_effect=changed):
            with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()

    def test_rejection_report_failure_preserves_native_authority_after_quiescence(self):
        original = self.report._append
        def failed(value):
            if value['kind'] == 'rejection': raise OSError('fake refusal evidence write failure')
            return original(value)
        with patch.object(self.report, '_append', side_effect=failed):
            with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()
        self.assertFalse(self.campaign.service.thread.is_alive())


class RefusalPreparationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = support.ClientEnvironmentTests(); self.fixture.setUp()
        self.clients = self.fixture.environment()
        self.clients.preflight(); self.clients.prepare(self.fixture.reference)
        self.namespace = Namespace(PREFIX + '0' * 32)
        identity = PublicIdentity.parse(FakeWindows(self.namespace, None).identity, self.namespace)
        hybrid = self.clients.encrypt().output
        classical = BoundedProcess()([self.clients.inputs.age.path, '--encrypt', '--recipient',
                                      self.fixture.reference.classical_recipient], PAYLOAD,
                                     self.clients.environment(True), 10)
        self.assertEqual(classical.exit_code, 0)
        self.prepared = PreparedRefusals(self.namespace, identity, hybrid, classical.stdout)

    def tearDown(self):
        self.fixture.tearDown()  # Public encryption only; no private/native key.

    def test_cross_namespace_or_other_receiver_ciphertext_cannot_become_prepared_input(self):
        with self.assertRaises(Stop):
            replace(self.prepared, namespace=Namespace(PREFIX + '1' * 32))
        other = ClientReferences.from_identity(self.prepared.wrong_identity(), self.namespace)
        encrypted = BoundedProcess()([self.clients.inputs.age.path, '--encrypt', '--recipient',
                                      other.classical_recipient], PAYLOAD, self.clients.environment(True), 10)
        self.assertEqual(encrypted.exit_code, 0)
        with self.assertRaises(Stop): replace(self.prepared, classical=encrypted.stdout)

    def test_payload_refusal_preserves_entire_header_and_only_changes_final_payload_byte(self):
        changed = self.prepared.ciphertext(Refusal.PAYLOAD_AUTH)
        self.assertTrue(changed[:-1] == self.prepared.hybrid[:-1])
        self.assertEqual(changed[-1] ^ self.prepared.hybrid[-1], 1)
        self.assertTrue(self.prepared.wrong_identity().encoded[:1187] == self.prepared.identity.encoded[:1187])
        for invalid in ('payload_auth', None):
            with self.assertRaises(Stop): self.prepared.ciphertext(invalid)
            with self.assertRaises(Stop): self.prepared.reference(invalid)


if __name__ == '__main__':
    unittest.main()
