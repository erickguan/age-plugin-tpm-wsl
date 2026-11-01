"""Read verdicts through real local IPC and exclusively fake native operations."""
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from post_quantum_client.authority import Namespace, PREFIX, Stop
from post_quantum_client.cases import ClientCase, PAYLOAD
from post_quantum_client.clients import ClientOutcome
from post_quantum_client.controller import CLEANUP_FAILED, Controller, frame, response
from post_quantum_client.journal import AUTHENTICATION_FAILED, INVALID, Journal
from post_quantum_client.outcomes import ReadDecision, ReadExpectation, ReadKind, classify_read, observe_read
from post_quantum_client.process import BinaryPin, ProcessResult, digest
from post_quantum_client.report import CampaignReport, ClientMeasurement
from post_quantum_client.service import ClientService
from post_quantum_client.wrapper import forward_stdio
from test_post_quantum_client_controller import FakeWindows, SID


class OutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name); self.directory.chmod(0o700)
        source = self.directory / 'source'; source.write_bytes(b'public fake source')
        image = self.directory / 'image'; image.write_bytes(b'never executed fake Windows image')
        pin = BinaryPin.stage(image, digest(image), self.directory, {str(source): digest(source)})
        self.namespace = Namespace(PREFIX + '0' * 32)
        self.journal = Journal.create(self.directory / 'journal', self.namespace, SID, pin.record())
        self.native = FakeWindows(self.namespace, self.journal)
        self.controller = Controller(self.journal, {}, self.native.observe, self.native.run)
        self.controller.admin('prepare')
        self.controller.forward(frame(8, b'\x00\x02' + self.namespace.key_name.encode()))
        self.service = ClientService(self.directory / 's', self.controller).start()
        self.case = ClientCase('minimal', PAYLOAD)
        self.positive = ReadExpectation(self.case, 'age', ReadKind.POSITIVE)
        self.invalid = ReadExpectation(self.case, 'age', ReadKind.KNOWN_INVALID)

    def tearDown(self):
        try:
            if not self.service.endpoint.closed:
                self.service.abandon()
        finally:
            self.temporary.cleanup()  # Only simulated state, never a TPM key/root.

    def client(self):
        # This test double substitutes a fixed mock protocol key. No actual
        # native executable is launched and no real file key enters this test.
        request = frame(9, b'\x05\x14' + self.native.identity + b'\x01' * 1153 + b'\x02' * 32)
        output = io.BytesIO()
        forward_stdio(self.directory / 's', os.getpid(), io.BytesIO(request), output)
        status, _ = response(output.getvalue(), 9)
        return ClientOutcome(ClientMeasurement('age', 'decrypt', 32, 50, 1 if status else 0, not status),
                             b'' if status else PAYLOAD)

    def rejection(self, status=INVALID):
        self.native.override = lambda operation: ProcessResult(0, frame(9, status=status))

    def assert_stopped(self):
        self.assertTrue(self.journal.failed)
        count = len(self.native.calls)
        with self.assertRaises(Stop): self.controller.forward(frame(4, self.native.identity))
        self.assertEqual(len(self.native.calls), count)
        self.assertTrue(self.journal.path.exists())
        self.assertTrue(self.native.key and self.native.root)

    def test_exact_positive_native_read_matches_and_retains_healthy_owner(self):
        decision = observe_read(self.controller, self.positive, self.client)
        self.assertIs(decision.kind, ReadKind.POSITIVE)
        self.assertTrue(decision.accepted and decision.measurement.passed)
        self.assertFalse(self.controller.summary()['cleanup_stopped'])

    def test_exact_invalid_is_known_but_never_a_successful_plaintext_read(self):
        self.rejection()
        decision = observe_read(self.controller, self.invalid, self.client)
        self.assertIs(decision.kind, ReadKind.KNOWN_INVALID)
        self.assertTrue(decision.accepted)
        self.assertFalse(decision.measurement.passed)
        self.assertFalse(self.controller.summary()['cleanup_stopped'])
        report = CampaignReport.create(self.directory / 'report', self.namespace, '1' * 64)
        report.authority(self.controller.read_audit().authority)
        report.client(decision.measurement)
        self.assertEqual(report.decryptions, 0)
        self.assertEqual(report.phase, 'failed')

    def test_nonzero_client_exit_without_native_evidence_is_uncertain_and_stops(self):
        failed = ClientOutcome(ClientMeasurement('age', 'decrypt', 32, 50, 1, False), b'')
        with self.assertRaises(Stop): observe_read(self.controller, self.invalid, lambda: failed)
        self.assert_stopped()

    def test_matching_plaintext_without_native_success_is_not_accepted(self):
        result = ClientOutcome(ClientMeasurement('age', 'decrypt', 32, 50, 0, True), PAYLOAD)
        with self.assertRaises(Stop): observe_read(self.controller, self.positive, lambda: result)
        self.assert_stopped()

    def test_positive_read_does_not_accept_a_known_rejection(self):
        self.rejection()
        with self.assertRaises(Stop): observe_read(self.controller, self.positive, self.client)
        self.assert_stopped()

    def test_unexpected_success_does_not_pass_an_invalid_expectation(self):
        with self.assertRaises(Stop): observe_read(self.controller, self.invalid, self.client)
        self.assert_stopped()

    def test_extra_native_read_cannot_be_misattributed_to_one_checked_read(self):
        def twice():
            self.client()
            return self.client()
        with self.assertRaises(Stop): observe_read(self.controller, self.positive, twice)
        self.assert_stopped()

    def test_rejection_of_a_different_operation_is_not_an_unwrap_rejection(self):
        self.native.override = lambda operation: ProcessResult(0, frame(2, status=INVALID))
        def inspect():
            self.controller.forward(frame(2, self.native.identity))
            return ClientOutcome(ClientMeasurement('age', 'decrypt', 32, 50, 1, False), b'')
        with self.assertRaises(Stop): observe_read(self.controller, self.invalid, inspect)
        self.assert_stopped()

    def test_fatal_status_cannot_be_classified_as_known_invalid(self):
        self.native.override = lambda operation: ProcessResult(0, frame(9, status=CLEANUP_FAILED))
        with self.assertRaises(Stop): observe_read(self.controller, self.invalid, self.client)
        self.assert_stopped()

    def test_valid_rejection_frame_with_process_exit_failure_is_unknown(self):
        self.native.override = lambda operation: ProcessResult(1, frame(9, status=INVALID))
        with self.assertRaises(Stop): observe_read(self.controller, self.invalid, self.client)
        self.assert_stopped()

    def test_truncated_response_is_unknown(self):
        self.native.override = lambda operation: ProcessResult(0, frame(9, status=INVALID)[:-1])
        with self.assertRaises(Stop): observe_read(self.controller, self.invalid, self.client)
        self.assert_stopped()

    def test_wrong_response_operation_is_unknown(self):
        self.native.override = lambda operation: ProcessResult(0, frame(10, status=INVALID))
        with self.assertRaises(Stop): observe_read(self.controller, self.invalid, self.client)
        self.assert_stopped()

    def test_timeout_is_unknown_even_for_an_expected_invalid(self):
        def timed_out(operation): raise TimeoutError('fake timeout')
        self.native.override = timed_out
        with self.assertRaises(Stop): observe_read(self.controller, self.invalid, self.client)
        self.assert_stopped()

    def test_interruption_after_valid_native_result_stops_before_further_actions(self):
        def failed_evidence():
            self.client()
            raise OSError('fake failed result reporting')
        with self.assertRaises(Stop): observe_read(self.controller, self.positive, failed_evidence)
        self.assert_stopped()

    def test_audit_requires_same_owner_history_pid_and_authority(self):
        before = self.controller.read_audit(); outcome = self.client(); after = self.controller.read_audit()
        for changed in (replace(after, journal=object()), replace(after, owner_pid=os.getpid() + 1),
                        replace(after, events=()),
                        replace(after, authority=replace(after.authority, sid_sha256='2' * 64))):
            with self.assertRaises(Stop): classify_read(self.positive, outcome, before, changed)
        self.assertNotIn(SID, repr(after))
        self.assertNotIn(self.native.identity.hex(), repr(after))

    def test_constructed_or_changed_receipts_never_authenticate_history(self):
        before = self.controller.read_audit()
        fabricated = replace(before, events=before.events +
                             (('intent', 'unwrap', 0), ('rejected', 'unwrap', INVALID)))
        failed = ClientOutcome(ClientMeasurement('age', 'decrypt', 32, 50, 1, False), b'')
        with self.assertRaises(Stop): classify_read(self.invalid, failed, before, fabricated)
        foreign = object()
        with self.assertRaises(Stop):
            classify_read(self.invalid, failed, replace(before, journal=foreign),
                          replace(fabricated, journal=foreign))
        with self.assertRaises(Stop):
            classify_read(self.invalid, failed, before, replace(before))

    def test_captured_rejection_cannot_pass_after_live_stop(self):
        self.rejection()
        before = self.controller.read_audit(); outcome = self.client(); after = self.controller.read_audit()
        try: self.controller.stop('deterministic fake late stop')
        except Stop: pass
        with self.assertRaises(Stop): classify_read(self.invalid, outcome, before, after)
        self.assert_stopped()

    def test_stop_between_second_audit_and_classification_is_not_accepted(self):
        self.rejection()
        original = self.controller.read_audit
        calls = []
        def capture():
            audit = original(); calls.append(audit)
            if len(calls) == 2:
                try: self.controller.stop('fake stop after capture')
                except Stop: pass
            return audit
        with patch.object(self.controller, 'read_audit', side_effect=capture):
            with self.assertRaises(Stop): observe_read(self.controller, self.invalid, self.client)
        self.assert_stopped()

    def test_classification_consumes_the_exact_issued_pair_once(self):
        self.rejection()
        before = self.controller.read_audit(); outcome = self.client(); after = self.controller.read_audit()
        self.assertTrue(classify_read(self.invalid, outcome, before, after).accepted)
        with self.assertRaises(Stop): classify_read(self.invalid, outcome, before, after)

    def test_new_journal_history_invalidates_a_captured_pair(self):
        before = self.controller.read_audit(); outcome = self.client(); after = self.controller.read_audit()
        self.controller.forward(frame(2, self.native.identity))
        with self.assertRaises(Stop): classify_read(self.positive, outcome, before, after)

    def test_local_poison_invalidates_genuine_captured_audits(self):
        before = self.controller.read_audit(); outcome = self.client(); after = self.controller.read_audit()
        self.journal.poison()
        with self.assertRaises(Stop): classify_read(self.positive, outcome, before, after)
        self.assert_stopped()

    def test_changed_issued_receipt_cannot_match_its_registered_content(self):
        before = self.controller.read_audit(); outcome = self.client(); after = self.controller.read_audit()
        object.__setattr__(after, 'events', before.events)
        with self.assertRaises(Stop): classify_read(self.positive, outcome, before, after)

    def test_poison_during_verdict_construction_prevents_returning_acceptance(self):
        before = self.controller.read_audit(); outcome = self.client(); after = self.controller.read_audit()
        journal = self.journal
        class PoisonedBytes(bytes):
            def __eq__(self, other):
                journal.poison()
                return True
        outcome = replace(outcome, output=PoisonedBytes(PAYLOAD))
        with self.assertRaises(Stop): classify_read(self.positive, outcome, before, after)
        self.assert_stopped()

    def public_report(self):
        report = CampaignReport.create(self.directory / 'report', self.namespace, '1' * 64)
        report.authority(self.controller.read_audit().authority)
        return report

    def test_caller_daemon_measurements_cannot_publish_reads_or_unlock_absence(self):
        report = self.public_report()
        original = report.path.read_bytes()
        for label in ('fnox_daemon_cold', 'fnox_daemon_warm', 'fnox_daemon_bypass'):
            for operation in ('decrypt', 'fnox-read'):
                with self.subTest(label=label, operation=operation):
                    measurement = ClientMeasurement('fnox', operation, 32, 1, 0, True, label, 'fnox')
                    with self.assertRaises(Stop): report.client(measurement)
        self.assertEqual(report.path.read_bytes(), original)
        self.assertEqual(report.decryptions, 0)
        self.assertFalse(report.daemon_native_reads or report.daemon_cache_hits)

    def test_fabricated_decision_cannot_be_published_as_positive_evidence(self):
        report = self.public_report()
        forged = ReadDecision(ReadKind.POSITIVE, ClientMeasurement('age', 'decrypt', 32, 50, 0, True))
        with self.assertRaises(Stop): report.checked_read(forged, self.journal)
        self.assertEqual(report.decryptions, 0)
        self.assert_stopped()

    def test_issued_decision_can_be_published_only_once(self):
        report = self.public_report()
        decision = observe_read(self.controller, self.positive, self.client)
        report.checked_read(decision, self.journal)
        self.assertEqual(report.decryptions, 1)
        with self.assertRaises(Stop): report.checked_read(decision, self.journal)
        self.assertEqual(report.decryptions, 1)
        self.assert_stopped()

    def test_stop_after_decision_invalidates_deferred_evidence(self):
        report = self.public_report()
        decision = observe_read(self.controller, self.positive, self.client)
        try: self.controller.stop('fake late deferred-report stop')
        except Stop: pass
        with self.assertRaises(Stop): report.checked_read(decision, self.journal)
        self.assertEqual(report.decryptions, 0)
        self.assert_stopped()

    def test_changed_decision_measurement_cannot_be_published(self):
        report = self.public_report()
        decision = observe_read(self.controller, self.positive, self.client)
        altered = replace(decision, measurement=replace(decision.measurement, elapsed_ms=1))
        with self.assertRaises(Stop): report.checked_read(altered, self.journal)
        self.assertEqual(report.decryptions, 0)
        self.assert_stopped()

    def test_known_rejection_without_both_checked_controls_cannot_be_reported(self):
        report = self.public_report(); self.rejection()
        expectation = ReadExpectation(ClientCase('component_mlkem', PAYLOAD), 'age', ReadKind.KNOWN_INVALID)
        decision = observe_read(self.controller, expectation, self.client)
        with self.assertRaises(Stop): report.checked_read(decision, self.journal)
        self.assertEqual(report.decryptions, 0)
        self.assertFalse(report.rejections)
        self.assert_stopped()

    def test_mutating_existing_measurement_cannot_change_issued_metadata(self):
        report = self.public_report()
        decision = observe_read(self.controller, self.positive, self.client)
        object.__setattr__(decision.measurement, 'elapsed_ms', 1)
        with self.assertRaises(Stop): report.checked_read(decision, self.journal)
        self.assertEqual(report.decryptions, 0)
        self.assert_stopped()

    def test_existing_rejection_measurement_cannot_be_relabelled_to_another_component(self):
        report = self.public_report()
        for client in ('age', 'rage'):
            expectation = ReadExpectation(ClientCase('control', PAYLOAD, 'age', (client,)), client, ReadKind.POSITIVE)
            def invoke():
                result = self.client()
                return replace(result, measurement=replace(result.measurement, client=client))
            report.checked_read(observe_read(self.controller, expectation, invoke), self.journal)
        self.rejection(AUTHENTICATION_FAILED)
        expectation = ReadExpectation(ClientCase('component_mlkem', PAYLOAD), 'age', ReadKind.AUTHENTICATION_REJECTED)
        decision = observe_read(self.controller, expectation, self.client)
        object.__setattr__(decision.measurement, 'case', 'component_p256')
        with self.assertRaises(Stop): report.checked_read(decision, self.journal)
        self.assertEqual(report.decryptions, 2)
        self.assertFalse(report.rejections)
        self.assert_stopped()

    def test_reopened_journal_cannot_issue_read_audits(self):
        reopened = Controller(Journal(self.journal.path), {}, self.native.observe, self.native.run)
        with self.assertRaises(Stop): reopened.read_audit()

    def test_over_bound_or_wrong_client_measurement_never_passes_known_invalid(self):
        self.rejection()
        before = self.controller.read_audit(); result = self.client(); after = self.controller.read_audit()
        measurements = (replace(result.measurement, elapsed_ms=10001),
                        replace(result.measurement, client='rage'),
                        replace(result.measurement, exit_code=2),
                        replace(result.measurement, payload_bytes=1))
        for measurement in measurements:
            # Every verdict consumes its genuinely issued pair, even uncertainty.
            decision = classify_read(self.invalid, replace(result, measurement=measurement), before, after)
            self.assertIs(decision.kind, ReadKind.UNCERTAIN)
            self.assertFalse(decision.accepted)
            before = self.controller.read_audit(); result = self.client(); after = self.controller.read_audit()

    def test_interrupted_protocol_output_ack_is_unknown(self):
        self.service.endpoint.seconds = 0.2  # Fake native only; production stays 10.
        class FailedOutput:
            def write(self, data): raise BrokenPipeError('simulated output failure')
        request = frame(9, b'\x05\x14' + self.native.identity + b'\x01' * 1153 + b'\x02' * 32)
        def interrupted():
            forward_stdio(self.directory / 's', os.getpid(), io.BytesIO(request), FailedOutput())
        with self.assertRaises(Stop): observe_read(self.controller, self.positive, interrupted)
        self.assert_stopped()

    def test_trailing_response_is_unknown(self):
        self.native.override = lambda operation: ProcessResult(0, frame(9, status=INVALID) + b'extra')
        with self.assertRaises(Stop): observe_read(self.controller, self.invalid, self.client)
        self.assert_stopped()

    def test_replay_refuses_unknown_rejection_status(self):
        with self.journal.locked() as session:
            session.append({'kind': 'intent', 'operation': 'unwrap'})
            with self.assertRaises(Stop):
                session.append({'kind': 'rejected', 'operation': 'unwrap', 'status': CLEANUP_FAILED})
        self.assert_stopped()

    def test_replay_refuses_unknown_or_mutating_rejection_events(self):
        with self.journal.locked() as session:
            session.append({'kind': 'intent', 'operation': 'delete'})
            with self.assertRaises(Stop):
                session.append({'kind': 'rejected', 'operation': 'delete', 'status': INVALID})
        self.assert_stopped()


if __name__ == '__main__':
    unittest.main()
