"""Checkpoint retirement with fake native state; real local files only."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from post_quantum_client.authority import Namespace, PREFIX, Stop
from post_quantum_client.controller import Controller, frame
from post_quantum_client.durable import Storage
from post_quantum_client.journal import Journal
from post_quantum_client.process import BinaryPin, digest
from post_quantum_client.report import AbsenceCheckpoint, AuthoritySnapshot, CampaignReport, ClientMeasurement
from test_post_quantum_client_controller import FakeWindows


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.directory.chmod(0o700)
        source = self.directory / 'source'
        source.write_bytes(b'fixed source')
        original = self.directory / 'original'
        original.write_bytes(b'never executed mock image')
        pin = BinaryPin.stage(original, digest(original), self.directory, {str(source): digest(source)})
        self.namespace = Namespace(PREFIX + '0' * 32)
        self.report = CampaignReport.create(self.directory / 'report', self.namespace, '1' * 64)
        self.journal = Journal.create(self.directory / 'journal', self.namespace, 'S-1-5-21-1001', pin.record())
        self.native = FakeWindows(self.namespace, self.journal)
        self.controller = Controller(self.journal, {}, self.native.observe, self.native.run)
        self.controller.admin('prepare')
        self.controller.forward(frame(8, b'\x00\x02' + self.namespace.key_name.encode()))
        self.report.authority(AuthoritySnapshot.from_summary(self.controller.summary()))
        self.report.client(ClientMeasurement('age', 'decrypt', 32, 100, 0, True))

    def tearDown(self):
        self.temporary.cleanup()

    def cleanup_checkpoint(self, final_absence=True):
        self.controller.forward(frame(4, self.native.identity))
        self.controller.admin('remove-root')
        if final_absence:
            self.controller.admin('absence')
        snapshot = AuthoritySnapshot.from_summary(self.controller.summary())
        self.report.authority(snapshot)
        return self.report.checkpoint(snapshot, self.native.observe(self.namespace))

    def test_valid_checkpoint_consumed_under_authority_before_report_completion(self):
        checkpoint = self.cleanup_checkpoint()
        receipt = self.journal.retire(checkpoint)
        self.assertFalse(self.journal.path.exists())
        self.assertTrue(self.journal.retired)
        self.assertFalse(self.native.key or self.native.root)
        self.report.complete(checkpoint, receipt)
        final = json.loads(self.report.path.read_text().splitlines()[-1])
        self.assertEqual(final, {'kind': 'complete', 'result': 'pass', 'authority_retired': True})
        with self.assertRaises(Stop):
            self.journal.retire(checkpoint)
        with self.assertRaises(Stop):
            self.report.failure('client')

    def test_no_checkpoint_or_no_final_absence_cannot_retire(self):
        with self.assertRaises(Stop):
            self.journal.retire(None)
        checkpoint = self.cleanup_checkpoint(final_absence=False)
        with self.assertRaises(Stop):
            self.journal.retire(checkpoint)
        self.assertTrue(self.journal.path.exists())
        self.assertTrue(self.journal.failed)

    def test_changed_report_retains_journal_and_never_claims_completion(self):
        checkpoint = self.cleanup_checkpoint()
        with self.report.path.open('ab') as stream:
            stream.write(b'{}\n')
        with self.assertRaises(Stop):
            self.journal.retire(checkpoint)
        self.assertTrue(self.journal.path.exists())
        self.assertFalse(self.journal.retired)

    def test_reopened_journal_cannot_consume_even_a_valid_checkpoint(self):
        checkpoint = self.cleanup_checkpoint()
        with self.assertRaises(Stop):
            Journal(self.journal.path).retire(checkpoint)
        self.assertTrue(self.journal.path.exists())
        self.journal.retire(checkpoint)
        self.assertTrue(self.journal.retired)

    def test_fatal_owner_cannot_reuse_an_earlier_healthy_checkpoint(self):
        checkpoint = self.cleanup_checkpoint()
        with self.assertRaises(Stop):
            self.controller.stop('controlled failure after checkpoint')
        with self.assertRaises(Stop):
            self.journal.retire(checkpoint)
        self.assertTrue(self.journal.path.exists())

    def test_replaced_authority_entry_is_preserved_even_after_valid_report_check(self):
        checkpoint = self.cleanup_checkpoint()
        original = AbsenceCheckpoint.verify
        retained = self.directory / 'retained-journal'
        def replace_after_verify(token, current):
            original(token, current)
            self.journal.path.rename(retained)
            self.journal.path.write_bytes(b'unrelated replacement')
            self.journal.path.chmod(0o600)
        with patch.object(AbsenceCheckpoint, 'verify', replace_after_verify):
            with self.assertRaises(Stop):
                self.journal.retire(checkpoint)
        self.assertEqual(self.journal.path.read_bytes(), b'unrelated replacement')
        self.assertTrue(retained.exists())

    def test_unlink_failure_keeps_full_journal_and_records_retirement_failure(self):
        checkpoint = self.cleanup_checkpoint()
        with patch.object(Storage, 'retire', side_effect=PermissionError('controlled unlink error')):
            with self.assertRaises(Stop):
                self.journal.retire(checkpoint)
        self.assertTrue(self.journal.path.exists())
        self.assertFalse(self.journal.retired)
        self.report.retirement_failed()
        self.assertEqual(json.loads(self.report.path.read_text().splitlines()[-1])['result'], 'fail')

    def test_directory_flush_failure_after_unlink_preserves_verified_absence_report(self):
        checkpoint = self.cleanup_checkpoint()
        count = len(self.native.calls)
        with patch('post_quantum_client.durable.os.fsync', side_effect=OSError('controlled directory flush')):
            with self.assertRaises(Stop):
                self.journal.retire(checkpoint)
        self.assertFalse(self.journal.path.exists())
        self.assertFalse(self.journal.retired)
        self.assertTrue(self.report.path.exists())
        self.report.retirement_failed()
        self.assertEqual(len(self.native.calls), count)
        self.assertFalse(self.native.root or self.native.key)
        self.assertEqual(json.loads(self.report.path.read_text().splitlines()[-1]),
                         {'kind': 'retirement_failure', 'result': 'fail'})

    def test_recreated_authority_path_prevents_final_report_completion(self):
        checkpoint = self.cleanup_checkpoint()
        receipt = self.journal.retire(checkpoint)
        self.journal.path.write_bytes(b'unrelated new entry')
        self.journal.path.chmod(0o600)
        with self.assertRaises(Stop):
            self.report.complete(checkpoint, receipt)
        self.assertEqual(self.journal.path.read_bytes(), b'unrelated new entry')
        self.assertEqual(self.report.phase, 'verified')

    def test_stop_during_checkpoint_verification_prevents_retirement(self):
        checkpoint = self.cleanup_checkpoint()
        original = AbsenceCheckpoint.verify
        def stop_after_verify(token, current):
            original(token, current)
            with self.assertRaises(Stop):
                self.controller.stop('concurrent lifecycle stop while retirement owns lock')
        with patch.object(AbsenceCheckpoint, 'verify', stop_after_verify):
            with self.assertRaises(Stop):
                self.journal.retire(checkpoint)
        self.assertTrue(self.journal.path.exists())
        self.assertFalse(self.journal.retired)
        self.assertTrue(self.journal.failed)

    def test_foreign_report_checkpoint_cannot_complete_changed_local_evidence(self):
        other = CampaignReport.create(self.directory / 'other-report', self.namespace, '1' * 64)
        other.authority(AuthoritySnapshot.from_summary(self.controller.summary()))
        other.client(ClientMeasurement('age', 'decrypt', 32, 100, 0, True))
        checkpoint = self.cleanup_checkpoint()
        current = AuthoritySnapshot.from_summary(self.controller.summary())
        other.authority(current)
        other.checkpoint(current, self.native.observe(self.namespace))
        receipt = self.journal.retire(checkpoint)
        with other.path.open('ab') as stream:
            stream.write(b'{"kind":"modified-evidence"}\n')
        with self.assertRaises(Stop):
            other.complete(checkpoint, receipt)
        events = [json.loads(line) for line in other.path.read_text().splitlines()]
        self.assertFalse(any(event.get('kind') == 'complete' for event in events))
        self.assertEqual(other.phase, 'verified')
        self.report.complete(checkpoint, receipt)
        self.assertEqual(self.report.phase, 'complete')

    def test_wrong_retirement_receipt_never_marks_the_report_complete(self):
        checkpoint = self.cleanup_checkpoint()
        with self.assertRaises(Stop):
            self.report.complete(checkpoint, None)
        self.assertTrue(self.journal.path.exists())
        self.assertEqual(self.report.phase, 'verified')


if __name__ == '__main__':
    unittest.main()
