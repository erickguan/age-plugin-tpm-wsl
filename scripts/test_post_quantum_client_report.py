"""Public fake authority and durable local evidence; no native or client execution."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from post_quantum_client.authority import Namespace, Observation, PREFIX, Stop
from post_quantum_client.durable import Storage
from post_quantum_client.report import AuthoritySnapshot, CampaignReport, ClientMeasurement

SID = 'S-1-5-21-1001'


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.directory.chmod(0o700)
        self.namespace = Namespace(PREFIX + '0' * 32)
        self.path = self.directory / 'report.jsonl'
        self.report = CampaignReport.create(self.path, self.namespace, '1' * 64)
        self.enrolled = AuthoritySnapshot(self.namespace.directory, hashlib.sha256(SID.encode()).hexdigest(),
                                           '2' * 64, True, False, False, False, True)
        self.clean = replace(self.enrolled, deleted=True, removed=True)
        self.measurement = ClientMeasurement('age', 'decrypt', 32, 500, 0, True)
        self.absent = Observation(SID, True, True)

    def tearDown(self):
        self.temporary.cleanup()

    def ready(self):
        self.report.authority(self.enrolled)
        self.report.client(self.measurement)
        self.report.authority(self.clean)

    def test_exact_private_bootstrap_is_reserved_exclusively_before_activity(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.path.read_text())['result'], 'incomplete')
        with self.assertRaises(FileExistsError):
            CampaignReport.create(self.path, self.namespace, '1' * 64)

    def test_verified_absence_checkpoint_contains_only_typed_public_metadata(self):
        self.ready()
        checkpoint = self.report.checkpoint(self.clean, self.absent)
        checkpoint.verify(self.clean)
        data = self.path.read_text()
        self.assertNotIn(SID, data)
        events = [json.loads(line) for line in data.splitlines()]
        self.assertEqual(events[-1]['kind'], 'verified_absence')
        self.assertEqual(events[-1]['successful_reads'], 1)
        self.assertEqual(set(events[2]), {'kind', 'client', 'operation', 'payload_bytes', 'elapsed_ms',
                                         'exit_code', 'matched', 'case', 'encryptor', 'result', 'bound_ms'})
        with self.assertRaises(Stop):
            self.report.failure('cleanup')

    def test_namespace_sid_and_identity_cannot_rotate_after_authority_is_saved(self):
        self.report.authority(self.enrolled)
        for snapshot in [replace(self.enrolled, namespace=PREFIX + '1' * 32),
                         replace(self.enrolled, sid_sha256='3' * 64),
                         replace(self.enrolled, identity_sha256='4' * 64)]:
            with self.assertRaises(Stop):
                self.report.authority(snapshot)

    def test_checkpoint_requires_successful_read_before_absence_can_be_accepted(self):
        self.report.authority(self.clean)
        with self.assertRaises(Stop):
            self.report.checkpoint(self.clean, self.absent)

    def test_checkpoint_requires_matching_independent_sid_and_root_key_absence(self):
        self.ready()
        for observed in [Observation(SID, False, True), Observation(SID, True, False),
                         Observation('S-1-5-21-2002', True, True)]:
            with self.assertRaises(Stop):
                self.report.checkpoint(self.clean, observed)
        self.report.checkpoint(self.clean, self.absent).verify(self.clean)

    def test_completed_cleanup_or_stop_cannot_roll_back_to_add_more_client_results(self):
        self.report.authority(self.clean)
        with self.assertRaises(Stop):
            self.report.authority(self.enrolled)
        self.report.authority(replace(self.clean, cleanup_stopped=True))
        with self.assertRaises(Stop):
            self.report.authority(self.clean)

    def test_nonzero_mismatch_or_over_bound_result_prevents_checkpoint(self):
        self.report.authority(self.enrolled)
        self.report.client(replace(self.measurement, elapsed_ms=10001))
        self.assertEqual(self.report.phase, 'failed')
        self.assertEqual(json.loads(self.path.read_text().splitlines()[-1])['result'], 'fail')
        with self.assertRaises(Stop):
            self.report.checkpoint(self.clean, self.absent)
        self.assertFalse(replace(self.measurement, exit_code=1).passed)
        self.assertFalse(replace(self.measurement, matched=False).passed)

    def test_failed_client_latches_phase_before_a_successful_write_can_be_interrupted(self):
        self.report.authority(self.enrolled)
        self.report.client(self.measurement)
        original = self.report._append
        def interrupted(value):
            original(value)
            if value.get('kind') == 'client' and value.get('result') == 'fail':
                raise KeyboardInterrupt('after failed-client evidence fsync')
        with patch.object(self.report, '_append', interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.report.client(replace(self.measurement, matched=False))
        # Even a caller that ignores the interruption cannot mint a checkpoint.
        try:
            self.report.authority(self.clean)
        except Stop:
            pass
        with self.assertRaises(Stop):
            self.report.checkpoint(self.clean, self.absent)
        self.assertEqual(self.report.phase, 'failed')

    def test_stopped_or_inspection_only_authority_never_grants_checkpoint(self):
        self.report.authority(self.enrolled)
        self.report.client(self.measurement)
        for snapshot in [replace(self.clean, cleanup_stopped=True),
                         replace(self.clean, cleanup_stopped=True, continuation_owned=False)]:
            self.report.authority(snapshot)
            with self.assertRaises(Stop):
                self.report.checkpoint(snapshot, self.absent)

    def test_strict_flags_and_client_fields_cannot_accept_boolean_numbers_or_payload_data(self):
        with self.assertRaises(Stop):
            replace(self.enrolled, prepared=1)
        with self.assertRaises(Stop):
            replace(self.enrolled, prepared=False)
        for measurement in [replace(self.measurement, exit_code=False), replace(self.measurement, matched=1),
                            replace(self.measurement, elapsed_ms=-1),
                            replace(self.measurement, payload_bytes=4194305),
                            replace(self.measurement, client='raw payload')]:
            with self.assertRaises(Stop):
                measurement.validate()

    def test_failed_evidence_write_stops_reuse_and_reopening_never_adopts_authority(self):
        with patch.object(Storage, 'append', side_effect=OSError('controlled report I/O failure')):
            with self.assertRaises(Stop):
                self.report.authority(self.enrolled)
        self.assertTrue(self.report.failed)
        with self.assertRaises(Stop):
            self.report.authority(self.enrolled)
        reopened = CampaignReport(self.path, self.namespace)
        with self.assertRaises(Stop):
            reopened.authority(self.enrolled)

    def test_checkpoint_changed_bytes_inode_or_ownership_must_be_rejected(self):
        self.ready()
        checkpoint = self.report.checkpoint(self.clean, self.absent)
        original = self.path.read_bytes()
        self.path.write_bytes(original + b'{}\n')
        with self.assertRaises(Stop):
            checkpoint.verify(self.clean)
        self.path.write_bytes(original)
        checkpoint.verify(self.clean)
        self.path.rename(self.directory / 'retained-report')
        self.path.write_bytes(original)
        self.path.chmod(0o600)
        with self.assertRaises(Stop):
            checkpoint.verify(self.clean)

    def test_checkpoint_cannot_be_reused_for_another_process_or_identity(self):
        self.ready()
        checkpoint = self.report.checkpoint(self.clean, self.absent)
        with self.assertRaises(Stop):
            checkpoint.verify(replace(self.clean, identity_sha256='3' * 64))
        with patch('post_quantum_client.report.os.getpid', return_value=os.getpid() + 1):
            with self.assertRaises(Stop):
                checkpoint.verify(self.clean)

    def test_failure_category_is_fixed_and_cannot_log_raw_exception_material(self):
        with self.assertRaises(Stop):
            self.report.failure('raw unknown diagnostic')
        self.report.failure('client')
        self.assertEqual(json.loads(self.path.read_text().splitlines()[-1]),
                         {'kind': 'failure', 'category': 'client', 'result': 'fail'})


if __name__ == '__main__':
    unittest.main()
