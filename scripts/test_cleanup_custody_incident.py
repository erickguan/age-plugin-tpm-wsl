"""Mocked one-namespace recovery order, fatal-stop and authority controls; no native calls."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('cleanup-custody-native-incident.py')
CONTROLLER_SOURCE = Path(__file__).with_name('validate-pq-custody-native.py')
spec = importlib.util.spec_from_file_location('incident_cleanup', SOURCE)
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)

NAMESPACE = 'age-tpm-wsl-pq-native-0123456789abcdef0123456789abcdef'
NAME = 'age-tpm-wsl-pq-0123456789abcdef0123456789abcdef'


class Campaign:
    def __init__(self, failure=None, absent=None):
        self.calls = []
        self.failure = failure
        self.absent = absent if absent is not None else {'key_absent': True, 'root_absent': True}

    def invoke(self, namespace, mode):
        self.calls.append((namespace, mode))
        if mode == self.failure:
            raise RuntimeError('injected ' + mode + ' uncertainty')
        return self.absent if mode == 'absence' else {'result': 'pass'}


class CleanupOrderTests(unittest.TestCase):
    def snapshots(self, before=None, after=None):
        values = iter([before or {'windows_sid': 'same-sid', 'objects': [NAMESPACE]},
                       after or {'windows_sid': 'same-sid', 'objects': ['foreign-reserved-root']}])
        self.snapshot_calls = []
        def invoke():
            self.snapshot_calls.append('snapshot')
            return next(values)
        return invoke

    def test_only_owned_namespace_and_exact_three_calls(self):
        campaign = Campaign()
        _, after = cleanup.matching_cleanup(campaign, self.snapshots(), 'same-sid', NAMESPACE)
        self.assertEqual(campaign.calls, [(NAMESPACE, mode) for mode in ['delete', 'remove-root', 'absence']])
        self.assertEqual(len(self.snapshot_calls), 2)
        self.assertEqual(after['objects'], ['foreign-reserved-root'])

    def test_wrong_sid_refuses_before_mutation(self):
        campaign = Campaign()
        with self.assertRaisesRegex(RuntimeError, 'SID differs'):
            cleanup.matching_cleanup(campaign, self.snapshots(before={'windows_sid': 'wrong', 'objects': []}), 'same-sid', NAMESPACE)
        self.assertEqual(campaign.calls, [])

    def test_delete_uncertainty_stops_without_root_removal_or_retry(self):
        campaign = Campaign(failure='delete')
        with self.assertRaisesRegex(RuntimeError, 'uncertainty'):
            cleanup.matching_cleanup(campaign, self.snapshots(), 'same-sid', NAMESPACE)
        self.assertEqual(campaign.calls, [(NAMESPACE, 'delete')])
        self.assertEqual(len(self.snapshot_calls), 1)

    def test_root_removal_uncertainty_stops_without_further_calls(self):
        campaign = Campaign(failure='remove-root')
        with self.assertRaisesRegex(RuntimeError, 'uncertainty'):
            cleanup.matching_cleanup(campaign, self.snapshots(), 'same-sid', NAMESPACE)
        self.assertEqual([mode for _, mode in campaign.calls], ['delete', 'remove-root'])
        self.assertEqual(len(self.snapshot_calls), 1)

    def test_incomplete_absence_never_advances_to_independent_snapshot(self):
        for absence in [{'key_absent': False, 'root_absent': True}, {'key_absent': True, 'root_absent': False}, {'key_absent': 1, 'root_absent': True}]:
            with self.subTest(absence=absence):
                campaign = Campaign(absent=absence)
                with self.assertRaisesRegex(RuntimeError, 'absence not verified'):
                    cleanup.matching_cleanup(campaign, self.snapshots(), 'same-sid', NAMESPACE)
                self.assertEqual(len(self.snapshot_calls), 1)

    def test_independent_presence_refuses_success(self):
        campaign = Campaign()
        with self.assertRaisesRegex(RuntimeError, 'reserved-namespace absence'):
            cleanup.matching_cleanup(campaign, self.snapshots(after={'windows_sid': 'same-sid', 'objects': [NAMESPACE]}), 'same-sid', NAMESPACE)
        self.assertEqual(len(campaign.calls), 3)
        self.assertEqual(len(self.snapshot_calls), 2)


def synthetic_incident(folder, executable_sha):
    identity = b'\x03\x00\x02' + bytes(1249) + b'\x2f' + NAME.encode()
    assert len(identity) == 1300
    encoded = identity.hex()
    journal = folder / 'journal.json'
    journal.write_text(json.dumps({NAMESPACE: encoded}))
    journal.chmod(0o600)
    incident = {'result': 'fail', 'executed': True, 'cleanup_stopped': True,
                'before': {'windows_sid': 'same-sid', 'objects': [NAMESPACE]},
                'public_reference_journal': str(journal),
                'native_steps': [
                    {'operation': 'create-final', 'namespace': NAMESPACE, 'result': {
                        'result': 'pass', 'root_created_exclusively': True, 'name': NAME,
                        'expected_identity_sha256': hashlib.sha256(identity).hexdigest(),
                        'expected_identity_bytes': 1300}},
                    {'operation': 'absence', 'namespace': NAMESPACE, 'result': {'result': 'fail'}},
                ],
                'source_sha256': {'helper/src/post_quantum/store/native_tests.rs': 'old', 'scripts/validate-pq-custody-native.py': 'old',
                                  'helper/src/post_quantum/store.rs': 'same'}}
    path = folder / 'incident.json'
    path.write_text(json.dumps(incident))
    software = {'result': 'pass', 'native_test_path': str(folder / 'executable.exe'),
                'native_test_sha256': executable_sha,
                'steps': [{'check': 'native Windows scripted TPM and lifecycle tests', 'exit_code': 0,
                           'test_summaries': [['17', '0', '1']]}],
                'source_sha256': dict(incident['source_sha256'], **{cleanup.CONTROLLER: cleanup.digest(CONTROLLER_SOURCE)})}
    software_path = folder / 'software.json'
    software_path.write_text(json.dumps(software))
    return path, software_path, journal, encoded


class PreflightAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='incident-authority-regression-')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.executable = self.folder / 'executable.exe'
        self.executable.write_bytes(b'tested executable')
        self.sha = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.staging = self.folder / 'staging'

    def preflight(self, path, software_path):
        return cleanup.preflight(path, software_path, self.staging)

    def load(self, path):
        return json.loads(path.read_text())

    def test_passing_authority_binds_identity_journal_and_allowlisted_changes(self):
        path, software_path, _, _ = synthetic_incident(self.folder, self.sha)
        software = self.load(software_path)
        software['source_sha256']['helper/src/post_quantum/store/native_tests.rs'] = 'new'
        software_path.write_text(json.dumps(software))
        public, encoded, journal, controller_source = self.preflight(path, software_path)
        self.assertEqual(public['namespace'], NAMESPACE)
        self.assertEqual(public['name'], NAME)
        self.assertEqual(public['expected_identity_bytes'], 1300)
        self.assertEqual(public['executable_sha256'], self.sha)
        self.assertEqual(public['executable'], str(self.staging / ('cleanup-' + self.sha[:16] + '.exe')))
        self.assertEqual(cleanup.digest(public['executable']), self.sha)
        self.assertEqual(controller_source, CONTROLLER_SOURCE.read_bytes())
        self.assertEqual(public['source_changes_since_incident'],
                         sorted(['helper/src/post_quantum/store/native_tests.rs', cleanup.CONTROLLER]))
        self.assertEqual(len(bytes.fromhex(encoded)), 1300)
        self.assertTrue(stat.S_IMODE(journal.stat().st_mode) == 0o600)

    def test_foreign_source_change_refuses(self):
        path, software_path, _, _ = synthetic_incident(self.folder, self.sha)
        software = self.load(software_path)
        software['source_sha256']['helper/src/post_quantum/store.rs'] = 'changed elsewhere'
        software_path.write_text(json.dumps(software))
        with self.assertRaisesRegex(RuntimeError, 'beyond the allowlisted'):
            self.preflight(path, software_path)

    def test_source_set_change_refuses(self):
        path, software_path, _, _ = synthetic_incident(self.folder, self.sha)
        software = self.load(software_path)
        software['source_sha256']['helper/src/post_quantum/pcp.rs'] = 'added'
        software_path.write_text(json.dumps(software))
        with self.assertRaisesRegex(RuntimeError, 'different files'):
            self.preflight(path, software_path)

    def test_nonpassing_software_or_wrong_summary_refuses(self):
        path, software_path, _, _ = synthetic_incident(self.folder, self.sha)
        software = self.load(software_path)
        software['result'] = 'fail'
        software_path.write_text(json.dumps(software))
        with self.assertRaisesRegex(RuntimeError, 'software validation must pass'):
            self.preflight(path, software_path)
        software['result'] = 'pass'
        software['steps'][0]['test_summaries'] = [['16', '0', '1']]
        software_path.write_text(json.dumps(software))
        with self.assertRaisesRegex(RuntimeError, '17 Windows software tests'):
            self.preflight(path, software_path)

    def test_live_controller_mismatch_or_missing_binding_refuses(self):
        path, software_path, _, _ = synthetic_incident(self.folder, self.sha)
        software = self.load(software_path)
        software['source_sha256'][cleanup.CONTROLLER] = '0' * 64
        software_path.write_text(json.dumps(software))
        with self.assertRaisesRegex(RuntimeError, 'live native controller differs'):
            self.preflight(path, software_path)
        del software['source_sha256'][cleanup.CONTROLLER]
        software_path.write_text(json.dumps(software))
        with self.assertRaisesRegex(RuntimeError, 'must bind the native controller source'):
            self.preflight(path, software_path)

    def test_executable_replacement_after_validation_or_foreign_staging_refuses(self):
        path, software_path, _, _ = synthetic_incident(self.folder, self.sha)
        public, _, _, _ = self.preflight(path, software_path)
        staged = Path(public['executable'])
        # Reuse of an existing identical staged copy is idempotent.
        again, _, _, _ = self.preflight(path, software_path)
        self.assertEqual(again['executable'], str(staged))
        # A rebuild that replaces the validated source pathname must refuse.
        self.executable.write_bytes(b'replacement executable B')
        with self.assertRaisesRegex(RuntimeError, 'executable changed'):
            self.preflight(path, software_path)
        self.executable.write_bytes(b'tested executable')
        # A symlink to matching validated content is never accepted.
        staged.unlink()
        os.symlink(self.executable, staged)
        with self.assertRaisesRegex(RuntimeError, 'not a safe regular file'):
            self.preflight(path, software_path)
        # A matching-content writable file is refused on staging permissions.
        staged.unlink()
        staged.write_bytes(self.executable.read_bytes())
        staged.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, 'mode-0500 regular file'):
            self.preflight(path, software_path)
        # Foreign content with valid staging metadata is refused on digest, never replaced.
        staged.chmod(0o200)
        staged.write_bytes(b'foreign staged bytes')
        staged.chmod(0o500)
        with self.assertRaisesRegex(RuntimeError, 'existing staged executable differs'):
            self.preflight(path, software_path)
        self.assertEqual(staged.read_bytes(), b'foreign staged bytes')
        # A pre-existing FIFO must be refused promptly instead of blocking the open.
        staged.unlink()
        os.mkfifo(staged, 0o500)
        import threading
        outcome = []
        def attempt():
            try:
                self.preflight(path, software_path)
                outcome.append('unexpected pass')
            except RuntimeError as failure:
                outcome.append(str(failure))
        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive(), 'preflight blocked on a staged FIFO')
        self.assertIn('mode-0500 regular file', outcome[0])

    def test_executable_hash_mismatch_refuses(self):
        path, software_path, _, _ = synthetic_incident(self.folder, '0' * 64)
        with self.assertRaisesRegex(RuntimeError, 'executable changed'):
            self.preflight(path, software_path)

    def test_journal_mode_or_extra_namespace_refuses(self):
        path, software_path, journal, _ = synthetic_incident(self.folder, self.sha)
        journal.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, 'ownership/mode'):
            self.preflight(path, software_path)
        journal.chmod(0o600)
        journal.write_text(json.dumps({NAMESPACE: '00', 'age-tpm-wsl-pq-native-fedcba9876543210fedcba9876543210': '00'}))
        with self.assertRaisesRegex(RuntimeError, 'exactly one namespace'):
            self.preflight(path, software_path)

    def test_identity_receipt_mismatch_or_prior_deletion_refuses(self):
        path, software_path, journal, encoded = synthetic_incident(self.folder, self.sha)
        identity = b'\x03\x00\x02' + bytes(1249) + b'\x2f' + NAME.encode()
        identity = identity[:100] + bytes([identity[100] ^ 1]) + identity[101:]
        journal.write_text(json.dumps({NAMESPACE: identity.hex()}))
        with self.assertRaisesRegex(RuntimeError, 'creation authority mismatch'):
            self.preflight(path, software_path)
        journal.write_text(json.dumps({NAMESPACE: encoded}))
        incident = self.load(path)
        incident['native_steps'].append({'operation': 'delete', 'namespace': NAMESPACE,
                                         'result': {'result': 'pass'}})
        path.write_text(json.dumps(incident))
        with self.assertRaisesRegex(RuntimeError, 'already removed'):
            self.preflight(path, software_path)

    def test_nonfailed_or_unexecuted_incident_refuses(self):
        path, software_path, _, _ = synthetic_incident(self.folder, self.sha)
        for field, value in (('result', 'pass'), ('executed', False), ('cleanup_stopped', False)):
            with self.subTest(field=field):
                incident = self.load(path)
                incident[field] = value
                path.write_text(json.dumps(incident))
                with self.assertRaisesRegex(RuntimeError, 'stopped on cleanup uncertainty'):
                    self.preflight(path, software_path)
                incident[field] = True if field != 'result' else 'fail'
                path.write_text(json.dumps(incident))


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='incident-evidence-regression-')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.journal = self.folder / 'public-reference.json'
        self.journal.write_bytes(b'public test reference')
        self.journal.chmod(0o600)
        status = self.journal.stat()
        self.public = {'namespace': NAMESPACE, 'executable': str(SOURCE), 'executable_sha256': cleanup.digest(SOURCE),
                       'incident_windows_sid': 'same-sid', 'journal_sha256': cleanup.digest(self.journal),
                       'journal_device': status.st_dev, 'journal_inode': status.st_ino}
        self.report = self.folder / 'evidence.jsonl'
        self.real_append = cleanup.append_checkpoint
        self.activity = []

    def run_main(self, failure_at=None, repeated=False, native_failure=False):
        calls = []
        def append(output, report):
            calls.append(len(calls) + 1)
            if failure_at is not None and (len(calls) == failure_at or (repeated and len(calls) >= failure_at)):
                raise OSError('injected evidence publication refusal')
            self.real_append(output, report)
        def native(campaign, snapshot, sid, namespace):
            self.activity.append(campaign)
            if native_failure:
                raise RuntimeError('native delete uncertainty')
            return {'windows_sid': sid, 'objects': [namespace]}, {'windows_sid': sid, 'objects': []}
        with patch.object(cleanup, 'preflight', return_value=(self.public, 'mock public encoding', self.journal, CONTROLLER_SOURCE.read_bytes())), \
             patch.object(cleanup, 'matching_cleanup', side_effect=native), \
             patch.object(cleanup, 'append_checkpoint', side_effect=append), \
             patch.object(sys, 'argv', [str(SOURCE), '--incident', 'unused', '--software-report', 'unused',
                                        '--report', str(self.report), '--execute']):
            cleanup.main()

    def lines(self):
        return [json.loads(line) for line in self.report.read_text().splitlines()]

    def test_report_open_failure_prevents_native_activity_and_retains_journal(self):
        obstruction = self.folder / 'not-a-directory'
        obstruction.write_bytes(b'unrelated file')
        self.report = obstruction / 'evidence.jsonl'
        with self.assertRaises(RuntimeError):
            self.run_main()
        self.assertEqual(self.activity, [])
        self.assertTrue(self.journal.exists())
        self.assertEqual(obstruction.read_bytes(), b'unrelated file')

    def test_initial_authority_write_failure_prevents_native_activity(self):
        with self.assertRaisesRegex(RuntimeError, 'publication refusal'):
            self.run_main(failure_at=1, repeated=True)
        self.assertEqual(self.activity, [])
        self.assertTrue(self.journal.exists())

    def test_absence_checkpoint_failure_retains_journal(self):
        with self.assertRaisesRegex(RuntimeError, 'publication refusal'):
            self.run_main(failure_at=2)
        self.assertEqual(len(self.activity), 1)
        self.assertTrue(self.activity[0].fatal)
        self.assertTrue(self.journal.exists())
        lines = self.lines()
        self.assertFalse(lines[0]['executed'])
        self.assertTrue(lines[-1]['cleanup_stopped'])
        self.assertTrue(lines[-1]['absence_verified'])
        self.assertFalse(lines[-1]['journal_removed_after_verified_absence'])

    def test_final_publication_failure_keeps_durable_absence_checkpoint(self):
        with self.assertRaisesRegex(RuntimeError, 'publication refusal'):
            self.run_main(failure_at=3, repeated=True)
        self.assertFalse(self.journal.exists())
        self.assertTrue(self.activity[0].fatal)
        checkpoint = self.lines()[-1]
        self.assertTrue(checkpoint['absence_verified'])
        self.assertIn('journal retained pending durable checkpoint', checkpoint['result'])
        self.assertFalse(checkpoint['journal_removed_after_verified_absence'])

    def test_publication_error_does_not_mask_native_failure(self):
        with self.assertRaises(RuntimeError) as caught:
            self.run_main(failure_at=2, repeated=True, native_failure=True)
        self.assertIn('native delete uncertainty', str(caught.exception))
        self.assertIn('evidence publication', str(caught.exception))
        self.assertTrue(self.activity[0].fatal)
        self.assertTrue(self.journal.exists())
        self.assertFalse(self.lines()[0]['executed'])


if __name__ == '__main__':
    unittest.main()
