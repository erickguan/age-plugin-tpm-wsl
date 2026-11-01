"""Controller safety with fake native results only; never launches a TPM helper."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from post_quantum_client.authority import Namespace, Observation, PREFIX, PublicIdentity, Stop
from post_quantum_client.controller import Controller, frame, response
from post_quantum_client.durable import Storage
from post_quantum_client.journal import Journal, Session
from post_quantum_client.process import BinaryPin, ProcessResult, digest

ROOT = Path(__file__).resolve().parents[1]
SID = 'S-1-5-21-1001'


class FakeWindows:
    def __init__(self, namespace, journal):
        self.namespace, self.journal = namespace, journal
        public = bytes.fromhex(json.loads((ROOT / 'notes/aws-lc-hybrid-evaluation/go-fixture.json').read_text())['public_key'])
        self.identity = b'\x03\x00\x02' + public + b'\x2f' + namespace.key_name.encode()
        self.root = self.key = False
        self.sid = SID
        self.calls = []
        self.override = None
        self.disagree = False

    def observe(self, namespace):
        assert namespace == self.namespace
        return Observation(self.sid, not self.root, False if self.disagree else not self.key)

    def run(self, command, payload, environment, seconds):
        assert seconds == 10
        saved = json.loads(self.journal.path.read_text().splitlines()[-1])
        assert saved['kind'] == 'intent', 'intent must be persisted before launch'
        operation = saved['operation']
        self.calls.append(operation)
        if self.override:
            return self.override(operation)
        if operation == 'prepare':
            self.root = True
            value = {'root_created_exclusively': True, 'namespace': self.namespace.directory,
                     'name': self.namespace.key_name}
        elif operation in {'absence', 'remove-root'}:
            if operation == 'remove-root':
                self.root = False
            value = {'root_absent': not self.root, 'key_absent': not self.key}
        else:
            code = payload[4]
            if operation == 'create':
                self.key = True
                result = self.identity
            elif operation == 'recover':
                result = self.identity
            elif operation == 'unwrap':
                result = b'\x5a' * 16
            elif operation == 'delete':
                self.key = False
                result = b''
            else:
                result = json.dumps({'name': self.namespace.key_name, 'scheme': 'mlkem768-p256'}).encode()
            return ProcessResult(0, frame(code, result))
        return ProcessResult(0, json.dumps(value).encode())


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        directory = Path(self.temporary.name)
        directory.chmod(0o700)
        self.source = directory / 'source.rs'
        self.source.write_text('fixed validated source')
        executable = directory / 'original.exe'
        executable.write_bytes(b'public mock executable')
        pin = BinaryPin.stage(executable, digest(executable), directory, {str(self.source): digest(self.source)})
        self.namespace = Namespace(PREFIX + '0' * 32)
        self.journal = Journal.create(directory / 'journal.jsonl', self.namespace, SID, pin.record())
        self.native = FakeWindows(self.namespace, self.journal)
        self.controller = Controller(self.journal, {}, self.native.observe, self.native.run)
        self.create = frame(8, b'\x00\x02' + self.namespace.key_name.encode())

    def tearDown(self):
        self.temporary.cleanup()

    def enrolled(self):
        self.controller.admin('prepare')
        status, identity = response(self.controller.forward(self.create), 8)
        self.assertEqual(status, 0)
        self.assertEqual(identity, self.native.identity)
        return identity

    def assert_stopped(self):
        count = len(self.native.calls)
        self.assertTrue(self.controller.summary()['cleanup_stopped'])
        with self.assertRaises(Stop):
            self.controller.forward(frame(4, self.native.identity))
        with self.assertRaises(Stop):
            self.controller.admin('remove-root')
        self.assertEqual(len(self.native.calls), count)

    def test_complete_lifecycle_journals_authority_and_verifies_independent_absence(self):
        identity = self.enrolled()
        self.assertEqual(self.journal.path.stat().st_mode & 0o777, 0o600)
        self.controller.forward(frame(2, identity))
        self.controller.forward(frame(10, self.namespace.key_name.encode()))
        unwrap = frame(9, b'\x05\x14' + identity + b'\x01' * 1153 + b'\x02' * 32)
        self.assertEqual(response(self.controller.forward(unwrap), 9), (0, b'\x5a' * 16))
        self.assertNotIn('5a' * 16, self.journal.path.read_text())
        self.controller.forward(frame(4, identity))
        self.assertEqual(self.controller.admin('absence'), {'root_absent': False, 'key_absent': True})
        self.controller.admin('remove-root')
        self.assertEqual(self.controller.admin('absence'), {'root_absent': True, 'key_absent': True})
        self.assertFalse(self.controller.summary()['cleanup_stopped'])
        self.assertTrue(self.controller.summary()['removed'])
        self.assertFalse(self.native.root or self.native.key)

    def test_cannot_create_before_exclusive_root_receipt_or_remove_before_delete(self):
        with self.assertRaises(Stop):
            self.controller.forward(self.create)
        self.enrolled()
        with self.assertRaises(Stop):
            self.controller.admin('prepare')
        with self.assertRaises(Stop):
            self.controller.admin('remove-root')
        self.assertEqual(self.native.calls, ['prepare', 'create'])

    def test_preexisting_root_and_sid_change_stop_before_launch(self):
        self.native.root = True
        with self.assertRaises(Stop):
            self.controller.admin('prepare')
        self.assertEqual(self.native.calls, [])
        self.assert_stopped()

    def test_changed_sid_is_not_a_new_cleanup_authority(self):
        self.enrolled()
        self.native.sid = 'S-1-5-21-9999'
        with self.assertRaises(Stop):
            self.controller.forward(frame(2, self.native.identity))
        self.assert_stopped()

    def test_changed_sources_stop_even_when_binary_is_unchanged(self):
        self.enrolled()
        self.source.write_text('unreviewed source')
        with self.assertRaises(Stop):
            self.controller.forward(frame(2, self.native.identity))
        self.assert_stopped()

    def test_wrong_reference_and_legacy_requests_never_launch(self):
        identity = self.enrolled()
        changed = identity[:-1] + b'1'
        for request in [frame(4, changed), frame(1), frame(8, b'wrong-name'), frame(10, b'wrong-name')]:
            with self.assertRaises(Stop):
                self.controller.forward(request)
        self.assertEqual(self.native.calls, ['prepare', 'create'])

    def test_malformed_fatal_or_unknown_create_response_latches_without_deleting(self):
        self.controller.admin('prepare')
        self.native.override = lambda _: ProcessResult(0, b'truncated')
        with self.assertRaises(Stop):
            self.controller.forward(self.create)
        self.assert_stopped()
        self.assertNotIn('delete', self.native.calls)

    def test_process_error_and_timeout_latch_before_any_cleanup(self):
        self.enrolled()
        def timeout(_):
            raise Stop('deadline exceeded')
        self.native.override = timeout
        with self.assertRaises(Stop):
            self.controller.forward(frame(2, self.native.identity))
        self.assert_stopped()

    def test_dangling_intent_after_restart_is_fatal_and_absence_cannot_clear_it(self):
        self.controller.admin('prepare')
        with self.journal.locked() as session:
            session.append({'kind': 'intent', 'operation': 'create'})
        self.assert_stopped()
        self.native.override = None
        self.controller.admin('absence')
        self.assert_stopped()

    def test_journal_failure_after_creation_retains_and_never_infers_name_only_cleanup(self):
        self.controller.admin('prepare')
        original = Session.append
        def fail_receipt(session, event):
            if event.get('kind') == 'success' and event.get('operation') == 'create':
                raise OSError('controlled disk error')
            return original(session, event)
        with patch.object(Session, 'append', fail_receipt):
            with self.assertRaises(Stop):
                self.controller.forward(self.create)
        self.assertTrue(self.native.key)
        self.assert_stopped()
        self.assertIsNone(self.controller.summary()['identity_sha256'])

    def test_numeric_ordinary_private_rejection_is_not_confused_with_transport_failure(self):
        self.enrolled()
        self.native.override = lambda _: ProcessResult(0, frame(2, status=0xA0010001))
        self.assertEqual(response(self.controller.forward(frame(2, self.native.identity)), 2)[0], 0xA0010001)
        self.assertFalse(self.controller.summary()['cleanup_stopped'])

    def test_fatal_status_and_delete_failure_prevent_all_later_mutations(self):
        self.enrolled()
        self.native.override = lambda _: ProcessResult(0, frame(4, status=0xA0010002))
        with self.assertRaises(Stop):
            self.controller.forward(frame(4, self.native.identity))
        self.assert_stopped()

    def test_independent_delete_absence_failure_prevents_root_removal(self):
        self.enrolled()
        self.native.disagree = True
        with self.assertRaises(Stop):
            self.controller.forward(frame(4, self.native.identity))
        self.assert_stopped()

    def test_preflight_and_uncertainty_write_failure_stay_latched_after_journal_reopen(self):
        self.enrolled()
        count = len(self.native.calls)
        original = Session.append
        def fail_uncertainty(session, event):
            if event['kind'] == 'uncertain':
                raise OSError('controlled full disk')
            return original(session, event)
        def bad_observation(_):
            raise OSError('controlled observation failure')
        self.controller.observe = bad_observation
        with patch.object(Session, 'append', fail_uncertainty):
            with self.assertRaises(Stop):
                self.controller.forward(frame(2, self.native.identity))
        self.assertTrue(self.journal.failed)
        self.controller.observe = self.native.observe
        self.assert_stopped()
        reopened = Controller(Journal(self.journal.path), {}, self.native.observe, self.native.run)
        self.assertTrue(reopened.summary()['cleanup_stopped'])
        with self.assertRaises(Stop):
            reopened.forward(frame(4, self.native.identity))
        self.assertEqual(len(self.native.calls), count)

    def test_unflushed_success_and_failed_uncertainty_leave_durable_marker(self):
        self.controller.admin('prepare')
        original = Storage.append
        def fail_flush(storage, encoded):
            event = json.loads(encoded)
            if event['kind'] == 'uncertain':
                raise OSError('uncertainty write failed')
            original(storage, encoded)
            if event['kind'] == 'success' and event['operation'] == 'create':
                raise OSError('success fsync failed after write')
        with patch.object(Storage, 'append', fail_flush):
            with self.assertRaises(Stop):
                self.controller.forward(self.create)
        self.assertTrue(self.native.key)
        marker = self.journal.path.with_name(self.journal.path.name + '.active')
        self.assertTrue(marker.exists())
        reopened = Controller(Journal(self.journal.path), {}, self.native.observe, self.native.run)
        self.assertTrue(reopened.summary()['cleanup_stopped'])
        with self.assertRaises(Stop):
            reopened.forward(frame(4, self.native.identity))
        self.assertNotIn('delete', self.native.calls)

    def test_marker_unlink_then_directory_flush_failure_cannot_resume_in_fresh_journal(self):
        self.enrolled()
        original = Storage.append
        def fail_uncertainty(storage, encoded):
            if json.loads(encoded)['kind'] == 'uncertain':
                raise OSError('uncertainty write disabled')
            return original(storage, encoded)
        def fail_retirement(storage):
            import os
            os.unlink(storage.marker, dir_fd=storage.directory)
            raise OSError('directory fsync failed after unlink')
        with patch.object(Storage, 'append', fail_uncertainty), patch.object(Storage, 'complete', fail_retirement):
            with self.assertRaises(Stop):
                self.controller.forward(frame(2, self.native.identity))
        count = len(self.native.calls)
        reopened = Controller(Journal(self.journal.path), {}, self.native.observe, self.native.run)
        with self.assertRaises(Stop):
            reopened.forward(frame(4, self.native.identity))
        with self.assertRaises(Stop):
            reopened.forward(frame(10, self.namespace.key_name.encode()))
        self.assertEqual(len(self.native.calls), count)
        self.assert_stopped()

    def test_even_clean_reopening_is_inspection_only_and_cannot_adopt_live_authority(self):
        self.enrolled()
        count = len(self.native.calls)
        reopened = Controller(Journal(self.journal.path), {}, self.native.observe, self.native.run)
        self.assertFalse(reopened.summary()['continuation_owned'])
        self.assertTrue(reopened.summary()['cleanup_stopped'])
        with self.assertRaises(Stop):
            reopened.forward(frame(4, self.native.identity))
        self.assertEqual(len(self.native.calls), count)
        # Reading through another object does not poison the actual owner.
        self.controller.forward(frame(2, self.native.identity))
        self.assertFalse(self.controller.summary()['cleanup_stopped'])

    def test_forked_owner_object_cannot_continue_the_parent_campaign(self):
        self.enrolled()
        count = len(self.native.calls)
        parent_pid = os.getpid()
        with patch('post_quantum_client.journal.os.getpid', return_value=parent_pid + 1):
            with self.assertRaises(Stop):
                self.controller.forward(frame(4, self.native.identity))
            self.assertFalse(self.controller.summary()['continuation_owned'])
        self.assertEqual(len(self.native.calls), count)
        self.controller.forward(frame(2, self.native.identity))

    def test_public_parser_rejects_coefficients_points_names_and_noncanonical_hex(self):
        valid = self.native.identity
        PublicIdentity.parse(valid, self.namespace)
        for encoded in [valid[:-1], valid + b'x', b'\x02' + valid[1:], valid[:-1] + b'A']:
            with self.assertRaises(Stop):
                PublicIdentity.parse(encoded, self.namespace)
        for offset in [3, 1187]:
            modified = bytearray(valid)
            modified[offset:offset + 3] = b'\xff\xff\xff'
            with self.assertRaises(Stop):
                PublicIdentity.parse(bytes(modified), self.namespace)
        with self.assertRaises(Stop):
            PublicIdentity.from_hex(valid.hex().upper(), self.namespace)


if __name__ == '__main__':
    unittest.main()
