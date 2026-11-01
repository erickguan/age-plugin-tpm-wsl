"""Driver stop/authority controls with subprocess fixtures; never opens Windows."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('custody_native', Path(__file__).with_name('validate-pq-custody-native.py'))
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
NS = NATIVE.PREFIX + '0' * 32
NAME = 'age-tpm-wsl-pq-' + '0' * 32
PUBLIC = bytes.fromhex(json.loads((NATIVE.PROJECT / 'notes/aws-lc-hybrid-evaluation/go-fixture.json').read_text())['public_key'])
IDENTITY = (b'\x03\x00\x02' + PUBLIC + b'\x2f' + NAME.encode()).hex()


class Fake:
    def __init__(self, change=None, *, exit_code=None):
        self.calls = []
        self.change = change or (lambda mode, body: body)
        self.exit_code = exit_code

    def __call__(self, command, *, env, **kwargs):
        mode = env['ATW_PQ_NATIVE_MODE']
        self.calls.append(mode)
        body = {'operation': mode, 'namespace': env['ATW_PQ_NATIVE_NAMESPACE'], 'name': NAME,
                'scope': 'ignored Windows test-only isolated Store; no production root access',
                'result': 'pass', 'cleanup_failed': False}
        if mode.startswith('create-'):
            body.update(root_created_exclusively=True, expected_identity_hex=IDENTITY)
        if mode == 'absence':
            body.update(key_absent=True, root_absent=True)
        if mode.startswith('fault-'):
            body.update(result='controlled_failure', cleanup_failed=True,
                        error='controlled reported release failure after actual release',
                        controlled_only_after_real_release=True, actual_transient_flushes=1,
                        actual_absence_checks=1, actual_context_closed=True, destructive_continuation=False)
        body = self.change(mode, body)
        code = self.exit_code(mode, body) if callable(self.exit_code) else self.exit_code
        if code is None:
            code = 97 if body.get('cleanup_failed') is True else (0 if body.get('result') == 'pass' else 1)
        return subprocess.CompletedProcess(command, code, 'running 1 test\n' + NATIVE.MARKER + json.dumps(body) + '\n', '')


class CampaignTests(unittest.TestCase):
    def campaign(self, fake, directory):
        return NATIVE.Campaign(Path('never-executed.exe'), {}, {'native_steps': []}, execute=fake, journal_directory=Path(directory))

    def test_genuine_cleanup_failure_latches_before_any_further_mutation(self):
        def fail(mode, body):
            if mode == 'delete':
                body.update(result='fail', cleanup_failed=True, error='real delete failure')
            return body
        with tempfile.TemporaryDirectory() as directory:
            fake = Fake(fail)
            campaign = self.campaign(fake, directory)
            campaign.references[NS] = IDENTITY
            campaign.roots.add(NS)
            with self.assertRaises(NATIVE.NativeError):
                campaign.cleanup_owned(NS)
            self.assertTrue(campaign.fatal)
            with self.assertRaises(NATIVE.NativeError):
                campaign.invoke(NS, 'remove-root')
            self.assertEqual(fake.calls, ['delete'])
            self.assertIn(NS, campaign.references)

    def test_control_requires_real_release_and_forbidden_continuation_markers(self):
        for field, bad in [('actual_context_closed', False), ('actual_transient_flushes', 0),
                           ('actual_absence_checks', 0), ('actual_transient_flushes', True),
                           ('actual_absence_checks', True), ('destructive_continuation', True)]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                fake = Fake(lambda mode, body: dict(body, **{field: bad}))
                campaign = self.campaign(fake, directory)
                with self.assertRaises(NATIVE.NativeError):
                    campaign.invoke(NS, 'fault-close')
                self.assertTrue(campaign.fatal)
        with tempfile.TemporaryDirectory() as directory:
            fake = Fake()
            campaign = self.campaign(fake, directory)
            campaign.invoke(NS, 'fault-close')
            campaign.cleanup_owned(NS)
            self.assertFalse(campaign.fatal)
            self.assertEqual(fake.calls, ['fault-close', 'absence'])

    def test_reference_captured_before_journal_io_failure_permits_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            bad_directory = Path(directory) / 'file'
            bad_directory.write_text('not a directory')
            fake = Fake()
            campaign = self.campaign(fake, bad_directory)
            with self.assertRaises(OSError):
                campaign.invoke(NS, 'create-final')
            self.assertEqual(campaign.references[NS], IDENTITY)
            self.assertIn(NS, campaign.roots)
            campaign.cleanup_owned(NS)
            self.assertEqual(fake.calls, ['create-final', 'delete', 'remove-root', 'absence'])
            self.assertFalse(campaign.references)
            self.assertFalse(campaign.roots)

    def test_raw_generated_public_identity_is_not_written_to_durable_report(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign = self.campaign(Fake(), directory)
            campaign.invoke(NS, 'create-final')
            encoded = json.dumps(campaign.report)
            self.assertNotIn(IDENTITY, encoded)
            self.assertEqual(campaign.report['native_steps'][0]['result']['expected_identity_bytes'], 1300)
            self.assertEqual(campaign.journal.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(campaign.journal.read_text())[NS], IDENTITY)

    def test_missing_or_ambiguous_protocol_or_timeout_stops_without_cleanup(self):
        def no_result(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, 'no result\n', '')
        def timeout(command, **kwargs):
            raise subprocess.TimeoutExpired(command, 180)
        for execute in [no_result, timeout]:
            with self.subTest(execute=execute.__name__), tempfile.TemporaryDirectory() as directory:
                campaign = self.campaign(execute, directory)
                with self.assertRaises((NATIVE.NativeError, subprocess.TimeoutExpired)):
                    campaign.invoke(NS, 'create-final')
                self.assertTrue(campaign.fatal)
                with self.assertRaises(NATIVE.NativeError):
                    campaign.invoke(NS, 'delete')

    def test_uncertain_process_retains_metadata_without_raw_output(self):
        secret = 'private-output-must-not-be-retained'
        cases = [
            ('missing', -1073741819, secret + '\n', secret, 0, False),
            ('ambiguous', 0, (NATIVE.MARKER + '{}\n') * 2 + secret, secret, 2, False),
            ('malformed', 1, NATIVE.MARKER + '{' + secret, secret, 1, False),
            ('nonobject', 0, NATIVE.MARKER + '[]\n' + secret, secret, 1, False),
            ('invalid-utf8', 1, b'\xff' + secret.encode(), secret.encode(), 0, False),
            ('timeout', None, secret.encode(), secret.encode(), 0, True),
            ('timeout-without-output', None, None, None, None, True),
        ]
        for label, code, stdout, stderr, markers, timed_out in cases:
            def execute(command, **kwargs):
                if timed_out:
                    raise subprocess.TimeoutExpired(command, 180, output=stdout, stderr=stderr)
                return subprocess.CompletedProcess(command, code, stdout, stderr)
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                campaign = self.campaign(execute, directory)
                with self.assertRaises((NATIVE.NativeError, subprocess.TimeoutExpired)):
                    campaign.invoke(NS, 'denials')
                self.assertTrue(campaign.fatal)
                self.assertTrue(campaign.report['cleanup_stopped'])
                self.assertEqual(len(campaign.report['native_steps']), 1)
                row = campaign.report['native_steps'][0]
                self.assertEqual(row['operation'], 'denials')
                self.assertEqual(row['namespace'], NS)
                self.assertEqual(row['exit_code'], code)
                self.assertEqual(row['marker_count'], markers)
                self.assertEqual(row['timed_out'], timed_out)
                for stream, value in [('stdout', stdout), ('stderr', stderr)]:
                    data = value.encode() if isinstance(value, str) else value
                    self.assertEqual(row[stream + '_bytes'], len(data) if data is not None else None)
                    self.assertEqual(row[stream + '_sha256'], hashlib.sha256(data).hexdigest() if data is not None else None)
                self.assertNotIn(secret, json.dumps(campaign.report))
                self.assertNotIn('result', row)
                self.assertFalse(campaign.references)
                self.assertFalse(campaign.roots)
                with self.assertRaises(NATIVE.NativeError):
                    campaign.invoke(NS, 'delete')

    def test_process_launch_failure_is_sanitized_and_blocks_cleanup(self):
        def unavailable(command, **kwargs):
            raise OSError('private-error-text-must-not-be-retained')
        with tempfile.TemporaryDirectory() as directory:
            campaign = self.campaign(unavailable, directory)
            with self.assertRaises(NATIVE.NativeError):
                campaign.invoke(NS, 'denials')
            self.assertTrue(campaign.fatal)
            self.assertTrue(campaign.report['cleanup_stopped'])
            self.assertNotIn('private-error-text', json.dumps(campaign.report))
            row = campaign.report['native_steps'][0]
            self.assertIsNone(row['exit_code'])
            self.assertIsNone(row['marker_count'])
            self.assertIsNone(row['stdout_sha256'])
            self.assertIsNone(row['stderr_sha256'])
            self.assertFalse(row['timed_out'])
            with self.assertRaises(NATIVE.NativeError):
                campaign.invoke(NS, 'delete')

    def test_parser_recursion_failure_retains_authority_and_blocks_cleanup(self):
        fake = Fake()
        with tempfile.TemporaryDirectory() as directory:
            campaign = self.campaign(fake, directory)
            campaign.references[NS] = IDENTITY
            campaign.roots.add(NS)
            # Force the decoder failure independently of Python's depth threshold.
            with patch.object(NATIVE.json, 'loads', side_effect=RecursionError('private-parser-detail')):
                with self.assertRaises(NATIVE.NativeError):
                    campaign.invoke(NS, 'denials')
            self.assertTrue(campaign.fatal)
            self.assertTrue(campaign.report['cleanup_stopped'])
            row = campaign.report['native_steps'][0]
            self.assertEqual(row['exit_code'], 0)
            self.assertEqual(row['marker_count'], 1)
            self.assertIsNotNone(row['stdout_sha256'])
            self.assertNotIn('result', row)
            self.assertNotIn('private-parser-detail', json.dumps(campaign.report))
            self.assertEqual(campaign.references[NS], IDENTITY)
            self.assertIn(NS, campaign.roots)
            with self.assertRaises(NATIVE.NativeError):
                campaign.cleanup_owned(NS)
            for mode in ['delete', 'remove-root']:
                with self.assertRaises(NATIVE.NativeError):
                    campaign.invoke(NS, mode)
            self.assertEqual(fake.calls, ['denials', 'absence'])
            self.assertEqual(campaign.references[NS], IDENTITY)
            self.assertIn(NS, campaign.roots)

    def test_failed_creation_cannot_remove_root_before_independent_key_absence(self):
        def query_failed(mode, body):
            if mode == 'absence':
                body['key_absent'] = False
            return body
        with tempfile.TemporaryDirectory() as directory:
            fake = Fake(query_failed)
            campaign = self.campaign(fake, directory)
            campaign.roots.add(NS)
            with self.assertRaises(NATIVE.NativeError):
                campaign.cleanup_owned(NS)
            self.assertTrue(campaign.fatal)
            self.assertEqual(fake.calls, ['absence'])
            self.assertIn(NS, campaign.roots)

    def test_final_snapshot_uncertainty_latches_failure_and_prevents_further_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Fake()
            campaign = self.campaign(fake, directory)
            campaign.report.update(result='pass', cleanup_stopped=False)
            NATIVE.cleanup_uncertain(campaign.report, campaign, 'snapshot unavailable')
            self.assertTrue(campaign.fatal)
            self.assertTrue(campaign.report['cleanup_stopped'])
            self.assertEqual(campaign.report['result'], 'fail')
            self.assertEqual(campaign.report['cleanup_error'], 'snapshot unavailable')
            with self.assertRaises(NATIVE.NativeError):
                campaign.invoke(NS, 'delete')
            self.assertEqual(fake.calls, [])

    def test_snapshot_schema_rejects_missing_fields_and_wrong_object_types(self):
        valid = {'objects': [], 'filesystem': 'NTFS', 'windows_sid': 'S-1-5-21-test', 'windows_version': '10.0.test'}
        self.assertEqual(NATIVE.snapshot_value(valid), valid)
        for bad in [None, [], {}, dict(valid, objects='not an array'),
                    dict(valid, windows_sid=None), dict(valid, objects=['custody/v1'])]:
            with self.subTest(value=bad), self.assertRaises(NATIVE.NativeError):
                NATIVE.snapshot_value(bad)

    def test_nonobject_or_ambiguous_native_response_cannot_permit_cleanup(self):
        for output in ['[]', '{}\n' + NATIVE.MARKER + '{}']:
            def malformed(command, **kwargs):
                return subprocess.CompletedProcess(command, 0, NATIVE.MARKER + output + '\n', '')
            with self.subTest(output=output), tempfile.TemporaryDirectory() as directory:
                campaign = self.campaign(malformed, directory)
                with self.assertRaises(NATIVE.NativeError):
                    campaign.invoke(NS, 'create-final')
                self.assertTrue(campaign.fatal)
                self.assertFalse(campaign.roots)
                self.assertFalse(campaign.references)
                with self.assertRaises(NATIVE.NativeError):
                    campaign.invoke(NS, 'delete')

    def test_invalid_result_status_combinations_block_cleanup_with_retained_authority(self):
        cases = [
            ('missing-result', {}, 0),
            ('null-result', {'result': None}, 0),
            ('integer-result', {'result': 1}, 0),
            ('array-result', {'result': []}, 0),
            ('unknown-result', {'result': 'unknown'}, 0),
            ('pass-fatal-exit', {'result': 'pass'}, 97),
            ('fail-fatal-exit-without-cleanup-failure', {'result': 'fail', 'error': 'failure'}, 97),
            ('pass-ordinary-exit', {'result': 'pass'}, 1),
            ('fail-success-exit', {'result': 'fail', 'error': 'failure'}, 0),
            ('pass-with-cleanup-failure', {'result': 'pass', 'cleanup_failed': True}, 0),
            ('fatal-with-ordinary-exit', {'result': 'fail', 'cleanup_failed': True, 'error': 'failure'}, 1),
            ('control-without-cleanup-failure', {'result': 'controlled_failure'}, 97),
            ('control-in-noncontrol-operation', {'result': 'controlled_failure', 'cleanup_failed': True, 'error': 'failure'}, 97),
            ('missing-cleanup-status', {'result': 'pass', 'cleanup_failed': None}, 0),
            ('nonboolean-cleanup-status', {'result': 'pass', 'cleanup_failed': 0}, 0),
            ('failure-without-error', {'result': 'fail'}, 1),
            ('failure-with-nonstring-error', {'result': 'fail', 'error': []}, 1),
            ('process-crash', {'result': 'pass'}, -9),
        ]
        for label, fields, code in cases:
            def change(mode, body):
                if mode == 'unwrap':
                    body.pop('result')
                    body.update(fields)
                return body
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                fake = Fake(change, exit_code=lambda mode, body: code if mode == 'unwrap' else None)
                campaign = self.campaign(fake, directory)
                campaign.references[NS] = IDENTITY
                campaign.roots.add(NS)
                with self.assertRaises(NATIVE.NativeError):
                    campaign.invoke(NS, 'unwrap')
                self.assertTrue(campaign.fatal)
                self.assertTrue(campaign.report['cleanup_stopped'])
                self.assertIsNone(campaign.journal)
                with self.assertRaises(NATIVE.NativeError):
                    campaign.cleanup_owned(NS)
                for forbidden in ['delete', 'remove-root']:
                    with self.assertRaises(NATIVE.NativeError):
                        campaign.invoke(NS, forbidden)
                self.assertEqual(fake.calls, ['unwrap', 'absence'])
                self.assertEqual(campaign.references[NS], IDENTITY)
                self.assertIn(NS, campaign.roots)

    def test_exact_scope_required_before_control_exception_or_new_cleanup_authority(self):
        for operation in ['fault-close', 'create-final']:
            for scope in [None, '', 'production root', NATIVE.SCOPE + ' extra', ['wrong type']]:
                def change(mode, body):
                    if mode == operation:
                        body.pop('scope')
                        if scope is not None:
                            body['scope'] = scope
                    return body
                with self.subTest(operation=operation, scope=scope), tempfile.TemporaryDirectory() as directory:
                    fake = Fake(change)
                    campaign = self.campaign(fake, directory)
                    if operation == 'fault-close':
                        campaign.references[NS] = IDENTITY
                        campaign.roots.add(NS)
                    with self.assertRaises(NATIVE.NativeError):
                        campaign.invoke(NS, operation)
                    self.assertTrue(campaign.fatal)
                    self.assertTrue(campaign.report['cleanup_stopped'])
                    self.assertIsNone(campaign.journal)
                    with self.assertRaises(NATIVE.NativeError):
                        campaign.cleanup_owned(NS)
                    self.assertEqual(fake.calls, [operation, 'absence'])
                    if operation == 'create-final':
                        self.assertFalse(campaign.references)
                        self.assertFalse(campaign.roots)
                    else:
                        self.assertEqual(campaign.references[NS], IDENTITY)
                        self.assertIn(NS, campaign.roots)

    def test_consistent_ordinary_failure_still_allows_matching_owned_cleanup(self):
        def fail(mode, body):
            if mode == 'unwrap':
                body.update(result='fail', cleanup_failed=False, error='ordinary refusal after successful release')
            return body
        with tempfile.TemporaryDirectory() as directory:
            fake = Fake(fail)
            campaign = self.campaign(fake, directory)
            campaign.references[NS] = IDENTITY
            campaign.roots.add(NS)
            with self.assertRaises(NATIVE.NativeError):
                campaign.invoke(NS, 'unwrap')
            self.assertFalse(campaign.fatal)
            campaign.cleanup_owned(NS)
            self.assertEqual(fake.calls, ['unwrap', 'delete', 'remove-root', 'absence'])
            self.assertFalse(campaign.references)
            self.assertFalse(campaign.roots)

    def test_response_namespace_mismatch_stops_before_reference_or_cleanup_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Fake(lambda mode, body: dict(body, namespace=NATIVE.PREFIX + '1' * 32))
            campaign = self.campaign(fake, directory)
            with self.assertRaises(NATIVE.NativeError):
                campaign.invoke(NS, 'create-final')
            self.assertTrue(campaign.fatal)
            self.assertFalse(campaign.references)
            self.assertFalse(campaign.roots)


if __name__ == '__main__':
    unittest.main()
