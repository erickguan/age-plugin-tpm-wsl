"""Fake native reads/cache metadata; real public fnox encryption and owned process.

Actual cache transitions are tested separately with plain disposable data. These
checks establish lifecycle ordering and journal verdicts, never native crypto.
"""
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

import test_post_quantum_client_clients as support
from test_post_quantum_client_campaign import NativeDouble
from post_quantum_client.authority import Namespace, PREFIX, Stop
from post_quantum_client.cases import PAYLOAD
from post_quantum_client.controller import frame, response
from post_quantum_client.fnox_daemon_campaign import FnoxDaemonCampaign
from post_quantum_client.fnox_daemon_clients import FnoxDaemonEnvironment
from post_quantum_client.fnox_daemon_owner import OwnedFnoxDaemon
from post_quantum_client.process import BinaryPin, BoundedProcess, ProcessResult, digest
from post_quantum_client.report import CampaignReport
from post_quantum_client.wrapper import forward_stdio


class MockCacheOwner(OwnedFnoxDaemon):
    entries = 0

    def _record_status(self, entries):
        # Explicitly mock cache metadata before issuance; real status() still
        # checks the original child, peer and CLI response on every observation.
        return super()._record_status(self.entries)


class RoutedProcess:
    def __init__(self, run, native):
        self.run, self.native = run, native
        self.clients = None
        self.skip_cold = self.skip_bypass = self.extra_warm = self.bad_cache = self.bad_plaintext = False
        self.gets = 0

    def rpc(self):
        request = frame(9, b'\x05\x14' + self.native.inner.identity + b'\x01' * 1153 + b'\x02' * 32)
        output = io.BytesIO()
        forward_stdio(self.run.path / 's', os.getpid(), io.BytesIO(request), output)
        status, _ = response(output.getvalue(), 9)
        if status: raise Stop('fake native IPC failed')  # Only the fixed fake file key enters this pipe.

    def __call__(self, command, payload, environment, seconds, **options):
        if command[-2:] == ['get', 'PQ_CLIENT_TEST']:
            index = self.clients._index
            self.gets += 1
            if ((index == 0 and not self.skip_cold) or (index == 1 and self.extra_warm)
                    or (index == 2 and not self.skip_bypass)):
                self.rpc()
            self.clients.daemon.entries = 0 if self.bad_cache and index == 1 else 1
            value = b'wrong-disposable-value' if self.bad_plaintext and index == 1 else PAYLOAD
            return ProcessResult(0, value + b'\n')
        return BoundedProcess()(command, payload, environment, seconds, **options)


class FnoxDaemonCampaignTests(unittest.TestCase):
    def setUp(self):
        self.fixture = support.ClientEnvironmentTests(); self.fixture.setUp()
        self.run = self.fixture.run
        binary = Path(shutil.which('fnox')).resolve()
        pin = BinaryPin.stage(binary, digest(binary), self.run.path,
                              self.fixture.staged.helper.source_hashes, 'fnox')
        staged = replace(self.fixture.staged, fnox=pin, fnox_version='fnox 1.42.1')
        self.namespace = Namespace(PREFIX + '0' * 32)
        self.report = CampaignReport.create(self.run.path / 'report', self.namespace, '1' * 64)
        self.native = NativeDouble(self.namespace, self.run, self.report)
        self.process = RoutedProcess(self.run, self.native)
        self.clients = FnoxDaemonEnvironment(self.run, staged, self.process, {'PATH': os.environ['PATH']}, MockCacheOwner)
        self.process.clients = self.clients
        self.campaign = FnoxDaemonCampaign(self.run, self.namespace, self.report, self.clients,
                                           self.native.observe, self.native.controller)

    def tearDown(self):
        self.clients.abandon_daemon()
        if self.clients.daemon.path.exists(): shutil.rmtree(self.clients.daemon.path)
        self.fixture.tearDown()  # Only simulated native state/software files.

    def assert_retained(self):
        self.assertTrue(self.native.inner.key and self.native.inner.root)
        self.assertTrue((self.run.path / 'journal').exists())
        self.assertTrue(self.campaign.controller.journal.failed)
        self.assertNotIn('delete', self.native.inner.calls)
        self.assertIsNotNone(self.clients.daemon.child.returncode)

    def test_inherited_direct_decrypt_cannot_invoke_an_unaudited_bypass(self):
        self.clients.preflight()
        self.clients.prepare(self.fixture.reference)
        encrypted = self.clients.encrypt(case='fnox_daemon_cold')
        self.assertTrue(encrypted.measurement.passed)
        with patch.object(self.clients, '_invoke', side_effect=AssertionError('unaudited fnox invocation')) as invoke:
            with self.assertRaises(Stop):
                self.clients.decrypt(encrypted.output, PAYLOAD, 'fnox', 'fnox_direct')
            invoke.assert_not_called()
        self.assertEqual(self.process.gets, 0)
        self.assertIsNone(self.clients.daemon.child)

    def test_complete_workflow_binds_two_native_reads_one_cache_hit_and_teardown_before_cleanup(self):
        def cleanup_check():
            self.clients.receipt.verify()
            self.assertTrue(self.report.daemon_retired)
            self.assertEqual(self.campaign.service.calls, 2)
        self.native.cleanup_probe = cleanup_check
        self.campaign.execute()
        events = [json.loads(line) for line in self.report.path.read_text().splitlines()]
        self.assertEqual(len([row for row in events if row['kind'] == 'client']), 3)
        hits = [row for row in events if row['kind'] == 'cache_hit']
        self.assertEqual(len(hits), 1)
        self.assertFalse(hits[0]['native'])
        self.assertEqual(hits[0]['native_unwrap_successes'], 0)
        self.assertEqual([state.entries for state in self.clients.cache_states], [0, 1, 1, 1])
        self.assertEqual(len({state.pid for state in self.clients.cache_states}), 1)
        retired = next(row for row in events if row['kind'] == 'daemon_retired')
        self.assertEqual([row['entries'] for row in retired['cache_states']], [0, 1, 1, 1])
        self.assertTrue(all(row['pid'] == retired['pid'] for row in retired['cache_states']))
        self.assertEqual(self.native.inner.calls.count('unwrap'), 2)
        self.assertEqual(events[-2]['successful_reads'], 3)
        self.assertTrue(events[-1]['authority_retired'])
        self.assertFalse(self.native.inner.key or self.native.inner.root)
        self.assertFalse((self.run.path / 'journal').exists())
        self.assertFalse(self.clients.daemon.path.exists())

    def fail_with_flag(self, name):
        setattr(self.process, name, True)
        with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()

    def test_matching_cold_without_native_unwrap_is_uncertain(self): self.fail_with_flag('skip_cold')
    def test_warm_with_extra_native_unwrap_is_uncertain(self): self.fail_with_flag('extra_warm')
    def test_matching_bypass_without_native_unwrap_is_uncertain(self): self.fail_with_flag('skip_bypass')
    def test_warm_with_wrong_cache_count_is_uncertain(self): self.fail_with_flag('bad_cache')
    def test_warm_with_wrong_plaintext_is_uncertain(self): self.fail_with_flag('bad_plaintext')

    def test_stop_failure_latches_native_authority_before_abandon_and_retains_runtime(self):
        original = self.clients.abandon_daemon
        def abandon():
            self.assertTrue(self.campaign.controller.journal.failed)
            original()
        with patch.object(self.clients.daemon, 'stop', side_effect=Stop('fake daemon stop failure')):
            with patch.object(self.clients, 'abandon_daemon', side_effect=abandon):
                with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()
        self.assertTrue(self.clients.daemon.path.exists())

    def test_warm_evidence_write_failure_retains_native_authority_after_owned_teardown(self):
        original = self.report._append
        def append(value):
            if value['kind'] == 'cache_hit': raise OSError('fake evidence failure')
            return original(value)
        with patch.object(self.report, '_append', side_effect=append):
            with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()
        self.assertFalse(self.clients.daemon.path.exists())

    def corrupt_retirement(self, change):
        original = self.clients.finish_daemon
        def finish():
            receipt = original()
            change()
            return receipt
        with patch.object(self.clients, 'finish_daemon', side_effect=finish):
            with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()
        self.assertFalse(self.report.daemon_retired)

    def test_same_value_replacement_cache_observation_is_not_original_owner_evidence(self):
        def change(): self.clients.cache_states[2] = replace(self.clients.cache_states[2])
        self.corrupt_retirement(change)

    def test_reordered_same_value_cache_observations_are_not_chronological_evidence(self):
        def change():
            states = self.clients.cache_states
            states[1], states[2] = states[2], states[1]
        self.corrupt_retirement(change)

    def test_configuration_change_after_daemon_exit_blocks_native_cleanup(self):
        def change(): (self.clients.project / 'fnox.toml').write_bytes(b'# changed after exit\n')
        self.corrupt_retirement(change)

    def test_config_change_between_cold_and_warm_stops_before_next_get(self):
        original = self.clients.execute
        def execute(controller, label):
            if label == 'fnox_daemon_warm':
                (self.clients.project / 'fnox.toml').write_bytes(b'# changed own config\n')
            return original(controller, label)
        with patch.object(self.clients, 'execute', side_effect=execute):
            with self.assertRaises(Stop): self.campaign.execute()
        self.assert_retained()
        self.assertEqual(self.process.gets, 1)


if __name__ == '__main__':
    unittest.main()
