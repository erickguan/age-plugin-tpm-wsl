"""Common component lifecycle with software sender and exclusively fake native state."""
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

import test_post_quantum_client_campaign as support
from post_quantum_client.authority import PublicIdentity, Stop
from post_quantum_client.component_campaign import ComponentCampaign
from post_quantum_client.controller import CLEANUP_FAILED, frame
from post_quantum_client.clients import ClientOutcome
from post_quantum_client.journal import AUTHENTICATION_FAILED, INVALID
from post_quantum_client.process import BoundedProcess, ProcessResult
from post_quantum_client.references import ClientReferences
from post_quantum_client.report import ClientMeasurement

ROOT = Path(__file__).resolve().parents[1]


class ComponentClients(support.FakeClients):
    def __init__(self, run, pin, native, ciphertext):
        super().__init__(run, pin, native)
        self.ciphertext = ciphertext
        self.fatal_rejection = False
        self.operational_rejection = False

    def encrypt(self, payload, client, case):
        return ClientOutcome(ClientMeasurement(client, 'encrypt', len(payload), 1, 0, True), self.ciphertext)

    def decrypt(self, ciphertext, expected, client, case):
        if ciphertext == self.ciphertext:
            self.native.inner.override = None
        else:
            status = (CLEANUP_FAILED if self.fatal_rejection else
                      INVALID if self.operational_rejection else AUTHENTICATION_FAILED)
            self.native.inner.override = lambda operation: ProcessResult(0, frame(9, status=status))
        return super().decrypt(ciphertext, expected, client, case)


class ComponentCampaignTests(unittest.TestCase):
    def setUp(self):
        self.fixture = support.CampaignTests()
        self.fixture.setUp()
        f = self.fixture
        public = bytes.fromhex(json.loads((ROOT / 'notes/aws-lc-hybrid-evaluation/go-fixture.json').read_text())['public_key'])
        identity = PublicIdentity.parse(b'\x03\x00\x02' + public + b'\x2f' + f.namespace.key_name.encode(), f.namespace)
        refs = ClientReferences.from_identity(identity, f.namespace)
        binary = f.run.subdirectory('public-bin')
        (binary / 'age-plugin-tagpq').symlink_to(ROOT / 'target/debug/age-plugin-tpm-wsl')
        env = {k: v for k, v in os.environ.items() if not k.startswith(('AGE', 'FNOX_'))}
        env.update(HOME=str(f.run.path), XDG_CONFIG_HOME=str(f.run.path), XDG_CACHE_HOME=str(f.run.path),
                   XDG_STATE_HOME=str(f.run.path), XDG_RUNTIME_DIR=str(f.run.path),
                   PATH=str(binary) + os.pathsep + os.environ['PATH'], AGE_TPM_WSL_HELPER='/nonexistent/offline.exe')
        encrypted = BoundedProcess()([str(Path(shutil.which('age')).resolve()), '--encrypt', '--recipient', refs.recipient],
                                     support.PAYLOAD, env, 10)
        self.assertEqual(encrypted.exit_code, 0)
        self.clients = ComponentClients(f.run, f.clients.inputs.helper, f.native, encrypted.stdout)
        self.campaign = ComponentCampaign(f.run, f.namespace, f.report, self.clients, f.native.observe,
                                          f.native.controller)
        f.campaign = self.campaign

    def tearDown(self):
        self.fixture.tearDown()  # Only mock native state.

    def test_two_controls_and_six_rejections_quiesce_then_share_one_cleanup_and_retirement(self):
        f = self.fixture
        def quiesced():
            self.assertFalse(self.campaign.service.thread.is_alive())
            self.assertFalse((f.run.path / 's').exists())
            f.native.inner.override = None  # End fake rejection response selection.
        f.native.cleanup_probe = quiesced
        self.campaign.execute()
        events = [json.loads(line) for line in f.report.path.read_text().splitlines()]
        clients = [event for event in events if event['kind'] == 'client']
        rejects = [event for event in events if event['kind'] == 'rejection']
        self.assertEqual(len(clients), 3)
        self.assertEqual(len(rejects), 6)
        self.assertEqual(f.report.decryptions, 2)
        self.assertTrue(all(event['exit_code'] == 1 and event['helper_status'] == AUTHENTICATION_FAILED
                            and event['plaintext_bytes'] == 0 and event['result'] == 'pass' for event in rejects))
        self.assertEqual(f.native.inner.calls.count('unwrap'), 8)
        self.assertEqual(f.native.inner.calls.count('delete'), 1)
        self.assertFalse((f.run.path / 'journal').exists())
        self.assertEqual(events[-2]['successful_reads'], 2)
        self.assertTrue(events[-1]['authority_retired'])

    def test_one_missing_component_rpc_never_counts_as_a_known_rejection_or_grants_cleanup(self):
        self.clients.skip_rpc_at = 3
        with self.assertRaises(Stop): self.campaign.execute()
        self.fixture.assert_retained_without_cleanup()
        self.assertEqual(self.fixture.report.decryptions, 0)

    def test_operational_invalid_after_successful_controls_cannot_pass_as_authentication_rejection(self):
        self.clients.operational_rejection = True
        with self.assertRaises(Stop): self.campaign.execute()
        self.fixture.assert_retained_without_cleanup()
        self.assertEqual(self.clients.decryptions, 3)
        rows = [json.loads(line) for line in self.fixture.report.path.read_text().splitlines()]
        self.assertFalse(any(row['kind'] == 'rejection' for row in rows))

    def test_fatal_status_never_becomes_expected_component_rejection(self):
        self.clients.fatal_rejection = True
        with self.assertRaises(Stop): self.campaign.execute()
        self.fixture.assert_retained_without_cleanup()

    def test_rejection_report_failure_poisons_before_propagation_and_blocks_cleanup(self):
        report = self.fixture.report
        original = report._append
        def failed(value):
            if value['kind'] == 'rejection': raise OSError('simulated evidence write failure')
            return original(value)
        with patch.object(report, '_append', side_effect=failed):
            with self.assertRaises(Stop): self.campaign.execute()
        self.fixture.assert_retained_without_cleanup()
        self.assertTrue(self.campaign.controller.journal.failed)

    def test_wrong_first_control_stops_before_any_component_read(self):
        self.clients.mismatch_at = 1
        with self.assertRaises(Stop): self.campaign.execute()
        self.fixture.assert_retained_without_cleanup()
        self.assertEqual(self.clients.decryptions, 1)


if __name__ == '__main__':
    unittest.main()
