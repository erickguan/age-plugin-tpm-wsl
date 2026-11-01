"""Real staged public encryption only; no Windows helper or native key is opened."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from post_quantum_client.authority import Namespace, PREFIX, PublicIdentity, Stop
from post_quantum_client.clients import ClientEnvironment, PAYLOAD
from post_quantum_client.cases import positive_cases
from post_quantum_client.controller import Controller, frame
from post_quantum_client.inputs import Artifact
from post_quantum_client.journal import Journal
from post_quantum_client.process import BinaryPin, digest
from post_quantum_client.references import ClientReferences
from post_quantum_client.run_directory import RunDirectory
from post_quantum_client.runtime import StagedRuntime
from post_quantum_client.service import ClientService
from test_post_quantum_client_controller import FakeWindows

ROOT = Path(__file__).resolve().parents[1]


class ClientEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        parent = Path(self.temporary.name)
        parent.chmod(0o700)
        self.run = RunDirectory.create(parent)
        source = parent / 'source'
        source.write_bytes(b'fixed dummy binding')
        image = parent / 'image'
        image.write_bytes(b'mock helper: never executed')
        hashes = {str(source): digest(source)}
        helper = BinaryPin.stage(image, digest(image), self.run.path, hashes)
        plugin_source = ROOT / 'target/debug/age-plugin-tpm-wsl'
        plugin = BinaryPin.stage(plugin_source, digest(plugin_source), self.run.path, hashes, 'age-plugin-tpm-wsl')
        age_source = Path(shutil.which('age')).resolve()
        age = BinaryPin.stage(age_source, digest(age_source), self.run.path, hashes, 'age')
        rage_source = Path(shutil.which('rage')).resolve()
        rage = BinaryPin.stage(rage_source, digest(rage_source), self.run.path, hashes, 'rage')
        python = Path(sys.executable).resolve()
        versions = json.loads((ROOT / 'notes/post-quantum-client-driver-primitives-offline-final.json').read_text())['clients']
        self.staged = StagedRuntime(helper, plugin, age, Artifact(python, digest(python)), versions['age']['version'],
                                    ROOT / 'scripts/post_quantum_client_wrapper.py', rage, versions['rage']['version'])
        public = bytes.fromhex(json.loads((ROOT / 'notes/aws-lc-hybrid-evaluation/go-fixture.json').read_text())['public_key'])
        namespace = Namespace(PREFIX + '0' * 32)
        identity = PublicIdentity.parse(b'\x03\x00\x02' + public + b'\x2f' + namespace.key_name.encode(), namespace)
        self.reference = ClientReferences.from_identity(identity, namespace)

    def tearDown(self):
        self.temporary.cleanup()

    def environment(self):
        return ClientEnvironment(self.run, self.staged, inherited={'PATH': os.environ['PATH'],
                                  'AGEDEBUG': '1', 'AGE_TPM_WSL_HELPER': '/production/not-used',
                                  'FNOX_CONFIG_FILE': '/production/not-read'})

    def test_staged_real_plugin_age_and_generated_frontend_support_offline_encryption(self):
        clients = self.environment()
        self.assertEqual(len(PAYLOAD), 32)
        self.assertFalse('FNOX_CONFIG_FILE' in clients.env)
        self.assertTrue(clients.env['HOME'].startswith(str(self.run.path)))
        self.assertEqual(clients.environment(True)['AGE_TPM_WSL_HELPER'], '/nonexistent/offline-only.exe')
        clients.preflight()
        clients.prepare(self.reference)
        outcome = clients.encrypt()
        self.assertTrue(outcome.measurement.passed)
        self.assertEqual(outcome.measurement.payload_bytes, 32)
        self.assertTrue(outcome.output.startswith(b'age-encryption.org/v1\n'))
        self.assertTrue(clients.frontend.path.read_text().startswith('#!' + str(self.staged.python.path) + ' -I\n'))
        self.assertEqual(clients.identity.path.stat().st_mode & 0o777, 0o600)

    def test_both_staged_clients_encrypt_every_positive_payload_with_helper_disabled(self):
        clients = self.environment()
        clients.preflight()
        clients.prepare(self.reference)
        for case in positive_cases():
            with self.subTest(case=case.label, client=case.encryptor):
                result = clients.encrypt(payload=case.payload, client=case.encryptor)
                self.assertTrue(result.measurement.passed)
                self.assertEqual(result.measurement.payload_bytes, len(case.payload))
                self.assertEqual(result.measurement.client, case.encryptor)
                self.assertEqual(clients.environment(True)['AGE_TPM_WSL_HELPER'], '/nonexistent/offline-only.exe')

    def test_generated_frontend_routes_to_owner_in_isolated_python_mode(self):
        clients = self.environment()
        namespace = Namespace(PREFIX + '0' * 32)
        journal = Journal.create(self.run.path / 'journal', namespace, 'S-1-5-21-1001', clients.inputs.helper.record())
        native = FakeWindows(namespace, journal)
        controller = Controller(journal, clients.env, native.observe, native.run)
        controller.admin('prepare')
        controller.forward(frame(8, b'\x00\x02' + namespace.key_name.encode()))
        service = ClientService(self.run.path / 's', controller).start()
        try:
            environment = dict(clients.environment(False), PYTHONHOME='/nonexistent/ignored',
                               PYTHONPATH='/nonexistent/ignored', PYTHONINSPECT='1')
            request = frame(9, b'\x05\x14' + native.identity + b'\x01' * 1153 + b'\x02' * 32)
            result = subprocess.run([str(clients.frontend.path)], input=request, env=environment,
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0)
            # Only the fixed public mock key bytes can enter this captured pipe.
            self.assertEqual(result.stdout, frame(9, b'\x5a' * 16))
            self.assertEqual(result.stderr, b'')
            service.quiesce()
            self.assertEqual(service.calls, 1)
        finally:
            if not service.endpoint.closed:
                try:
                    controller.stop('unit test interrupted')
                except Stop:
                    pass
                service.abandon()

    def test_frontend_or_discovery_tampering_stops_before_any_client_command(self):
        clients = self.environment()
        clients.frontend.path.write_bytes(b'changed frontend')
        with self.assertRaises(Stop):
            clients.verify()

    def test_runtime_pin_staging_rejects_arbitrary_destination_names(self):
        with self.assertRaises(Stop):
            BinaryPin.stage(self.staged.python.path, self.staged.python.sha256,
                            self.run.path, self.staged.helper.source_hashes, '../outside')


if __name__ == '__main__':
    unittest.main()
