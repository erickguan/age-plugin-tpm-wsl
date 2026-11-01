"""Actual isolated fnox public commands; private reads mocked, never Windows."""
import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from post_quantum_client.authority import Namespace, PREFIX, PublicIdentity, Stop
from post_quantum_client.cases import PAYLOAD
from post_quantum_client.fnox import CHANGED_SOURCE, FnoxEnvironment, fnox_cases
from post_quantum_client.inputs import Artifact
from post_quantum_client.process import BinaryPin, BoundedProcess, ProcessResult, digest
from post_quantum_client.references import ClientReferences
from post_quantum_client.run_directory import RunDirectory
from post_quantum_client.runtime import StagedRuntime

ROOT = Path(__file__).resolve().parents[1]


class PublicProcess:
    def __init__(self):
        self.commands = []
        self.wrong_cache = False

    def __call__(self, command, payload, environment, seconds, **options):
        self.commands.append((command, dict(environment), seconds, options))
        if command[-2:] == ['get', 'PQ_CLIENT_TEST']:
            value = CHANGED_SOURCE.encode() if self.wrong_cache else PAYLOAD
            return ProcessResult(0, value + b'\n')
        return BoundedProcess()(command, payload, environment, seconds, **options)


class FnoxTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        parent = Path(self.temporary.name)
        parent.chmod(0o700)
        self.run = RunDirectory.create(parent)
        source = parent / 'source'; source.write_bytes(b'public test-only source binding')
        image = parent / 'image'; image.write_bytes(b'never executed mock native helper')
        hashes = {str(source): digest(source)}
        helper = BinaryPin.stage(image, digest(image), self.run.path, hashes)
        pins = {}
        for name in ('plugin', 'age', 'rage', 'fnox'):
            path = ROOT / 'target/debug/age-plugin-tpm-wsl' if name == 'plugin' else Path(shutil.which(name)).resolve()
            pins[name] = BinaryPin.stage(path, digest(path), self.run.path, hashes,
                                        'age-plugin-tpm-wsl' if name == 'plugin' else name)
        python = Path(sys.executable).resolve()
        versions = json.loads((ROOT / 'notes/post-quantum-client-driver-primitives-offline-final.json').read_text())['clients']
        staged = StagedRuntime(helper, pins['plugin'], pins['age'], Artifact(python, digest(python)),
                               versions['age']['version'], ROOT / 'scripts/post_quantum_client_wrapper.py',
                               pins['rage'], versions['rage']['version'], pins['fnox'], 'fnox 1.42.1')
        self.process = PublicProcess()
        self.clients = FnoxEnvironment(self.run, staged, self.process,
                                       {'PATH': os.environ['PATH'], 'FNOX_CONFIG_FILE': '/production/not-read',
                                        'AGE_TPM_WSL_HELPER': '/production/not-run'})
        public = bytes.fromhex(json.loads((ROOT / 'notes/aws-lc-hybrid-evaluation/go-fixture.json').read_text())['public_key'])
        namespace = Namespace(PREFIX + '0' * 32)
        identity = PublicIdentity.parse(b'\x03\x00\x02' + public + b'\x2f' + namespace.key_name.encode(), namespace)
        self.clients.preflight()
        self.clients.prepare(ClientReferences.from_identity(identity, namespace))

    def tearDown(self):
        self.temporary.cleanup()  # Public software fixtures only; no actual resource.

    def direct(self):
        case = fnox_cases()[0]
        return self.clients.encrypt(case.payload, case.encryptor, case.label)

    def advance_to_cache(self):
        direct = self.direct()
        read = self.clients.decrypt(direct.output, PAYLOAD, 'fnox', 'fnox_direct')
        self.assertTrue(read.measurement.passed)
        return self.clients.encrypt(PAYLOAD, 'fnox', 'fnox_cache')

    def test_real_fnox_public_direct_and_sync_encrypt_with_helper_disabled_and_private_configuration(self):
        for case in fnox_cases():
            encrypted = self.clients.encrypt(case.payload, case.encryptor, case.label)
            self.assertTrue(encrypted.measurement.passed)
            wrapped = (base64.b64decode(encrypted.output.decode().split(':')[1], validate=True)
                       if case.label == 'fnox_cache' else encrypted.output)
            self.assertEqual(wrapped.count(b'-> mlkem768p256tag '), 1)
            read = self.clients.decrypt(encrypted.output, PAYLOAD, 'fnox', case.label)
            self.assertTrue(read.measurement.passed)
        self.assertEqual(self.clients.phase, 4)
        commands = [call for call in self.process.commands if '--config' in call[0]]
        self.assertEqual(len(commands), 4)
        for command, environment, seconds, options in commands:
            self.assertEqual(command[1:3], ['--config', 'fnox.toml'])
            self.assertIn('--no-daemon', command)
            self.assertIn('--non-interactive', command)
            self.assertIn('--if-missing', command)
            self.assertEqual(options['cwd'], self.clients.project)
            self.assertEqual(seconds, 10)
            self.assertNotIn('FNOX_CONFIG_FILE', environment)
            if 'get' in command:
                self.assertEqual(environment['AGE_TPM_WSL_HELPER'], str(self.clients.frontend.path))
            else:
                self.assertEqual(environment['AGE_TPM_WSL_HELPER'], '/nonexistent/offline-only.exe')
        self.assertEqual(self.clients._read('fnox.toml')['secrets']['PQ_CLIENT_TEST']['value'], CHANGED_SOURCE)
        self.assertEqual(self.clients._read('fnox.local.toml')['secrets']['PQ_CLIENT_TEST']['value'], CHANGED_SOURCE)
        for name in ('fnox.toml', 'fnox.local.toml'):
            self.assertEqual((self.clients.project / name).stat().st_mode & 0o777, 0o600)

    def test_actual_fnox_private_read_with_disabled_helper_fails_without_returning_plaintext(self):
        self.direct()
        result = BoundedProcess()([self.clients.inputs.fnox.path, '--config', 'fnox.toml', '--no-daemon',
                                   '--non-interactive', '--no-color', '--if-missing', 'error', 'get', 'PQ_CLIENT_TEST'],
                                  b'', self.clients.environment(True), 10, cwd=self.clients.project)
        self.assertNotEqual(result.exit_code, 0)
        self.assertTrue(result.stdout == b'', 'helper-disabled get returned output')

    def test_actual_fnox_cached_get_cannot_fall_back_to_either_plaintext_copy(self):
        self.advance_to_cache()
        result = BoundedProcess()([self.clients.inputs.fnox.path, '--config', 'fnox.toml', '--no-daemon',
                                   '--non-interactive', '--no-color', '--if-missing', 'error', 'get', 'PQ_CLIENT_TEST'],
                                  b'', self.clients.environment(True), 10, cwd=self.clients.project)
        self.assertNotEqual(result.exit_code, 0)
        self.assertTrue(result.stdout == b'', 'helper-disabled cached get returned output')
        plain = ('[secrets.PQ_CLIENT_TEST]\nprovider = "source"\nvalue = '
                 + json.dumps(CHANGED_SOURCE) + '\n').encode()
        self.clients._write('fnox.local.toml', plain)
        plain_result = BoundedProcess()([self.clients.inputs.fnox.path, '--config', 'fnox.toml', '--no-daemon',
                                        '--non-interactive', '--no-color', '--if-missing', 'error', 'get', 'PQ_CLIENT_TEST'],
                                       b'', self.clients.environment(True), 10, cwd=self.clients.project)
        self.assertEqual(plain_result.exit_code, 0)
        self.assertTrue(plain_result.stdout == CHANGED_SOURCE.encode() + b'\n', 'unexpected CLI output')

    def test_original_plaintext_in_the_local_override_blocks_cache_acceptance(self):
        encrypted = self.advance_to_cache()
        path = self.clients.project / 'fnox.local.toml'
        original = path.read_bytes()
        changed = original.replace(json.dumps(CHANGED_SOURCE).encode(), json.dumps(PAYLOAD.decode()).encode(), 1)
        self.clients._write('fnox.local.toml', changed)
        before = len(self.process.commands)
        with self.assertRaises(Stop): self.clients.decrypt(encrypted.output, PAYLOAD, 'fnox', 'fnox_cache')
        self.assertEqual(len(self.process.commands), before)

    def test_batch_cache_envelope_requires_provider_canonical_segments_and_expected_lengths(self):
        encrypted = self.advance_to_cache()
        path = self.clients.project / 'fnox.local.toml'
        original = path.read_bytes()
        parts = encrypted.output.decode().split(':')
        malformed = [':'.join(['unknown-batch', *parts[1:]]),
                     ':'.join([parts[0], parts[1], base64.b64encode(b'short').decode()]),
                     ':'.join([parts[0], '!not-base64', parts[2]]),
                     ':'.join([parts[0], base64.b64encode(b'no hybrid age wrapper').decode(), parts[2]])]
        for value in malformed:
            bad = original.replace(json.dumps(encrypted.output.decode()).encode(), json.dumps(value).encode())
            self.clients._write('fnox.local.toml', bad)
            with self.assertRaises((Stop, ValueError)): self.clients._ciphertext('fnox_cache')
        self.clients._write('fnox.local.toml', original.replace(b'provider = "pq_age"', b'provider = "source"'))
        with self.assertRaises(Stop): self.clients._ciphertext('fnox_cache')

    def test_changed_plain_source_cannot_be_accepted_as_a_persistent_cache_read(self):
        encrypted = self.advance_to_cache()
        self.process.wrong_cache = True
        result = self.clients.decrypt(encrypted.output, PAYLOAD, 'fnox', 'fnox_cache')
        self.assertFalse(result.measurement.passed)
        self.assertEqual(result.output, b'')
        self.assertEqual(self.clients.phase, 3)

    def test_ciphertext_mismatch_stops_before_another_fnox_command(self):
        self.direct()
        before = len(self.process.commands)
        with self.assertRaises(Stop):
            self.clients.decrypt(b'wrong ciphertext', PAYLOAD, 'fnox', 'fnox_direct')
        self.assertEqual(len(self.process.commands), before)

    def test_workflow_order_and_fixed_disposable_payload_are_required(self):
        before = len(self.process.commands)
        for operation in (lambda: self.clients.decrypt(b'', PAYLOAD, 'fnox', 'fnox_direct'),
                          lambda: self.clients.encrypt(b'unexpected value', 'fnox', 'fnox_direct'),
                          lambda: self.clients.encrypt(PAYLOAD, 'fnox', 'fnox_cache')):
            with self.assertRaises(Stop): operation()
        self.assertEqual(len(self.process.commands), before)

    def test_changed_source_proof_cannot_be_removed_before_the_cache_read(self):
        encrypted = self.advance_to_cache()
        self.clients._config(PAYLOAD.decode())
        with self.assertRaises(Stop):
            self.clients.decrypt(encrypted.output, PAYLOAD, 'fnox', 'fnox_cache')

    def test_project_replacement_and_config_symlink_are_rejected(self):
        self.direct()
        config = self.clients.project / 'fnox.toml'
        saved = self.clients.project / 'saved.toml'
        config.rename(saved); config.symlink_to(saved)
        with self.assertRaises(OSError): self.clients._read('fnox.toml')
        config.unlink(); saved.rename(config)
        old = self.clients.project.with_name('old-fnox-project')
        self.clients.project.rename(old); self.clients.project.mkdir(mode=0o700)
        with self.assertRaises(Stop): self.clients._read('fnox.toml')

    def test_changed_staged_fnox_or_version_stops_before_another_command(self):
        self.clients.inputs = replace(self.clients.inputs, fnox_version='fnox wrong-version')
        with self.assertRaises(Stop): self.clients.preflight()
        path = Path(self.clients.inputs.fnox.path)
        replacement = self.run.path / 'replacement-image'
        replacement.write_bytes(b'changed binary'); replacement.chmod(0o500)
        replacement.replace(path)
        before = len(self.process.commands)
        with self.assertRaises(Stop): self.direct()
        self.assertEqual(len(self.process.commands), before)


if __name__ == '__main__':
    unittest.main()
