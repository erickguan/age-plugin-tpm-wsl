"""Diagnostic enum through bounded real pipes and isolated public/software clients."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_post_quantum_client_clients as support
from post_quantum_client.authority import Stop
from post_quantum_client.diagnostics import Diagnostic
from post_quantum_client.durable import PrivateFile
from post_quantum_client.process import BinaryPin, BoundedProcess
from post_quantum_client.recovery_key import RecoveryKey
from post_quantum_client.references import encode_reference


class DiagnosticProcessTests(unittest.TestCase):
    def result(self, stderr, client='age', status=1, stdout=b''):
        body = ('import sys\n' + f'sys.stderr.buffer.write({stderr!r})\n'
                + f'sys.stdout.buffer.write({stdout!r})\n' + f'raise SystemExit({status})\n')
        return BoundedProcess()([sys.executable, '-I', '-c', body], b'', os.environ.copy(), 3,
                                diagnostic_client=client)

    def test_known_categories_are_redacted_and_reader_specific(self):
        cases = [('age', b'age: error: no identity matched any of the recipients', Diagnostic.NO_MATCH),
                 ('rage', b'Error: No matching keys found', Diagnostic.NO_MATCH),
                 ('age', b'invalid post-quantum stanza shape', Diagnostic.STANZA_SHAPE),
                 ('rage', b'invalid post-quantum stanza shape', Diagnostic.STANZA_SHAPE),
                 ('age', b'parsing age header: unexpected intro', Diagnostic.FILE_VERSION),
                 ('rage', 'Unknown \u2068age\u2069 format.'.encode(), Diagnostic.FILE_VERSION),
                 ('age', b'unsupported recipient version or suite', Diagnostic.IDENTITY_VERSION),
                 ('rage', b'unsupported recipient version or suite', Diagnostic.IDENTITY_VERSION),
                 ('age', b'failed to decrypt and authenticate payload chunk', Diagnostic.PAYLOAD_AUTH),
                 ('rage', b'Error: decryption error', Diagnostic.PAYLOAD_AUTH)]
        for client, stderr, expected in cases:
            with self.subTest(client=client, expected=expected):
                result = self.result(stderr, client)
                self.assertIs(result.diagnostic, expected)
                self.assertFalse(hasattr(result, 'stderr'))
                self.assertEqual(result.stdout, b'')

    def test_unknown_operational_conflicting_and_malformed_messages_are_never_categories(self):
        for stderr in (b'permission denied: no identity matched any of the recipients',
                       b'helper failed: no identity matched any of the recipients',
                       b'no identity matched any of the recipients\ninvalid post-quantum stanza shape',
                       b'invalid post-quantum stanza shape\xff',
                       b'failed to decrypt and authenticate payload chunk\nHeader MAC is invalid',
                       b'Decryption failed', b'unrecognized client failure'):
            with self.subTest():
                self.assertIs(self.result(stderr).diagnostic, Diagnostic.UNKNOWN)
        self.assertIs(self.result(b'Error: decryption error', 'age').diagnostic, Diagnostic.UNKNOWN)
        self.assertIs(self.result(b'parsing age header: unexpected intro', 'rage').diagnostic, Diagnostic.UNKNOWN)

    def test_nonzero_output_or_other_exit_code_does_not_get_a_refusal_category(self):
        text = b'no identity matched any of the recipients'
        for status, output in ((0, b''), (2, b''), (1, b'unexpected disposable bytes')):
            with self.subTest(status=status):
                self.assertIs(self.result(text, status=status, stdout=output).diagnostic, Diagnostic.UNKNOWN)

    def test_default_helper_path_still_discards_stderr_and_never_classifies(self):
        text = b'no identity matched any of the recipients' + b'x' * 100000
        self.assertIs(self.result(text, client=None).diagnostic, Diagnostic.UNKNOWN)

    def test_stderr_overflow_stops_even_after_a_known_refusal_prefix(self):
        with self.assertRaises(Stop):
            self.result(b'no identity matched any of the recipients' + b'x' * 100000)

    def test_diagnostic_reader_must_finish_under_the_same_deadline(self):
        body = ('import os, sys, time\nif os.fork() == 0:\n'
                ' os.close(0); os.close(1)\n'
                ' sys.stderr.write("no identity matched any of the recipients"); sys.stderr.flush()\n'
                ' time.sleep(0.3); os._exit(0)\nos._exit(1)\n')
        with self.assertRaises(Stop):
            BoundedProcess()([sys.executable, '-I', '-c', body], b'', os.environ.copy(), 0.05,
                             diagnostic_client='age')

    def test_invalid_capture_option_never_launches(self):
        for client in (True, [], 'helper', 'unknown'):
            with patch('post_quantum_client.process.subprocess.Popen') as launch:
                with self.assertRaises(Stop):
                    BoundedProcess()(['never-executed'], b'', {}, diagnostic_client=client)
                launch.assert_not_called()


class ActualClientDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.fixture = support.ClientEnvironmentTests(); self.fixture.setUp()
        self.clients = self.fixture.environment()
        self.clients.preflight(); self.clients.prepare(self.fixture.reference)

    def tearDown(self):
        self.fixture.tearDown()  # Public/software files only; no native state.

    def read(self, client, ciphertext, identity):
        pin, _ = self.clients.inputs.client(client)
        environment = dict(self.clients.environment(True), LC_ALL='C', LANG='C')
        return BoundedProcess()([pin.path, '--decrypt', '--identity', str(identity)], ciphertext,
                                environment, 10, diagnostic_client=client)

    def test_actual_parser_identity_markers_and_unavailable_helper_remain_distinct(self):
        original = self.clients.encrypt().output
        parts = original.split(b'\n', 3)
        parts[1] = b' '.join(parts[1].split(b' ')[:3])
        malformed = b'\n'.join(parts)
        unsupported = original.replace(b'age-encryption.org/v1\n', b'age-encryption.org/v9\n', 1)
        # An intentionally invalid version with otherwise bounded public bytes.
        invalid = encode_reference('age-plugin-tpm-wsl-', b'\xff' + b'\x00' * 1299).upper()
        identity = self.fixture.run.write_public('invalid-identity', (invalid + '\n').encode())
        for client in ('age', 'rage'):
            for ciphertext, path, expected in ((malformed, self.clients.identity.path, Diagnostic.STANZA_SHAPE),
                                               (unsupported, self.clients.identity.path, Diagnostic.FILE_VERSION),
                                               (original, identity.path, Diagnostic.IDENTITY_VERSION),
                                               (original, self.clients.identity.path, Diagnostic.UNKNOWN)):
                with self.subTest(client=client, expected=expected):
                    result = self.read(client, ciphertext, path)
                    self.assertEqual(result.exit_code, 1)
                    self.assertEqual(result.stdout, b'')
                    self.assertIs(result.diagnostic, expected)

    def test_actual_payload_markers_preserve_no_private_reads_and_exact_key_retirement(self):
        source = Path(shutil.which('age-keygen')).resolve()
        # Public readiness supplies the selected generator hash; no old runtime
        # consumer approval is inferred after these source changes.
        import json
        expected = json.loads((support.ROOT / 'notes/post-quantum-recovery-workflow-software-absence.json').read_text())
        pin = BinaryPin.stage(source, expected['binaries']['age_keygen']['sha256'], self.fixture.run.path,
                              self.clients.inputs.helper.source_hashes, 'age-keygen')
        key = PrivateFile.create(self.fixture.run.path / 'software.key', b'')
        environment = self.clients.environment(True)
        with key.locked() as storage:
            result = subprocess.run([pin.path], env=environment, stdin=subprocess.DEVNULL,
                                    stdout=storage.descriptor, stderr=subprocess.DEVNULL, timeout=10, umask=0o077)
            self.assertEqual(result.returncode, 0)
            os.fsync(storage.descriptor)
            metadata = RecoveryKey._metadata(storage.descriptor)
        recipient = BoundedProcess()([pin.path, '-y', str(key.path)], b'', environment, 10)
        encrypted = BoundedProcess()([self.clients.inputs.age.path, '--encrypt', '--recipient',
                                     recipient.stdout.decode().strip()], support.PAYLOAD, environment, 10)
        self.assertEqual(encrypted.exit_code, 0)
        changed = encrypted.stdout[:-1] + bytes([encrypted.stdout[-1] ^ 1])
        for client in ('age', 'rage'):
            positive = self.read(client, encrypted.stdout, key.path)
            self.assertTrue(positive.exit_code == 0 and positive.stdout == support.PAYLOAD)
            result = self.read(client, changed, key.path)
            self.assertEqual(result.exit_code, 1)
            self.assertEqual(result.stdout, b'')
            self.assertIs(result.diagnostic, Diagnostic.PAYLOAD_AUTH)
        with key.locked() as storage:
            self.assertEqual(RecoveryKey._metadata(storage.descriptor), metadata)
            storage.retire()
        self.assertFalse(os.path.lexists(key.path))


if __name__ == '__main__':
    unittest.main()
