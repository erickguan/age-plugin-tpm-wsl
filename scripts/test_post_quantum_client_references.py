"""Known checksum and real offline Rust parser checks; no Windows helper runs."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from post_quantum_client.authority import Namespace, PREFIX, PublicIdentity, Stop
from post_quantum_client.references import ClientReferences, encode_reference

ROOT = Path(__file__).resolve().parents[1]


class ReferenceTests(unittest.TestCase):
    def test_original_bech32_checksum_vector(self):
        self.assertEqual(encode_reference('a', b''), 'a12uel5l')

    def test_actual_offline_plugin_reads_encoded_canonical_identity_and_extracts_same_recipient(self):
        public = bytes.fromhex(json.loads((ROOT / 'notes/aws-lc-hybrid-evaluation/go-fixture.json').read_text())['public_key'])
        namespace = Namespace(PREFIX + '0' * 32)
        identity = PublicIdentity.parse(b'\x03\x00\x02' + public + b'\x2f' + namespace.key_name.encode(), namespace)
        reference = ClientReferences.from_identity(identity, namespace)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'public-identity.txt'
            path.write_text(reference.identity + '\n')
            path.chmod(0o600)
            environment = dict(os.environ, HOME=temporary, AGE_TPM_WSL_HELPER='/nonexistent/offline-only.exe')
            result = subprocess.run([str(ROOT / 'target/debug/age-plugin-tpm-wsl'), 'recipient', str(path)],
                                    env=environment, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.decode().strip(), reference.recipient)
        with self.assertRaises(Stop):
            ClientReferences.from_identity(identity, Namespace(PREFIX + '1' * 32))


if __name__ == '__main__':
    unittest.main()
