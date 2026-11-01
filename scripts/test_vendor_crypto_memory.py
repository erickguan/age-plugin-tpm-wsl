"""No-replace receipt paths and failure retirement for crypto source adoption."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('crypto_vendor', SCRIPTS / 'vendor-crypto-memory.py')
vendor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vendor)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class AdoptionPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='crypto-adoption-regression-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.folder = self.root / 'notes/crypto-memory-integration'
        self.folder.mkdir(parents=True)
        (self.root / 'target').mkdir()
        (self.root / 'vendor').mkdir()
        for name, value in [('ROOT', self.root), ('VENDOR', self.root / 'vendor/crypto-memory'),
                            ('PROVENANCE', self.root / 'vendor/crypto-memory-provenance.json')]:
            replacement = patch.object(vendor, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)

    def test_dangling_record_link_cannot_redirect_sidecar_publication(self):
        requested = self.root / 'outside-record.json'
        requested.symlink_to(self.folder / 'new-receipt.json')
        foreign = requested.with_suffix('.metadata.json')
        foreign.write_bytes(b'unrelated evidence')
        with self.assertRaisesRegex(RuntimeError, 'symlinked record'):
            vendor.receipt_paths(requested)
        self.assertEqual(foreign.read_bytes(), b'unrelated evidence')
        self.assertFalse((self.folder / 'new-receipt.json').exists())

    def test_dangling_metadata_link_is_rejected(self):
        requested = self.folder / 'receipt.json'
        requested.with_suffix('.metadata.json').symlink_to(self.root / 'foreign')
        with self.assertRaisesRegex(RuntimeError, 'symlinked record'):
            vendor.receipt_paths(requested)
        self.assertFalse((self.root / 'foreign').exists())

    def test_canonical_paths_are_used_and_existing_files_cannot_be_replaced(self):
        requested = self.folder / 'receipt.json'
        record, metadata = vendor.receipt_paths(requested)
        self.assertEqual(record, requested.resolve())
        self.assertEqual(metadata, requested.resolve().with_suffix('.metadata.json'))
        metadata.write_bytes(b'existing')
        owned = {}
        with self.assertRaises(FileExistsError):
            vendor.publish_receipt(metadata, b'new', owned)
        self.assertEqual(metadata.read_bytes(), b'existing')
        self.assertEqual(owned, {})

    def test_exclusive_creation_rejects_a_link_inserted_after_preflight(self):
        record, _ = vendor.receipt_paths(self.folder / 'receipt.json')
        foreign = self.root / 'foreign'
        record.symlink_to(foreign)
        with self.assertRaises(FileExistsError):
            vendor.publish_receipt(record, b'new', {})
        self.assertFalse(foreign.exists())

    def test_partially_published_receipt_is_retired_as_failure_evidence(self):
        record, _ = vendor.receipt_paths(self.folder / 'receipt.json')
        owned = {}
        with patch.object(vendor.os, 'fsync', side_effect=OSError('injected publication failure')):
            with self.assertRaises(OSError):
                vendor.publish_receipt(record, b'{"result":"source selected"}', owned)
        directory, errors = vendor.retire_receipts(owned, 'injected publication failure', 'original selectors restored')
        self.assertEqual(errors, [])
        self.assertFalse(record.exists())
        failure = json.loads((directory / 'failure.json').read_text())
        self.assertEqual(failure['result'], 'failed; receipts are not acceptance')
        self.assertEqual(failure['selector_rollback'], 'original selectors restored')
        self.assertEqual(len(failure['uncommitted_receipts']), 1)
        self.assertTrue(Path(failure['uncommitted_receipts'][0]['uncommitted_path']).is_file())

    def test_foreign_replacement_is_not_retired(self):
        record, _ = vendor.receipt_paths(self.folder / 'receipt.json')
        owned = {}
        vendor.publish_receipt(record, b'owned', owned)
        record.rename(self.root / 'original-owned')
        record.write_bytes(b'foreign')
        _, errors = vendor.retire_receipts(owned, 'failure', 'restored')
        self.assertEqual(len(errors), 1)
        self.assertIn('receipt changed', errors[0]['error'])
        self.assertEqual(record.read_bytes(), b'foreign')

    def test_multi_receipt_retirement_continues_after_foreign_replacement(self):
        paths = [self.folder / name for name in ['metadata.json', 'adoption.json', 'provenance.json']]
        owned = {}
        for path in paths:
            vendor.publish_receipt(path, b'owned source selection receipt', owned)
        paths[0].rename(self.root / 'original-metadata')
        paths[0].write_bytes(b'foreign metadata')
        directory, errors = vendor.retire_receipts(owned, 'publication failed', 'original selectors restored')
        self.assertEqual(len(errors), 1)
        self.assertEqual(paths[0].read_bytes(), b'foreign metadata')
        self.assertFalse(paths[1].exists())
        self.assertFalse(paths[2].exists())
        failure = json.loads((directory / 'failure.json').read_text())
        self.assertEqual(len(failure['uncommitted_receipts']), 2)
        self.assertEqual(len(failure['retirement_errors']), 1)

    def test_simultaneous_rollback_and_retirement_failure_are_both_reported(self):
        self.publication_failure(3, simultaneous=True)

    def test_each_late_publication_failure_restores_selectors_and_retires_receipts(self):
        for position in [1, 2, 3]:
            with self.subTest(publication=position):
                self.publication_failure(position)

    def publication_failure(self, position, simultaneous=False):
        # Drive real main/rollback/publication in a scratch root. Source and
        # Cargo admission use deterministic local seams; no native work runs.
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            root = Path(directory)
            folder = root / 'notes/crypto-memory-integration'
            folder.mkdir(parents=True)
            (root / 'target').mkdir()
            (root / 'vendor').mkdir()
            (root / 'scripts').mkdir()
            script = root / 'scripts/vendor-crypto-memory.py'
            script.write_bytes(b'bound scratch transfer source')
            (root / 'scripts/test_vendor_crypto_memory.py').write_bytes(b'bound scratch regression source')
            old_manifest = b'[patch.crates-io]\n'
            old_lock = b'original lock'
            (root / 'Cargo.toml').write_bytes(old_manifest)
            (root / 'Cargo.lock').write_bytes(old_lock)
            workspace = root / 'target/proposal'
            workspace.mkdir()
            (workspace / 'Cargo.lock').write_bytes(b'accepted proposed lock')
            provenance = {}
            for family, versions in vendor.FAMILIES.items():
                provenance[family] = {}
                for version in versions:
                    source = workspace / 'crypto-sources' / (family + '-' + version)
                    source.mkdir(parents=True)
                    (source / 'Cargo.toml').write_bytes(b'accepted package')
                    provenance[family][version] = {'patched_sha256': {'Cargo.toml': sha(b'accepted package')}}
            proposal_path = folder / 'proposal.json'
            proposal_path.write_text(json.dumps({'destination': str(workspace), 'crypto_provenance': provenance}))
            client_report = folder / 'client.json'
            client_report.write_bytes(b'accepted software report')
            before = {'Cargo.toml': sha(old_manifest), 'Cargo.lock': sha(old_lock)}
            validation = {'result': 'pass', 'source_snapshot_unchanged': True, 'source_sha256': before,
                          'clients': [{'report': str(client_report), 'sha256': sha(client_report.read_bytes())}] * 6,
                          'steps': [{'check': 'client optimization boundary regressions', 'exit_code': 0}],
                          'proposal_sha256': sha(proposal_path.read_bytes())}
            validation_path = folder / 'validation-assertions.json'
            validation_path.write_text(json.dumps(validation))
            actual = {'packages': []}
            calls = []
            real_publish = vendor.publish_receipt
            def publish(path, data, owned):
                calls.append(path)
                if len(calls) == position:
                    if simultaneous:
                        (root / 'Cargo.toml').write_bytes(b'foreign selector edit')
                        metadata = folder / 'adoption.metadata.json'
                        metadata.rename(root / 'original-owned-metadata')
                        metadata.write_bytes(b'foreign metadata')
                    raise OSError('injected late publication refusal')
                real_publish(path, data, owned)
            with patch.object(vendor, 'ROOT', root), patch.object(vendor, 'VENDOR', root / 'vendor/crypto-memory'), \
                 patch.object(vendor, 'PROVENANCE', root / 'vendor/crypto-memory-provenance.json'), \
                 patch.object(vendor, '__file__', str(script)), patch.object(vendor, 'snapshot', return_value=before), \
                 patch.object(vendor, 'metadata', return_value=actual), patch.object(vendor, 'feature_map', return_value={}), \
                 patch.object(vendor, 'check_sources', return_value=actual), \
                 patch.object(vendor, 'load', return_value=SimpleNamespace(verify_evidence=lambda ignored: None)), \
                 patch.object(vendor, 'publish_receipt', side_effect=publish), \
                 patch.object(vendor.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='', stderr='Ran 9 tests\nOK\n')), \
                 patch.object(sys, 'argv', [str(script)]):
                with self.assertRaises(RuntimeError) as caught:
                    vendor.main()
            if simultaneous:
                self.assertIn('automatic rollback refused', str(caught.exception))
                self.assertIn('receipt retirement incomplete', str(caught.exception))
                self.assertEqual((root / 'Cargo.toml').read_bytes(), b'foreign selector edit')
                self.assertEqual((root / 'Cargo.lock').read_bytes(), b'accepted proposed lock')
                self.assertEqual((folder / 'adoption.metadata.json').read_bytes(), b'foreign metadata')
            else:
                self.assertIn('receipts retired', str(caught.exception))
                self.assertEqual((root / 'Cargo.toml').read_bytes(), old_manifest)
                self.assertEqual((root / 'Cargo.lock').read_bytes(), old_lock)
                self.assertFalse((folder / 'adoption.metadata.json').exists())
            self.assertFalse((folder / 'adoption.json').exists())
            self.assertFalse((root / 'vendor/crypto-memory-provenance.json').exists())
            failures = list((root / 'target').glob('crypto-adoption-failed-*/failure.json'))
            self.assertEqual(len(failures), 1)
            failure = json.loads(failures[0].read_text())
            self.assertIn('failed or refused' if simultaneous else 'original selectors restored', failure['selector_rollback'])
            self.assertEqual(len(failure['uncommitted_receipts']), position - 1 - int(simultaneous))
            self.assertEqual(len(failure['retirement_errors']), int(simultaneous))


if __name__ == '__main__':
    unittest.main()
