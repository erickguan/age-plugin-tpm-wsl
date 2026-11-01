"""SDK source-publication regressions in disposable directories; no SDK execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('sdk_vendor', Path(__file__).with_name('vendor-age-sdk.py'))
VENDOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VENDOR)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class PublicationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.project = Path(directory.name)
        self.vendor = self.project / 'vendor'
        self.vendor.mkdir()
        self.provenance = self.vendor / 'age-sdk-provenance.json'
        self.baseline = self.project / 'root-before.lock'
        self.baseline.write_bytes(b'baseline evidence')
        self.unrelated = self.vendor / 'unrelated.txt'
        self.unrelated.write_bytes(b'operator changes')
        self.temporary = self.vendor / '.staging-fixture'
        self.temporary.mkdir()
        for name, version in VENDOR.VERSIONS.items():
            source = self.temporary / (name + '-' + version)
            source.mkdir()
            (source / 'fixture.rs').write_text(name)
        for attribute, value in [('PROJECT', self.project), ('PROVENANCE', self.provenance)]:
            change = patch.object(VENDOR, attribute, value)
            change.start()
            self.addCleanup(change.stop)

    def assert_rolled_back(self):
        for name in VENDOR.VERSIONS:
            self.assertFalse((self.vendor / name).exists())
        self.assertFalse(self.provenance.exists())
        self.assertEqual(self.baseline.read_bytes(), b'baseline evidence')
        self.assertEqual(self.unrelated.read_bytes(), b'operator changes')

    def test_second_package_move_failure_removes_only_new_destinations(self):
        real_replace = VENDOR.os.replace
        def fail_second(source, destination):
            if Path(destination).name == 'age-plugin':
                raise OSError('injected move failure')
            return real_replace(source, destination)
        with patch.object(VENDOR.os, 'replace', side_effect=fail_second):
            with self.assertRaises(OSError):
                VENDOR.publish_sources(self.temporary, {'fixture': True})
        self.assert_rolled_back()

    def test_provenance_move_failure_rolls_back_packages_and_reservation(self):
        real_replace = VENDOR.os.replace
        def fail_receipt(source, destination):
            if Path(destination) == self.provenance:
                raise OSError('injected provenance move failure')
            return real_replace(source, destination)
        with patch.object(VENDOR.os, 'replace', side_effect=fail_receipt):
            with self.assertRaises(OSError):
                VENDOR.publish_sources(self.temporary, {'fixture': True})
        self.assert_rolled_back()

    def test_final_verification_failure_rolls_back_all_new_publications(self):
        with patch.object(VENDOR, 'verify_sources', side_effect=RuntimeError('injected verification failure')):
            with self.assertRaises(RuntimeError):
                VENDOR.publish_sources(self.temporary, {'fixture': True})
        self.assert_rolled_back()

    def test_existing_later_destination_is_never_removed(self):
        existing = self.vendor / 'age-plugin'
        existing.mkdir()
        (existing / 'operator.txt').write_text('preserve me')
        with self.assertRaises(FileExistsError):
            VENDOR.publish_sources(self.temporary, {'fixture': True})
        self.assertFalse((self.vendor / 'age-core').exists())
        self.assertEqual((existing / 'operator.txt').read_text(), 'preserve me')
        self.assertFalse(self.provenance.exists())
        self.assertEqual(self.baseline.read_bytes(), b'baseline evidence')

    def test_existing_provenance_is_never_replaced(self):
        self.provenance.write_text('operator receipt')
        with self.assertRaises(FileExistsError):
            VENDOR.publish_sources(self.temporary, {'fixture': True})
        for name in VENDOR.VERSIONS:
            self.assertFalse((self.vendor / name).exists())
        self.assertEqual(self.provenance.read_text(), 'operator receipt')

    def test_success_publishes_both_packages_and_complete_receipt(self):
        record = {'fixture': True}
        def verify():
            for name in VENDOR.VERSIONS:
                self.assertEqual((self.vendor / name / 'fixture.rs').read_text(), name)
            self.assertEqual(json.loads(self.provenance.read_text()), record)
            return record
        with patch.object(VENDOR, 'verify_sources', side_effect=verify):
            self.assertEqual(VENDOR.publish_sources(self.temporary, record), record)
        self.assertEqual(self.baseline.read_bytes(), b'baseline evidence')
        self.assertEqual(self.unrelated.read_bytes(), b'operator changes')

    def test_baseline_evidence_is_exclusive_and_preserved(self):
        VENDOR.preserve_baseline(self.baseline, b'baseline evidence')
        with self.assertRaises(RuntimeError):
            VENDOR.preserve_baseline(self.baseline, b'different')
        self.assertEqual(self.baseline.read_bytes(), b'baseline evidence')
        new = self.project / 'new-before.lock'
        VENDOR.preserve_baseline(new, b'new complete evidence')
        self.assertEqual(new.read_bytes(), b'new complete evidence')
        self.assertFalse(list(self.project.glob('.sdk-baseline-*')))

    def test_check_rejects_modified_patch_artifacts(self):
        report_path = self.project / 'validation.json'
        packages, patches = {}, {}
        for name, version in VENDOR.VERSIONS.items():
            source = self.vendor / name
            source.mkdir()
            (source / 'fixture.rs').write_text(name)
            packages[name] = {'version': version, 'final_sha256': {'fixture.rs': sha(name.encode())}}
            artifact = self.project / (name + '-memory.patch')
            artifact.write_text(name + ' patch fixture')
            patches[artifact.name] = VENDOR.digest(artifact)
        report = {'result': 'pass', 'patch_sha256': patches, 'staged_provenance': {'packages': packages},
                  'source_sha256': {'Cargo.lock': VENDOR.digest(self.baseline)}}
        report_path.write_text(json.dumps(report))
        record = {'schema': 1, 'validation_report': 'validation.json', 'validation_report_sha256': VENDOR.digest(report_path),
                  'packages': packages, 'patch_sha256': patches, 'root_before_adoption_lock': self.baseline.name,
                  'root_before_adoption_lock_sha256': VENDOR.digest(self.baseline)}
        self.provenance.write_text(json.dumps(record))
        self.assertEqual(VENDOR.verify_sources(), record)
        (self.project / 'age-core-memory.patch').write_text('stale or edited patch')
        with self.assertRaisesRegex(RuntimeError, 'accepted SDK patch changed'):
            VENDOR.verify_sources()


if __name__ == '__main__':
    unittest.main()
