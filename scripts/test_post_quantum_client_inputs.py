"""Synthetic pinned evidence and fake executable bytes; never executes them."""
import json
from pathlib import Path
import tempfile
import unittest

from post_quantum_client.authority import Stop
from post_quantum_client.inputs import FixtureInputs, WIRE_CONTROLS
from post_quantum_client.process import digest


class InputsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        for name in ('source.rs', 'scripts/validate-post-quantum-fixture-wire.py',
                     'scripts/post_quantum_client/__init__.py', 'scripts/post_quantum_client/controller.py',
                     'scripts/post_quantum_client/observe-windows.ps1', 'scripts/post_quantum_client_wrapper.py',
                     'target/protocol.exe', 'target/software.exe'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'public synthetic input: ' + name.encode())
        self.directory = self.root / 'staged'
        self.directory.mkdir(mode=0o700)
        self.wire = {'result': 'pass', 'executable_sha256': digest(self.root / 'target/protocol.exe'),
                     'validator_sha256': digest(self.root / 'scripts/validate-post-quantum-fixture-wire.py'),
                     'checks': {name: {'result': 'pass'} for name in WIRE_CONTROLS}}
        self.report = {'result': 'pass', 'scope': 'software/build/framing readiness only; no root/key/lifecycle operations',
                       'steps': [{'exit_code': 0, 'expected_failure': False}, {'exit_code': 101, 'expected_failure': True}],
                       'source_sha256': {name: digest(self.root / name) for name in
                                         ('source.rs', 'scripts/validate-post-quantum-fixture-wire.py')},
                       'executables': {label: {'path': str(self.root / name), 'sha256': digest(self.root / name)}
                                       for label, name in [('protocol_fixture', 'target/protocol.exe'),
                                                           ('software_test', 'target/software.exe')]},
                       'wire_report': 'wire.json'}
        self.runtime = {str(path.relative_to(self.root)): digest(path)
                        for path in (self.root / 'scripts/post_quantum_client').iterdir()}
        entry = 'scripts/post_quantum_client_wrapper.py'
        self.runtime[entry] = digest(self.root / entry)
        self.save()

    def tearDown(self):
        self.temporary.cleanup()

    def save(self):
        (self.root / 'wire.json').write_text(json.dumps(self.wire))
        self.report['wire_sha256'] = digest(self.root / 'wire.json')
        (self.root / 'report.json').write_text(json.dumps(self.report))

    def load(self):
        return FixtureInputs.load(self.root, 'report.json', digest(self.root / 'report.json'))

    def test_stage_carries_source_report_wire_and_runtime_pins(self):
        inputs = self.load()
        pin = inputs.stage(self.directory, self.runtime)
        self.assertEqual(Path(pin.path).read_bytes(), (self.root / 'target/protocol.exe').read_bytes())
        self.assertEqual(Path(pin.path).stat().st_mode & 0o777, 0o500)
        self.assertIn(str(self.root / 'report.json'), pin.source_hashes)
        self.assertIn(str(self.root / 'wire.json'), pin.source_hashes)
        pin.verify()
        # Cargo can rebuild its original without replacing the private clone.
        (self.root / 'target/protocol.exe').write_bytes(b'new Cargo output')
        pin.verify()
        (self.root / 'source.rs').write_bytes(b'changed validated source')
        with self.assertRaises(Stop):
            pin.verify()

    def test_report_hash_is_explicit_and_cannot_be_inferred_from_current_bytes(self):
        with self.assertRaises(Stop):
            FixtureInputs.load(self.root, 'report.json', '0' * 64)

    def test_failed_build_status_and_inverted_expected_failure_are_rejected(self):
        for step in [{'exit_code': 1, 'expected_failure': False}, {'exit_code': 0, 'expected_failure': True},
                     {'exit_code': False, 'expected_failure': False}]:
            self.report['steps'] = [step]
            self.save()
            with self.assertRaises(Stop):
                self.load()

    def test_wire_report_must_match_executable_validator_and_all_fifteen_cases(self):
        original = dict(self.wire)
        for changes in [{'executable_sha256': '0' * 64}, {'validator_sha256': '0' * 64},
                        {'checks': {}}, {'result': 'fail'}]:
            self.wire = dict(original, **changes)
            self.save()
            with self.assertRaises(Stop):
                self.load()

    def test_missing_software_binary_and_changed_source_do_not_stage(self):
        (self.root / 'target/software.exe').write_bytes(b'changed software-test binary')
        with self.assertRaises(Stop):
            self.load()
        self.assertFalse((self.directory / 'client-fixture.exe').exists())

    def test_source_paths_reject_escape_absolute_and_noncanonical_components(self):
        for name in ['../outside', str(self.root / 'source.rs'), './source.rs', 'scripts//x']:
            self.report['source_sha256'] = {name: '0' * 64}
            self.save()
            with self.assertRaises(Stop):
                self.load()

    def test_runtime_snapshot_must_cover_every_existing_adapter_file(self):
        inputs = self.load()
        with self.assertRaises(Stop):
            inputs.stage(self.directory, {})
        self.assertFalse((self.directory / 'client-fixture.exe').exists())
        self.runtime['source.rs'] = '0' * 64
        with self.assertRaises(Stop):
            inputs.stage(self.directory, self.runtime)
        self.assertFalse((self.directory / 'client-fixture.exe').exists())

    def test_changed_report_or_wire_stops_before_copy(self):
        inputs = self.load()
        (self.root / 'wire.json').write_bytes(b'changed')
        with self.assertRaises(Stop):
            inputs.stage(self.directory, self.runtime)
        self.assertFalse((self.directory / 'client-fixture.exe').exists())

    def test_duplicate_report_field_is_rejected_even_with_matching_hash(self):
        path = self.root / 'report.json'
        path.write_text(path.read_text()[:-1] + ',"result":"pass"}')
        with self.assertRaises(Stop):
            self.load()


if __name__ == '__main__':
    unittest.main()
