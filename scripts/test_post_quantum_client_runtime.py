"""Synthetic approval records; CLI preflight must never create/probe native state."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from post_quantum_client.authority import Stop
from post_quantum_client.inputs import APPROVED_SHA256
from post_quantum_client.native_cli import main
from post_quantum_client.process import digest
from post_quantum_client.runtime import ENTRY, OFFLINE, OFFLINE_CHECKS, RuntimeInputs

ROOT = Path(__file__).resolve().parents[1]


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        names = [str(path.relative_to(ROOT)) for path in (ROOT / 'scripts/post_quantum_client').glob('*.py')]
        names += ['scripts/post_quantum_client/observe-windows.ps1',
                  'scripts/post_quantum_client_wrapper.py', ENTRY, OFFLINE, 'target/plugin', 'target/age', 'target/rage']
        for name in names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'synthetic nonexecuted input: ' + name.encode())
        sources = {name: digest(self.root / name) for name in names if not name.startswith('target/')}
        self.offline = {'result': 'pass', 'plugin_sha256': digest(self.root / 'target/plugin'),
                        'source_sha256': sources[OFFLINE],
                        'reference_encoder_sha256': sources['scripts/post_quantum_client/references.py'],
                        'clients': {name: {'version': 'vTEST', 'executable_sha256': digest(self.root / ('target/' + name)),
                                           'checks': {name: {'result': 'pass'} for name in OFFLINE_CHECKS}}
                                    for name in ('age', 'rage')}}
        self.data = {'result': 'pass', 'role': 'native-driver-readiness', 'fixture_report_sha256': APPROVED_SHA256,
                     'source_sha256': sources, 'offline_report': 'offline.json',
                     'binaries': {label: {'path': str(path), 'sha256': digest(path)} for label, path in
                                  [('python', Path(sys.executable).resolve()), ('plugin', self.root / 'target/plugin'),
                                   ('age', self.root / 'target/age'), ('rage', self.root / 'target/rage')]}}
        self.save()

    def tearDown(self):
        self.temporary.cleanup()

    def save(self):
        (self.root / 'offline.json').write_text(json.dumps(self.offline))
        self.data['offline_report_sha256'] = digest(self.root / 'offline.json')
        (self.root / 'runtime.json').write_text(json.dumps(self.data))

    def load(self):
        return RuntimeInputs.load(self.root, 'runtime.json', digest(self.root / 'runtime.json'))

    def test_explicit_complete_approval_binds_runtime_and_current_interpreter(self):
        runtime = self.load()
        runtime.verify()
        self.assertEqual(runtime.python.path, Path(sys.executable).resolve())
        self.assertEqual(runtime.age_version, 'vTEST')
        self.assertIn('runtime.json', runtime.sources)
        self.assertIn('offline.json', runtime.sources)

    def test_support_report_role_or_omitted_entry_is_not_native_readiness(self):
        self.data['role'] = 'retirement-support-only'
        self.save()
        with self.assertRaises(Stop):
            self.load()
        self.data['role'] = 'native-driver-readiness'
        del self.data['source_sha256'][ENTRY]
        self.save()
        with self.assertRaises(Stop):
            self.load()

    def test_approval_hash_is_required_and_changed_source_invalidates_runtime(self):
        with self.assertRaises(Stop):
            RuntimeInputs.load(self.root, 'runtime.json', '0' * 64)
        runtime = self.load()
        (self.root / ENTRY).write_bytes(b'changed after approval')
        with self.assertRaises(Stop):
            runtime.verify()

    def test_offline_proof_must_bind_encoder_client_plugin_and_full_checks(self):
        for field in ('reference_encoder_sha256', 'plugin_sha256', 'source_sha256'):
            original = self.offline[field]
            self.offline[field] = '0' * 64
            self.save()
            with self.assertRaises(Stop):
                self.load()
            self.offline[field] = original
        self.offline['clients']['age']['checks'] = {}
        self.save()
        with self.assertRaises(Stop):
            self.load()

    def test_rage_binary_must_match_the_reviewed_offline_client_proof(self):
        self.offline['clients']['rage']['executable_sha256'] = '0' * 64
        self.save()
        with self.assertRaises(Stop):
            self.load()

    def test_six_passing_unrelated_labels_cannot_replace_the_required_offline_scenarios(self):
        checks = self.offline['clients']['age']['checks']
        checks['unrelated-passing-scenario'] = checks.pop('mixed_plugin_groups')
        self.save()
        with self.assertRaises(Stop):
            self.load()

    def test_default_cli_preflight_never_stages_creates_or_observes(self):
        runtime = Mock()
        fixture = Mock()
        with patch('post_quantum_client.native_cli.RuntimeInputs.load', return_value=runtime), \
             patch('post_quantum_client.native_cli.FixtureInputs.approved', return_value=fixture), \
             patch('post_quantum_client.native_cli.RunDirectory.create', side_effect=AssertionError('unexpected creation')), \
             patch('post_quantum_client.native_cli.WindowsObserver', side_effect=AssertionError('unexpected probe')), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(['--runtime-report', 'approved.json', '--runtime-sha256', '1' * 64, '--positive-matrix']), 0)
        runtime.stage.assert_not_called()
        fixture.verify.assert_called_once()

    def test_optional_fnox_pin_requires_its_hash_and_bounded_version(self):
        path = self.root / 'target/fnox'
        path.write_bytes(b'never executed fnox')
        self.data['binaries']['fnox'] = {'path': str(path), 'sha256': digest(path)}
        self.save()
        with self.assertRaises(Stop): self.load()
        self.data['fnox_version'] = 'fnox 1.42.1'; self.save()
        runtime = self.load()
        self.assertEqual(runtime.fnox.path, path)
        self.assertEqual(runtime.fnox_version, 'fnox 1.42.1')
        path.write_bytes(b'changed fnox')
        with self.assertRaises(Stop): runtime.verify()

    def test_fnox_mode_without_its_pin_stops_before_run_or_observer(self):
        with patch('post_quantum_client.native_cli.RuntimeInputs.load', return_value=Mock(fnox=None)), \
             patch('post_quantum_client.native_cli.RunDirectory.create') as create, \
             patch('post_quantum_client.native_cli.WindowsObserver') as observe, \
             redirect_stderr(io.StringIO()):
            self.assertEqual(main(['--runtime-report', 'approved.json', '--runtime-sha256', '1' * 64,
                                   '--fnox-positive', '--native', '--acknowledge', 'isolated-disposable-only']), 1)
        create.assert_not_called(); observe.assert_not_called()

    def test_fnox_default_preflight_never_constructs_an_adapter_or_native_probe(self):
        with patch('post_quantum_client.native_cli.RuntimeInputs.load', return_value=Mock()), \
             patch('post_quantum_client.native_cli.FixtureInputs.approved'), \
             patch('post_quantum_client.native_cli.FnoxEnvironment') as adapter, \
             patch('post_quantum_client.native_cli.RunDirectory.create') as create, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--runtime-report', 'approved.json', '--runtime-sha256', '1' * 64,
                                   '--fnox-positive']), 0)
        create.assert_not_called(); adapter.assert_not_called()

    def test_sixth_key_generator_pin_requires_its_own_version_and_hash(self):
        for name in ('fnox', 'age_keygen'):
            path = self.root / ('target/' + name)
            path.write_bytes(b'never executed optional tool')
            self.data['binaries'][name] = {'path': str(path), 'sha256': digest(path)}
        self.data['fnox_version'] = 'fnox vTEST'; self.save()
        with self.assertRaises(Stop): self.load()
        self.data['age_keygen_version'] = 'vTEST'; self.save()
        runtime = self.load()
        self.assertEqual(runtime.keygen_version, 'vTEST')
        (self.root / 'target/age_keygen').write_bytes(b'changed optional tool')
        with self.assertRaises(Stop): runtime.verify()

    def test_component_default_preflight_does_not_construct_a_native_campaign(self):
        with patch('post_quantum_client.native_cli.RuntimeInputs.load', return_value=Mock()), \
             patch('post_quantum_client.native_cli.FixtureInputs.approved'), \
             patch('post_quantum_client.native_cli.RunDirectory.create') as create, \
             patch('post_quantum_client.native_cli.ComponentCampaign') as campaign, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--runtime-report', 'approved.json', '--runtime-sha256', '1' * 64,
                                   '--component-matrix']), 0)
        create.assert_not_called(); campaign.assert_not_called()

    def test_recovery_default_preflight_never_constructs_adapter_key_or_native_probe(self):
        with patch('post_quantum_client.native_cli.RuntimeInputs.load', return_value=Mock()), \
             patch('post_quantum_client.native_cli.FixtureInputs.approved'), \
             patch('post_quantum_client.native_cli.RunDirectory.create') as create, \
             patch('post_quantum_client.native_cli.WindowsObserver') as observe, \
             patch('post_quantum_client.native_cli.RecoveryEnvironment') as adapter, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--runtime-report', 'approved.json', '--runtime-sha256', '1' * 64,
                                   '--recovery-matrix']), 0)
        create.assert_not_called(); observe.assert_not_called(); adapter.assert_not_called()

    def test_recovery_requires_its_generator_pin_even_before_default_preflight(self):
        with patch('post_quantum_client.native_cli.RuntimeInputs.load', return_value=Mock(keygen=None)), \
             patch('post_quantum_client.native_cli.RunDirectory.create') as create, \
             patch('post_quantum_client.native_cli.WindowsObserver') as observe, \
             patch('post_quantum_client.native_cli.RecoveryEnvironment') as adapter, \
             redirect_stderr(io.StringIO()):
            self.assertEqual(main(['--runtime-report', 'approved.json', '--runtime-sha256', '1' * 64,
                                   '--recovery-matrix']), 1)
        create.assert_not_called(); observe.assert_not_called(); adapter.assert_not_called()

    def test_refusal_default_preflight_never_constructs_an_adapter_or_native_probe(self):
        with patch('post_quantum_client.native_cli.RuntimeInputs.load', return_value=Mock()), \
             patch('post_quantum_client.native_cli.FixtureInputs.approved'), \
             patch('post_quantum_client.native_cli.RunDirectory.create') as create, \
             patch('post_quantum_client.native_cli.WindowsObserver') as observe, \
             patch('post_quantum_client.native_cli.RefusalEnvironment') as adapter, \
             patch('post_quantum_client.native_cli.RefusalCampaign') as campaign, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--runtime-report', 'approved.json', '--runtime-sha256', '1' * 64,
                                   '--refusal-matrix']), 0)
        create.assert_not_called(); observe.assert_not_called(); adapter.assert_not_called(); campaign.assert_not_called()

    def test_daemon_default_preflight_never_constructs_an_owner_or_native_probe(self):
        with patch('post_quantum_client.native_cli.RuntimeInputs.load', return_value=Mock()), \
             patch('post_quantum_client.native_cli.FixtureInputs.approved'), \
             patch('post_quantum_client.native_cli.RunDirectory.create') as create, \
             patch('post_quantum_client.native_cli.WindowsObserver') as observe, \
             patch('post_quantum_client.native_cli.FnoxDaemonEnvironment') as adapter, \
             patch('post_quantum_client.native_cli.FnoxDaemonCampaign') as campaign, \
             patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(main(['--runtime-report', 'approved.json', '--runtime-sha256', '1' * 64,
                                   '--fnox-daemon']), 0)
        create.assert_not_called(); observe.assert_not_called()
        adapter.assert_not_called(); campaign.assert_not_called()

    def test_daemon_requires_its_fnox_pin_before_any_run_or_owner(self):
        with patch('post_quantum_client.native_cli.RuntimeInputs.load', return_value=Mock(fnox=None)), \
             patch('post_quantum_client.native_cli.RunDirectory.create') as create, \
             patch('post_quantum_client.native_cli.FnoxDaemonEnvironment') as adapter, \
             patch('sys.stderr', new_callable=io.StringIO):
            self.assertEqual(main(['--runtime-report', 'approved.json', '--runtime-sha256', '1' * 64,
                                   '--fnox-daemon', '--native', '--acknowledge', 'isolated-disposable-only']), 1)
        create.assert_not_called(); adapter.assert_not_called()

    def test_native_acknowledgment_is_required_before_loading_any_inputs(self):
        with patch('post_quantum_client.native_cli.RuntimeInputs.load') as loader, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(['--runtime-report', 'approved.json', '--runtime-sha256', '1' * 64, '--native']), 1)
        loader.assert_not_called()


if __name__ == '__main__':
    unittest.main()
