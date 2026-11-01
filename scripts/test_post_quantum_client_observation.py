"""Observer adapter tests use fake process results only; no Windows query runs."""
import json
from pathlib import Path
import tempfile
import unittest

from post_quantum_client.authority import Namespace, PREFIX, Stop
from post_quantum_client.observation import POWERSHELL, WSLPATH, WindowsObserver
from post_quantum_client.process import ProcessResult, digest

SCRIPT = Path(__file__).parent / 'post_quantum_client/observe-windows.ps1'


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.script = Path(self.temporary.name) / 'observe-windows.ps1'
        self.script.write_bytes(SCRIPT.read_bytes())
        self.namespace = Namespace(PREFIX + '0' * 32)
        self.value = {'namespace': self.namespace.directory, 'name': self.namespace.key_name,
                      'sid': 'S-1-5-21-1001', 'root_absent': True, 'key_absent': True}
        self.calls = []
        self.path_result = ProcessResult(0, b'\\\\wsl.localhost\\Test\\observe-windows.ps1\n')
        self.output = None

    def tearDown(self):
        self.temporary.cleanup()

    def run_process(self, command, payload, environment, seconds):
        self.calls.append(command)
        self.assertEqual(payload, b'')
        self.assertEqual(seconds, 10)
        if command[0] == WSLPATH:
            return self.path_result
        self.assertEqual(command[0], POWERSHELL)
        return self.output or ProcessResult(0, json.dumps(self.value).encode())

    def observer(self):
        return WindowsObserver(self.script, digest(self.script), {}, self.run_process)

    def test_construction_converts_path_without_launching_windows_probe(self):
        observer = self.observer()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0], WSLPATH)
        self.assertEqual(observer.windows_script, r'\\wsl.localhost\Test\observe-windows.ps1')

    def test_valid_bound_observation_becomes_typed_public_data(self):
        observation = self.observer()(self.namespace)
        self.assertEqual(observation.sid, self.value['sid'])
        self.assertTrue(observation.root_absent and observation.key_absent)
        self.assertIn('-NonInteractive', self.calls[-1])
        self.assertIn('-NoProfile', self.calls[-1])
        self.assertEqual(self.calls[-1][-2:], ['-Namespace', self.namespace.directory])

    def test_presence_is_reported_without_being_confused_with_query_failure(self):
        self.value.update(root_absent=False, key_absent=False)
        observation = self.observer()(self.namespace)
        self.assertFalse(observation.root_absent or observation.key_absent)

    def test_wrong_source_stops_before_even_path_conversion(self):
        with self.assertRaises(Stop):
            WindowsObserver(self.script, '0' * 64, {}, self.run_process)
        self.assertEqual(self.calls, [])

    def test_changed_probe_stops_before_windows_invocation(self):
        observer = self.observer()
        self.script.write_text('unreviewed source')
        with self.assertRaises(Stop):
            observer(self.namespace)
        self.assertEqual(len(self.calls), 1)

    def test_conversion_rejects_failure_partial_multiple_relative_and_nul_paths(self):
        for result in [ProcessResult(1, b''), ProcessResult(False, b'C:\\a\n'),
                       ProcessResult(0, b'C:\\a'), ProcessResult(0, b'C:\\a\nC:\\b\n'),
                       ProcessResult(0, b'relative\n'), ProcessResult(0, b'C:\\a\0b\n'),
                       ProcessResult(0, b'\xff\n')]:
            with self.subTest(result=result):
                self.path_result = result
                with self.assertRaises(Stop):
                    self.observer()

    def test_process_error_and_transport_failure_never_establish_absence(self):
        observer = self.observer()
        self.output = ProcessResult(1, json.dumps(self.value).encode())
        with self.assertRaises(Stop):
            observer(self.namespace)
        self.output = ProcessResult(False, json.dumps(self.value).encode())
        with self.assertRaises(Stop):
            observer(self.namespace)
        def timeout(*_):
            raise Stop('test deadline exceeded')
        observer.run = timeout
        with self.assertRaises(Stop):
            observer(self.namespace)

    def test_namespace_name_schema_and_boolean_binding_are_strict(self):
        observer = self.observer()
        original = dict(self.value)
        for changes in [{'namespace': PREFIX + '1' * 32}, {'name': 'unrelated-key'},
                        {'root_absent': 1}, {'key_absent': None}, {'sid': 'untrusted'},
                        {'extra': True}]:
            with self.subTest(changes=changes):
                self.value = dict(original, **changes)
                with self.assertRaises(Stop):
                    observer(self.namespace)
        self.value = {key: value for key, value in original.items() if key != 'sid'}
        with self.assertRaises(Stop):
            observer(self.namespace)

    def test_duplicate_truncated_trailing_non_object_and_non_json_outputs_rejected(self):
        observer = self.observer()
        duplicate = json.dumps(self.value)[:-1] + ',"key_absent":true}'
        for data in [duplicate.encode(), b'{', b'[]', b'null', b'ATW1',
                     json.dumps(self.value).encode() + b'garbage']:
            with self.subTest(data=data):
                self.output = ProcessResult(0, data)
                with self.assertRaises(Stop):
                    observer(self.namespace)

    def test_software_command_is_explicit_and_unvalidated_namespace_never_runs(self):
        observer = self.observer()
        self.assertEqual(observer.command(self.namespace, software_only=True)[-1], '-SoftwareOnly')
        self.assertNotIn('-SoftwareOnly', observer.command(self.namespace))
        with self.assertRaises(Stop):
            observer.command(self.namespace.directory)
        self.assertEqual(len(self.calls), 1)


if __name__ == '__main__':
    unittest.main()
