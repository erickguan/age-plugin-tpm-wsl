"""Client assertions must remain active before any matrix import or activity."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = r'''
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch
root, name = Path(sys.argv[1]), sys.argv[2]
source = root / 'scripts/run-memory-crypto-client.py'
spec = importlib.util.spec_from_file_location('client_wrapper', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
events = []
loader = SimpleNamespace(exec_module=lambda ignored: events.append('import'))
client = SimpleNamespace(main=lambda: events.append('client'))
sys.argv = [str(source), '--workspace', str(root / 'target/optimization-probe'),
            '--client', name, '--algorithm', 'p256-hpke', '--output', str(root / 'target/unused-probe.json')]
with patch('importlib.util.spec_from_file_location', return_value=SimpleNamespace(loader=loader)), \
     patch('importlib.util.module_from_spec', return_value=client):
    try:
        module.main()
    except RuntimeError as error:
        outcome = str(error)
    else:
        outcome = 'ran'
print(json.dumps({'debug': __debug__, 'events': events, 'outcome': outcome}))
'''


class ClientOptimizationTests(unittest.TestCase):
    def probe(self, client, optimized=False, environment=False):
        env = os.environ.copy()
        env.pop('PYTHONOPTIMIZE', None)
        if environment:
            env['PYTHONOPTIMIZE'] = '1'
        command = [sys.executable] + (['-O'] if optimized else []) + ['-c', PROBE, str(ROOT), client]
        process = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(process.returncode, 0, process.stderr)
        return json.loads(process.stdout)

    def test_normal_clients_reach_the_matrix(self):
        for client in ['age', 'rage', 'fnox']:
            with self.subTest(client=client):
                result = self.probe(client)
                self.assertTrue(result['debug'])
                self.assertEqual(result['events'], ['import', 'client'])
                self.assertEqual(result['outcome'], 'ran')

    def test_optimized_flag_refuses_before_matrix_import(self):
        for client in ['age', 'rage', 'fnox']:
            with self.subTest(client=client):
                result = self.probe(client, optimized=True)
                self.assertFalse(result['debug'])
                self.assertEqual(result['events'], [])
                self.assertEqual(result['outcome'], 'software client validation requires active Python assertions')

    def test_optimized_environment_refuses_before_matrix_import(self):
        for client in ['age', 'rage', 'fnox']:
            with self.subTest(client=client):
                result = self.probe(client, environment=True)
                self.assertFalse(result['debug'])
                self.assertEqual(result['events'], [])
                self.assertEqual(result['outcome'], 'software client validation requires active Python assertions')


if __name__ == '__main__':
    unittest.main()
