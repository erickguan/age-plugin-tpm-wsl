"""Finite positive plans and explicit client pipe caps; no native operation."""
import os
import sys
import unittest
from unittest.mock import patch

from post_quantum_client.authority import Stop
from post_quantum_client.cases import ClientCase, SIZES, minimal_cases, positive_cases
from post_quantum_client.process import BoundedProcess, MAX_CLIENT_OUTPUT, MAX_OUTPUT


class PositivePlanTests(unittest.TestCase):
    def test_finite_plan_has_all_boundaries_repeats_and_cross_client_directions(self):
        cases = positive_cases()
        self.assertEqual(len(cases), 28)
        self.assertEqual(sum(len(case.decryptors) for case in cases), 56)
        self.assertEqual({len(case.payload) for case in cases}, set(SIZES) | {32})
        self.assertEqual({case.label for case in cases if len(case.payload) == 32}, {'first', 'warm'})
        self.assertEqual({(case.encryptor, target) for case in cases for target in case.decryptors},
                         {('age', 'age'), ('age', 'rage'), ('rage', 'age'), ('rage', 'rage')})
        self.assertEqual(len(minimal_cases()), 1)
        self.assertEqual(len(minimal_cases()[0].payload), 32)
        self.assertNotIn('payload=', repr(cases[-1]))

    def test_invalid_or_mislabeled_cases_are_rejected(self):
        for arguments in [('bytes_4', b'wrong'), ('unknown', b''), ('first', b'', 'other'),
                          ('first', b'', 'age', ('age', 'age')), ('first', b'', 'age', ())]:
            with self.assertRaises(Stop):
                ClientCase(*arguments)

    def test_large_public_client_pipe_roundtrip_is_explicitly_bounded(self):
        payload = bytes(range(256)) * 16384
        command = [sys.executable, '-I', '-c', 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())']
        result = BoundedProcess()(command, payload, os.environ.copy(), 5, stdout_limit=MAX_CLIENT_OUTPUT)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(result.stdout), 4194304)
        self.assertTrue(result.stdout == payload)
        # The unchanged helper default still rejects the same oversized stream.
        with self.assertRaises(Stop):
            BoundedProcess()(command, payload, os.environ.copy(), 0.1)
        self.assertEqual(MAX_OUTPUT, 8205)

    def test_unbounded_or_invalid_pipe_limit_never_launches_a_process(self):
        for limit in (None, True, 0, 8204, MAX_CLIENT_OUTPUT + 1):
            with patch('post_quantum_client.process.subprocess.Popen') as launch:
                with self.assertRaises(Stop):
                    BoundedProcess()(['never-executed'], b'', {}, stdout_limit=limit)
                launch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
