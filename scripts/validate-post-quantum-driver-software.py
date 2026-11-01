#!/usr/bin/env python3
"""Produce source-bound driver readiness using fake native state and offline clients."""
import argparse
import ast
import json
import os
from pathlib import Path
import shutil
import sys
import unittest

from post_quantum_client.cases import positive_cases
from post_quantum_client.fnox import fnox_cases
from post_quantum_client.inputs import FixtureInputs
from post_quantum_client.process import BoundedProcess, digest
from post_quantum_client.runtime import RuntimeInputs
from post_quantum_client.refusal_cases import LOCAL_REFUSALS, REFUSAL_PLAN, Refusal

ROOT = Path(__file__).resolve().parents[1]
OFFLINE_REPORT = 'notes/post-quantum-client-driver-primitives-offline-final.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path, help='fresh output within this repository')
    arguments = parser.parse_args()
    path = arguments.report.resolve()
    if not path.is_relative_to(ROOT):
        parser.error('report must be within the repository')
    with path.open('x') as stream:
        stream.write('{"result":"incomplete","role":"native-driver-readiness"}\n')
        stream.flush()
        os.fsync(stream.fileno())
    try:
        fixture = FixtureInputs.approved(ROOT)
        files = set(Path(name) for name in fixture.sources)
        files |= set((ROOT / 'scripts/post_quantum_client').glob('*.py'))
        files |= set((ROOT / 'scripts').glob('test_post_quantum_client_*.py'))
        files |= {ROOT / name for name in ('scripts/post_quantum_client/observe-windows.ps1',
                  'scripts/post_quantum_client_wrapper.py', 'scripts/validate-post-quantum-clients-native.py',
                  'scripts/validate-post-quantum-offline-clients.py', OFFLINE_REPORT)}
        files |= {Path(__file__).resolve(), fixture.report.path, fixture.wire.path}
        for source in files:
            if source.suffix == '.py':
                ast.parse(source.read_text(), filename=str(source))
        before = {str(source.relative_to(ROOT)): digest(source) for source in sorted(files)}
        binaries = {name: {'path': str(binary), 'sha256': digest(binary)} for name, binary in
                    [('python', Path(sys.executable).resolve()),
                     ('plugin', ROOT / 'target/debug/age-plugin-tpm-wsl'),
                     ('age', Path(shutil.which('age')).resolve()),
                     ('rage', Path(shutil.which('rage')).resolve()),
                     ('fnox', Path(shutil.which('fnox')).resolve()),
                     ('age_keygen', Path(shutil.which('age-keygen')).resolve())]}
        version = BoundedProcess()([binaries['fnox']['path'], '--version'], b'', os.environ.copy(), 10)
        fnox_version = version.stdout.decode('utf-8').strip()
        if version.exit_code != 0 or not fnox_version.startswith('fnox ') or len(fnox_version) > 100:
            raise RuntimeError('fnox version probe failed')
        keygen = BoundedProcess()([binaries['age_keygen']['path'], '--version'], b'', os.environ.copy(), 10)
        keygen_version = keygen.stdout.decode('utf-8').strip()
        if keygen.exit_code != 0 or not 1 <= len(keygen_version) <= 100:
            raise RuntimeError('key generator version probe failed')
        offline = json.loads((ROOT / OFFLINE_REPORT).read_text())
        if (offline['result'] != 'pass' or offline['plugin_sha256'] != binaries['plugin']['sha256']
                or offline['clients']['age']['executable_sha256'] != binaries['age']['sha256']
                or offline['clients']['rage']['executable_sha256'] != binaries['rage']['sha256']
                or offline['source_sha256'] != before['scripts/validate-post-quantum-offline-clients.py']
                or offline['reference_encoder_sha256'] != before['scripts/post_quantum_client/references.py']):
            raise RuntimeError('offline evidence inputs changed; rerun that gate explicitly')
        suite = unittest.defaultTestLoader.discover(str(ROOT / 'scripts'), pattern='test_post_quantum_client_*.py')
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        if not result.wasSuccessful():
            raise RuntimeError('driver software tests failed')
        fixture.verify()
        if before != {str(source.relative_to(ROOT)): digest(source) for source in sorted(files)}:
            raise RuntimeError('source changed during validation')
        for item in binaries.values():
            if digest(Path(item['path'])) != item['sha256']:
                raise RuntimeError('executable changed during validation')
        report = {'result': 'pass', 'role': 'native-driver-readiness', 'linux_tests': result.testsRun,
                  'source_sha256': before, 'binaries': binaries, 'python_version': sys.version.split()[0],
                  'fixture_report_sha256': fixture.report.sha256, 'fixture_sources_verified': len(fixture.sources),
                  'offline_report': OFFLINE_REPORT, 'offline_report_sha256': digest(ROOT / OFFLINE_REPORT),
                  'prior_offline_checks': 12,
                  'positive_encryption_cases': len(positive_cases()),
                  'positive_native_decryptions': sum(len(case.decryptors) for case in positive_cases()),
                  'fnox_version': fnox_version, 'age_keygen_version': keygen_version,
                  'fnox_encryption_cases': len(fnox_cases()),
                  'fnox_native_decryptions': sum(len(case.decryptors) for case in fnox_cases()),
                  'fnox_daemon_encryption_cases': 1, 'fnox_daemon_native_decryptions': 2,
                  'fnox_daemon_cache_hits': 1, 'fnox_daemon_logical_reads': 3,
                  'fnox_daemon_cache_states': [0, 1, 1, 1],
                  'component_positive_reads': 2, 'component_rejections': 6,
                  'recovery_native_reads': 3, 'recovery_software_reads': 1,
                  'refusal_positive_reads': sum(case is Refusal.CONTROL for case, _ in REFUSAL_PLAN),
                  'refusal_local_rejections': sum(case in LOCAL_REFUSALS for case, _ in REFUSAL_PLAN),
                  'refusal_payload_rejections': sum(case is Refusal.PAYLOAD_AUTH for case, _ in REFUSAL_PLAN),
                  'refusal_native_unwrap_successes': sum(case not in LOCAL_REFUSALS for case, _ in REFUSAL_PLAN),
                  'scope': 'Driver software only: fake native positive/component/recovery/refusal matrices, local IPC, actual isolated client refusals and software payload checks, staged age/rage encryption, real software PQ OR recovery and isolated fnox direct/cache plus owned-daemon lifecycle workflow (native reads and daemon-profile cache metadata mocked; separate plain-data owner tests use actual cache transitions)',
                  'limits': ['No actual Windows observer, TPM key/root, Windows private operation or native campaign ran',
                             'Native execution still requires independent review and explicit approved report digest',
                             'No actual TPM-shared OR acceptance, durable off-machine provisioning, restart/wrong-machine/deployment or process-attestation claim']}
        path.write_text(json.dumps(report, indent=2) + '\n')
        # Exercise the consumer schema too; this is software validation, not
        # independent approval of the digest for a native execution.
        RuntimeInputs.load(ROOT, str(path.relative_to(ROOT)), digest(path)).verify()
        print(str(result.testsRun) + ' local tests passed; source/runtime/fixture pins verified. No native operation ran.')
        return 0
    except BaseException:
        path.write_text('{"result":"fail","role":"native-driver-readiness","category":"software-validation"}\n')
        print('Driver software gate failed; inspect test output.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
