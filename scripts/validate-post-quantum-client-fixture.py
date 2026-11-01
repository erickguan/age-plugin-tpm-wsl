#!/usr/bin/env python3
"""Build and check the native client fixture without creating a root or key."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SoftwareGate:
    def __init__(self):
        self.env = os.environ.copy()
        self.env.update(RUSTC_WRAPPER='', CARGO_TARGET_DIR=str(ROOT / 'target/pq-custody-software'))
        sources = [path for folder in ('src', 'helper/src', 'helper/examples', 'crates/post_quantum/src', 'crates/custody-fs/src', 'tests')
                   for path in (ROOT / folder).rglob('*.rs')]
        sources += [ROOT / name for name in ('Cargo.toml', 'Cargo.lock', 'helper/Cargo.toml',
                    'crates/post_quantum/Cargo.toml', 'crates/custody-fs/Cargo.toml',
                    'scripts/windows-linker.sh', 'scripts/validate-post-quantum-fixture-wire.py',
                    'notes/aws-lc-hybrid-evaluation/go-fixture.json')]
        sources.append(Path(__file__).resolve())
        self.report = {'result': 'incomplete', 'scope': 'software/build/framing readiness only; no root/key/lifecycle operations',
                       'source_sha256': {str(path.relative_to(ROOT)): digest(path) for path in sorted(sources)},
                       'steps': [], 'executables': {}}

    def run(self, command, label, *, must_fail=False):
        print(label, flush=True)
        result = subprocess.run(command, cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=900)
        passed = result.returncode != 0 if must_fail else result.returncode == 0
        self.report['steps'].append({'check': label, 'command': command, 'exit_code': result.returncode,
                                    'expected_failure': must_fail,
                                    'stdout_sha256': hashlib.sha256(result.stdout.encode()).hexdigest(),
                                    'stderr_sha256': hashlib.sha256(result.stderr.encode()).hexdigest(),
                                    'test_summaries': re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', result.stdout)})
        if not passed:
            # Compiler diagnostics contain source locations, never protocol output.
            print(result.stderr[-6000:], flush=True)
            raise RuntimeError(label + ' failed')
        return result

    def windows(self):
        tools = ROOT / 'target/windows-toolchain/usr/bin'
        linker = ROOT / 'scripts/windows-linker.sh'
        self.env.update(PATH=str(tools) + os.pathsep + self.env['PATH'],
                        CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=str(linker),
                        CC_x86_64_pc_windows_gnu=str(linker),
                        AR_x86_64_pc_windows_gnu=str(tools / 'x86_64-w64-mingw32-ar'))

    def executable(self, output, *, test):
        records = [json.loads(line) for line in output.splitlines()]
        paths = [Path(record['executable']) for record in records
                 if record.get('reason') == 'compiler-artifact' and record.get('executable')
                 and record.get('target', {}).get('name') == 'post_quantum_fixture'
                 and record.get('profile', {}).get('test') == test]
        if len(paths) != 1:
            raise RuntimeError('expected exactly one fixture executable')
        self.report['executables']['software_test' if test else 'protocol_fixture'] = {
            'path': str(paths[0]), 'sha256': digest(paths[0])}
        return paths[0]

    def verify_inputs(self):
        for name, expected in self.report['source_sha256'].items():
            if digest(ROOT / name) != expected:
                raise RuntimeError('source changed during gate: ' + name)
        for entry in self.report['executables'].values():
            if digest(Path(entry['path'])) != entry['sha256']:
                raise RuntimeError('executable changed during gate')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True, help='new report path; never replace earlier evidence')
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open('x') as reserved:
        reserved.write('{"result": "incomplete"}\n')
    gate = SoftwareGate()
    package = ['--locked', '--offline', '--package', 'age-tpm-wsl-helper']
    fixture = ['--features', 'client-validation', '--example', 'post_quantum_fixture']
    try:
        gate.run(['cargo', 'fmt', '--all', '--check'], 'formatting')
        refused = gate.run(['cargo', 'build', *package, '--example', 'post_quantum_fixture'],
                           'feature-off example refusal', must_fail=True)
        if 'requires' not in refused.stderr or 'client-validation' not in refused.stderr:
            raise RuntimeError('feature-off failure was not the expected Cargo feature guard')
        gate.run(['cargo', 'test', '--workspace', '--locked', '--offline'], 'Linux workspace regression tests')
        gate.run(['cargo', 'test', *package, *fixture], 'Linux fixture authority tests')
        gate.run(['cargo', 'clippy', *package, '--features', 'client-validation', '--all-targets', '--', '--deny', 'warnings'],
                 'Linux workspace/helper fixture Clippy')
        gate.windows()
        target = ['--target', 'x86_64-pc-windows-gnu']
        gate.run(['cargo', 'clippy', *package, '--features', 'client-validation', '--all-targets', *target, '--', '--deny', 'warnings'],
                 'Windows helper/fixture Clippy')
        tests = gate.run(['cargo', 'test', *package, *fixture, *target, '--no-run', '--message-format=json'],
                         'Windows software fixture build')
        test = gate.executable(tests.stdout, test=True)
        gate.run([str(test), '--test-threads=1'], 'Windows fixture software tests; live lifecycle ignored')
        built = gate.run(['cargo', 'build', *package, *fixture, *target, '--message-format=json'], 'Windows protocol fixture build')
        executable = gate.executable(built.stdout, test=False)
        wire_report = args.report.with_name(args.report.stem + '-wire.json')
        gate.run(['python3', 'scripts/validate-post-quantum-fixture-wire.py', '--executable', str(executable), '--report', str(wire_report)],
                 'Windows malformed framing controls only')
        wire = json.loads(wire_report.read_text())
        if wire['result'] != 'pass' or wire['executable_sha256'] != digest(executable):
            raise RuntimeError('wire evidence/executable mismatch')
        gate.report['wire_report'] = str(wire_report)
        gate.report['wire_sha256'] = digest(wire_report)
        gate.verify_inputs()
        gate.report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        gate.report['result'] = 'fail'
        gate.report['error'] = str(error)
        raise
    finally:
        args.report.write_text(json.dumps(gate.report, indent=2) + '\n')


if __name__ == '__main__':
    main()
