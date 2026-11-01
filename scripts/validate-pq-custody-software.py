#!/usr/bin/env python3
"""Check the private custody adapter without enrollment or live TPM operations."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    inputs = [p for folder in ['src', 'helper/src', 'crates/post_quantum/src', 'crates/custody-fs/src', 'tests'] for p in (ROOT / folder).rglob('*.rs')]
    inputs += [ROOT / name for name in ['Cargo.toml', 'Cargo.lock', 'helper/Cargo.toml', 'crates/post_quantum/Cargo.toml', 'crates/custody-fs/Cargo.toml', 'scripts/windows-linker.sh', 'scripts/validate-helper-wire.py', 'scripts/validate-pq-wire.py', 'scripts/validate-pq-custody-native.py', 'scripts/test_validate_pq_custody_native.py', 'notes/aws-lc-hybrid-evaluation/go-fixture.json', 'vendor/aws-lc-rs-provenance.json']]
    inputs.append(Path(__file__).resolve())
    sdk_provenance = json.loads((ROOT / 'vendor/age-sdk-provenance.json').read_text())
    inputs += [ROOT / 'vendor/age-sdk-provenance.json', ROOT / 'scripts/vendor-age-sdk.py',
               ROOT / sdk_provenance['validation_report'], ROOT / sdk_provenance['root_before_adoption_lock']]
    for name, package in sdk_provenance['packages'].items():
        inputs += [ROOT / 'vendor' / name / path for path in package['final_sha256']]
        inputs.append((ROOT / sdk_provenance['validation_report']).parent / (name + '-memory.patch'))
    report = {'result': 'fail', 'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_sha256': {str(p.relative_to(ROOT)): digest(p) for p in sorted(inputs)}, 'steps': [],
              'limits': ['Software tests and Windows compilation/execution of scripted transport fixtures only; no real TPM contexts, PCP keys or storage enrollments',
                         'Full private lifecycle source review and disposable isolated native store validation remain required',
                         'Root backend identities and feature unification must be independently compared and scanned before acceptance']}
    env = os.environ.copy()
    env.update(RUSTC_WRAPPER='', CARGO_TARGET_DIR=str(ROOT / 'target/pq-custody-software'))

    def run(command, label):
        print('Running ' + label, flush=True)
        p = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=1200)
        report['steps'].append({'check': label, 'command': command, 'exit_code': p.returncode,
                                'stdout_sha256': hashlib.sha256(p.stdout.encode()).hexdigest(),
                                'stderr_sha256': hashlib.sha256(p.stderr.encode()).hexdigest(),
                                'test_summaries': re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', p.stdout)})
        if p.stderr:
            print(p.stderr, end='', flush=True)
        if '--message-format=json' not in command and 'metadata' not in command:
            print(p.stdout, end='', flush=True)
        elif p.returncode != 0:
            diagnostics = args.report.with_name(args.report.stem + '-failed-compiler.jsonl')
            diagnostics.parent.mkdir(parents=True, exist_ok=True)
            diagnostics.write_text(p.stdout)
            report['steps'][-1]['stdout_path'] = str(diagnostics)
            for line in p.stdout.splitlines():
                record = json.loads(line)
                if record.get('reason') == 'compiler-message':
                    message = record['message']
                    print(message.get('rendered') or message['message'], end='', flush=True)
        if p.returncode != 0:
            raise RuntimeError(label + ' failed')
        return p.stdout

    try:
        run(['python3', 'scripts/vendor-age-sdk.py', '--check'], 'actual root SDK source provenance')
        metadata = json.loads(run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1'], 'actual root SDK package identities'))
        report['sdk_packages'] = []
        nodes = {node['id']: node for node in metadata['resolve']['nodes']}
        for name, expected in sdk_provenance['packages'].items():
            package = next(p for p in metadata['packages'] if p['name'] == name)
            if (package['source'] is not None or package['version'] != expected['version']
                    or Path(package['manifest_path']).resolve() != (ROOT / 'vendor' / name / 'Cargo.toml').resolve()):
                raise RuntimeError('actual root SDK identity/path mismatch: ' + name)
            report['sdk_packages'].append({'name': name, 'version': package['version'], 'manifest_path': package['manifest_path'],
                                           'features': nodes[package['id']]['features']})
        run(['cargo', 'fmt', '--all', '--check'], 'formatting')
        run(['python3', '-m', 'unittest', 'discover', '--start-directory', 'scripts', '--pattern', 'test_validate_pq_custody_native.py'], 'native driver cleanup-stop and authority controls')
        run(['cargo', 'test', '--offline', '--locked', '--workspace'], 'workspace and scripted TPM cleanup regression tests')
        run(['cargo', 'clippy', '--offline', '--locked', '--workspace', '--all-targets', '--', '--deny', 'warnings'], 'Linux workspace Clippy')
        tools = ROOT / 'target/windows-toolchain/usr/bin'
        linker = ROOT / 'scripts/windows-linker.sh'
        env.update(PATH=str(tools) + os.pathsep + env.get('PATH', ''), CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=str(linker),
                   CC_x86_64_pc_windows_gnu=str(linker), AR_x86_64_pc_windows_gnu=str(tools / 'x86_64-w64-mingw32-ar'))
        target = ['--target', 'x86_64-pc-windows-gnu']
        raw = run(['cargo', 'build', '--offline', '--locked', '--package', 'age-tpm-wsl-helper'] + target + ['--message-format=json'], 'Windows custody helper build')
        executables = [Path(r['executable']) for line in raw.splitlines() if (r := json.loads(line)).get('reason') == 'compiler-artifact' and r.get('executable')]
        if len(executables) != 1:
            raise RuntimeError('expected one actual helper executable')
        helper = executables[0]
        report['helper_path'] = str(helper)
        report['helper_sha256'] = digest(helper)
        run(['cargo', 'clippy', '--offline', '--locked', '--package', 'age-tpm-wsl-helper'] + target + ['--all-targets', '--', '--deny', 'warnings'], 'Windows helper Clippy')
        raw = run(['cargo', 'test', '--offline', '--locked', '--package', 'age-tpm-wsl-helper'] + target + ['--no-run', '--message-format=json'], 'Windows software test build')
        tests = [Path(r['executable']) for line in raw.splitlines() if (r := json.loads(line)).get('reason') == 'compiler-artifact' and r.get('executable') and r.get('profile', {}).get('test')]
        if len(tests) != 1:
            raise RuntimeError('expected one native software test executable')
        report['native_test_path'] = str(tests[0])
        report['native_test_sha256'] = digest(tests[0])
        run([str(tests[0]), '--test-threads=1'], 'native Windows scripted TPM and lifecycle tests')
        # Existing script sends only malformed creates/suites and cannot enroll.
        report['native_legacy_controls'] = json.loads(run(['python3', 'scripts/validate-helper-wire.py', '--helper', str(helper)], 'native legacy hostile framing controls'))
        run(['python3', 'scripts/vendor-age-sdk.py', '--check'], 'final root SDK source provenance')
        for name, expected in report['source_sha256'].items():
            if digest(ROOT / name) != expected:
                raise RuntimeError('validation source changed: ' + name)
        if digest(helper) != report['helper_sha256'] or digest(tests[0]) != report['native_test_sha256']:
            raise RuntimeError('native executable changed during validation')
        report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved software-only custody report:', args.report, flush=True)


if __name__ == '__main__':
    main()
