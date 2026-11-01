#!/usr/bin/env python3
"""Validate bounded PQ request parsing and unavailable Windows-handler behavior."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct

PROJECT = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    inputs = [p for folder in ['src', 'helper/src', 'crates/post_quantum/src', 'crates/custody-fs/src', 'tests'] for p in (PROJECT / folder).rglob('*.rs')]
    inputs += [PROJECT / p for p in ['Cargo.toml', 'Cargo.lock', 'helper/Cargo.toml', 'crates/post_quantum/Cargo.toml', 'crates/custody-fs/Cargo.toml', 'scripts/windows-linker.sh', 'scripts/validate-helper-wire.py', 'vendor/aws-lc-rs-provenance.json', 'notes/aws-lc-hybrid-evaluation/go-fixture.json']]
    inputs.append(Path(__file__).resolve())
    report = {'result': 'fail', 'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_sha256': {str(p.relative_to(PROJECT)): sha256(p) for p in sorted(inputs)}, 'steps': [],
              'limits': ['PQ helper payloads and file-key response checks only; Windows PQ handler intentionally rejects all requests before provider/storage acquisition',
                         'No new scheme/CLI enrollment, private custody, keys or filesystem enrollments are exercised',
                         'Existing RSA/P-256 request formats and client deadline remain unchanged; no hardware round-trip acceptance']}
    env = os.environ.copy()
    env.update(RUSTC_WRAPPER='', CARGO_TARGET_DIR=str(PROJECT / 'target/pq-wire-validation'))

    def run(command, label):
        print('Running ' + label, flush=True)
        p = subprocess.run(command, cwd=PROJECT, env=env, capture_output=True, text=True, timeout=900)
        report['steps'].append({'check': label, 'exit_code': p.returncode, 'command': command,
                                'stdout_sha256': hashlib.sha256(p.stdout.encode()).hexdigest(),
                                'stderr_sha256': hashlib.sha256(p.stderr.encode()).hexdigest()})
        if p.stderr:
            print(p.stderr, end='', flush=True)
        if '--message-format=json' not in command:
            print(p.stdout, end='', flush=True)
        if p.returncode != 0:
            raise RuntimeError(label + ' failed')
        return p.stdout

    def native_case(helper, label, operation, payload, status=0):
        request = b'ATW1' + bytes([operation]) + struct.pack('<II', status, len(payload)) + payload
        p = subprocess.run([str(helper)], input=request, capture_output=True, timeout=20)
        expected = request[:5]
        if p.returncode != 0 or len(p.stdout) != 13 or p.stdout[:5] != expected:
            raise RuntimeError('invalid native refusal framing: ' + label)
        code, length = struct.unpack('<II', p.stdout[5:])
        if code == 0 or length != 0:
            raise RuntimeError('unavailable PQ operation succeeded: ' + label)
        report['native_refusals'].append({'case': label, 'status': f'0x{code:08x}', 'exit_code': p.returncode,
                                           'stdout_sha256': hashlib.sha256(p.stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(p.stderr).hexdigest()})

    try:
        # These controls intentionally send well-formed CREATE_POST_QUANTUM requests. They
        # are safe only for the accepted stub that rejects before acquisition.
        # Later lifecycle validation must use an explicit isolated test store.
        unavailable_dispatch = '8fe965b0a6b4387088a646f7262bf4cc7d1286c70b98add2b7027c311a63893d'
        if sha256(PROJECT / 'helper/src/main.rs') != unavailable_dispatch:
            raise RuntimeError('historical unavailable-handler controls require the exact accepted stub; do not run valid create requests against a live custody handler')
        run(['cargo', 'fmt', '--all', '--check'], 'formatting')
        run(['cargo', 'test', '--offline', '--locked', '--workspace'], 'workspace legacy and PQ payload regression tests')
        run(['cargo', 'clippy', '--offline', '--locked', '--workspace', '--all-targets', '--', '--deny', 'warnings'], 'Linux workspace Clippy')
        tools = PROJECT / 'target/windows-toolchain/usr/bin'
        linker = PROJECT / 'scripts/windows-linker.sh'
        env.update(PATH=str(tools) + os.pathsep + env.get('PATH', ''), CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=str(linker),
                   CC_x86_64_pc_windows_gnu=str(linker), AR_x86_64_pc_windows_gnu=str(tools / 'x86_64-w64-mingw32-ar'))
        target = ['--target', 'x86_64-pc-windows-gnu']
        raw = run(['cargo', 'build', '--offline', '--locked', '--package', 'age-tpm-wsl-helper'] + target + ['--message-format=json'], 'Windows helper build')
        executables = [Path(r['executable']) for line in raw.splitlines() if (r := json.loads(line)).get('reason') == 'compiler-artifact' and r.get('executable')]
        if len(executables) != 1:
            raise RuntimeError('expected one actual helper executable')
        helper = executables[0]
        report['helper_sha256'] = sha256(helper)
        run(['cargo', 'clippy', '--offline', '--locked', '--package', 'age-tpm-wsl-helper'] + target + ['--all-targets', '--', '--deny', 'warnings'], 'Windows helper Clippy')
        report['legacy_native_framing'] = json.loads(run(['python3', 'scripts/validate-helper-wire.py', '--helper', str(helper)], 'existing native hostile framing controls'))
        public = json.loads((PROJECT / 'notes/aws-lc-hybrid-evaluation/go-fixture.json').read_text())
        name = b'age-tpm-wsl-pq-' + b'0' * 32
        identity = b'\x03\x00\x02' + bytes.fromhex(public['public_key']) + b'\x2f' + name
        enc = bytes.fromhex(public['enc'])
        body = bytes.fromhex(public['body'])
        unwrap = b'\x05\x14' + identity + enc + body
        report['native_refusals'] = []
        for label, operation, payload in [('valid_create_unavailable', 8, b'\x00\x02' + name),
                                           ('valid_unwrap_unavailable', 9, unwrap), ('valid_recover_unavailable', 10, name),
                                           ('wrong_suite', 8, b'\x00\x01' + name), ('classical_name', 8, b'\x00\x02' + b'age-tpm-wsl-' + b'0' * 32),
                                           ('short_unwrap', 9, unwrap[:-1]), ('bad_identity_length', 9, b'\xff\xff' + unwrap[2:]),
                                           ('trailing_recover', 10, name + b'\x00')]:
            native_case(helper, label, operation, payload)
        native_case(helper, 'nonzero_pq_status', 8, b'', status=1)
        # ATW1 forbids nonzero status combined with a payload before dispatch.
        # This is a framing failure, so no response frame may be emitted.
        payload = b'\x00\x02' + name
        request = b'ATW1\x08' + struct.pack('<II', 1, len(payload)) + payload
        p = subprocess.run([str(helper)], input=request, capture_output=True, timeout=20)
        report['native_transport_rejections'] = [{'case': 'nonzero_status_with_payload',
            'exit_code': p.returncode, 'stdout_sha256': hashlib.sha256(p.stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(p.stderr).hexdigest(), 'stdout_bytes': len(p.stdout)}]
        if p.returncode == 0 or p.stdout:
            raise RuntimeError('forbidden status-plus-payload frame did not fail transport')
        for p, h in report['source_sha256'].items():
            if sha256(PROJECT / p) != h:
                raise RuntimeError('source changed during validation: ' + p)
        if sha256(helper) != report['helper_sha256']:
            raise RuntimeError('helper executable changed during validation')
        report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved PQ boundary report:', args.report, flush=True)


if __name__ == '__main__':
    main()
