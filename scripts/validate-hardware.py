#!/usr/bin/env python3
"""Validate disposable TPM keys for both schemes and independently verify cleanup."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, required=True)
    args = parser.parse_args()
    env = os.environ.copy()
    env['AGE_TPM_WSL_HELPER'] = str(args.helper.resolve())
    env['PATH'] = str(ROOT / 'target/debug') + os.pathsep + env['PATH']
    plugin = str(ROOT / 'target/debug/age-plugin-tpm-wsl')
    checker = str(ROOT / 'target/debug/age-tpm-wsl-check')

    def run(argv, **kwargs):
        result = subprocess.run(argv, env=env, capture_output=True, timeout=180, **kwargs)
        if result.returncode:
            raise RuntimeError('Validation failed: ' + ' '.join(argv) + '\n' + result.stderr.decode())
        return result

    run(['python3', str(ROOT / 'scripts/validate-helper-wire.py'), '--helper', env['AGE_TPM_WSL_HELPER'],
         '--output', str(ROOT / 'notes/multi-scheme-hardware-wire.json')])
    reports = {}
    for scheme in ['rsa2048', 'p256-hpke']:
        # The checker owns and cleans up its keys. A failure stops this driver.
        test = run([checker, '--algorithm', scheme])
        reports[scheme] = json.loads(test.stdout)
        (ROOT / f'notes/multi-scheme-check-{scheme}.json').write_text(json.dumps(reports[scheme], indent=2) + '\n')
    with tempfile.TemporaryDirectory(prefix='tpm-wsl-hardware-') as temporary:
        identities = []
        try:
            for scheme in ['rsa2048', 'p256-hpke']:
                identity = Path(temporary) / f'{scheme}.txt'
                generated = run([plugin, 'keygen', '--algorithm', scheme])
                identity.write_bytes(generated.stdout)
                identity.chmod(0o600)
                identities.append(identity)
                for client in ['age', 'rage']:
                    run(['python3', str(ROOT / 'scripts/validate-age.py'), '--identity', str(identity),
                         '--algorithm', scheme, '--client', client,
                         '--output', str(ROOT / f'notes/multi-scheme-hardware-{scheme}-{client}.json')])
                run(['python3', str(ROOT / 'scripts/validate-fnox.py'), '--identity', str(identity),
                     '--algorithm', scheme, '--output', str(ROOT / f'notes/multi-scheme-hardware-{scheme}-fnox.json')])
            recipients = [run([plugin, 'recipient', str(identity)]).stdout.decode().strip() for identity in identities]
            for sender in ['age', 'rage']:
                encrypted = run([sender, '--encrypt', '--recipient', recipients[0], '--recipient', recipients[1]], input=b'disposable-mixed-scheme-value').stdout
                assert encrypted.count(b'-> tpm-wsl-rsa ') == 1
                assert encrypted.count(b'-> tpm-wsl-hpke ') == 1
                for receiver in ['age', 'rage']:
                    for identity in identities:
                        assert run([receiver, '--decrypt', '--identity', str(identity)], input=encrypted).stdout == b'disposable-mixed-scheme-value'
            reports['mixed_recipients_cross_client'] = 'pass'
        finally:
            failures = []
            for identity in identities:
                try:
                    run([plugin, 'delete', str(identity)])
                    missing = subprocess.run([plugin, 'inspect', str(identity)], env=env, capture_output=True, timeout=30)
                    if missing.returncode == 0 or b'0x80090016' not in missing.stderr:
                        raise RuntimeError('Independent missing-key verification failed')
                except Exception as error:
                    failures.append(f'{identity}: {error}')
            if failures:
                raise RuntimeError('Cleanup failed; stop and inspect disposable keys:\n' + '\n'.join(failures))
    reports['matrix_cleanup'] = 'pass; independent helper processes confirmed absence'
    (ROOT / 'notes/multi-scheme-hardware-summary.json').write_text(json.dumps(reports, indent=2) + '\n')
    print('Both schemes, age/rage, isolated fnox, mixed recipients and independent cleanup passed.')


if __name__ == '__main__':
    main()
