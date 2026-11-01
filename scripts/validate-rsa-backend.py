#!/usr/bin/env python3
"""Validate the RSA sender against PCP using disposable keys and isolated values."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def cleanup_owned(plugin, identity_bytes, env, run, report, save):
    """Use the successful creation response, independent of local file writes."""
    try:
        run([plugin, 'delete', '/dev/stdin'], input=identity_bytes)
        missing = subprocess.run([str(plugin), 'inspect', '/dev/stdin'], env=env,
                                 input=identity_bytes, capture_output=True, timeout=30)
        if missing.returncode == 0 or b'0x80090016' not in missing.stderr:
            raise RuntimeError('Independent absence verification failed')
    except Exception:
        report['cleanup'] = 'failed; stop and inspect owned key'
        print('Cleanup failed for ' + report.get('owned_key_name', 'unreported owned key'), file=sys.stderr)
        save()
        raise
    report['cleanup'] = 'pass; separate helper process confirmed 0x80090016'
    save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    plugin = ROOT / 'target/debug/age-plugin-tpm-wsl'
    checker = ROOT / 'target/debug/age-tpm-wsl-check'
    helper = args.helper.resolve()
    env = os.environ.copy()
    env['AGE_TPM_WSL_HELPER'] = str(helper)
    env['PATH'] = str(plugin.parent) + os.pathsep + env['PATH']
    report = {
        'result': 'running',
        'binaries': {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in [plugin, checker, helper]},
        'cleanup': 'not yet run',
    }
    summary = output / 'summary.json'

    def save():
        summary.write_text(json.dumps(report, indent=2) + '\n')

    def run(argv, **kwargs):
        result = subprocess.run([str(arg) for arg in argv], env=env, capture_output=True,
                                timeout=180, **kwargs)
        if result.returncode:
            raise RuntimeError(f'Command failed: {argv[0]}\n' + result.stderr.decode(errors='replace'))
        return result

    save()
    checked = run([checker, '--algorithm', 'rsa2048'])
    (output / 'checker.json').write_bytes(checked.stdout)
    report['checker'] = json.loads(checked.stdout)
    save()
    with tempfile.TemporaryDirectory(prefix='tpm-wsl-rsa-backend-') as temporary:
        identity = Path(temporary) / 'identity.txt'
        # Create the destination before enrollment; only successful creation owns a key.
        identity.touch(mode=0o600)
        generated = run([plugin, 'keygen', '--algorithm', 'rsa2048'])
        try:
            names = re.findall(rb'creating rsa2048 key (age-tpm-wsl-[0-9a-f]{32})', generated.stderr)
            if len(names) != 1:
                raise RuntimeError('Successful creation did not report its owned key reference')
            report['owned_key_name'] = names[0].decode()
            save()
            identity.write_bytes(generated.stdout)
            for client in ['age', 'rage']:
                run(['python3', ROOT / 'scripts/validate-age.py', '--identity', identity,
                     '--algorithm', 'rsa2048', '--client', client,
                     '--output', output / f'{client}.json'])
            run(['python3', ROOT / 'scripts/validate-fnox.py', '--identity', identity,
                 '--algorithm', 'rsa2048', '--output', output / 'fnox.json'])
            report['matrices'] = 'age, rage and isolated fnox passed'
        finally:
            cleanup_owned(plugin, generated.stdout, env, run, report, save)
    report['result'] = 'pass'
    save()
    print('RSA PCP checker, age/rage, isolated fnox and independent cleanup passed.')


if __name__ == '__main__':
    main()
