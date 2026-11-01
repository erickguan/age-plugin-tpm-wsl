#!/usr/bin/env python3
"""Validate fnox direct and sync-cache reads in a temporary configuration."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--algorithm', choices=['rsa2048', 'p256-hpke'], default='rsa2048')
    args = parser.parse_args()
    env = os.environ.copy()
    for variable in list(env):
        if variable.startswith('FNOX_'):
            del env[variable]
    env['PATH'] = str(ROOT / 'target/debug') + os.pathsep + env['PATH']
    report = {'mode': 'hardware' if args.identity else 'software fixture', 'algorithm': args.algorithm, 'checks': {}}
    with tempfile.TemporaryDirectory(prefix='tpm-wsl-fnox-') as temporary:
        work = Path(temporary)
        # Isolate global configuration and daemon locations as well as project config.
        env['HOME'] = str(work)
        env['XDG_CONFIG_HOME'] = str(work / 'config')
        env['XDG_CACHE_HOME'] = str(work / 'cache')
        env['XDG_STATE_HOME'] = str(work / 'state')
        env['XDG_RUNTIME_DIR'] = str(work / 'runtime')
        (work / 'runtime').mkdir(mode=0o700)
        def run(argv, **kwargs):
            return subprocess.run(argv, cwd=work, env=env, capture_output=True, check=True, timeout=120, **kwargs)
        if args.identity:
            identity = args.identity.resolve()
        else:
            fixture = str(ROOT / 'target/debug/examples/software_fixture')
            env['TPM_WSL_FIXTURE_DIR'] = str(work)
            env['AGE_TPM_WSL_HELPER'] = fixture
            identity = work / 'identity.txt'
            identity.write_bytes(run([fixture, 'generate', '--algorithm', args.algorithm]).stdout)
        recipient = run([str(ROOT / 'target/debug/age-plugin-tpm-wsl'), 'recipient', str(identity)]).stdout.decode().strip()
        config = work / 'fnox.toml'
        config.write_text('[providers.test_age]\ntype = "age"\nrecipients = [' + json.dumps(recipient) + ']\nkey_file = ' + json.dumps(str(identity)) + '\n')
        base = ['fnox', '--no-daemon', '--non-interactive', '--no-color']
        value = 'disposable-fnox-value-1234'
        run(base + ['set', 'TPM_WSL_TEST', value, '--provider', 'test_age'])
        started = time.monotonic()
        assert run(base + ['get', 'TPM_WSL_TEST']).stdout.decode().rstrip('\n') == value
        report['checks']['direct_get'] = {'result': 'pass', 'elapsed_ms': round((time.monotonic() - started) * 1000)}
        config.write_text('[providers.source]\ntype = "plain"\n[providers.test_age]\ntype = "age"\nrecipients = [' + json.dumps(recipient) + ']\nkey_file = ' + json.dumps(str(identity)) + '\n[secrets.TPM_WSL_TEST]\nprovider = "source"\nvalue = ' + json.dumps(value) + '\n')
        helper = env['AGE_TPM_WSL_HELPER']
        env['AGE_TPM_WSL_HELPER'] = '/nonexistent/helper.exe'
        run(base + ['sync', '--provider', 'test_age', '--local-file', '--force'])
        report['checks']['offline_sync_encryption'] = {'result': 'pass'}
        env['AGE_TPM_WSL_HELPER'] = helper
        assert (work / 'fnox.local.toml').exists()
        # Change the source to prove the old cached value is selected.
        config.write_text(config.read_text().replace(value, 'changed-disposable-source'))
        assert run(base + ['get', 'TPM_WSL_TEST']).stdout.decode().rstrip('\n') == value
        report['checks']['persistent_cache_get'] = {'result': 'pass'}
        env['AGE_TPM_WSL_HELPER'] = '/nonexistent/helper.exe'
        failed = subprocess.run(base + ['get', 'TPM_WSL_TEST'], cwd=work, env=env, capture_output=True, timeout=30)
        assert failed.returncode != 0 and value.encode() not in failed.stdout
        report['checks']['cache_helper_failure'] = {'result': 'pass'}
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
