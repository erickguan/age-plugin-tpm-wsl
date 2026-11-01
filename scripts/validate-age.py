#!/usr/bin/env python3
"""Run age CLI tests with isolated disposable values; emit no plaintext."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SIZES = [0, 4, 256, 1024, 2048, 4096, 8192, 65535, 65536, 65537, 1048576, 4194304]


def run(argv, env, **kwargs):
    return subprocess.run(argv, env=env, check=True, capture_output=True, timeout=120, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', type=Path, help='Disposable hardware identity; caller owns cleanup')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--algorithm', choices=['rsa2048', 'p256-hpke'], default='rsa2048')
    parser.add_argument('--client', choices=['age', 'rage'], default='age')
    args = parser.parse_args()
    env = os.environ.copy()
    env['PATH'] = str(ROOT / 'target/debug') + os.pathsep + env['PATH']
    plugin = str(ROOT / 'target/debug/age-plugin-tpm-wsl')
    report = {'mode': 'hardware' if args.identity else 'software fixture', 'algorithm': args.algorithm, 'client': args.client, 'sizes': []}
    with tempfile.TemporaryDirectory(prefix='tpm-wsl-age-') as temporary:
        work = Path(temporary)
        if args.identity:
            identity = args.identity.resolve()
        else:
            env['TPM_WSL_FIXTURE_DIR'] = str(work)
            fixture = ROOT / 'target/debug/examples/software_fixture'
            env['AGE_TPM_WSL_HELPER'] = str(fixture)
            identity = work / 'identity.txt'
            identity.write_bytes(run([str(fixture), 'generate', '--algorithm', args.algorithm], env).stdout)
        recipient = run([plugin, 'recipient', str(identity)], env).stdout.decode().strip()
        tag = b'tpm-wsl-rsa' if args.algorithm == 'rsa2048' else b'tpm-wsl-hpke'
        version = b'1' if args.algorithm == 'rsa2048' else b'2'
        for size in SIZES:
            payload = os.urandom(size)
            started = time.monotonic()
            encrypted = run([args.client, '--encrypt', '--recipient', recipient], env, input=payload).stdout
            decrypted = run([args.client, '--decrypt', '--identity', str(identity)], env, input=encrypted).stdout
            assert hashlib.sha256(decrypted).digest() == hashlib.sha256(payload).digest()
            assert len(decrypted) == size
            report['sizes'].append({'bytes': size, 'result': 'pass', 'elapsed_ms': round((time.monotonic() - started) * 1000)})
        # Encryption from an identity must not invoke Windows.
        offline = env.copy()
        offline['AGE_TPM_WSL_HELPER'] = '/nonexistent/helper.exe'
        encrypted = run([args.client, '--encrypt', '--identity', str(identity)], offline, input=b'abcd').stdout
        assert run([args.client, '--decrypt', '--identity', str(identity)], env, input=encrypted).stdout == b'abcd'
        report['offline_identity_encryption'] = 'pass'
        # Two identical recipients must produce two usable stanzas.
        encrypted = run([args.client, '--encrypt', '--recipient', recipient, '--recipient', recipient], env, input=b'abcd').stdout
        assert encrypted.count(b'-> ' + tag + b' ') == 2
        assert run([args.client, '--decrypt', '--identity', str(identity)], env, input=encrypted).stdout == b'abcd'
        report['duplicate_recipients'] = 'pass'
        # Native recovery recipient and plugin can coexist.
        native = work / 'native.txt'
        run(['age-keygen', '--output', str(native)], env)
        native_recipient = run(['age-keygen', '-y', str(native)], env).stdout.decode().strip()
        encrypted = run([args.client, '--encrypt', '--recipient', recipient, '--recipient', native_recipient], env, input=b'abcd').stdout
        for key in [identity, native]:
            assert run([args.client, '--decrypt', '--identity', str(key)], env, input=encrypted).stdout == b'abcd'
        report['native_recovery_recipient'] = 'pass'
        # Wrong identity and payload/header corruption must fail.
        failed = subprocess.run([args.client, '--decrypt', '--identity', str(native)], env=env,
                                input=run([args.client, '--encrypt', '--recipient', recipient], env, input=b'abcd').stdout,
                                capture_output=True, timeout=30)
        assert failed.returncode != 0 and failed.stdout == b''
        report['wrong_identity'] = 'pass'
        # A different plugin identity must be skipped by fingerprint before calling Windows.
        other_dir = work / 'other-fixture'
        other_dir.mkdir(mode=0o700)
        other_env = env.copy()
        other_env['TPM_WSL_FIXTURE_DIR'] = str(other_dir)
        other_identity = other_dir / 'identity.txt'
        other_identity.write_bytes(run([str(ROOT / 'target/debug/examples/software_fixture'), 'generate', '--algorithm', args.algorithm], other_env).stdout)
        failed = subprocess.run([args.client, '--decrypt', '--identity', str(other_identity)], env=offline,
                                input=run([args.client, '--encrypt', '--recipient', recipient], env, input=b'abcd').stdout,
                                capture_output=True, timeout=30)
        assert failed.returncode != 0 and failed.stdout == b''
        report['wrong_plugin_identity'] = 'pass'
        plugin_cipher = run([args.client, '--encrypt', '--recipient', recipient], env, input=b'abcd').stdout
        for name, corrupted in [
            ('payload_corruption', plugin_cipher[:-1] + bytes([plugin_cipher[-1] ^ 1])),
            ('stanza_version', plugin_cipher.replace(b'-> ' + tag + b' ' + version + b' ', b'-> ' + tag + b' 99 ', 1)),
        ]:
            failed = subprocess.run([args.client, '--decrypt', '--identity', str(identity)], env=env,
                                    input=corrupted, capture_output=True, timeout=30)
            assert failed.returncode != 0 and failed.stdout == b'', name
            report[name] = 'pass'
        # Exercise deadline and interrupted response through the real age interface.
        hostile = work / 'hostile-helper'
        hostile_env = env.copy()
        hostile_env['AGE_TPM_WSL_HELPER'] = str(hostile)
        hostile_env['AGE_TPM_WSL_TIMEOUT'] = '1'
        for name, behavior in [('helper_timeout', 'time.sleep(30)'), ('helper_interruption', 'sys.exit(1)'),
                               ('helper_malformed', "sys.stdout.buffer.write(b'invalid')")]:
            hostile.write_text('#!/usr/bin/env python3\nimport sys, time\nsys.stdin.buffer.read()\n' + behavior + '\n')
            hostile.chmod(0o700)
            started = time.monotonic()
            failed = subprocess.run([args.client, '--decrypt', '--identity', str(identity)], env=hostile_env,
                                    input=plugin_cipher, capture_output=True, timeout=5)
            assert failed.returncode != 0 and failed.stdout == b''
            assert time.monotonic() - started < 4
            report[name] = 'pass'
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
