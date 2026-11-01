#!/usr/bin/env python3
"""Exercise actual old/new binaries and independent HPKE with disposable TPM keys."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

MISSING = 0x80090016


def frame(operation, payload=b''):
    return b'ATW1' + bytes([operation]) + struct.pack('<II', 0, len(payload)) + payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['old-plugin', 'new-plugin', 'old-helper', 'new-helper', 'oracle']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--feature-revision', default='uncommitted working copy; see binary hashes')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binaries = {name: getattr(args, name.replace('-', '_')).resolve()
                for name in ['old-plugin', 'new-plugin', 'old-helper', 'new-helper', 'oracle']}
    report = {'result': 'running', 'baseline_commit': '03c77bce77d3ad806b3c9c6851aa8fbd20fbbabf',
              'feature_revision': args.feature_revision,
              'binaries': {name: {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                           for name, path in binaries.items()}, 'checks': {}, 'owned_key_names': [], 'cleanup': []}

    def save():
        args.output.write_text(json.dumps(report, indent=2) + '\n')

    def run(argv, env=None, input=None, expect=True):
        result = subprocess.run([str(arg) for arg in argv], env=env, input=input,
                                capture_output=True, timeout=45)
        if expect and result.returncode:
            # Inputs and stdout can include file keys; diagnostics never print them.
            raise RuntimeError('Command failed: ' + str(argv[0]) + '\n' + result.stderr.decode(errors='replace'))
        return result

    def call(helper, operation, payload=b''):
        result = run([helper], input=frame(operation, payload), expect=False)
        if result.returncode:
            return result.returncode, None, b''
        output = result.stdout
        if len(output) < 13 or output[:5] != b'ATW1' + bytes([operation]):
            raise RuntimeError('Invalid helper response header')
        status, length = struct.unpack('<II', output[5:13])
        if length > 8192 or len(output) != 13 + length or (status and length):
            raise RuntimeError('Invalid helper response payload')
        return 0, status, output[13:]

    def require(condition, label):
        if not condition:
            raise RuntimeError(label)

    with tempfile.TemporaryDirectory(prefix='tpm-wsl-cross-version-') as temporary:
        root = Path(temporary)
        owned = []
        pending_name = None
        pending_identity = None

        def environment(plugin, helper, label):
            bindir = root / label
            bindir.mkdir(exist_ok=True)
            link = bindir / 'age-plugin-tpm-wsl'
            if not link.exists():
                link.symlink_to(plugin)
            env = os.environ.copy()
            env['PATH'] = str(bindir) + os.pathsep + env['PATH']
            env['AGE_TPM_WSL_HELPER'] = str(helper)
            return env

        def create(label, plugin, helper, algorithm=None):
            nonlocal pending_name, pending_identity
            env = environment(plugin, helper, label)
            command = [plugin, 'keygen']
            if algorithm:
                command.extend(['--algorithm', algorithm])
            result = run(command, env=env, expect=False)
            match = re.search(rb'age-tpm-wsl-[0-9a-f]{32}', result.stderr)
            # Preserve the reference if the process failed after persistence.
            pending_name = match.group().decode() if match else None
            require(result.returncode == 0, 'Key creation failed; possible reference: ' + str(pending_name))
            require(pending_name is not None, 'Creation did not report a recoverable key name')
            pending_identity = root / (label + '.txt')
            pending_identity.touch(mode=0o600)
            pending_identity.write_bytes(result.stdout)
            owned.append((pending_identity, pending_name))
            report['owned_key_names'].append(pending_name)
            save()
            identity = pending_identity
            pending_name = pending_identity = None
            return identity, env

        save()
        try:
            for label, client_name, helper_name in [
                ('old-client-new-helper', 'old-plugin', 'new-helper'),
                ('new-client-old-helper', 'new-plugin', 'old-helper'),
            ]:
                plugin, helper = binaries[client_name], binaries[helper_name]
                identity, env = create(label, plugin, helper)
                recipient = run([plugin, 'recipient', identity], env=env).stdout.strip().decode()
                original = [line for line in identity.read_text().splitlines() if line.startswith('AGE-PLUGIN-')]
                name = owned[-1][1]
                recovered = run([plugin, 'recover', name], env=env).stdout.decode().splitlines()
                require([line for line in recovered if line.startswith('AGE-PLUGIN-')] == original,
                        'Recovery changed identity bytes')
                run([plugin, 'inspect', identity], env=env)
                # Each client encrypts without Windows; the other client decrypts.
                for sender, receiver in [('age', 'rage'), ('rage', 'age')]:
                    for length in [0, 16, 65537]:
                        sample = bytes(index % 251 for index in range(length))
                        offline = env | {'AGE_TPM_WSL_HELPER': str(root / 'nonexistent-helper.exe')}
                        encrypted = run([sender, '--encrypt', '--recipient', recipient], env=offline, input=sample).stdout
                        restored = run([receiver, '--decrypt', '--identity', identity], env=env, input=encrypted).stdout
                        require(restored == sample, 'Cross-version age payload mismatch')
                # Independently exercise the opposite Linux release with this same identity.
                other_plugin = binaries['new-plugin' if client_name == 'old-plugin' else 'old-plugin']
                other_env = environment(other_plugin, helper, label + '-other-client')
                run([other_plugin, 'inspect', identity], env=other_env)
                report['checks'][label] = {'result': 'pass', 'rsa_lifecycle_and_unwrap': 'pass',
                                          'age_rage_cross_decryption': 'pass', 'payload_lengths': [0, 16, 65537]}
                save()

            # A new client must receive an actual legacy helper's failure once,
            # without retrying creation as RSA. Verify the proposed name absent.
            env = environment(binaries['new-plugin'], binaries['old-helper'], 'new-p256-old-helper')
            trace = root / 'legacy-helper-operations.jsonl'
            proxy = root / 'trace-legacy-helper.py'
            proxy.write_text(
                '#!' + sys.executable + '\n'
                'import json, subprocess, sys\n'
                'request = sys.stdin.buffer.read(8206)\n'
                f'with open({str(trace)!r}, "a") as log:\n'
                '    log.write(json.dumps(request[4] if len(request) >= 5 else None) + "\\n")\n'
                f'result = subprocess.run([{str(binaries["old-helper"])!r}], input=request, capture_output=True, timeout=40)\n'
                'sys.stdout.buffer.write(result.stdout)\n'
                'sys.stderr.buffer.write(result.stderr)\n'
                'sys.exit(result.returncode)\n')
            proxy.chmod(0o700)
            env['AGE_TPM_WSL_HELPER'] = str(proxy)
            failed_create = run([binaries['new-plugin'], 'keygen', '--algorithm', 'p256-hpke'], env=env, expect=False)
            names = re.findall(rb'creating p256-hpke key (age-tpm-wsl-[0-9a-f]{32})', failed_create.stderr)
            require(failed_create.returncode != 0 and failed_create.stdout == b'' and len(names) == 1,
                    'Unsupported creation was accepted or retried')
            require([json.loads(line) for line in trace.read_text().splitlines()] == [6],
                    'Client retried unsupported creation or changed operation')
            absent_name = names[0].decode()
            code, status, _ = call(binaries['new-helper'], 5, absent_name.encode())
            require(code == 0 and status == MISSING, 'Legacy rejection left a persisted key')
            report['checks']['new-p256-create-old-helper'] = {'result': 'pass', 'key_name': absent_name,
                                                             'helper_operations': [6],
                                                             'independent_absence_status': hex(status)}
            save()

            identity, env = create('independent-p256', binaries['new-plugin'], binaries['new-helper'], 'p256-hpke')
            name = owned[-1][1]
            code, status, raw_identity = call(binaries['new-helper'], 5, name.encode())
            require(code == 0 and status == 0 and len(raw_identity) == 113
                    and raw_identity[:3] == b'\x02\x00\x01'
                    and raw_identity[68] == 44 and raw_identity[69:] == name.encode(),
                    'P-256 recovery returned an invalid canonical identity')
            oracle = json.loads(run([binaries['oracle'], '--recipient', raw_identity[:68].hex()]).stdout)
            body = bytes.fromhex(oracle['body'])
            request = len(raw_identity).to_bytes(2, 'big') + raw_identity + body
            code, status, plain = call(binaries['new-helper'], 7, request)
            require(code == 0 and status == 0 and plain == bytes.fromhex(oracle['plaintext']),
                    'Independent Go sender to native Windows receiver failed')
            for offset in [65, 96]:
                broken = bytearray(body)
                broken[offset] ^= 1
                code, status, output = call(binaries['new-helper'], 7,
                                            len(raw_identity).to_bytes(2, 'big') + raw_identity + broken)
                require(code == 0 and status not in [0, 0xA0010002] and output == b'',
                        'Native receiver accepted modified independent ciphertext')
            report['checks']['independent-go-to-tpm-hpke'] = {
                'result': 'pass', 'generator': oracle['generator'], 'ciphertext_and_tag_tamper': 'rejected',
                'recipient_sha256': hashlib.sha256(raw_identity[:68]).hexdigest()}

            recipient = run([binaries['new-plugin'], 'recipient', identity], env=env).stdout.strip().decode()
            trace.write_text('')
            for client in ['age', 'rage']:
                encrypted = run([client, '--encrypt', '--recipient', recipient], env=env,
                                input=b'public-cross-version-test-value').stdout
                legacy_env = environment(binaries['new-plugin'], binaries['old-helper'], 'new-p256-old-helper')
                legacy_env['AGE_TPM_WSL_HELPER'] = str(proxy)
                result = run([client, '--decrypt', '--identity', identity], env=legacy_env,
                             input=encrypted, expect=False)
                require(result.returncode != 0 and result.stdout == b'', 'Unsupported P-256 unwrap was accepted')
            require([json.loads(line) for line in trace.read_text().splitlines()] == [7, 7],
                    'Client retried unsupported unwrap or changed scheme')
            code, status, output = call(binaries['old-helper'], 7, request)
            require(code != 0 and status is None and output == b'', 'Legacy helper did not reject new operation')
            # The key still works after rejection by the legacy helper.
            code, status, plain = call(binaries['new-helper'], 7, request)
            require(code == 0 and status == 0 and plain == bytes.fromhex(oracle['plaintext']),
                    'Post-rejection native control failed')
            report['checks']['new-p256-unwrap-old-helper'] = {'result': 'pass', 'age_rage': 'rejected',
                                                            'helper_operations': [7, 7],
                                                            'native_new_operation': 'rejected',
                                                            'new_helper_control': 'pass'}
            report['result'] = 'pass'
        except BaseException as error:
            report['result'] = 'fail'
            report['error'] = str(error)
            if pending_name:
                report['interrupted_creation_reference'] = pending_name
            raise
        finally:
            failures = []
            # Use both deletion implementations, then a distinct opposite-version
            # helper process for the missing-key check. P-256 requires the new helper.
            for index, (identity, name) in enumerate(owned):
                helper = binaries['old-helper'] if index == 1 else binaries['new-helper']
                plugin = binaries['old-plugin'] if index == 1 else binaries['new-plugin']
                try:
                    run([plugin, 'delete', identity], env=environment(plugin, helper, 'cleanup-' + str(index)))
                    verifier = binaries['new-helper'] if index == 1 else binaries['old-helper']
                    code, status, output = call(verifier, 5, name.encode())
                    require(code == 0 and status == MISSING and output == b'', 'Independent absence check failed')
                    report['cleanup'].append({'key_name': name, 'result': 'pass', 'absence_status': hex(status)})
                except BaseException as error:
                    failures.append(name + ': ' + str(error))
            if failures or pending_name:
                report['result'] = 'cleanup-failed'
                report['cleanup_errors'] = failures
            save()
            if failures or pending_name:
                raise RuntimeError('Cleanup incomplete; stop and inspect only reported disposable key names')
    print('Cross-version RSA, fail-closed P-256, independent Go-to-TPM HPKE and cleanup passed.')


if __name__ == '__main__':
    main()
