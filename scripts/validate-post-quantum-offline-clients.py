#!/usr/bin/env python3
"""Check actual clients' offline wrapping and label behavior with public fixtures.

This checks encryption only. It creates no TPM keys, opens no Windows helper,
reads no user identity and makes no claim about decryption or custody.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

from post_quantum_client import references

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class PublicFixture:
    native_recipient: str
    classical_recipient: str
    identity: str

    @classmethod
    def load(cls, path):
        public = bytes.fromhex(json.loads(path.read_text())['public_key'])
        name = b'age-tpm-wsl-pq-0123456789abcdef0123456789abcdef'
        identity = b'\x03\x00\x02' + public + bytes([len(name)]) + name
        if len(public) != 1249 or len(identity) != 1300:
            raise ValueError('unexpected public fixture length')
        return cls(references.encode_reference('age1tagpq', public),
                   references.encode_reference('age1tpm-wsl', b'\x02\x00\x01' + public[1184:]),
                   references.encode_reference('age-plugin-tpm-wsl-', identity).upper())


@dataclass(frozen=True)
class Scenario:
    name: str
    arguments: tuple[str, ...]
    success: bool
    hybrid_stanzas: int


def scenarios(fixture, identity):
    native, classical = fixture.native_recipient, fixture.classical_recipient
    return [
        Scenario('classical_control', ('--recipient', classical), True, 0),
        Scenario('native_hybrid_recipient', ('--recipient', native), True, 1),
        Scenario('hybrid_identity', ('--identity', str(identity)), True, 1),
        Scenario('duplicate_hybrid_recipients', ('--recipient', native, '--recipient', native), True, 2),
        Scenario('mixed_plugin_groups', ('--recipient', native, '--recipient', classical), False, 0),
        Scenario('mixed_same_plugin_identity_and_recipient',
                 ('--identity', str(identity), '--recipient', classical), False, 0),
    ]


class OfflineEnvironment:
    """Temporary launchers, public identity and isolated client configuration."""
    def __init__(self, work, plugin, fixture):
        self.work = work
        self.calls = work / 'calls'
        self.identity = work / 'identity.txt'
        self.identity.write_text(fixture.identity + '\n')
        self.identity.chmod(0o600)
        commands = work / 'bin'
        commands.mkdir()
        launcher = commands / 'age-plugin-tpm-wsl'
        launcher.write_text('#!/bin/sh\nprintf \'%s\\n\' "${0##*/}" >> '
                            + shlex.quote(str(self.calls)) + '\nexec '
                            + shlex.quote(str(plugin)) + ' "$@"\n')
        launcher.chmod(0o700)
        (commands / 'age-plugin-tagpq').symlink_to(launcher.name)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('AGE', 'FNOX_'))}
        self.env.update(HOME=str(work), XDG_CONFIG_HOME=str(work / 'config'),
                        XDG_CACHE_HOME=str(work / 'cache'), XDG_STATE_HOME=str(work / 'state'),
                        PATH=str(commands) + os.pathsep + os.environ['PATH'],
                        AGE_TPM_WSL_HELPER='/nonexistent/offline-helper.exe', AGEDEBUG='')
        extracted = subprocess.run([str(plugin), 'recipient', str(self.identity)], check=True,
                                   capture_output=True, env=self.env, timeout=10).stdout.decode().strip()
        if extracted != fixture.native_recipient:
            raise ValueError('plugin disagrees with reference recipient encoding')

    def measure(self, executable, scenario):
        self.calls.write_text('')
        result = subprocess.run([executable, '--encrypt', *scenario.arguments],
                                input=b'public-disposable-offline-fixture', env=self.env,
                                cwd=self.work, capture_output=True, timeout=30)
        count = result.stdout.count(b'-> mlkem768p256tag ')
        # Rejection must emit no ciphertext. This avoids treating partial output
        # followed by an error as successful label enforcement.
        passed = ((result.returncode == 0) == scenario.success
                  and count == scenario.hybrid_stanzas
                  and (scenario.success or not result.stdout))
        report = {'exit_code': result.returncode, 'expected_success': scenario.success,
                  'result': 'pass' if passed else 'fail', 'hybrid_stanzas': count,
                  'plugin_invocations': self.calls.read_text().splitlines()}
        if result.returncode:
            report['diagnostic'] = result.stderr.decode(errors='replace').replace(str(self.work), '<temporary>')[:1000]
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True, help='new output path; existing reports are preserved')
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    # Reserve evidence before launching commands; incomplete evidence is visible.
    with args.report.open('x') as reserved:
        reserved.write('{"result": "incomplete"}\n')
    plugin = ROOT / 'target/debug/age-plugin-tpm-wsl'
    fixture_path = ROOT / 'notes/aws-lc-hybrid-evaluation/go-fixture.json'
    report = {'scope': 'offline public fixture encryption and labels only; no decryption or TPM access',
              'source_sha256': sha256(Path(__file__)),
              'reference_encoder_sha256': sha256(Path(references.__file__)), 'plugin_sha256': sha256(plugin),
              'fixture_sha256': sha256(fixture_path), 'clients': {}, 'result': 'incomplete'}
    try:
        fixture = PublicFixture.load(fixture_path)
        with tempfile.TemporaryDirectory(prefix='post-quantum-offline-') as temporary:
            environment = OfflineEnvironment(Path(temporary), plugin, fixture)
            for name in ('age', 'rage'):
                executable = shutil.which(name)
                if not executable:
                    raise RuntimeError('required client missing: ' + name)
                version = subprocess.run([executable, '--version'], check=True, capture_output=True,
                                         env=environment.env, timeout=10).stdout.decode().strip()
                checks = {case.name: environment.measure(executable, case)
                          for case in scenarios(fixture, environment.identity)}
                report['clients'][name] = {'version': version,
                                          'executable_sha256': sha256(Path(executable)), 'checks': checks}
                print(name + ': ' + ', '.join(label + '=' + check['result'] for label, check in checks.items()))
        report['temporary_files_removed'] = True
        report['result'] = 'pass' if all(check['result'] == 'pass' for client in report['clients'].values()
                                        for check in client['checks'].values()) else 'fail'
        if report['result'] != 'pass':
            raise RuntimeError('offline client acceptance failed; inspect report')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report['result'] = 'fail'
        report['error'] = str(error)
        raise
    finally:
        args.report.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
