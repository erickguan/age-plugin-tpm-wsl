#!/usr/bin/env python3
"""Prepare or reopen one installed-plugin disposable PQ restart checkpoint."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

VALUE = b'disposable-installed-pq-restart-1'
POWERSHELL = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    temporary = path.with_name(path.name + '.pending')
    with temporary.open('x') as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run(command, environment, directory, payload=None, offline=False):
    child = dict(environment)
    if offline:
        child['AGE_TPM_WSL_HELPER'] = '/nonexistent/offline-encryption-only.exe'
    started = time.monotonic()
    result = subprocess.run([str(arg) for arg in command], input=payload, capture_output=True,
                            cwd=directory, env=child, timeout=20)
    if result.returncode:
        raise RuntimeError(Path(command[0]).name + ' failed; checkpoint retained')
    return result.stdout, round((time.monotonic() - started) * 1000)


def context(environment, directory):
    command = "$i=[System.Security.Principal.WindowsIdentity]::GetCurrent(); $o=Get-CimInstance Win32_OperatingSystem; [Console]::Out.WriteLine((@{sid=$i.User.Value;windows_boot_utc=$o.LastBootUpTime.ToUniversalTime().ToString('o');windows_version=$o.Version} | ConvertTo-Json -Compress))"
    output, _ = run([POWERSHELL, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command], environment, directory)
    value = json.loads(output)
    value['sid_sha256'] = hashlib.sha256(value.pop('sid').encode()).hexdigest()
    value['linux_boot_id'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    return value


def verify_files(record):
    for item in record['installed_files'].values():
        if digest(item['path']) != item['sha256']:
            raise RuntimeError('installed image/config changed; checkpoint retained')
    alias = Path(record['alias'])
    if not alias.is_symlink() or alias.readlink() != Path('age-plugin-tpm-wsl'):
        raise RuntimeError('installed PQ discovery alias changed')


def reads(record, environment, directory):
    expected = record['checkpoint_files']
    for name, sha in expected.items():
        if digest(directory / name) != sha:
            raise RuntimeError('checkpoint artifact changed: ' + name)
    identity = directory / 'identity.txt'
    plugin = record['installed_files']['launcher']['path']
    recipient, _ = run([plugin, 'recipient', identity], environment, directory)
    if recipient != (directory / 'recipient.txt').read_bytes():
        raise RuntimeError('original public identity/recipient binding changed')
    inspection, _ = run([plugin, 'inspect', identity], environment, directory)
    if json.loads(inspection).get('name') != record['key_name']:
        raise RuntimeError('installed inspection identity mismatch')
    measurements = {}
    for name, path in record['clients'].items():
        output, elapsed = run([path, '--decrypt', '--identity', identity, directory / 'value.age'], environment, directory)
        if output != VALUE or elapsed > 10000:
            raise RuntimeError('installed read mismatch or exceeded ten seconds')
        measurements[name] = {'result': 'pass', 'matched': True, 'payload_bytes': len(VALUE), 'elapsed_ms': elapsed}
    output, elapsed = run([record['fnox'], '--config', str(directory / 'fnox.toml'), '--no-daemon',
                          '--non-interactive', '--no-color', '--if-missing', 'error', 'get', 'RESTART_TEST'],
                         environment, directory)
    if output != VALUE + b'\n' or elapsed > 10000:
        raise RuntimeError('isolated installed fnox read failed or exceeded ten seconds')
    measurements['fnox_direct'] = {'result': 'pass', 'matched': True, 'payload_bytes': len(VALUE), 'elapsed_ms': elapsed}
    return measurements


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'resume'])
    parser.add_argument('--directory', type=Path, required=True, help='private deployment backup directory')
    parser.add_argument('--event', choices=['same-session', 'wsl-restart', 'windows-login', 'windows-reboot'],
                        default='same-session', help='operator description; recorded alongside actual boot evidence')
    args = parser.parse_args()
    directory = args.directory.resolve(strict=True) / 'checkpoint'
    receipt = directory / 'checkpoint.json'
    environment = {key: value for key, value in os.environ.items() if not key.startswith(('AGE', 'FNOX_'))}
    environment['PATH'] = str(Path.home() / '.local/bin') + os.pathsep + environment.get('PATH', '')
    if args.action == 'prepare':
        deployment = json.loads((args.directory / 'installation.json').read_bytes())
        if deployment['status'] != 'installed-verified':
            raise RuntimeError('verified matched installation required before explicit enrollment')
        directory.mkdir(mode=0o700)
        record = {'status': 'preparing', 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'installed_files': deployment['installed_files'], 'alias': str(Path.home() / '.local/bin/age-plugin-tagpq'),
                  'clients': {name: str(Path(shutil.which(name)).resolve()) for name in ('age', 'rage')},
                  'fnox': str(Path(shutil.which('fnox')).resolve()), 'source_commit': deployment['source_commit']}
        save(receipt, record)
    else:
        record = json.loads(receipt.read_bytes())
        if record['status'] != 'ready-for-restart':
            raise RuntimeError('only a complete original checkpoint may resume; no automatic reenrollment')
    for name in ('config', 'cache', 'state', 'runtime', 'data'):
        path = directory / name
        path.mkdir(mode=0o700, exist_ok=True)
    environment.update(XDG_CONFIG_HOME=str(directory / 'config'), XDG_CACHE_HOME=str(directory / 'cache'),
                       XDG_STATE_HOME=str(directory / 'state'), XDG_RUNTIME_DIR=str(directory / 'runtime'),
                       FNOX_CONFIG_DIR=str(directory / 'config'), FNOX_STATE_DIR=str(directory / 'state'),
                       FNOX_DATA_DIR=str(directory / 'data'), FNOX_DAEMON='off', AGE_TPM_WSL_TIMEOUT='10')
    verify_files(record)
    current = context(environment, directory)
    if args.action == 'prepare':
        record.update(status='creating-disposable-key', before=current)
        save(receipt, record)
        # Persist the public reference and diagnostic key name even if creation is interrupted.
        identity = directory / 'identity.txt'
        diagnostic = directory / 'creation.stderr'
        with identity.open('xb') as output, diagnostic.open('xb') as errors:
            os.chmod(identity, 0o600); os.chmod(diagnostic, 0o600)
            created = subprocess.run([record['installed_files']['launcher']['path'], 'keygen', '--algorithm', 'mlkem768-p256'],
                                     cwd=directory, env=environment, stdout=output, stderr=errors, timeout=20)
        name = re.search(rb'creating mlkem768-p256 key (age-tpm-wsl-pq-[0-9a-f]{32})', diagnostic.read_bytes())
        if name:
            record['key_name'] = name[1].decode()
            save(receipt, record)
        if created.returncode or not name:
            raise RuntimeError('creation incomplete; retain checkpoint/key name and stop without retry')
        recipient, _ = run([record['installed_files']['launcher']['path'], 'recipient', identity], environment, directory)
        (directory / 'recipient.txt').write_bytes(recipient)
        ciphertext, _ = run([record['clients']['age'], '--encrypt', '--recipient', recipient.decode().strip()],
                             environment, directory, VALUE, offline=True)
        (directory / 'value.age').write_bytes(ciphertext)
        provider = '[providers.restart]\ntype = "age"\nrecipients = [' + json.dumps(recipient.decode().strip()) + ']\nkey_file = ' + json.dumps(str(identity)) + '\n'
        config = directory / 'fnox.toml'
        config.write_text(provider); config.chmod(0o600)
        run([record['fnox'], '--config', config, '--no-daemon', '--non-interactive', '--no-color',
             '--if-missing', 'error', 'set', 'RESTART_TEST', VALUE.decode(), '--provider', 'restart'],
            environment, directory, offline=True)
        for name in ('recipient.txt', 'value.age', 'fnox.toml'):
            (directory / name).chmod(0o600)
        for name in ('identity.txt', 'recipient.txt', 'value.age', 'fnox.toml', 'creation.stderr'):
            with (directory / name).open('rb') as stream:
                os.fsync(stream.fileno())
        record['checkpoint_files'] = {name: digest(directory / name) for name in
                                      ('identity.txt', 'recipient.txt', 'value.age', 'fnox.toml')}
        save(receipt, record)
        record['baseline'] = reads(record, environment, directory)
        record['status'] = 'ready-for-restart'
        save(receipt, record)
        print(json.dumps({'status': record['status'], 'receipt': str(receipt), 'key_name': record['key_name'],
                          'baseline': record['baseline'], 'retained_for_next_run': True}, indent=2))
    else:
        if current['sid_sha256'] != record['before']['sid_sha256']:
            raise RuntimeError('Windows SID differs; retain checkpoint and stop')
        result = {'result': 'pass', 'event_assertion': args.event, 'context': current,
                  'linux_boot_changed': current['linux_boot_id'] != record['before']['linux_boot_id'],
                  'windows_boot_changed': current['windows_boot_utc'] != record['before']['windows_boot_utc'],
                  'same_windows_sid': True, 'reads': reads(record, environment, directory),
                  'key_retained_pending_explicit_cleanup': True}
        path = directory / ('resume-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.json')
        if path.exists():
            raise RuntimeError('fresh resume evidence path required')
        save(path, result)
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(type(error).__name__ + ': ' + str(error), file=__import__('sys').stderr)
        raise SystemExit(1)
