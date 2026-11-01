"""Fixed fnox direct/cache workflow in a retained private project; no daemon."""
import base64
import json
import math
import os
import stat
import time
import tomllib

from .authority import Stop
from .cases import ClientCase, PAYLOAD
from .clients import ClientEnvironment, ClientOutcome
from .durable import checked_directory
from .report import ClientMeasurement

SECRET = 'PQ_CLIENT_TEST'
PROVIDER = 'pq_age'
CHANGED_SOURCE = 'changed-disposable-source'


def fnox_cases():
    return tuple(ClientCase(label, PAYLOAD, 'fnox', ('fnox',))
                 for label in ('fnox_direct', 'fnox_cache'))


class FnoxEnvironment(ClientEnvironment):
    """Same isolated discovery/owner frontend; a finite four-command workflow.

    Fnox 1.42 rejects absolute --config with --local-file. Use an explicit bare
    filename in a verified private cwd so its adjacent override actually loads.
    All diagnostics and returned plaintext stay in memory, outside reports.
    """
    def __init__(self, run, staged, process=None, inherited=None):
        super().__init__(run, staged, process, inherited)
        self.inputs.client('fnox')  # Require the separate pinned/staged binary.
        self.project = run.subdirectory('fnox-project')
        info = self.project.lstat()
        self.project_identity = (info.st_dev, info.st_ino)
        self.phase = 0
        self.providers = None

    def _directory(self):
        self.verify()
        descriptor = os.open(self.project, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            checked_directory(descriptor, self.project_identity)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _check_file(descriptor):
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
            raise Stop('private bounded fnox artifact required')

    def _read(self, name):
        directory = self._directory()
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                self._check_file(descriptor)
                content = os.read(descriptor, 16385)
                if len(content) > 16384:
                    raise Stop('fnox configuration exceeds bound')
                return tomllib.loads(content.decode('utf-8'))
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)

    def _write(self, name, data, *, create=False):
        if name not in {'fnox.toml', 'fnox.local.toml'} or not isinstance(data, bytes) or len(data) > 16384:
            raise Stop('bounded private fnox configuration required')
        directory = self._directory()
        try:
            flags = os.O_WRONLY | os.O_NOFOLLOW
            if create:
                flags |= os.O_CREAT | os.O_EXCL
            descriptor = os.open(name, flags, 0o600, dir_fd=directory)
            try:
                self._check_file(descriptor)
                os.ftruncate(descriptor, 0)
                if os.write(descriptor, data) != len(data):
                    raise Stop('incomplete private fnox configuration')
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(directory)
        finally:
            os.close(directory)

    def _config(self, source=None, *, create=False):
        body = self.providers
        if source is not None:
            body += ('[providers.source]\ntype = "plain"\n[secrets.' + SECRET + ']\n'
                     'provider = "source"\nvalue = ' + json.dumps(source) + '\n')
        self._write('fnox.toml', body.encode(), create=create)

    @staticmethod
    def _base64(encoded):
        if not isinstance(encoded, str) or len(encoded) > 8192:
            raise Stop('bounded fnox ciphertext required')
        value = base64.b64decode(encoded, validate=True)
        if base64.b64encode(value).decode() != encoded:
            raise Stop('canonical fnox Base64 required')
        return value

    def _ciphertext(self, case):
        name = 'fnox.toml' if case == 'fnox_direct' else 'fnox.local.toml'
        secret = self._read(name)['secrets'][SECRET]
        if case == 'fnox_cache':
            if (set(secret) != {'provider', 'value', 'sync'} or secret['provider'] != 'source'
                    or secret['value'] not in {PAYLOAD.decode('ascii'), CHANGED_SOURCE}):
                raise Stop('expected private fnox cache source reference required')
            secret = secret['sync']
        if set(secret) != {'provider', 'value'} or secret['provider'] != PROVIDER:
            raise Stop('fnox output did not select the expected encryption provider')
        encoded = secret['value']
        if not isinstance(encoded, str) or len(encoded) > 8192:
            raise Stop('bounded fnox ciphertext required')
        if case == 'fnox_cache':
            parts = encoded.split(':')
            if len(parts) != 3 or parts[0] != 'fnox-age-batch-v1':
                raise Stop('expected fnox batch cache envelope required')
            wrapped = self._base64(parts[1])
            if len(self._base64(parts[2])) != len(PAYLOAD) + 12 + 16:
                raise Stop('bounded nonce/ciphertext/tag cache value required')
        else:
            wrapped = self._base64(encoded)
        if (not wrapped.startswith(b'age-encryption.org/v1\n')
                or wrapped.count(b'-> mlkem768p256tag ') != 1):
            raise Stop('fnox did not produce one hybrid age ciphertext')
        return encoded.encode('ascii') if case == 'fnox_cache' else wrapped

    def _change_sources(self, ciphertext):
        # Local sync clones the original reference. Alter BOTH plaintext copies
        # while preserving the encrypted cache, so neither fallback can match.
        self._config(CHANGED_SOURCE)
        local = ('[secrets.' + SECRET + ']\nprovider = "source"\nvalue = '
                 + json.dumps(CHANGED_SOURCE) + '\n[secrets.' + SECRET + '.sync]\n'
                 'provider = ' + json.dumps(PROVIDER) + '\nvalue = '
                 + json.dumps(ciphertext.decode('ascii')) + '\n')
        self._write('fnox.local.toml', local.encode())

    def _invoke(self, arguments, offline):
        os.close(self._directory())
        command = [self.inputs.fnox.path, '--config', 'fnox.toml', '--no-daemon',
                   '--non-interactive', '--no-color', '--if-missing', 'error', *arguments]
        return self.process(command, b'', self.environment(offline), 10, cwd=self.project)

    def preflight(self):
        super().preflight()
        pin, expected = self.inputs.client('fnox')
        result = self.process([pin.path, '--version'], b'', self.environment(True), 10, cwd=self.project)
        if result.exit_code != 0 or result.stdout.decode('utf-8').strip() != expected:
            raise Stop('staged fnox version differs from approval')

    def prepare(self, reference):
        super().prepare(reference)
        self.providers = ('[providers.' + PROVIDER + ']\ntype = "age"\nrecipients = ['
                          + json.dumps(reference.recipient) + ']\nkey_file = '
                          + json.dumps(str(self.identity.path)) + '\n')
        self._config(create=True)

    def _expect(self, operation, case, client, payload):
        steps = (('encrypt', 'fnox_direct'), ('decrypt', 'fnox_direct'),
                 ('encrypt', 'fnox_cache'), ('decrypt', 'fnox_cache'))
        if (self.phase >= len(steps) or (operation, case) != steps[self.phase]
                or client != 'fnox' or payload != PAYLOAD or self.providers is None):
            raise Stop('fixed ordered disposable fnox workflow required')

    def encrypt(self, payload=PAYLOAD, client='fnox', case=None):
        self._expect('encrypt', case, client, payload)
        started = time.monotonic()
        if case == 'fnox_direct':
            arguments = ['set', SECRET, payload.decode('ascii'), '--provider', PROVIDER]
        else:
            self._config(PAYLOAD.decode('ascii'))
            arguments = ['sync', '--provider', PROVIDER, '--local-file', '--force']
        result = self._invoke(arguments, True)
        ciphertext = self._ciphertext(case) if result.exit_code == 0 else b''
        if result.exit_code == 0 and case == 'fnox_cache':
            self._change_sources(ciphertext)
        measurement = ClientMeasurement('fnox', 'encrypt', len(payload),
                                        math.ceil((time.monotonic() - started) * 1000),
                                        result.exit_code, bool(ciphertext))
        if measurement.passed:
            self.phase += 1
        return ClientOutcome(measurement, ciphertext)

    def decrypt(self, ciphertext, expected=PAYLOAD, client='fnox', case=None):
        self._expect('decrypt', case, client, expected)
        started = time.monotonic()
        if self._ciphertext(case) != ciphertext:
            raise Stop('fnox decryption input differs from retained encrypted artifact')
        if case == 'fnox_cache':
            source = self._read('fnox.toml')['secrets'][SECRET]
            local = self._read('fnox.local.toml')['secrets'][SECRET]
            if (source != {'provider': 'source', 'value': CHANGED_SOURCE}
                    or local['provider'] != 'source' or local['value'] != CHANGED_SOURCE):
                raise Stop('cache selection requires both changed disposable sources')
        result = self._invoke(['get', SECRET], False)
        # The fixed text payload has no newline. Require fnox's single terminator.
        matched = result.stdout == expected + b'\n'
        measurement = ClientMeasurement('fnox', 'decrypt', len(expected),
                                        math.ceil((time.monotonic() - started) * 1000),
                                        result.exit_code, matched)
        if measurement.passed:
            self.phase += 1
        return ClientOutcome(measurement, expected if matched else b'')
