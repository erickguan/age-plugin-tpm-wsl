"""Isolated age commands and fixed disposable payload; no raw diagnostics/logs."""
from dataclasses import dataclass
import math
import os
from pathlib import Path
import time

from .authority import Stop
from .cases import PAYLOAD
from .diagnostics import Diagnostic
from .process import BoundedProcess, MAX_CLIENT_OUTPUT
from .report import ClientMeasurement


@dataclass(frozen=True)
class ClientOutcome:
    measurement: ClientMeasurement
    output: bytes
    diagnostic: Diagnostic = Diagnostic.UNKNOWN


class ClientEnvironment:
    def __init__(self, run, staged, process=None, inherited=None):
        self.run = run
        self.process = process or BoundedProcess()
        inherited = os.environ if inherited is None else inherited
        self.env = {key: value for key, value in inherited.items() if not key.startswith(('AGE', 'FNOX_'))}
        locations = {name: run.subdirectory(name) for name in ('home', 'config', 'cache', 'state', 'runtime', 'bin')}
        self.env.update(HOME=str(locations['home']), XDG_CONFIG_HOME=str(locations['config']),
                        XDG_CACHE_HOME=str(locations['cache']), XDG_STATE_HOME=str(locations['state']),
                        XDG_RUNTIME_DIR=str(locations['runtime']), AGEDEBUG='',
                        PATH=str(locations['bin']) + os.pathsep + inherited.get('PATH', '/usr/bin:/bin'))
        interpreter = str(staged.python.path)
        if any(char.isspace() for char in interpreter) or len(interpreter.encode()) > 200:
            raise Stop('pinned interpreter path cannot form a safe direct shebang')
        entry = str(staged.entry)
        body = (f'#!{interpreter} -I\nimport runpy, sys\n'
                f'sys.path.insert(0, {str(staged.entry.parent)!r})\n'
                f'sys.argv = [{entry!r}, "--socket", {str(run.path / "s")!r}, '
                f'"--owner-pid", {str(os.getpid())!r}]\n'
                f'runpy.run_path({entry!r}, run_name="__main__")\n').encode()
        self.frontend = run.write_public('frontend', body, 0o700)
        self.inputs = staged.with_public(self.frontend)
        for name in ('age-plugin-tpm-wsl', 'age-plugin-tagpq'):
            (locations['bin'] / name).symlink_to(staged.plugin.path)
        self.bin = locations['bin']
        self.identity = None
        self.reference = None

    def verify(self):
        self.run.verify()
        self.inputs.verify()
        self.frontend.verify()
        for name in ('age-plugin-tpm-wsl', 'age-plugin-tagpq'):
            path = self.bin / name
            if not path.is_symlink() or path.readlink() != Path(self.inputs.plugin.path):
                raise Stop('private plugin discovery changed')
        if self.identity is not None:
            self.identity.verify()

    def environment(self, offline):
        return dict(self.env, AGE_TPM_WSL_HELPER='/nonexistent/offline-only.exe' if offline else str(self.frontend.path))

    def preflight(self):
        self.verify()
        for name in ('age', 'rage'):
            if name == 'rage' and self.inputs.rage is None:
                continue
            pin, expected = self.inputs.client(name)
            version = self.process([pin.path, '--version'], b'', self.environment(True), 10)
            if type(version.exit_code) is not int or version.exit_code != 0 or version.stdout.decode('utf-8').strip() != expected:
                raise Stop('staged client version differs from approved input')
        schemes = self.process([self.inputs.plugin.path, 'schemes'], b'', self.environment(True), 10)
        if schemes.exit_code != 0 or b'mlkem768-p256:' not in schemes.stdout:
            raise Stop('staged plugin lacks the required scheme')

    def prepare(self, reference):
        self.reference = reference
        self.identity = self.run.write_public('identity.txt', (reference.identity + '\n').encode())
        self.verify()
        result = self.process([self.inputs.plugin.path, 'recipient', str(self.identity.path)],
                              b'', self.environment(True), 10)
        if result.exit_code != 0 or result.stdout.decode('utf-8').strip() != reference.recipient:
            raise Stop('staged plugin disagrees with canonical public reference')

    def _call(self, operation, payload, client, expected):
        self.verify()
        if (self.identity is None or not isinstance(expected, bytes) or len(expected) > 4194304
                or not isinstance(payload, bytes) or len(payload) > MAX_CLIENT_OUTPUT):
            raise Stop('bounded disposable payload and retained identity required')
        pin, _ = self.inputs.client(client)
        started = time.monotonic()
        result = self.process([pin.path, '--' + operation, '--identity', str(self.identity.path)],
                              payload, self.environment(operation == 'encrypt'), 10,
                              stdout_limit=len(expected) + 65536)
        elapsed = time.monotonic() - started
        milliseconds = math.ceil(elapsed * 1000)
        if operation == 'encrypt':
            matched = result.stdout.startswith(b'age-encryption.org/v1\n') and result.stdout.count(b'-> mlkem768p256tag ') == 1
        else:
            matched = result.stdout == expected
        measurement = ClientMeasurement(client, operation, len(expected), milliseconds, result.exit_code, matched)
        return ClientOutcome(measurement, result.stdout)

    def encrypt(self, payload=PAYLOAD, client='age', case=None):
        return self._call('encrypt', payload, client, payload)

    def decrypt(self, ciphertext, expected=PAYLOAD, client='age', case=None):
        return self._call('decrypt', ciphertext, client, expected)
