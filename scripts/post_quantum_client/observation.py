"""Bounded, source-bound read-only Windows observation; construction probes no key."""
import json
from pathlib import Path
import re

from .authority import Namespace, Observation, Stop
from .process import BoundedProcess, digest

POWERSHELL = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
WSLPATH = '/usr/bin/wslpath'


def object_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Stop('duplicate observation field')
        result[key] = value
    return result


class WindowsObserver:
    """The campaign pins this adapter, its PS script and the interpreter inputs.

    Script conversion is local. A call observes one exact namespace only, with
    no fallback provider, key enumeration or lifecycle action.
    """
    def __init__(self, script, expected_hash, environment, run=None):
        self.script = Path(script).resolve(strict=True)
        self.expected_hash = expected_hash
        self.environment = dict(environment)
        self.run = run or BoundedProcess()
        self.verify_source()
        result = self.run([WSLPATH, '-w', str(self.script)], b'', self.environment, 10)
        if type(result.exit_code) is not int or result.exit_code != 0:
            raise Stop('observer script path conversion failed')
        try:
            text = result.stdout.decode('utf-8')
        except (UnicodeError, AttributeError):
            raise Stop('invalid observer Windows path') from None
        if not text.endswith('\n'):
            raise Stop('incomplete observer Windows path')
        self.windows_script = text[:-1].removesuffix('\r')
        if (any(char in self.windows_script for char in '\r\n\0')
                or not (self.windows_script.startswith('\\\\')
                        or re.match(r'\A[A-Za-z]:\\', self.windows_script))):
            raise Stop('absolute observer Windows path required')

    def verify_source(self):
        if (not isinstance(self.expected_hash, str)
                or re.fullmatch('[0-9a-f]{64}', self.expected_hash) is None
                or digest(self.script) != self.expected_hash):
            raise Stop('independent observer source changed')

    def command(self, namespace, software_only=False):
        if not isinstance(namespace, Namespace):
            raise Stop('validated observer namespace required')
        self.verify_source()
        command = [POWERSHELL, '-NoLogo', '-NoProfile', '-NonInteractive',
                   '-ExecutionPolicy', 'Bypass', '-File', self.windows_script,
                   '-Namespace', namespace.directory]
        if software_only:
            command.append('-SoftwareOnly')
        return command

    def __call__(self, namespace):
        result = self.run(self.command(namespace), b'', self.environment, 10)
        if type(result.exit_code) is not int or result.exit_code != 0:
            raise Stop('independent observation process failed')
        try:
            value = json.loads(result.stdout, object_pairs_hook=object_fields)
            if (not isinstance(value, dict)
                    or set(value) != {'namespace', 'name', 'sid', 'root_absent', 'key_absent'}
                    or value['namespace'] != namespace.directory or value['name'] != namespace.key_name):
                raise Stop('observation namespace binding failed')
            return Observation(value['sid'], value['root_absent'], value['key_absent']).validate()
        except (ValueError, TypeError, KeyError, RecursionError):
            raise Stop('invalid independent observation response') from None
