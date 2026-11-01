"""Own one foreground fnox process and a short private Unix runtime directory."""
import ctypes
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import tempfile
import time

from .authority import Stop
from .durable import checked_directory
from .inputs import Artifact
from .process import BoundedProcess, digest


@dataclass(frozen=True)
class CacheStatus:
    pid: int
    entries: int


@dataclass(frozen=True)
class DaemonRetirement:
    owner: object = field(repr=False, compare=False)
    pid: int

    def checked_cache_states(self, states):
        """Return only the original owner's fixed start/cold/warm/bypass observations."""
        self.verify()
        issued = self.owner._statuses
        if (not isinstance(states, tuple) or len(states) != 4 or len(issued) != 7
                or tuple(entries for _, _, entries in issued) != (0, 0, 1, 1, 1, 1, 1)):
            raise Stop('complete ordered owned-daemon cache observations required')
        for state, index in zip(states, (0, 2, 4, 6)):
            original, pid, entries = issued[index]
            if (state is not original or (state.pid, state.entries) != (pid, entries) or pid != self.pid):
                raise Stop('cache observation was replaced, changed or reordered')
        return states

    def verify(self):
        owner = self.owner
        if (owner.owner_pid != os.getpid() or owner.receipt is not self or not owner.retired
                or owner.child is None or owner.child.pid != self.pid or owner.child.returncode != 0):
            raise Stop('original owned daemon retirement required')
        owner.run.verify(); owner.pin.verify()
        if owner.config is None:
            raise Stop('retired daemon must retain its exact configuration binding')
        owner._verify_config()
        owner._directory_identity(owner.project, owner.project_identity)
        for path in (owner.socket_path, owner.path):
            if path is not None and os.path.lexists(path):
                raise Stop('retired daemon artifact path exists')


class OwnedFnoxDaemon:
    """No socket/PID adoption. On failure the caller latches native authority first,
    then calls abandon() to stop only this exact child; private state is retained.
    """
    def __init__(self, run, pin, project, environment, process=None):
        self.run, self.pin, self.project = run, pin, Path(project)
        self.process = process or BoundedProcess()
        self.owner_pid = os.getpid()
        self.child = self.socket_path = self.socket_identity = self.config = self.receipt = None
        self.retired = self.started = self.stopped = False
        self.config_identity = None
        self._statuses = []
        self.project_identity = self._directory_identity(self.project)
        self.path = Path(tempfile.mkdtemp(prefix='fnox-r-', dir='/tmp'))
        self.path.chmod(0o700)
        self.directories = []
        for suffix in ('runtime', 'runtime/fnox', 'tmp', 'config', 'state', 'data'):
            path = self.path / suffix
            path.mkdir(mode=0o700)
            self.directories.append((path, self._directory_identity(path)))
        self.identity = self._directory_identity(self.path)
        self.socket_directory = self.path / 'runtime/fnox'
        if len(os.fsencode(self.socket_directory / ('0' * 16 + '-fnoxd.sock'))) >= 90:
            raise Stop('daemon runtime would risk socket-path fallback')
        # Provider/credential variables are not inherited. Preserve only private
        # client discovery and the WSL process context needed by the owner bridge.
        allowed = {'PATH', 'HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME',
                   'WSL_INTEROP', 'WSL_DISTRO_NAME', 'WSLENV', 'USER', 'LOGNAME',
                   'AGEDEBUG', 'AGE_TPM_WSL_HELPER'}
        self._environment = {key: value for key, value in environment.items() if key in allowed}
        self._environment.update(XDG_RUNTIME_DIR=str(self.path / 'runtime'), TMPDIR=str(self.path / 'tmp'),
                                 FNOX_CONFIG_DIR=str(self.path / 'config'), FNOX_STATE_DIR=str(self.path / 'state'),
                                 FNOX_DATA_DIR=str(self.path / 'data'), FNOX_DAEMON='on',
                                 FNOX_DAEMON_IDLE_TIMEOUT='60s', LANG='C', LC_ALL='C', NO_COLOR='1')
        self._environment_snapshot = tuple(sorted(self._environment.items()))
        self.run.write_public('daemon-runtime.json', (json.dumps({'path': str(self.path),
                              'device': self.identity[0], 'inode': self.identity[1]}) + '\n').encode())
        self.verify()

    @staticmethod
    def _directory_identity(path, expected=None):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            return checked_directory(descriptor, expected)
        finally:
            os.close(descriptor)

    def verify(self):
        if self.owner_pid != os.getpid() or self.retired:
            raise Stop('only the original live daemon owner may continue')
        self.run.verify(); self.pin.verify()
        self._directory_identity(self.project, self.project_identity)
        self._directory_identity(self.path, self.identity)
        for path, identity in self.directories:
            self._directory_identity(path, identity)
        if tuple(sorted(self._environment.items())) != self._environment_snapshot:
            raise Stop('daemon environment changed')
        if self.config is not None:
            self._verify_config()

    def _verify_config(self):
        info = self.config.path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384
                or (info.st_dev, info.st_ino) != self.config_identity):
            raise Stop('original private daemon configuration identity required')
        self.config.verify()

    def environment(self):
        self.verify()
        return dict(self._environment)

    def command(self, arguments, *, bypass=False):
        self.verify()
        return [self.pin.path, '--config', str(self.project / 'fnox.toml'), '--non-interactive',
                '--no-color', '--if-missing', 'error', *(['--no-daemon'] if bypass else []), *arguments]

    def _invoke(self, arguments):
        return self.process(self.command(arguments), b'', self.environment(), 10, cwd=self.project)

    def _socket(self):
        self.verify()
        if self.child is None or self.child.poll() is not None or self.socket_path is None:
            raise Stop('original foreground daemon must still be alive')
        paths = list(self.socket_directory.iterdir())
        if paths != [self.socket_path]:
            raise Stop('private runtime must contain only the owned socket')
        info = self.socket_path.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or (info.st_dev, info.st_ino) != self.socket_identity):
            raise Stop('daemon socket ownership/identity changed')
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(10)
            peer.connect(str(self.socket_path))
            pid, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if pid != self.child.pid or uid != os.getuid():
                raise Stop('daemon peer is not the owned foreground child')

    def start(self):
        self.verify()
        if self.started or list(self.socket_directory.iterdir()):
            raise Stop('fresh empty runtime and one explicit daemon start required')
        config = self.project / 'fnox.toml'
        info = config.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
            raise Stop('private bounded daemon configuration required')
        self.config = Artifact(config, digest(config))
        self.config_identity = (info.st_dev, info.st_ino)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]; libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        watch = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if watch < 0: raise Stop('daemon readiness observation unavailable')
        try:
            if libc.inotify_add_watch(watch, os.fsencode(self.socket_directory), 0x100 | 0x4 | 0x80) < 0:
                raise Stop('daemon readiness watch failed')
            self.started = True
            deadline = time.monotonic() + 10
            self.child = subprocess.Popen(self.command(['daemon', 'serve']), env=self.environment(),
                                          cwd=self.project, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL, umask=0o077)
            while True:
                if self.child.poll() is not None:
                    raise Stop('owned daemon exited before readiness')
                paths = list(self.socket_directory.iterdir())
                if paths:
                    if len(paths) != 1 or re.fullmatch('[0-9a-f]{16}-fnoxd.sock', paths[0].name) is None:
                        raise Stop('unexpected private daemon runtime entry')
                    info = paths[0].lstat()
                    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                        raise Stop('invalid private daemon socket')
                    if stat.S_IMODE(info.st_mode) == 0o600:
                        self.socket_path, self.socket_identity = paths[0], (info.st_dev, info.st_ino)
                        break
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([watch], [], [], max(0, remaining))[0]:
                    raise Stop('daemon readiness deadline exceeded')
                os.read(watch, 4096)
        finally:
            os.close(watch)
        status = self.status()
        if status.entries != 0:
            raise Stop('new owned daemon cache must be empty')
        return status

    def status(self):
        self._socket()
        result = self._invoke(['daemon', 'status'])
        match = re.fullmatch(rb'fnox daemon running\npid: ([0-9]{1,10})\ncached_entries: ([0-9]{1,6})\n', result.stdout)
        self._socket()
        if result.exit_code != 0 or match is None or int(match[1]) != self.child.pid:
            raise Stop('owned daemon status malformed or mismatched')
        return self._record_status(int(match[2]))

    def _record_status(self, entries):
        status = CacheStatus(self.child.pid, entries)
        self._statuses.append((status, status.pid, status.entries))
        return status

    def stop(self):
        if self.stopped:
            raise Stop('daemon stop cannot be repeated')
        self._socket()
        self.stopped = True
        result = self._invoke(['daemon', 'stop'])
        if result.exit_code != 0:
            raise Stop('owned daemon stop failed')
        try: self.child.wait(timeout=10)
        except subprocess.TimeoutExpired: raise Stop('owned daemon exit unconfirmed') from None
        if self.child.returncode != 0 or os.path.lexists(self.socket_path) or list(self.socket_directory.iterdir()):
            raise Stop('successful daemon exit and socket absence required')
        self.verify()
        # Remove only known, verified EMPTY directories, never recursively.
        for path, identity in reversed(self.directories):
            self._directory_identity(path, identity)
            os.rmdir(path)
        self._directory_identity(self.path, self.identity)
        os.rmdir(self.path)
        if os.path.lexists(self.path):
            raise Stop('daemon runtime still exists')
        self.retired = True
        self.receipt = DaemonRetirement(self, self.child.pid)
        self.receipt.verify()
        return self.receipt

    def abandon(self):
        """Native authority must already be latched; stop only this child, retain files."""
        if self.owner_pid != os.getpid():
            raise Stop('another process cannot stop this daemon')
        if self.child is not None and self.child.poll() is None:
            self.child.terminate()
            try: self.child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.child.kill(); self.child.wait(timeout=5)
        if self.child is not None and self.child.poll() is None:
            raise Stop('owned daemon teardown failed; retain native and runtime state')
