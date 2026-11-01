"""Private retained run artifacts. Nothing here auto-cleans a live campaign."""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat

from .authority import Stop
from .durable import checked_directory
from .inputs import Artifact


def leaf(name):
    if not isinstance(name, str) or re.fullmatch('[a-z][a-z0-9_.-]{0,63}', name) is None:
        raise Stop('simple reserved run-artifact name required')
    return name


@dataclass(frozen=True)
class RunDirectory:
    path: Path
    identity: tuple
    owner_pid: int

    @classmethod
    def create(cls, parent):
        parent = Path(parent).absolute()
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
                raise Stop('owned non-writable-by-others run parent required')
            name = 'pq-client-' + secrets.token_hex(12)
            path = parent / name
            if len(os.fsencode(path / 's')) > 107:
                raise Stop('run path too long for private Unix socket')
            os.mkdir(name, 0o700, dir_fd=descriptor)
            os.fsync(descriptor)
            created = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        finally:
            os.close(descriptor)
        run = cls(path, (created.st_dev, created.st_ino), os.getpid())
        run.verify()
        return run

    def open(self):
        if self.owner_pid != os.getpid():
            raise Stop('only the creating process owns the retained run')
        descriptor = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            checked_directory(descriptor, self.identity)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def verify(self):
        os.close(self.open())

    def write_public(self, name, data, mode=0o600):
        """Exclusive public identity/launcher bytes only, never a file key/log."""
        leaf(name)
        if not isinstance(data, bytes) or len(data) > 16384 or mode not in {0o600, 0o700}:
            raise Stop('bounded public artifact and private file mode required')
        directory = self.open()
        try:
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 mode, dir_fd=directory)
            try:
                os.fchmod(descriptor, mode)
                if os.write(descriptor, data) != len(data):
                    raise Stop('partial public artifact write')
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(directory)
        finally:
            os.close(directory)
        return Artifact(self.path / name, hashlib.sha256(data).hexdigest())

    def subdirectory(self, name):
        directory = self.open()
        try:
            os.mkdir(leaf(name), 0o700, dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)
        return self.path / name
