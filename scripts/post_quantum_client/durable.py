"""Verified private-directory handles, append storage and outstanding intent marker."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat

from .authority import Stop

LIMIT = 1024 * 1024


def checked_directory(descriptor, expected=None):
    info = os.fstat(descriptor)
    identity = (info.st_dev, info.st_ino)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or (expected is not None and identity != expected)):
        raise Stop('journal parent ownership, identity or private mode mismatch')
    return identity


class Storage:
    def __init__(self, directory, descriptor, name):
        self.directory, self.descriptor, self.name = directory, descriptor, name
        self.marker = name + '.active'
        self.created_marker = None

    def read(self):
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        data = os.read(self.descriptor, LIMIT + 1)
        if not data.endswith(b'\n') or len(data) > LIMIT:
            raise Stop('incomplete or oversized journal')
        return data

    def append(self, encoded):
        checked_directory(self.directory)
        info = os.fstat(self.descriptor)
        if info.st_nlink != 1 or info.st_size + len(encoded) > LIMIT:
            raise Stop('journal unlinked or size bound exceeded')
        if os.write(self.descriptor, encoded) != len(encoded):
            raise Stop('partial journal write')
        os.fsync(self.descriptor)

    def active(self):
        try:
            info = os.stat(self.marker, dir_fd=self.directory, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise Stop('invalid operation marker')
        return True

    def begin(self):
        checked_directory(self.directory)
        marker = os.open(self.marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.directory)
        try:
            if os.write(marker, b'outstanding intent\n') != 19:
                raise Stop('partial operation marker')
            os.fsync(marker)
            info = os.fstat(marker)
            self.created_marker = (info.st_dev, info.st_ino)
        finally:
            os.close(marker)
        os.fsync(self.directory)

    def retire(self):
        """Unlink only this verified journal after its caller checks a checkpoint."""
        checked_directory(self.directory)
        if self.active():
            raise Stop('outstanding operation marker prevents retirement')
        current = os.stat(self.name, dir_fd=self.directory, follow_symlinks=False)
        held = os.fstat(self.descriptor)
        if (not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid()
                or current.st_nlink != 1 or stat.S_IMODE(current.st_mode) != 0o600
                or (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)):
            raise Stop('authority path changed before retirement')
        os.unlink(self.name, dir_fd=self.directory)
        os.fsync(self.directory)

    def complete(self):
        checked_directory(self.directory)
        info = os.stat(self.marker, dir_fd=self.directory, follow_symlinks=False)
        if self.created_marker != (info.st_dev, info.st_ino):
            raise Stop('operation marker changed')
        os.unlink(self.marker, dir_fd=self.directory)
        os.fsync(self.directory)
        self.created_marker = None


class PrivateFile:
    """Pin the directory and journal inodes; all later opens are handle-relative."""
    def __init__(self, path):
        self.path = Path(path)
        directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.parent_identity = checked_directory(directory)
            info = os.stat(self.path.name, dir_fd=directory, follow_symlinks=False)
            self.identity = (info.st_dev, info.st_ino)
        finally:
            os.close(directory)

    @classmethod
    def create(cls, path, bootstrap):
        path = Path(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            checked_directory(directory)
            descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            try:
                if os.write(descriptor, bootstrap) != len(bootstrap):
                    raise Stop('partial bootstrap write')
                os.fsync(descriptor)
                os.fsync(directory)
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)
        return cls(path)

    @contextmanager
    def locked(self):
        directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptor = None
        try:
            checked_directory(directory, self.parent_identity)
            descriptor = os.open(self.path.name, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW,
                                 dir_fd=directory)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > LIMIT
                    or (info.st_dev, info.st_ino) != self.identity):
                raise Stop('journal ownership/type/mode/identity/size mismatch')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Stop('another operation owns the journal; no continuation permitted') from None
            yield Storage(directory, descriptor, self.path.name)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)
