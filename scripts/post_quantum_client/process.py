"""Pin one staged executable and run it with bounded pipes and a deadline."""
from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import Path
import queue
import stat
import subprocess
import threading
import time

from .authority import Stop
from .diagnostics import Diagnostic, classify

MAX_DIAGNOSTIC = 8192

MAX_OUTPUT = 8192 + 13
MAX_CLIENT_OUTPUT = 4194304 + 65536


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@dataclass(frozen=True)
class BinaryPin:
    path: str
    sha256: str
    device: int
    inode: int
    source_hashes: dict

    @classmethod
    def stage(cls, source, expected_hash, directory, source_hashes, filename='client-fixture.exe'):
        if filename not in {'client-fixture.exe', 'age-plugin-tpm-wsl', 'age', 'rage', 'fnox', 'age-keygen'}:
            raise Stop('known fixture/plugin/client staging name required')
        directory = Path(directory)
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise Stop('binary staging requires an owned private directory')
        target = directory / filename
        input_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        output_fd = None
        try:
            if not stat.S_ISREG(os.fstat(input_fd).st_mode):
                raise Stop('approved executable must be a regular file')
            output_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
            hasher = hashlib.sha256()
            while block := os.read(input_fd, 1024 * 1024):
                hasher.update(block)
                view = memoryview(block)
                while view:
                    count = os.write(output_fd, view)
                    if count <= 0:
                        raise Stop('incomplete staged executable')
                    view = view[count:]
            if hasher.hexdigest() != expected_hash:
                raise Stop('approved executable digest mismatch')
            os.fchmod(output_fd, 0o500)
            os.fsync(output_fd)
            info = os.fstat(output_fd)
        finally:
            os.close(input_fd)
            if output_fd is not None:
                os.close(output_fd)
        pin = cls(str(target.absolute()), expected_hash, info.st_dev, info.st_ino, dict(source_hashes))
        pin.verify()
        return pin

    def record(self):
        return asdict(self)

    @classmethod
    def load(cls, value):
        if not isinstance(value, dict) or set(value) != {'path', 'sha256', 'device', 'inode', 'source_hashes'}:
            raise Stop('invalid staged executable pin')
        return cls(**value)

    def verify(self):
        path = Path(self.path)
        info = path.lstat()
        if (not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o500
                or (info.st_dev, info.st_ino) != (self.device, self.inode)
                or digest(path) != self.sha256):
            raise Stop('staged executable identity or digest changed')
        if not isinstance(self.source_hashes, dict) or not self.source_hashes:
            raise Stop('source binding required')
        for name, expected in self.source_hashes.items():
            if not Path(name).is_absolute() or digest(name) != expected:
                raise Stop('validated source changed')


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int
    stdout: bytes
    diagnostic: Diagnostic = Diagnostic.UNKNOWN


class BoundedProcess:
    """Bound all requested streams; return only redacted client diagnostics."""
    def __call__(self, command, payload, environment, seconds=10, *, stdout_limit=MAX_OUTPUT,
                 cwd=None, diagnostic_client=None):
        if type(stdout_limit) is not int or not MAX_OUTPUT <= stdout_limit <= MAX_CLIENT_OUTPUT:
            raise Stop('explicit bounded helper/client output limit required')
        if cwd is not None and not Path(cwd).is_absolute():
            raise Stop('explicit absolute working directory required')
        if diagnostic_client is not None and (not isinstance(diagnostic_client, str)
                                              or diagnostic_client not in {'age', 'rage'}):
            raise Stop('diagnostic capture requires an explicit age/rage client')
        deadline = time.monotonic() + seconds
        process = subprocess.Popen(command, env=environment, cwd=cwd, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE if diagnostic_client else subprocess.DEVNULL,
                                   umask=0o077)
        writes, reads, diagnostics = queue.Queue(), queue.Queue(), queue.Queue()

        def write():
            try:
                with process.stdin as stream:
                    stream.write(payload)
                writes.put(True)
            except OSError:
                writes.put(False)

        def read(stream, results, limit):
            try:
                with stream:
                    results.put(stream.read(limit + 1))
            except OSError:
                results.put(None)

        threading.Thread(target=write, daemon=True).start()
        threading.Thread(target=read, args=(process.stdout, reads, stdout_limit), daemon=True).start()
        if diagnostic_client:
            threading.Thread(target=read, args=(process.stderr, diagnostics, MAX_DIAGNOSTIC), daemon=True).start()
        remaining = lambda: max(0, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining())
            output = reads.get(timeout=remaining())
            written = writes.get(timeout=remaining())
            stderr = diagnostics.get(timeout=remaining()) if diagnostic_client else b''
            if (not written or output is None or len(output) > stdout_limit
                    or stderr is None or len(stderr) > MAX_DIAGNOSTIC):
                raise Stop('fixture pipe failure or output bound exceeded')
            diagnostic = (classify(diagnostic_client, stderr)
                          if diagnostic_client and process.returncode == 1 and not output
                          else Diagnostic.UNKNOWN)
            return ProcessResult(process.returncode, output, diagnostic)
        except (subprocess.TimeoutExpired, queue.Empty):
            raise Stop('fixture deadline exceeded; completion is uncertain') from None
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
