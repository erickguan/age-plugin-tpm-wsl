"""Own one disposable software PQ key without reading/hashing private bytes."""
import os
import re
import stat
import subprocess

from .authority import Stop
from .durable import PrivateFile, checked_directory
from .process import BoundedProcess


class RecoveryKey:
    def __init__(self, run, inputs, environment, process):
        self.run, self.inputs = run, inputs
        self.environment, self.process = dict(environment), process
        self.file = None
        self.metadata = None
        self.retired = False
        self._recipient = None

    @staticmethod
    def _metadata(descriptor):
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or not 50 <= info.st_size <= 16384):
            raise Stop('bounded private recovery key file required')
        return info.st_size, info.st_mtime_ns, info.st_ctime_ns

    @classmethod
    def generate(cls, run, inputs, environment, process=None):
        process = process or BoundedProcess()
        run.verify(); inputs.verify()
        pin, expected = inputs.client('age_keygen')
        version = process([pin.path, '--version'], b'', environment, 10)
        if version.exit_code != 0 or version.stdout.decode('utf-8').strip() != expected:
            raise Stop('staged key generator version differs from approval')
        key = cls(run, inputs, environment, process)
        directory = run.subdirectory('recovery-key')
        key.file = PrivateFile.create(directory / 'recovery.key', b'')
        try:
            # The file is reserved first. Private stdout goes directly to its
            # owned descriptor, never a capture pipe, string, digest or report.
            with key.file.locked() as storage:
                child = subprocess.Popen([pin.path, '-pq'], env=key.environment,
                                         stdin=subprocess.DEVNULL, stdout=storage.descriptor,
                                         stderr=subprocess.DEVNULL, umask=0o077)
                try:
                    child.wait(timeout=10)
                    if child.returncode != 0:
                        raise Stop('recovery key generation failed')
                finally:
                    if child.poll() is None:
                        child.kill(); child.wait(timeout=5)
                os.fsync(storage.descriptor); os.fsync(storage.directory)
                key.metadata = key._metadata(storage.descriptor)
            key.recipient()  # Require the native PQ format before enrollment.
            return key
        except BaseException:
            # Keep a partial/uncertain key protected in the retained run. This
            # method creates no native resource and never invents cleanup rights.
            raise Stop('recovery key preparation failed; retain private run') from None

    def _absent(self):
        directory = os.open(self.file.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            checked_directory(directory, self.file.parent_identity)
            try:
                os.stat(self.file.path.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise Stop('recovery key path exists after retirement')
        finally:
            os.close(directory)

    def verify(self):
        self.run.verify(); self.inputs.verify()
        if self.file is None or self.metadata is None:
            raise Stop('complete original recovery key ownership required')
        if self.retired:
            self._absent()
            return
        with self.file.locked() as storage:
            if self._metadata(storage.descriptor) != self.metadata:
                raise Stop('recovery key metadata changed')

    def recipient(self):
        self.verify()
        if self.retired:
            raise Stop('retired recovery key cannot derive a recipient')
        pin, _ = self.inputs.client('age_keygen')
        result = self.process([pin.path, '-y', str(self.file.path)], b'', self.environment, 10)
        self.verify()
        if result.exit_code != 0:
            raise Stop('recovery public recipient derivation failed')
        recipient = result.stdout.decode('ascii').strip()
        if re.fullmatch(r'age1pq1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{20,4000}', recipient) is None:
            raise Stop('bounded native post-quantum public recipient required')
        if self._recipient is not None and recipient != self._recipient:
            raise Stop('recovery public recipient changed')
        self._recipient = recipient
        return recipient

    def retire(self):
        """Caller must first prove native absence; remove only this exact file."""
        self.verify()
        if self.retired:
            raise Stop('recovery key retirement cannot be repeated')
        with self.file.locked() as storage:
            if self._metadata(storage.descriptor) != self.metadata:
                raise Stop('recovery key changed before retirement')
            storage.retire()
        self._absent()
        self.retired = True
