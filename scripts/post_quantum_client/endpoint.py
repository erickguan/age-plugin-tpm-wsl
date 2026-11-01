"""One owning controller services private unwrap requests, without payload logs."""
import os
from pathlib import Path
import socket
import threading

from .authority import Stop
from .channel import (ACK, REQUEST_END, RESPONSE_END, Channel, check_peer,
                      private_parent, socket_identity, validate_frame)


class Endpoint:
    def __init__(self, path, controller, seconds=10):
        summary = controller.summary()
        if not summary['continuation_owned'] or summary['cleanup_stopped']:
            raise Stop('only the healthy original controller can host clients')
        self.path, self.controller, self.seconds = Path(path), controller, seconds
        self.parent = private_parent(self.path)
        self.pid = os.getpid()
        self.busy = threading.Lock()
        self.closed = False
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # The private parent protects the entry while its mode is tightened.
            # bind() is exclusive: an existing entry is never unlinked/replaced.
            self.listener.bind(str(self.path))
            self.path.chmod(0o600)
            self.identity = socket_identity(self.path)
            self.listener.listen(1)
        except (OSError, Stop):
            self.listener.close()
            raise

    def verify(self):
        if (self.closed or os.getpid() != self.pid or private_parent(self.path) != self.parent
                or socket_identity(self.path) != self.identity):
            raise Stop('owning endpoint identity changed')

    def fail(self):
        self.controller.stop('local IPC completion uncertain; no automatic cleanup')

    def serve_once(self, wait_seconds=0.1):
        """Return false on idle accept, true only after wrapper output acknowledgment.

        Driver callers must stop/report any exception. There is no autonomous
        retry, helper recovery, native cleanup or background lifecycle action.
        """
        if not self.busy.acquire(blocking=False):
            raise Stop('another request is active; no concurrent service permitted')
        try:
            self.verify()
            self.listener.settimeout(wait_seconds)
            try:
                stream, _ = self.listener.accept()
            except socket.timeout:
                return False
            with stream:
                channel = Channel(stream, self.seconds)
                check_peer(stream)
                self.verify()
                request = channel.frame(request=True)
                channel.marker(REQUEST_END)
                def deliver(returned):
                    returned = validate_frame(returned)
                    channel.send(returned + RESPONSE_END)
                    # Keep the journal lock until protocol stdout is flushed and
                    # acknowledged. Lifecycle calls cannot race delivery.
                    channel.marker(ACK)
                    channel.eof()

                self.controller.forward(request, delivery=deliver)
                return True
        except BaseException:
            # Interruptions after a durable unwrap result still leave transport
            # completion unknown. Latch before relinquishing the owning service.
            self.fail()
            raise Stop('local IPC failed') from None
        finally:
            self.busy.release()

    def close(self):
        if self.closed:
            return
        if not self.busy.acquire(blocking=False):
            raise Stop('client request still active; retain endpoint and stop')
        try:
            self.verify()
            self.listener.close()
            self.path.unlink()  # Exact verified socket only; never a directory.
            self.closed = True
        except (OSError, Stop):
            self.listener.close()
            self.fail()
            raise
        finally:
            self.busy.release()

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.close()
