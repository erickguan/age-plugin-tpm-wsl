"""One owning IPC thread, explicit quiescence, and no native cleanup actions."""
import threading

from .authority import Stop
from .endpoint import Endpoint


class ClientService:
    def __init__(self, path, controller):
        self.controller = controller
        self.endpoint = Endpoint(path, controller)
        self.stopping = threading.Event()
        self.failed = threading.Event()
        self.thread = None
        self.calls = 0

    def start(self):
        if self.thread is not None:
            raise Stop('client service cannot be started twice')
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def _serve(self):
        try:
            while not self.stopping.is_set():
                if self.endpoint.serve_once(wait_seconds=0.05):
                    self.calls += 1
        except BaseException:
            # Latch authority before publishing a failure or doing fallible IO.
            try:
                self.controller.stop('owning client service failed; retain authority')
            except BaseException:
                pass
            self.failed.set()
            self.stopping.set()

    def quiesce(self):
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(timeout=25)
            if self.thread.is_alive():
                raise Stop('client service still active; retain endpoint and authority')
        if self.failed.is_set():
            raise Stop('client service failed; no native cleanup permitted')
        self.endpoint.close()

    def abandon(self):
        """Caller must latch its controller first; remove only idle local IPC."""
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(timeout=25)
            if self.thread.is_alive():
                raise Stop('active request retained; no teardown or native cleanup')
        self.endpoint.close()
