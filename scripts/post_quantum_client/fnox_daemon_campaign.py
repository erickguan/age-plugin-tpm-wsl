"""Finite owned-daemon workflow; software teardown precedes all native cleanup."""
import sys

from .authority import Stop
from .campaign import MinimalCampaign
from .cases import ClientCase, PAYLOAD
from .fnox_daemon_clients import DAEMON_READS


class FnoxDaemonCampaign(MinimalCampaign):
    def _exercise(self):
        self.service = self.service_factory(self.run.path / 's', self.controller)
        self.service.start()
        control = ClientCase(DAEMON_READS[0], PAYLOAD, 'fnox', ('fnox',))
        encrypted = self.clients.encrypt(payload=PAYLOAD, client='fnox', case=control.label)
        self.report.client(self._check_client(encrypted, control, 'fnox', 'encrypt'))
        self.clients.start_daemon(self.identity, self.namespace)
        decisions = [self.clients.execute(self.controller, label) for label in DAEMON_READS]
        self.category = 'cleanup'
        receipt = self.clients.finish_daemon()
        self.service.quiesce()
        if self.service.calls != 2:
            raise Stop('cold and explicit bypass must make exactly two owning-service calls')
        self.category = 'evidence'
        self.report.authority(self.snapshot())
        for decision in decisions:
            self.report.checked_read(decision, self.controller.journal)
        self.report.daemon_retirement(receipt, tuple(self.clients.cache_states))
        if not self.report.daemon_retired:
            raise Stop('owned daemon retirement evidence required before native cleanup')

    def _stop(self, category):
        super()._stop(category)  # Latch original native authority FIRST.
        try:
            self.clients.abandon_daemon()
        except BaseException:
            print('Owned daemon teardown unconfirmed; retain run and short runtime.', file=sys.stderr)
            raise Stop('owned daemon teardown unconfirmed; no native cleanup or retry') from None
