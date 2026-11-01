"""Two positive controls and twelve finite client refusals in one lifecycle."""
from .authority import Stop
from .campaign import MinimalCampaign
from .cases import ClientCase, PAYLOAD
from .refusal_cases import REFUSAL_PLAN


class RefusalCampaign(MinimalCampaign):
    def _exercise(self):
        self.service = self.service_factory(self.run.path / 's', self.controller)
        self.service.start()
        encrypted = self.clients.encrypt(PAYLOAD, 'age', 'control')
        self.report.client(self._check_client(encrypted, ClientCase('control', PAYLOAD), 'age', 'encrypt'))
        classical = self.clients.prepare_refusals(self.identity, self.namespace)
        self.report.client(self._check_client(classical, ClientCase('no_downgrade', PAYLOAD), 'age', 'encrypt'))
        decisions = [self.clients.execute(self.controller, case, reader) for case, reader in REFUSAL_PLAN]
        self.service.quiesce()
        if self.service.calls != 4 or not self.clients.complete:
            raise Stop('two controls and two payload refusals require exactly four acknowledged native calls')
        for decision in decisions:
            self.report.checked_read(decision, self.controller.journal)
        if self.report.decryptions != 2 or len(self.report.rejections) != 12:
            raise Stop('both controls and all twelve distinct client refusals required')
