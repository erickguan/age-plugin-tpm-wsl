"""Component exercise within the shared original-owner enrollment lifecycle."""
from .authority import Stop
from .campaign import MinimalCampaign
from .cases import ClientCase, PAYLOAD
from .mutations import Mutation, PreparedRead


class ComponentCampaign(MinimalCampaign):
    def _exercise(self):
        self.service = self.service_factory(self.run.path / 's', self.controller)
        self.service.start()
        control = ClientCase('control', PAYLOAD, 'age', ('age', 'rage'))
        encrypted = self.clients.encrypt(payload=PAYLOAD, client='age', case='control')
        self.report.client(self._check_client(encrypted, control, 'age', 'encrypt'))
        decisions = []
        for mutation in Mutation:
            prepared = PreparedRead(self.namespace, self.identity, encrypted.output, mutation)
            for client in control.decryptors:
                decisions.append(prepared.execute(self.clients, self.controller, client))
        self.service.quiesce()
        if self.service.calls != 8 or len(decisions) != 8:
            raise Stop('component exercise requires exactly eight completed owning-service reads')
        for decision in decisions:
            self.report.checked_read(decision, self.controller.journal)
        expected = {(case, client) for case in ('component_mlkem', 'component_p256', 'component_tag')
                    for client in ('age', 'rage')}
        if (self.report.decryptions != 2 or self.report.control_readers != {'age', 'rage'}
                or self.report.rejections != expected):
            raise Stop('positive controls and complete bounded rejection coverage required')
