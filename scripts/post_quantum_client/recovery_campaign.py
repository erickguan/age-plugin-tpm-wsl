"""Duplicate-recipient and independent PQ recovery within one shared lifecycle."""
from .authority import Stop
from .campaign import MinimalCampaign
from .cases import ClientCase, PAYLOAD
from .outcomes import ReadExpectation, ReadKind, observe_read


class RecoveryCampaign(MinimalCampaign):
    def _exercise(self):
        self.service = self.service_factory(self.run.path / 's', self.controller)
        self.service.start()
        decisions = []
        cases = (ClientCase('duplicate', PAYLOAD, 'age', ('age', 'rage')),
                 ClientCase('or_shared', PAYLOAD))
        for case in cases:
            encrypted = self.clients.encrypt(payload=PAYLOAD, client='age', case=case.label)
            self.report.client(self._check_client(encrypted, case, 'age', 'encrypt'))
            for client in case.decryptors:
                expected = ReadExpectation(case, client, ReadKind.POSITIVE)
                def invoke():
                    return self.clients.decrypt(encrypted.output, expected=PAYLOAD, client=client, case=case.label)
                decisions.append(observe_read(self.controller, expected, invoke))
        recovery = ReadExpectation(ClientCase('or_recovery', PAYLOAD), 'age', ReadKind.SOFTWARE_RECOVERY)
        decisions.append(observe_read(self.controller, recovery, self.clients.recover))
        self.service.quiesce()
        if self.service.calls != 3 or len(decisions) != 4:
            raise Stop('three native reads and one zero-helper recovery required')
        for decision in decisions:
            self.report.checked_read(decision, self.controller.journal)
        if self.report.decryptions != 3 or self.report.software_recovery_reads != 1:
            raise Stop('complete distinct native and software recovery evidence required')

    def _after_verified_absence(self, current):
        if not current.verified_absence():
            raise Stop('native absence must precede recovery key retirement')
        self.clients.retire_recovery()
        self.report.recovery_key_retired(self.clients.key, current)
