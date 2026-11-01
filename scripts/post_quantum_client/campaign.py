"""One explicitly enrolled disposable age round trip; no implicit cleanup/retry."""
from dataclasses import replace

from .authority import PublicIdentity, Stop
from .cases import ClientCase, minimal_cases
from .controller import Controller, frame, response
from .journal import Journal
from .references import ClientReferences
from .report import AuthoritySnapshot
from .service import ClientService


class MinimalCampaign:
    def __init__(self, run, namespace, report, clients, observe,
                 controller_factory=Controller, service_factory=ClientService, cases=None):
        self.run, self.namespace, self.report, self.clients = run, namespace, report, clients
        self.observe = observe
        self.controller_factory, self.service_factory = controller_factory, service_factory
        self.controller = self.service = None
        self.identity = None
        self.category = 'preflight'
        self.failed_measurement = None
        self.cases = minimal_cases() if cases is None else tuple(cases)
        if not self.cases or any(not isinstance(case, ClientCase) for case in self.cases):
            raise Stop('explicit nonempty bounded client plan required')

    def snapshot(self):
        return AuthoritySnapshot.from_summary(self.controller.summary())

    def _check_client(self, outcome, case, client, operation):
        measurement = replace(outcome.measurement, case=case.label, encryptor=case.encryptor).validate()
        matched = (measurement.client == client and measurement.operation == operation
                   and measurement.payload_bytes == len(case.payload))
        if operation == 'decrypt':
            matched = matched and outcome.output == case.payload
        else:
            matched = matched and bool(outcome.output)
        if not matched or not measurement.passed:
            self.failed_measurement = replace(measurement, matched=False)
            raise Stop('disposable client result failed or exceeded the default bound')
        return measurement

    def _exercise(self):
        self.service = self.service_factory(self.run.path / 's', self.controller)
        self.service.start()
        reads = []
        for case in self.cases:
            encrypted = self.clients.encrypt(payload=case.payload, client=case.encryptor, case=case.label)
            self.report.client(self._check_client(encrypted, case, case.encryptor, 'encrypt'))
            for client in case.decryptors:
                decrypted = self.clients.decrypt(encrypted.output, expected=case.payload, client=client, case=case.label)
                reads.append(self._check_client(decrypted, case, client, 'decrypt'))
        self.service.quiesce()  # Includes final ACK before any native cleanup.
        if self.service.calls < len(reads):
            raise Stop('not every positive decryption traversed the owning helper service')
        for measurement in reads:
            self.report.client(measurement)

    def _after_verified_absence(self, current):
        """Optional client-owned private-file retirement, never native cleanup."""

    def _stop(self, category):
        # Do this FIRST: even report failure and service teardown can fail.
        if self.controller is not None:
            try:
                self.controller.stop('minimal campaign failed; retain full authority')
            except BaseException:
                pass
        if self.service is not None:
            try:
                self.service.abandon()
            except BaseException:
                pass
        try:
            if self.report.phase == 'verified':
                self.report.retirement_failed()
            elif self.report.phase != 'complete':
                if self.failed_measurement is not None:
                    self.report.client(self.failed_measurement)
                self.report.failure(category)
        except BaseException:
            pass  # The reserved report and exact private journal remain evidence.

    def execute(self):
        try:
            self.run.verify()
            self.clients.preflight()
            before = self.observe(self.namespace).validate()
            if not before.key_absent or not before.root_absent:
                raise Stop('new namespace/key must independently be absent')
            journal = Journal.create(self.run.path / 'journal', self.namespace, before.sid,
                                     self.clients.inputs.helper.record())
            self.controller = self.controller_factory(journal, self.clients.env, self.observe)
            self.report.authority(self.snapshot())
            self.category = 'enrollment'
            self.controller.admin('prepare')
            status, encoded = response(self.controller.forward(frame(8, b'\x00\x02' + self.namespace.key_name.encode())), 8)
            if status:
                raise Stop('disposable enrollment failed')
            identity = PublicIdentity.parse(encoded, self.namespace)
            self.identity = identity
            self.category = 'evidence'
            self.report.authority(self.snapshot())
            self.clients.prepare(ClientReferences.from_identity(identity, self.namespace))
            self.category = 'client'
            self._exercise()
            self.category = 'cleanup'
            self.controller.forward(frame(4, identity.encoded))
            self.controller.admin('remove-root')
            absence = self.controller.admin('absence')
            if absence != {'key_absent': True, 'root_absent': True}:
                raise Stop('final native absence receipt must confirm both key and root absence')
            current = self.snapshot()
            self.report.authority(current)
            observation = self.observe(self.namespace)
            self.report.validate_absence(current, observation)
            self._after_verified_absence(current)
            checkpoint = self.report.checkpoint(current, observation)
            retired = journal.retire(checkpoint)
            self.report.complete(checkpoint, retired)
            return self.report.path
        except BaseException as error:
            category = 'interrupted' if isinstance(error, (KeyboardInterrupt, SystemExit)) else self.category
            self._stop(category)
            raise Stop('minimal campaign stopped; retain run artifacts and full public journal') from None
