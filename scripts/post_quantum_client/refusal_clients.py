"""Own the finite refusal inputs and bind each diagnostic-aware invocation."""
import hashlib
import math
import time

from .authority import PublicIdentity, Stop
from .cases import ClientCase, PAYLOAD
from .clients import ClientEnvironment, ClientOutcome
from .outcomes import ReadExpectation, ReadKind, observe_read
from .references import ClientReferences
from .refusal_cases import REFUSAL_PLAN, Refusal
from .refusals import PreparedRefusals
from .report import ClientMeasurement


class RefusalEnvironment(ClientEnvironment):
    def __init__(self, run, staged, process=None, inherited=None):
        self._hybrid = self._prepared = None
        self._identities = {}
        self._index = 0
        super().__init__(run, staged, process, inherited)
        self.inputs.client('rage')

    def verify(self):
        super().verify()
        if self._prepared is not None:
            if (self._hybrid != self._prepared.hybrid
                    or self.reference != ClientReferences.from_identity(self._prepared.identity, self._prepared.namespace)):
                raise Stop('prepared refusal inputs or public reference changed')
            for artifact in self._identities.values():
                artifact.verify()

    def encrypt(self, payload=PAYLOAD, client='age', case=None):
        if self._hybrid is not None or case != 'control' or client != 'age' or payload != PAYLOAD:
            raise Stop('one fixed age control encryption required')
        result = super().encrypt(payload, client, case)
        if result.measurement.passed:
            self._hybrid = result.output
        return result

    def prepare_refusals(self, identity, namespace):
        self.verify()
        if self._hybrid is None or self._prepared is not None or self._index:
            raise Stop('original control ciphertext required for one preparation')
        canonical = PublicIdentity.parse(identity.encoded, namespace)
        if self.reference != ClientReferences.from_identity(canonical, namespace):
            raise Stop('refusal preparation must bind the original enrolled identity')
        started = time.monotonic()
        result = self.process([self.inputs.age.path, '--encrypt', '--recipient', self.reference.classical_recipient],
                              PAYLOAD, self.environment(True), 10)
        if result.exit_code != 0:
            raise Stop('offline no-downgrade encryption failed')
        self._prepared = PreparedRefusals(namespace, canonical, self._hybrid, result.stdout)
        for case in (Refusal.WRONG_IDENTITY, Refusal.IDENTITY_VERSION):
            self._identities[case] = self.run.write_public(case.label + '.txt',
                                                         (self._prepared.reference(case) + '\n').encode())
        self.verify()
        measurement = ClientMeasurement('age', 'encrypt', 32, math.ceil((time.monotonic() - started) * 1000),
                                        result.exit_code, True)
        return ClientOutcome(measurement, result.stdout)

    @property
    def complete(self):
        return self._index == len(REFUSAL_PLAN)

    def execute(self, controller, case, reader):
        if (self._prepared is None or self.complete
                or (case, reader) != REFUSAL_PLAN[self._index]):
            raise Stop('fixed ordered refusal case and reader required')
        self.verify()
        if controller.summary()['identity_sha256'] != hashlib.sha256(self._prepared.identity.encoded).hexdigest():
            raise Stop('prepared refusals do not match current enrolled authority')
        kind = (ReadKind.POSITIVE if case is Refusal.CONTROL else
                ReadKind.PAYLOAD_REJECTED if case is Refusal.PAYLOAD_AUTH else ReadKind.LOCAL_REJECTED)
        expected = ReadExpectation(ClientCase(case.label, PAYLOAD, 'age', (reader,)), reader, kind)
        def invoke():
            self.verify()
            artifact = self._identities.get(case, self.identity)
            pin, _ = self.inputs.client(reader)
            environment = dict(self.environment(False), LC_ALL='C', LANG='C', NO_COLOR='1')
            started = time.monotonic()
            result = self.process([pin.path, '--decrypt', '--identity', str(artifact.path)],
                                  self._prepared.ciphertext(case), environment, 10,
                                  stdout_limit=65568, diagnostic_client=reader)
            self.verify()
            measurement = ClientMeasurement(reader, 'decrypt', 32, math.ceil((time.monotonic() - started) * 1000),
                                            result.exit_code, result.stdout == PAYLOAD)
            return ClientOutcome(measurement, result.stdout, result.diagnostic)
        decision = observe_read(controller, expected, invoke)
        self._index += 1
        return decision
