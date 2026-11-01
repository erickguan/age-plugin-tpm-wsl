"""Finite duplicate/OR client adapter; software recovery never invokes the helper."""
import math
import time

from .authority import Stop
from .cases import PAYLOAD
from .clients import ClientEnvironment, ClientOutcome
from .recovery_key import RecoveryKey
from .report import ClientMeasurement


class RecoveryEnvironment(ClientEnvironment):
    def __init__(self, run, staged, process=None, inherited=None):
        self.key = None
        self.phase = 0
        self._ciphertexts = {}
        self._shared_ciphertext = None
        super().__init__(run, staged, process, inherited)
        self.inputs.client('age_keygen')

    def verify(self):
        super().verify()
        if self.key is not None:
            self.key.verify()
        if self._shared_ciphertext is not None and self._ciphertexts.get('or_shared') != self._shared_ciphertext:
            raise Stop('retained shared ciphertext changed')

    def preflight(self):
        super().preflight()
        if self.key is not None:
            raise Stop('recovery key generation cannot be repeated')
        # Called by the explicit native runner before Journal/root enrollment.
        self.key = RecoveryKey.generate(self.run, self.inputs, self.environment(True), self.process)

    def _expect(self, operation, case, client, payload):
        steps = (('encrypt', 'duplicate', 'age'), ('decrypt', 'duplicate', 'age'),
                 ('decrypt', 'duplicate', 'rage'), ('encrypt', 'or_shared', 'age'),
                 ('decrypt', 'or_shared', 'age'), ('recover', 'or_recovery', 'age'))
        if (self.phase >= len(steps) or (operation, case, client) != steps[self.phase]
                or payload != PAYLOAD or self.key is None or self.reference is None):
            raise Stop('fixed ordered duplicate/OR workflow required')
        self.verify()

    def encrypt(self, payload=PAYLOAD, client='age', case=None):
        self._expect('encrypt', case, client, payload)
        started = time.monotonic()
        extra = self.reference.recipient if case == 'duplicate' else self.key.recipient()
        command = [self.inputs.age.path, '--encrypt', '--recipient', self.reference.recipient,
                   '--recipient', extra]
        result = self.process(command, payload, self.environment(True), 10)
        self.verify()
        header, separator, _ = result.stdout.partition(b'\n--- ')
        expected_hybrid = 2 if case == 'duplicate' else 1
        matched = (bool(separator) and header.startswith(b'age-encryption.org/v1\n')
                   and header.count(b'\n-> mlkem768p256tag ') == expected_hybrid
                   and header.count(b'\n-> ') == 2)
        measurement = ClientMeasurement('age', 'encrypt', 32, math.ceil((time.monotonic() - started) * 1000),
                                        result.exit_code, matched)
        if measurement.passed:
            self._ciphertexts[case] = result.stdout
            if case == 'or_shared':
                self._shared_ciphertext = result.stdout
            self.phase += 1
        return ClientOutcome(measurement, result.stdout)

    def decrypt(self, ciphertext, expected=PAYLOAD, client='age', case=None):
        self._expect('decrypt', case, client, expected)
        if ciphertext != self._ciphertexts.get(case):
            raise Stop('native read must use the exact retained case ciphertext')
        outcome = super().decrypt(ciphertext, expected, client, case)
        self.verify()
        if outcome.measurement.passed:
            self.phase += 1
        return outcome

    def recover(self):
        self._expect('recover', 'or_recovery', 'age', PAYLOAD)
        ciphertext = self._shared_ciphertext
        if not isinstance(ciphertext, bytes):
            raise Stop('exact original shared ciphertext required for recovery')
        started = time.monotonic()
        self.key.recipient()  # Recheck the generated key's public continuity.
        result = self.process([self.inputs.age.path, '--decrypt', '--identity', str(self.key.file.path)],
                              ciphertext, self.environment(True), 10)
        self.verify()
        measurement = ClientMeasurement('age', 'decrypt', 32, math.ceil((time.monotonic() - started) * 1000),
                                        result.exit_code, result.stdout == PAYLOAD)
        if measurement.passed:
            self.phase += 1
        return ClientOutcome(measurement, result.stdout)

    def retire_recovery(self):
        if self.phase != 6 or self.key is None:
            raise Stop('successful complete recovery workflow required before key retirement')
        self.key.retire()
        self.phase += 1
