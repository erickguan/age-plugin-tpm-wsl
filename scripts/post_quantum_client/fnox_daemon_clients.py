"""One encrypted fnox artifact read cold, from memory, and with explicit bypass."""
import hashlib
import math
import time

from .authority import PublicIdentity, Stop
from .cases import ClientCase, PAYLOAD
from .clients import ClientOutcome
from .fnox import FnoxEnvironment, SECRET
from .fnox_daemon_owner import OwnedFnoxDaemon
from .outcomes import ReadExpectation, ReadKind, observe_read
from .references import ClientReferences
from .report import ClientMeasurement

DAEMON_READS = ('fnox_daemon_cold', 'fnox_daemon_warm', 'fnox_daemon_bypass')


class FnoxDaemonEnvironment(FnoxEnvironment):
    def __init__(self, run, staged, process=None, inherited=None, owner_factory=OwnedFnoxDaemon):
        self.daemon = self.receipt = None
        self._original = self._identity_hash = None
        self._index = 0
        self.cache_states = []
        super().__init__(run, staged, process, inherited)
        self.daemon = owner_factory(run, self.inputs.fnox, self.project, self.environment(False), self.process)

    def verify(self):
        super().verify()
        if self.receipt is not None:
            self.receipt.verify()
        elif self.daemon is not None:
            self.daemon.verify()

    def _invoke(self, arguments, offline):
        # Encryption always bypasses the daemon and disables the native helper.
        environment = self.daemon.environment()
        if offline:
            environment['AGE_TPM_WSL_HELPER'] = '/nonexistent/offline-only.exe'
        return self.process(self.daemon.command(arguments, bypass=True), b'', environment,
                            10, cwd=self.project)

    def prepare(self, reference):
        super().prepare(reference)
        self.providers = '[daemon]\nenabled = true\n' + self.providers
        self._config()

    def encrypt(self, payload=PAYLOAD, client='fnox', case=None):
        if (self._original is not None or case != DAEMON_READS[0] or payload != PAYLOAD or client != 'fnox'):
            raise Stop('one fixed offline fnox daemon encryption required')
        result = super().encrypt(payload, client, 'fnox_direct')
        if result.measurement.passed:
            self._original = result.output
        return result

    def decrypt(self, ciphertext, expected=PAYLOAD, client='fnox', case=None):
        raise Stop('daemon reads require the fixed audited execute entry point')

    def _unchanged(self):
        self.verify()
        if self._original is None or self._ciphertext('fnox_direct') != self._original:
            raise Stop('daemon reads require the exact original encrypted artifact')

    def start_daemon(self, identity, namespace):
        self._unchanged()
        canonical = PublicIdentity.parse(identity.encoded, namespace)
        if self.reference != ClientReferences.from_identity(canonical, namespace):
            raise Stop('daemon project must bind the enrolled canonical identity')
        self._identity_hash = hashlib.sha256(canonical.encoded).hexdigest()
        status = self.daemon.start()
        self.cache_states.append(status)
        return status

    def execute(self, controller, case):
        if (self._identity_hash is None or self._index >= len(DAEMON_READS)
                or case != DAEMON_READS[self._index]):
            raise Stop('fixed ordered daemon cold/warm/bypass reads required')
        if controller.summary()['identity_sha256'] != self._identity_hash:
            raise Stop('daemon input does not match original native authority')
        kind = ReadKind.DAEMON_CACHE_HIT if case == 'fnox_daemon_warm' else ReadKind.POSITIVE
        expected = ReadExpectation(ClientCase(case, PAYLOAD, 'fnox', ('fnox',)), 'fnox', kind)
        def invoke():
            started = time.monotonic()
            self._unchanged()
            before = self.daemon.status()
            required = 0 if case == DAEMON_READS[0] else 1
            if before.entries != required:
                raise Stop('owned daemon cache state does not match the read phase')
            result = self.process(self.daemon.command(['get', SECRET], bypass=case == 'fnox_daemon_bypass'),
                                  b'', self.daemon.environment(), 10, cwd=self.project)
            self._unchanged()
            after = self.daemon.status()
            if after.pid != before.pid or after.entries != 1:
                raise Stop('daemon read changed owner or failed to populate the single cache entry')
            matched = result.stdout == PAYLOAD + b'\n'
            measurement = ClientMeasurement('fnox', 'decrypt', 32, math.ceil((time.monotonic() - started) * 1000),
                                            result.exit_code, matched)
            self.cache_states.append(after)
            return ClientOutcome(measurement, PAYLOAD if matched else b'')
        decision = observe_read(controller, expected, invoke)
        self._index += 1
        return decision

    def finish_daemon(self):
        if self._index != len(DAEMON_READS) or self.receipt is not None:
            raise Stop('all matching daemon reads required before one teardown')
        self._unchanged()
        self.receipt = self.daemon.stop()
        self.verify()
        return self.receipt

    def abandon_daemon(self):
        if self.daemon is not None:
            self.daemon.abandon()
