"""Read verdicts from original-owner journal transitions, never response bodies.

Read expectations do not prepare input or grant cleanup authority. Local and
payload refusals require confirmed diagnostics and distinct native transitions.
"""
from dataclasses import dataclass, field, replace
from enum import Enum
import os

from .authority import Stop
from .cases import ClientCase
from .clients import ClientOutcome
from .journal import AUTHENTICATION_FAILED, INVALID, Journal
from .report import AuthoritySnapshot, ClientMeasurement
from .refusal_cases import LOCAL_REFUSALS, Refusal


class ReadKind(Enum):
    POSITIVE = 'positive'
    KNOWN_INVALID = 'known-invalid'
    AUTHENTICATION_REJECTED = 'authentication-rejected'
    SOFTWARE_RECOVERY = 'software-recovery'
    LOCAL_REJECTED = 'local-rejected'
    PAYLOAD_REJECTED = 'payload-rejected'
    DAEMON_CACHE_HIT = 'daemon-cache-hit'
    UNCERTAIN = 'uncertain'


@dataclass(frozen=True)
class ReadExpectation:
    case: ClientCase = field(repr=False)
    client: str
    kind: ReadKind

    def __post_init__(self):
        if (not isinstance(self.case, ClientCase) or self.client not in self.case.decryptors
                or not isinstance(self.kind, ReadKind)
                or self.kind not in {ReadKind.POSITIVE, ReadKind.KNOWN_INVALID, ReadKind.AUTHENTICATION_REJECTED,
                                     ReadKind.SOFTWARE_RECOVERY, ReadKind.LOCAL_REJECTED, ReadKind.PAYLOAD_REJECTED,
                                     ReadKind.DAEMON_CACHE_HIT}):
            raise Stop('explicit bounded read expectation required')
        if self.kind is ReadKind.SOFTWARE_RECOVERY and (self.case.label != 'or_recovery' or self.client != 'age'):
            raise Stop('software recovery requires its explicit case and reader')
        if self.kind is ReadKind.DAEMON_CACHE_HIT and (self.case.label != 'fnox_daemon_warm' or self.client != 'fnox'):
            raise Stop('memory-cache outcome requires the explicit owned-daemon warm read')
        refusal = Refusal.for_label(self.case.label)
        if (self.kind is ReadKind.LOCAL_REJECTED and refusal not in LOCAL_REFUSALS
                or self.kind is ReadKind.PAYLOAD_REJECTED and refusal is not Refusal.PAYLOAD_AUTH):
            raise Stop('refusal kind must match its finite prepared case')


@dataclass(frozen=True)
class ReadAudit:
    journal: object = field(repr=False, compare=False)
    authority: AuthoritySnapshot
    events: tuple
    owner_pid: int = field(default_factory=os.getpid)


@dataclass(frozen=True)
class ReadDecision:
    kind: ReadKind
    measurement: ClientMeasurement

    @property
    def accepted(self):
        return self.kind in {ReadKind.POSITIVE, ReadKind.KNOWN_INVALID, ReadKind.AUTHENTICATION_REJECTED,
                             ReadKind.SOFTWARE_RECOVERY, ReadKind.LOCAL_REJECTED, ReadKind.PAYLOAD_REJECTED,
                             ReadKind.DAEMON_CACHE_HIT}


def classify_read(expectation, outcome, before, after):
    """Classify once under live journal ownership, receipt and history checks.

    A successful client must match its bytes AND one successful native unwrap.
    A known invalid client requires exit 1, no plaintext and one exact durable
    unwrap rejection. Other refusals require a confirmed client diagnostic and
    the finite case's exact zero/success native transition.
    """
    if not isinstance(expectation, ReadExpectation) or not isinstance(outcome, ClientOutcome):
        raise Stop('typed read expectation and client outcome required')
    if (not isinstance(before, ReadAudit) or not isinstance(after, ReadAudit)
            or type(after.journal) is not Journal):
        raise Stop('original-owner read audit pair required')
    measurement = replace(outcome.measurement, case=expectation.case.label,
                          encryptor=expectation.case.encryptor).validate()
    with after.journal.validated_read_delta(before, after) as delta:
        kind = ReadKind.UNCERTAIN
        matched = (measurement.client == expectation.client and measurement.operation == 'decrypt'
                   and measurement.payload_bytes == len(expectation.case.payload)
                   and measurement.elapsed_ms <= 10000 and isinstance(outcome.output, bytes))
        if matched:
            success = (('intent', 'unwrap', 0), ('success', 'unwrap', 0))
            rejected_status = (AUTHENTICATION_FAILED if expectation.kind is ReadKind.AUTHENTICATION_REJECTED
                               else INVALID)
            rejected = (('intent', 'unwrap', 0), ('rejected', 'unwrap', rejected_status))
            if (expectation.kind is ReadKind.POSITIVE and delta == success
                    and measurement.passed and outcome.output == expectation.case.payload):
                kind = ReadKind.POSITIVE
            elif (expectation.kind in {ReadKind.SOFTWARE_RECOVERY, ReadKind.DAEMON_CACHE_HIT} and delta == ()
                  and measurement.passed and outcome.output == expectation.case.payload):
                kind = expectation.kind
            elif (expectation.kind in {ReadKind.LOCAL_REJECTED, ReadKind.PAYLOAD_REJECTED}
                  and measurement.exit_code == 1 and not measurement.matched and outcome.output == b''
                  and outcome.diagnostic is Refusal.for_label(expectation.case.label).diagnostic
                  and delta == (() if expectation.kind is ReadKind.LOCAL_REJECTED else success)):
                kind = expectation.kind
            elif (expectation.kind in {ReadKind.KNOWN_INVALID, ReadKind.AUTHENTICATION_REJECTED} and delta == rejected
                  and measurement.exit_code == 1 and not measurement.matched and outcome.output == b''):
                kind = expectation.kind
        decision = ReadDecision(kind, measurement)
        if decision.accepted:
            after.journal._register_read_decision(decision)
    return decision


def observe_read(controller, expectation, invoke):
    """Capture a single read's evidence and latch uncertainty before fallible IO.

    The later finite-mutation workflow must bind invoke to its prepared input.
    This function neither consumes protocol frames nor performs native cleanup.
    """
    try:
        if not isinstance(expectation, ReadExpectation):
            raise Stop('typed expectation required before client invocation')
        before = controller.read_audit()
        outcome = invoke()
        after = controller.read_audit()
        decision = classify_read(expectation, outcome, before, after)
        if not decision.accepted:
            raise Stop('client/native result is not the exact expected read outcome')
        return decision
    except BaseException:
        try:
            controller.stop('read classification or invocation uncertain; retain authority')
        except BaseException:
            pass
        raise Stop('read outcome uncertain; no cleanup or retry authority') from None
