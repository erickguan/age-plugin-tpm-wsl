"""Typed, redacted evidence and durable absence checkpoints; no live execution."""
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re

from .authority import Namespace, Stop
from .durable import PrivateFile, checked_directory
from .inputs import sha256_text
from .refusal_cases import LOCAL_REFUSALS, REFUSAL_LABELS, Refusal


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


@dataclass(frozen=True)
class AuthoritySnapshot:
    namespace: str
    sid_sha256: str
    identity_sha256: str | None
    prepared: bool
    deleted: bool
    removed: bool
    cleanup_stopped: bool
    continuation_owned: bool

    def __post_init__(self):
        Namespace(self.namespace)
        sha256_text(self.sid_sha256)
        if self.identity_sha256 is not None:
            sha256_text(self.identity_sha256)
        for name in ('prepared', 'deleted', 'removed', 'cleanup_stopped', 'continuation_owned'):
            if type(getattr(self, name)) is not bool:
                raise Stop('strict authority flags required')
        if ((self.identity_sha256 is not None and not self.prepared)
                or (self.deleted and self.identity_sha256 is None) or (self.removed and not self.deleted)
                or (not self.continuation_owned and not self.cleanup_stopped)):
            raise Stop('inconsistent public authority state')

    @classmethod
    def from_summary(cls, value):
        fields = set(cls.__dataclass_fields__)
        if not isinstance(value, dict) or set(value) != fields | {'operations'}:
            raise Stop('exact public authority summary required')
        return cls(**{name: value[name] for name in fields})

    def verified_absence(self):
        return (self.prepared and self.deleted and self.removed and self.identity_sha256 is not None
                and self.continuation_owned and not self.cleanup_stopped)


@dataclass(frozen=True)
class ClientMeasurement:
    client: str
    operation: str
    payload_bytes: int
    elapsed_ms: int
    exit_code: int
    matched: bool
    case: str = 'minimal'
    encryptor: str = 'age'

    def validate(self):
        if (self.client not in {'age', 'rage', 'fnox'}
                or self.operation not in {'encrypt', 'decrypt', 'fnox-read'}
                or type(self.payload_bytes) is not int or not 0 <= self.payload_bytes <= 4194304
                or type(self.elapsed_ms) is not int or self.elapsed_ms < 0
                or type(self.exit_code) is not int or type(self.matched) is not bool
                or self.encryptor not in {'age', 'rage', 'fnox'}
                or not isinstance(self.case, str)
                or (re.fullmatch(r'minimal|first|warm|bytes_[0-9]{1,7}|fnox_direct|fnox_cache|control|component_mlkem|component_p256|component_tag|duplicate|or_shared|or_recovery|fnox_daemon_cold|fnox_daemon_warm|fnox_daemon_bypass', self.case) is None
                    and self.case not in REFUSAL_LABELS)):
            raise Stop('invalid public client measurement')
        if self.case.startswith('bytes_') and int(self.case[6:]) != self.payload_bytes:
            raise Stop('measurement case must match its public payload length')
        return self

    @property
    def passed(self):
        return self.exit_code == 0 and self.matched and self.elapsed_ms <= 10000


@dataclass(frozen=True)
class AbsenceCheckpoint:
    file: PrivateFile
    sha256: str
    snapshot: AuthoritySnapshot
    owner_pid: int

    def verify(self, current):
        if (os.getpid() != self.owner_pid or current != self.snapshot
                or not current.verified_absence()):
            raise Stop('checkpoint does not match current owned cleanup authority')
        with self.file.locked() as storage:
            data = storage.read()
            if hashlib.sha256(data).hexdigest() != self.sha256:
                raise Stop('durable absence checkpoint changed')
            final = json.loads(data.splitlines()[-1])
            if (final['kind'] != 'verified_absence' or final['root_absent'] is not True
                    or final['key_absent'] is not True or final['authority'] != asdict(current)):
                raise Stop('durable absence record mismatch')


@dataclass(frozen=True)
class RetiredAuthority:
    snapshot: AuthoritySnapshot
    checkpoint_sha256: str
    owner_pid: int
    journal_file: PrivateFile

    def verify(self, checkpoint):
        if (self.owner_pid != os.getpid() or self.snapshot != checkpoint.snapshot
                or self.checkpoint_sha256 != checkpoint.sha256):
            raise Stop('retirement receipt ownership/checkpoint mismatch')
        directory = os.open(self.journal_file.path.parent,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            checked_directory(directory, self.journal_file.parent_identity)
            try:
                os.stat(self.journal_file.path.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise Stop('authority path exists after reported retirement')
        finally:
            os.close(directory)


class CampaignReport:
    """Only the creating object/PID can append; methods accept public types only.

    The driver must stop its owning Controller before handling report failure.
    This object never initiates native cleanup or retires the authority journal.
    """
    def __init__(self, path, namespace):
        self.path, self.namespace = Path(path), namespace
        self.file = PrivateFile(path)
        self.owner_pid = None
        self.failed = False
        self.phase = 'open'
        self.latest = None
        self.sid = self.identity = None
        self.decryptions = 0
        self.control_readers = set()
        self.rejections = set()
        self.native_recovery_reads = set()
        self.software_recovery_reads = 0
        self.recovery_key_removed = False
        self.daemon_native_reads = set()
        self.daemon_cache_hits = 0
        self.daemon_retired = False

    @classmethod
    def create(cls, path, namespace, inputs_sha256):
        sha256_text(inputs_sha256)
        PrivateFile.create(path, encoded({'kind': 'campaign', 'namespace': namespace.directory,
                                          'inputs_sha256': inputs_sha256, 'result': 'incomplete'}))
        report = cls(path, namespace)
        report.owner_pid = os.getpid()
        return report

    def _append(self, value):
        if self.owner_pid != os.getpid() or self.failed:
            raise Stop('report reopening/failure does not grant continuation')
        try:
            with self.file.locked() as storage:
                storage.append(encoded(value))
        except BaseException:
            self.failed = True
            raise Stop('durable report write failed; retain authority and stop') from None

    def authority(self, snapshot):
        if self.phase != 'open' or snapshot.namespace != self.namespace.directory:
            raise Stop('report namespace or phase mismatch')
        if self.sid is not None and snapshot.sid_sha256 != self.sid:
            raise Stop('report SID binding changed')
        if self.identity is not None and snapshot.identity_sha256 != self.identity:
            raise Stop('report retained identity changed')
        if self.latest is not None and any(
                getattr(self.latest, name) and not getattr(snapshot, name)
                for name in ('prepared', 'deleted', 'removed', 'cleanup_stopped')):
            raise Stop('report authority cannot roll back completed or stopped state')
        self._append({'kind': 'authority', 'authority': asdict(snapshot)})
        self.latest = snapshot
        self.sid = snapshot.sid_sha256
        self.identity = snapshot.identity_sha256

    def client(self, measurement):
        measurement.validate()
        if measurement.case.startswith('fnox_daemon_') and measurement.operation in {'decrypt', 'fnox-read'}:
            raise Stop('daemon reads require an original journal-issued checked decision')
        self._publish_client(measurement)

    def _publish_client(self, measurement):
        measurement.validate()
        if (self.phase != 'open' or self.latest is None or self.identity is None
                or self.latest.cleanup_stopped or not self.latest.continuation_owned
                or self.latest.deleted or self.latest.removed):
            raise Stop('client evidence requires healthy retained enrollment authority')
        if not measurement.passed:
            self.phase = 'failed'  # Latch before fallible evidence or interruption.
        self._append({'kind': 'client', **asdict(measurement),
                      'result': 'pass' if measurement.passed else 'fail', 'bound_ms': 10000})
        if measurement.passed and measurement.operation in {'decrypt', 'fnox-read'}:
            self.decryptions += 1

    def checked_read(self, decision, journal):
        """Publish only single-use journal-issued decisions, never failed reads as successes."""
        from .outcomes import ReadDecision, ReadKind
        from .journal import AUTHENTICATION_FAILED, Journal
        if not isinstance(decision, ReadDecision) or type(journal) is not Journal:
            raise Stop('issued read decision and original journal required')
        measurement = decision.measurement.validate()
        if (self.phase != 'open' or self.latest is None or self.identity is None
                or self.latest.cleanup_stopped or not self.latest.continuation_owned
                or self.latest.deleted or self.latest.removed):
            raise Stop('checked read evidence requires healthy report authority')
        def publish():
            if decision.kind is ReadKind.POSITIVE:
                if measurement.case.startswith('fnox_daemon_'):
                    expected_reads = set() if measurement.case == 'fnox_daemon_cold' else {'fnox_daemon_cold'}
                    expected_hits = 0 if measurement.case == 'fnox_daemon_cold' else 1
                    if (measurement.case not in {'fnox_daemon_cold', 'fnox_daemon_bypass'}
                            or measurement.client != 'fnox' or self.daemon_native_reads != expected_reads
                            or self.daemon_cache_hits != expected_hits):
                        raise Stop('daemon native controls must surround one checked warm read')
                self._publish_client(measurement)
                if measurement.case.startswith('fnox_daemon_'):
                    self.daemon_native_reads.add(measurement.case)
                if measurement.case == 'control' and measurement.client in {'age', 'rage'}:
                    self.control_readers.add(measurement.client)
                if measurement.case in {'duplicate', 'or_shared'}:
                    key = (measurement.case, measurement.client)
                    if key in self.native_recovery_reads:
                        raise Stop('recovery native case cannot be published twice')
                    self.native_recovery_reads.add(key)
            elif decision.kind is ReadKind.DAEMON_CACHE_HIT:
                if (self.daemon_native_reads != {'fnox_daemon_cold'} or self.daemon_cache_hits
                        or self.decryptions != 1 or measurement.case != 'fnox_daemon_warm'
                        or measurement.client != 'fnox' or measurement.operation != 'decrypt'
                        or measurement.payload_bytes != 32 or not measurement.passed):
                    raise Stop('one checked daemon memory hit must follow its genuine cold control')
                self._append({'kind': 'cache_hit', **asdict(measurement), 'result': 'pass', 'native': False,
                              'native_unwrap_successes': 0, 'cache_entries': 1, 'bound_ms': 10000,
                              'evidence': 'owned-fnox-daemon-memory-cache'})
                self.daemon_cache_hits += 1
                self.decryptions += 1
            elif decision.kind is ReadKind.SOFTWARE_RECOVERY:
                expected = {('duplicate', 'age'), ('duplicate', 'rage'), ('or_shared', 'age')}
                if (self.native_recovery_reads != expected or self.decryptions != 3
                        or self.software_recovery_reads or measurement.case != 'or_recovery'
                        or measurement.client != 'age' or measurement.operation != 'decrypt'
                        or measurement.payload_bytes != 32 or not measurement.passed):
                    raise Stop('software recovery requires all three genuine native controls')
                self._append({'kind': 'recovery', **asdict(measurement), 'result': 'pass',
                              'native': False, 'bound_ms': 10000,
                              'evidence': 'independent-pq-key-helper-disabled'})
                self.software_recovery_reads += 1
            elif decision.kind in {ReadKind.LOCAL_REJECTED, ReadKind.PAYLOAD_REJECTED}:
                refusal = Refusal.for_label(measurement.case)
                payload = decision.kind is ReadKind.PAYLOAD_REJECTED
                key = (measurement.case, measurement.client)
                if (refusal is None or payload != (refusal is Refusal.PAYLOAD_AUTH)
                        or (not payload and refusal not in LOCAL_REFUSALS)
                        or self.control_readers != {'age', 'rage'} or self.decryptions != 2
                        or measurement.client not in {'age', 'rage'} or measurement.operation != 'decrypt'
                        or measurement.payload_bytes != 32 or measurement.encryptor != 'age'
                        or measurement.exit_code != 1 or measurement.matched or measurement.elapsed_ms > 10000
                        or key in self.rejections):
                    raise Stop('distinct client refusal requires both genuine positive controls')
                self._append({'kind': 'rejection', **asdict(measurement), 'result': 'pass',
                              'bound_ms': 10000, 'plaintext_bytes': 0,
                              'diagnostic': refusal.diagnostic.value,
                              'native_unwrap_successes': 1 if payload else 0,
                              'evidence': 'client-payload-authentication-failure' if payload else 'client-local-refusal'})
                self.rejections.add(key)
            elif decision.kind is ReadKind.AUTHENTICATION_REJECTED:
                key = (measurement.case, measurement.client)
                if (self.control_readers != {'age', 'rage'} or measurement.client not in {'age', 'rage'}
                        or measurement.case not in {'component_mlkem', 'component_p256', 'component_tag'}
                        or measurement.operation != 'decrypt' or measurement.payload_bytes != 32
                        or measurement.encryptor != 'age' or measurement.matched
                        or measurement.exit_code != 1 or measurement.elapsed_ms > 10000
                        or key in self.rejections):
                    raise Stop('bounded distinct component rejection requires both positive controls')
                self._append({'kind': 'rejection', **asdict(measurement), 'result': 'pass',
                              'bound_ms': 10000, 'helper_status': AUTHENTICATION_FAILED,
                              'evidence': 'helper-authentication-failure', 'plaintext_bytes': 0})
                self.rejections.add(key)
            else:
                raise Stop('uncertain read can never be accepted evidence')
        journal.publish_read_decision(decision, self.latest, publish)

    def daemon_retirement(self, receipt, states):
        from .fnox_daemon_owner import DaemonRetirement
        if (not isinstance(receipt, DaemonRetirement) or receipt.owner.run.path != self.path.parent
                or self.phase != 'open' or self.latest is None or self.latest.cleanup_stopped
                or self.latest.deleted or self.latest.removed or not self.latest.continuation_owned
                or self.daemon_native_reads != {'fnox_daemon_cold', 'fnox_daemon_bypass'}
                or self.daemon_cache_hits != 1 or self.decryptions != 3 or self.daemon_retired):
            raise Stop('daemon retirement requires its complete original-owner read matrix')
        states = receipt.checked_cache_states(states)
        self._append({'kind': 'daemon_retired', 'result': 'pass', 'pid': receipt.pid,
                      'cache_states': [asdict(state) for state in states],
                      'socket_absent': True, 'runtime_absent': True})
        self.daemon_retired = True

    def recovery_key_retired(self, key, authority):
        from .recovery_key import RecoveryKey
        if (not isinstance(key, RecoveryKey) or not key.retired or key.run.path != self.path.parent
                or self.phase != 'open' or self.latest != authority or not authority.verified_absence()
                or self.software_recovery_reads != 1 or self.recovery_key_removed):
            raise Stop('owned recovery key absence requires completed native absence first')
        key.verify()
        self._append({'kind': 'recovery_key_retired', 'result': 'pass', 'key_absent': True})
        self.recovery_key_removed = True

    def failure(self, category):
        if self.phase in {'verified', 'complete'} or category not in {'preflight', 'enrollment', 'client', 'cleanup', 'evidence', 'interrupted'}:
            raise Stop('fixed failure category required before verified completion')
        self.phase = 'failed'
        self._append({'kind': 'failure', 'category': category, 'result': 'fail'})

    def complete(self, checkpoint, retired):
        if (self.phase != 'verified' or not isinstance(checkpoint, AbsenceCheckpoint)
                or checkpoint.file is not self.file or not isinstance(retired, RetiredAuthority)
                or retired.owner_pid != self.owner_pid or retired.owner_pid != os.getpid()
                or retired.snapshot != checkpoint.snapshot or retired.checkpoint_sha256 != checkpoint.sha256
                or self.latest != checkpoint.snapshot):
            raise Stop('matching successful journal retirement required')
        retired.verify(checkpoint)
        checkpoint.verify(self.latest)
        self.phase = 'complete'
        self._append({'kind': 'complete', 'result': 'pass', 'authority_retired': True})

    def retirement_failed(self):
        if self.phase != 'verified':
            raise Stop('retirement failure requires a prior durable absence checkpoint')
        self.phase = 'failed'
        self._append({'kind': 'retirement_failure', 'result': 'fail'})

    def validate_absence(self, snapshot, observation):
        """Check fresh independent absence before any client-owned key retirement."""
        observation.validate()
        if (self.phase != 'open' or not self.decryptions or self.latest != snapshot
                or not snapshot.verified_absence() or snapshot.namespace != self.namespace.directory
                or snapshot.sid_sha256 != hashlib.sha256(observation.sid.encode()).hexdigest()
                or not observation.root_absent or not observation.key_absent):
            raise Stop('matching independent absence and successful client result required')

    def checkpoint(self, snapshot, observation):
        self.validate_absence(snapshot, observation)
        if self.software_recovery_reads and not self.recovery_key_removed:
            raise Stop('owned recovery key absence must precede the checkpoint')
        if self.daemon_cache_hits and not self.daemon_retired:
            raise Stop('owned daemon retirement must precede the absence checkpoint')
        self.phase = 'verified'
        self._append({'kind': 'verified_absence', 'authority': asdict(snapshot),
                      'root_absent': True, 'key_absent': True, 'successful_reads': self.decryptions})
        with self.file.locked() as storage:
            checksum = hashlib.sha256(storage.read()).hexdigest()
        return AbsenceCheckpoint(self.file, checksum, snapshot, self.owner_pid)
