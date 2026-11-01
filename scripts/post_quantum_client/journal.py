"""Durable public-authority state and replay. It never contains file keys."""
from contextlib import contextmanager
from dataclasses import astuple, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import threading

from .authority import Namespace, Observation, PublicIdentity, Stop
from .durable import PrivateFile

INVALID = 0xA0010001
AUTHENTICATION_FAILED = 0xA0010003  # Validation fixture only; unwrap authentication.


def known_rejection(operation, status):
    return type(status) is int and (
        (operation in {'inspect', 'recover', 'unwrap'} and status == INVALID)
        or (operation == 'unwrap' and status == AUTHENTICATION_FAILED))


OPERATIONS = {'prepare', 'create', 'inspect', 'recover', 'unwrap', 'delete', 'absence', 'remove-root'}


@dataclass
class State:
    namespace: Namespace
    sid: str
    pin: dict
    prepared: bool = False
    identity: PublicIdentity | None = None
    deleted: bool = False
    removed: bool = False
    fatal: bool = False
    pending: str | None = None
    steps: list = field(default_factory=list)
    continuation_owned: bool = True

    def authorize(self, operation):
        if not self.continuation_owned and operation != 'absence':
            raise Stop('reopened journal permits inspection only; no automatic continuation')
        if operation not in OPERATIONS or self.pending:
            raise Stop('invalid operation or unresolved intent')
        if self.fatal and operation != 'absence':
            raise Stop('uncertainty latched; mutation and private operations forbidden')
        if operation == 'prepare' and (self.prepared or self.identity or self.removed):
            raise Stop('root preparation cannot be repeated')
        if operation == 'create' and (not self.prepared or self.identity or self.removed):
            raise Stop('creation requires exclusive root receipt and no prior identity')
        if operation in {'inspect', 'recover', 'unwrap', 'delete'} and (
                not self.prepared or self.identity is None or self.deleted):
            raise Stop('existing operation requires retained enrollment authority')
        if operation == 'remove-root' and (not self.prepared or not self.deleted or self.removed):
            raise Stop('root removal requires successful matching deletion')

    def summary(self):
        """Public state projection, usable while the journal lock is held."""
        return {'namespace': self.namespace.directory,
                'sid_sha256': hashlib.sha256(self.sid.encode()).hexdigest(),
                'identity_sha256': hashlib.sha256(self.identity.encoded).hexdigest() if self.identity else None,
                'prepared': self.prepared, 'deleted': self.deleted, 'removed': self.removed,
                'cleanup_stopped': self.fatal or not self.continuation_owned,
                'continuation_owned': self.continuation_owned,
                'operations': [event['operation'] for event in self.steps if event['kind'] == 'success']}

    def complete(self, operation, result):
        if operation == 'prepare':
            if result != {'namespace': self.namespace.directory, 'name': self.namespace.key_name,
                          'root_created_exclusively': True}:
                raise Stop('exclusive root receipt mismatch')
            self.prepared = True
        elif operation == 'create':
            self.identity = PublicIdentity.from_hex(result['identity'], self.namespace)
        elif operation == 'delete':
            self.deleted = True
        elif operation == 'remove-root':
            if result != {'root_absent': True, 'key_absent': True}:
                raise Stop('root removal absence unverified')
            self.removed = True
        elif operation == 'absence':
            if (set(result) != {'root_absent', 'key_absent'}
                    or any(type(value) is not bool for value in result.values())):
                raise Stop('invalid absence result')
        elif result != {}:
            raise Stop('unexpected journal result fields')


class Session:
    def __init__(self, storage, events, poison, failed=False, owns_campaign=False):
        self.storage, self.poison = storage, poison
        if not events or events[0].get('kind') != 'bootstrap':
            raise Stop('missing durable bootstrap')
        first = events[0]
        namespace = Namespace(first['namespace'])
        Observation(first['sid'], True, True).validate()
        self.state = State(namespace, first['sid'], first['pin'])
        for event in events[1:]:
            self.apply(event)
        # The marker survives even when a success/uncertainty append was not
        # fsynced. Reopening a Journal object can never silently clear it.
        if self.state.pending or self.storage.active() or failed:
            self.state.fatal = True
            self.poison()
            self.append({'kind': 'uncertain', 'reason': 'unfinished or uncertain prior operation'})
        # Replay describes historical authority. Only the process-local object
        # returned by create() owns continuation; disk state cannot grant it.
        self.state.continuation_owned = owns_campaign

    def apply(self, event):
        kind = event['kind']
        if kind == 'intent':
            self.state.authorize(event['operation'])
            self.state.pending = event['operation']
        elif kind in {'success', 'rejected'}:
            if self.state.pending != event['operation']:
                raise Stop('journal result has no matching intent')
            if kind == 'success':
                self.state.complete(event['operation'], event['result'])
            elif (set(event) != {'kind', 'operation', 'status'}
                  or not known_rejection(event['operation'], event['status'])):
                raise Stop('only an exact read-only rejection status is replayable')
            self.state.pending = None
        elif kind == 'uncertain':
            self.state.fatal = True
            self.state.pending = None
        else:
            raise Stop('unknown journal event')
        self.state.steps.append(event)

    def append(self, event):
        try:
            if event['kind'] == 'intent' and not self.state.fatal:
                self.state.authorize(event['operation'])
                self.storage.begin()
            encoded = (json.dumps(event, sort_keys=True) + '\n').encode()
            self.storage.append(encoded)
            self.apply(event)
            if event['kind'] in {'success', 'rejected'} and not self.state.fatal:
                self.storage.complete()
        except (OSError, ValueError, KeyError, TypeError, Stop):
            self.state.fatal = True
            self.poison()
            raise Stop('durable journal update failed; retain state and stop') from None

    def stop(self, reason):
        # Latch outside this transient Session BEFORE fallible evidence IO.
        self.state.fatal = True
        self.poison()
        try:
            self.append({'kind': 'uncertain', 'reason': reason})
        except (OSError, Stop):
            raise Stop('uncertainty could not be saved; retain journal and stop') from None
        raise Stop(reason)


class Journal:
    def __init__(self, path):
        self.path = Path(path)
        self.file = PrivateFile(path)
        self.failed = False
        self.retired = False
        self._owner_pid = None
        self._read_audits = {}
        self._read_decisions = {}
        self._active_read_validation = None

    def poison(self):
        self.failed = True
        self._read_audits.clear()
        self._read_decisions.clear()

    def _read_view(self, session):
        from .report import AuthoritySnapshot
        state = session.state
        authority = AuthoritySnapshot.from_summary(state.summary())
        if (self.failed or not authority.continuation_owned or authority.cleanup_stopped or state.pending
                or not authority.prepared or authority.identity_sha256 is None
                or authority.deleted or authority.removed):
            raise Stop('healthy original enrolled authority required for read audit')
        events = tuple((event['kind'], event.get('operation'), event.get('status', 0))
                       for event in state.steps)
        return authority, events

    def read_audit(self):
        """Issue a process-local receipt; public construction grants no evidence."""
        from .outcomes import ReadAudit
        with self.locked() as session:
            authority, events = self._read_view(session)
            audit = ReadAudit(self, authority, events)
            self._read_audits[id(audit)] = (audit, audit.owner_pid, authority, events)
            return audit

    @contextmanager
    def validated_read_delta(self, before, after):
        """Authenticate and consume two receipts while holding live authority.

        The classifier constructs its decision inside this lock. A later stop
        cannot revive issued receipts; poison invalidates all outstanding ones.
        """
        from .outcomes import ReadAudit
        with self.locked() as session:
            try:
                for audit in (before, after):
                    issued = self._read_audits.get(id(audit))
                    if (not isinstance(audit, ReadAudit) or issued is None or issued[0] is not audit
                            or audit.journal is not self or audit.owner_pid != os.getpid()
                            or issued[1:] != (audit.owner_pid, audit.authority, audit.events)):
                        raise Stop('read receipt was not issued unchanged by this original journal')
                authority, events = self._read_view(session)
                if (before is after or before.authority != authority or after.authority != authority
                        or after.events != events or len(before.events) > len(events)
                        or events[:len(before.events)] != before.events):
                    raise Stop('read receipt authority or live history no longer matches')
                self._active_read_validation = (threading.get_ident(), before, after, authority, events)
                yield events[len(before.events):]
                if self.failed:
                    raise Stop('late uncertainty prevents read acceptance')
            finally:
                self._active_read_validation = None
                # Classification, including failure, is a single-use operation.
                self._read_audits.pop(id(before), None)
                self._read_audits.pop(id(after), None)

    def _register_read_decision(self, decision):
        """Called only by the classifier inside its owning validation window."""
        from .outcomes import ReadDecision
        window = self._active_read_validation
        if (self.failed or window is None or window[0] != threading.get_ident()
                or not isinstance(decision, ReadDecision) or not decision.accepted):
            raise Stop('accepted read requires its active original-journal validation')
        self._read_decisions[id(decision)] = (decision, decision.kind, astuple(decision.measurement),
                                             window[3], window[4])

    def publish_read_decision(self, decision, authority, publish):
        """Consume issued evidence once, with live authority, before cleanup."""
        with self.locked() as session:
            try:
                issued = self._read_decisions.get(id(decision))
                if (issued is None or issued[0] is not decision
                        or issued[1:3] != (decision.kind, astuple(decision.measurement))):
                    raise Stop('read evidence was not issued unchanged by this journal')
                current, events = self._read_view(session)
                if (current != authority or current != issued[3]
                        or events[:len(issued[4])] != issued[4]):
                    raise Stop('read evidence no longer matches live report authority/history')
                publish()
                if self.failed:
                    raise Stop('late stop prevents evidence acceptance')
            except BaseException:
                self.poison()  # Before propagating even a failed report append.
                raise Stop('read evidence failed; retain authority') from None
            finally:
                self._read_decisions.pop(id(decision), None)

    @classmethod
    def create(cls, path, namespace, sid, pin):
        Observation(sid, True, True).validate()
        data = (json.dumps({'kind': 'bootstrap', 'namespace': namespace.directory,
                            'sid': sid, 'pin': pin}, sort_keys=True) + '\n').encode()
        PrivateFile.create(path, data)
        journal = cls(path)
        journal._owner_pid = os.getpid()
        return journal

    def retire(self, checkpoint):
        """Consume matching durable absence evidence under the original authority."""
        from .report import AbsenceCheckpoint, AuthoritySnapshot, RetiredAuthority
        if self.retired or not isinstance(checkpoint, AbsenceCheckpoint):
            raise Stop('unconsumed typed absence checkpoint required')
        with self.locked() as session:
            try:
                current = AuthoritySnapshot.from_summary(session.state.summary())
                successes = [step for step in session.state.steps if step['kind'] == 'success']
                if (not current.verified_absence() or session.state.pending or not successes
                        or successes[-1] != {'kind': 'success', 'operation': 'absence',
                                            'result': {'root_absent': True, 'key_absent': True}}):
                    raise Stop('final independent absence receipt and healthy original owner required')
                if checkpoint.file.identity == self.file.identity:
                    raise Stop('absence evidence must be separate from authority being retired')
                checkpoint.verify(current)
                if self.failed:
                    raise Stop('concurrent stop prevents authority retirement')
                session.storage.retire()
                self.retired = True
                return RetiredAuthority(current, checkpoint.sha256, os.getpid(), self.file)
            except BaseException:
                self.poison()  # May already be unlinked; never infer permission to retry.
                raise Stop('journal retirement failed; retain report/state and stop') from None

    @contextmanager
    def locked(self):
        ready = False
        try:
            with self.file.locked() as storage:
                try:
                    events = [json.loads(line) for line in storage.read().splitlines()]
                    if any(not isinstance(event, dict) for event in events):
                        raise Stop('journal events must be objects')
                    session = Session(storage, events, self.poison, self.failed,
                                      self._owner_pid == os.getpid())
                except (ValueError, TypeError, KeyError, RecursionError):
                    raise Stop('invalid journal; cleanup authority cannot be inferred') from None
                ready = True
                yield session
        except (OSError, Stop) as error:
            if not ready or isinstance(error, OSError):
                self.poison()
            raise
