"""One-enrollment lifecycle: authority is durable before every native request."""
import json
import struct

from .authority import PublicIdentity, Stop
from .journal import INVALID, known_rejection
from .process import BinaryPin, BoundedProcess

CLEANUP_FAILED = 0xA0010002
CODES = {'create': 8, 'inspect': 2, 'unwrap': 9, 'delete': 4, 'recover': 10}
MODES = {'prepare': '--prepare-root', 'absence': '--absence', 'remove-root': '--remove-root'}


def frame(operation, payload=b'', status=0):
    if not isinstance(payload, bytes) or len(payload) > 8192:
        raise Stop('invalid bounded protocol payload')
    return b'ATW1' + bytes([operation]) + struct.pack('<II', status, len(payload)) + payload


def response(data, operation):
    if not isinstance(data, bytes) or len(data) < 13 or data[:5] != b'ATW1' + bytes([operation]):
        raise Stop('invalid fixture response header')
    status, length = struct.unpack('<II', data[5:13])
    if length > 8192 or len(data) != 13 + length or (status and length):
        raise Stop('invalid fixture response shape')
    return status, data[13:]


def public_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Stop('duplicate public response field')
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise Stop('public response must be an object')
    return value


class Controller:
    """Inject the process and independent Windows observer for software tests.

    The eventual client wrapper calls forward() directly. Its returned bytes may
    contain a file key; they must go only to the plugin pipe, never into evidence.
    """
    def __init__(self, journal, environment, observe, run=None):
        self.journal, self.environment, self.observe = journal, dict(environment), observe
        self.run = run or BoundedProcess()

    def _checked_observation(self, session):
        observed = self.observe(session.state.namespace).validate()
        if observed.sid != session.state.sid:
            raise Stop('Windows SID changed; no continuation permitted')
        return observed

    def _run(self, session, operation, payload=b''):
        state = session.state
        state.authorize(operation)
        try:
            # Persist outstanding intent before executable/source/SID checks:
            # those observations can fail, and uncertainty logging can fail too.
            session.append({'kind': 'intent', 'operation': operation})
            pin = BinaryPin.load(state.pin)
            pin.verify()
            before = self._checked_observation(session)
            if operation == 'prepare' and not (before.root_absent and before.key_absent):
                raise Stop('reserved namespace or key already exists')
            if operation == 'create' and (before.root_absent or not before.key_absent):
                raise Stop('exclusive prepared root or absent key no longer matches')
            if operation == 'remove-root' and not before.key_absent:
                raise Stop('key absence must precede root removal')
            arguments = [pin.path, '--acknowledge', 'isolated-disposable-only',
                         '--namespace', state.namespace.directory, MODES.get(operation, '--serve')]
            if state.identity is not None:
                arguments += ['--expected-identity', state.identity.encoded.hex()]
            result = self.run(arguments, payload, self.environment, 10)
            if type(result.exit_code) is not int or result.exit_code != 0:
                raise Stop('fixture process failed; completion is uncertain')
            return result.stdout
        except BaseException:
            session.stop('fixture invocation or evidence failed; completion uncertain')

    def admin(self, operation):
        if operation not in MODES:
            raise Stop('unsupported administrative operation')
        with self.journal.locked() as session:
            output = self._run(session, operation)
            try:
                value = public_json(output)
                if operation == 'prepare':
                    if (set(value) != {'namespace', 'name', 'root_created_exclusively'}
                            or value['namespace'] != session.state.namespace.directory
                            or value['name'] != session.state.namespace.key_name
                            or value['root_created_exclusively'] is not True):
                        raise Stop('invalid exclusive root receipt')
                else:
                    if (set(value) != {'key_absent', 'root_absent'} or value['key_absent'] is not True
                            or type(value['root_absent']) is not bool):
                        raise Stop('invalid root/key absence response')
                    observed = self._checked_observation(session)
                    if value != {'key_absent': observed.key_absent, 'root_absent': observed.root_absent}:
                        raise Stop('independent absence observation disagrees')
                    if operation == 'remove-root' and value['root_absent'] is not True:
                        raise Stop('removed root still exists')
                session.append({'kind': 'success', 'operation': operation, 'result': value})
                return value
            except BaseException:
                session.stop('administrative response or durable receipt uncertain')

    def forward(self, request, delivery=None):
        """Relay a frame; an optional pipe delivery holds the journal through ACK."""
        if not isinstance(request, bytes) or len(request) < 13:
            raise Stop('invalid client frame')
        operation = next((name for name, code in CODES.items() if code == request[4]), None)
        if operation is None:
            raise Stop('only post-quantum lifecycle operations are supported')
        request_status, payload = response(request, CODES[operation])
        if request_status:
            raise Stop('client request status must be zero')
        with self.journal.locked() as session:
            state = session.state
            if operation == 'create':
                valid = payload == b'\x00\x02' + state.namespace.key_name.encode()
            elif operation == 'recover':
                valid = payload == state.namespace.key_name.encode()
            elif operation == 'unwrap':
                valid = (state.identity is not None and len(payload) == 2 + 1300 + 1153 + 32
                         and payload[:2] == b'\x05\x14' and payload[2:1302] == state.identity.encoded)
            else:
                valid = state.identity is not None and payload == state.identity.encoded
            if not valid:
                raise Stop('request does not match retained fixture authority')
            output = self._run(session, operation, request)
            try:
                status, returned = response(output, CODES[operation])
                if status:
                    if not known_rejection(operation, status):
                        raise Stop('fatal, unknown or mutation failure status')
                    session.append({'kind': 'rejected', 'operation': operation, 'status': status})
                    return self._deliver(session, output, delivery)
                result = {}
                if operation in {'create', 'recover'}:
                    identity = PublicIdentity.parse(returned, state.namespace)
                    if operation == 'recover' and identity != state.identity:
                        raise Stop('recovery changed retained public identity')
                    if operation == 'create':
                        result['identity'] = identity.encoded.hex()
                elif operation == 'unwrap' and len(returned) != 16:
                    raise Stop('invalid authenticated file key length')
                elif operation == 'inspect':
                    value = public_json(returned)
                    if value.get('name') != state.namespace.key_name or value.get('scheme') != 'mlkem768-p256':
                        raise Stop('inspection identity mismatch')
                elif operation == 'delete':
                    if returned or not self._checked_observation(session).key_absent:
                        raise Stop('matching deletion absence unverified')
                session.append({'kind': 'success', 'operation': operation, 'result': result})
                return self._deliver(session, output, delivery)
            except BaseException:
                # Includes interruption after success/marker retirement and
                # before delivery begins. Latch while still holding authority.
                session.stop('fixture response, receipt or delivery uncertain')

    def _deliver(self, session, output, delivery):
        try:
            if delivery is not None:
                delivery(output)  # Protocol pipe only; never record these bytes.
            if self.journal.failed:
                raise Stop('another caller failed while this operation held authority')
        except BaseException:
            session.stop('protocol delivery interrupted or uncertain; retain state')
        return output

    def stop(self, reason):
        """Latch an external client/transport failure before any cleanup attempt."""
        with self.journal.locked() as session:
            session.stop(reason)

    def read_audit(self):
        """Original-journal receipt only; no response bytes or key hashes."""
        return self.journal.read_audit()

    def summary(self):
        with self.journal.locked() as session:
            return session.state.summary()
