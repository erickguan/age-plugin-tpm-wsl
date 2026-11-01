"""Finite component mutations bound to their exact client invocation; no CLI."""
import base64
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac

from .authority import Namespace, PublicIdentity, Stop
from .cases import ClientCase, PAYLOAD
from .outcomes import ReadExpectation, ReadKind, observe_read

INFO = b'age-encryption.org/mlkem768p256tag'
VERSION = b'age-encryption.org/v1'
TAG = b'mlkem768p256tag'


def decode(text, length):
    try:
        value = base64.b64decode(text + b'=' * (-len(text) % 4), validate=True)
    except ValueError:
        raise Stop('invalid canonical public mutation input') from None
    if len(value) != length or encode(value) != text:
        raise Stop('unexpected canonical mutation input length')
    return value


def encode(value):
    return base64.b64encode(value).rstrip(b'=')


def routing_tag(public, enc):
    # Exact public prefilter from crates/post_quantum/src/crypto.rs. No private
    # material: HMAC-SHA256(INFO, enc || SHA256(public P256 point)[:4])[:4].
    fingerprint = hashlib.sha256(public[1184:]).digest()[:4]
    return hmac.digest(INFO, enc + fingerprint, 'sha256')[:4]


class Mutation(Enum):
    CONTROL = 'control'
    MLKEM = 'mlkem'
    P256 = 'p256'
    WRAPPED_TAG = 'wrapped-tag'


@dataclass(frozen=True)
class SingleHybrid:
    enc: bytes = field(repr=False)
    body: bytes = field(repr=False)
    mac: bytes = field(repr=False)
    payload: bytes = field(repr=False)

    @classmethod
    def parse(cls, ciphertext, public):
        # Intentionally one age-generated stanza and one fixed 32-byte payload.
        # This is not an arbitrary age parser; grease/multiple stanzas refuse.
        if not isinstance(ciphertext, bytes) or not 100 <= len(ciphertext) <= 4096:
            raise Stop('bounded single-stanza ciphertext required')
        header, separator, tail = ciphertext.partition(b'\n--- ')
        lines = header.split(b'\n')
        if not separator or len(lines) != 3 or lines[0] != VERSION:
            raise Stop('one canonical hybrid stanza required')
        arguments = lines[1].split(b' ')
        if len(arguments) != 4 or arguments[:2] != [b'->', TAG]:
            raise Stop('canonical hybrid stanza arguments required')
        tag, enc = decode(arguments[2], 4), decode(arguments[3], 1153)
        body = decode(lines[2], 32)
        mac, separator, payload = tail.partition(b'\n')
        if not separator or len(payload) != 16 + len(PAYLOAD) + 16:
            raise Stop('one bounded disposable age payload required')
        decode(mac, 32)
        if enc[1088] != 4 or tag != routing_tag(public, enc):
            raise Stop('hybrid routing does not bind the retained public identity')
        parsed = cls(enc, body, mac, payload)
        if parsed.render(public) != ciphertext:
            raise Stop('noncanonical mutation input refused')
        return parsed

    def render(self, public):
        header = (VERSION + b'\n-> ' + TAG + b' ' + encode(routing_tag(public, self.enc))
                  + b' ' + encode(self.enc) + b'\n' + encode(self.body))
        return header + b'\n--- ' + self.mac + b'\n' + self.payload


@dataclass(frozen=True)
class PreparedRead:
    namespace: Namespace
    identity: PublicIdentity = field(repr=False)
    original: bytes = field(repr=False)
    mutation: Mutation

    def __post_init__(self):
        if not isinstance(self.namespace, Namespace) or not isinstance(self.identity, PublicIdentity):
            raise Stop('typed retained identity and namespace required')
        PublicIdentity.parse(self.identity.encoded, self.namespace)
        if not isinstance(self.mutation, Mutation):
            raise Stop('finite prepared mutation required')
        SingleHybrid.parse(self.original, self.public)

    @property
    def public(self):
        return self.identity.encoded[3:1252]

    def ciphertext(self):
        parsed = SingleHybrid.parse(self.original, self.public)
        enc, body = bytearray(parsed.enc), bytearray(parsed.body)
        if self.mutation is Mutation.MLKEM:
            enc[0] ^= 1
        elif self.mutation is Mutation.P256:
            # Use the retained valid receiver point, not an off-curve bit flip
            # that would be refused by Linux's public routing check.
            point = self.public[1184:]
            if enc[1088:] == point:
                raise Stop('P-256 mutation must change the original encapsulation')
            enc[1088:] = point
        elif self.mutation is Mutation.WRAPPED_TAG:
            body[-1] ^= 1
        return SingleHybrid(bytes(enc), bytes(body), parsed.mac, parsed.payload).render(self.public)

    @property
    def label(self):
        return {Mutation.CONTROL: 'control', Mutation.MLKEM: 'component_mlkem',
                Mutation.P256: 'component_p256', Mutation.WRAPPED_TAG: 'component_tag'}[self.mutation]

    def execute(self, clients, controller, client='age'):
        if client not in {'age', 'rage'}:
            raise Stop('prepared component reads require age or rage')
        kind = ReadKind.POSITIVE if self.mutation is Mutation.CONTROL else ReadKind.AUTHENTICATION_REJECTED
        expectation = ReadExpectation(ClientCase(self.label, PAYLOAD, 'age', (client,)), client, kind)
        def invoke():
            # Preparation and invocation are one seam: callers cannot substitute
            # ciphertext or a callback after the expected mutation is selected.
            identity_hash = hashlib.sha256(self.identity.encoded).hexdigest()
            if controller.summary()['identity_sha256'] != identity_hash:
                raise Stop('prepared input does not match current enrolled identity')
            return clients.decrypt(self.ciphertext(), expected=PAYLOAD, client=client, case='minimal')
        return observe_read(controller, expectation, invoke)
