"""Finite public refusal inputs; never touches file keys or native storage."""
from dataclasses import dataclass, field
import hashlib

from .authority import Namespace, PublicIdentity, Stop
from .cases import PAYLOAD
from .mutations import SingleHybrid, VERSION, decode, encode, routing_tag
from .references import ClientReferences, encode_reference
from .refusal_cases import Refusal


@dataclass(frozen=True)
class PreparedRefusals:
    namespace: Namespace
    identity: PublicIdentity = field(repr=False)
    hybrid: bytes = field(repr=False)
    classical: bytes = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.namespace, Namespace) or not isinstance(self.identity, PublicIdentity):
            raise Stop('typed canonical identity and namespace required')
        PublicIdentity.parse(self.identity.encoded, self.namespace)
        SingleHybrid.parse(self.hybrid, self.public)
        self._check_classical()
        wrong = self.wrong_identity()
        encapsulation = SingleHybrid.parse(self.hybrid, self.public).enc
        if routing_tag(self.public, encapsulation) == routing_tag(wrong.encoded[3:1252], encapsulation):
            raise Stop('wrong identity must have a distinct public routing tag')

    @property
    def public(self):
        return self.identity.encoded[3:1252]

    def _check_classical(self):
        if not isinstance(self.classical, bytes) or not 100 <= len(self.classical) <= 4096:
            raise Stop('bounded classical ciphertext required for no-downgrade case')
        header, separator, tail = self.classical.partition(b'\n--- ')
        lines = header.split(b'\n')
        fingerprint = encode(hashlib.sha256(b'\x02\x00\x01' + self.public[1184:]).digest())
        stanza = b'-> tpm-wsl-hpke 2 ' + fingerprint
        if not separator or len(lines) < 3 or lines[:2] != [VERSION, stanza]:
            raise Stop('classical ciphertext must target the retained PCP public point only')
        body = decode(b''.join(lines[2:]), 97)
        mac, separator, payload = tail.partition(b'\n')
        decode(mac, 32)
        if not separator or len(payload) != 16 + len(PAYLOAD) + 16:
            raise Stop('one fixed classical payload required')
        text = encode(body)
        canonical = (VERSION + b'\n' + stanza + b'\n'
                     + b'\n'.join(text[index:index + 64] for index in range(0, len(text), 64))
                     + b'\n--- ' + mac + b'\n' + payload)
        if canonical != self.classical:
            raise Stop('noncanonical classical ciphertext refused')

    def wrong_identity(self):
        # Negation keeps a valid P-256 point, changing public routing without
        # requiring another private key or a second native enrollment.
        point = self.public[1184:]
        prime = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        other = point[:33] + ((-int.from_bytes(point[33:], 'big')) % prime).to_bytes(32, 'big')
        encoded = self.identity.encoded[:3] + self.public[:1184] + other + self.identity.encoded[1252:]
        return PublicIdentity.parse(encoded, self.namespace)

    def reference(self, case):
        if not isinstance(case, Refusal):
            raise Stop('finite refusal case required')
        if case is Refusal.WRONG_IDENTITY:
            return ClientReferences.from_identity(self.wrong_identity(), self.namespace).identity
        if case is Refusal.IDENTITY_VERSION:
            return encode_reference('age-plugin-tpm-wsl-', b'\xff' + self.identity.encoded[1:]).upper()
        return ClientReferences.from_identity(self.identity, self.namespace).identity

    def ciphertext(self, case):
        if not isinstance(case, Refusal):
            raise Stop('finite refusal case required')
        if case is Refusal.NO_DOWNGRADE:
            return self.classical
        if case is Refusal.STANZA_SHAPE:
            lines = self.hybrid.split(b'\n', 3)
            lines[1] = b' '.join(lines[1].split(b' ')[:3])
            return b'\n'.join(lines)
        if case is Refusal.FILE_VERSION:
            return self.hybrid.replace(VERSION + b'\n', b'age-encryption.org/v9\n', 1)
        if case is Refusal.PAYLOAD_AUTH:
            return self.hybrid[:-1] + bytes([self.hybrid[-1] ^ 1])
        return self.hybrid
