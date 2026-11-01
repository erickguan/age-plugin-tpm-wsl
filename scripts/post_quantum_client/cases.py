"""Finite positive payload/client plans; never creates native resources."""
from dataclasses import dataclass, field
import re

from .authority import Stop
from .refusal_cases import REFUSAL_LABELS

PAYLOAD = b'disposable-post-quantum-client-1'
SIZES = (0, 4, 256, 1024, 2048, 4096, 8192, 65535, 65536, 65537, 1048576, 4194304)


@dataclass(frozen=True)
class ClientCase:
    label: str
    payload: bytes = field(repr=False)
    encryptor: str = 'age'
    decryptors: tuple = ('age',)

    def __post_init__(self):
        if (not isinstance(self.label, str) or (re.fullmatch(r'minimal|first|warm|bytes_[0-9]{1,7}|fnox_direct|fnox_cache|control|component_mlkem|component_p256|component_tag|duplicate|or_shared|or_recovery|fnox_daemon_cold|fnox_daemon_warm|fnox_daemon_bypass', self.label) is None
                                              and self.label not in REFUSAL_LABELS)
                or not isinstance(self.payload, bytes) or len(self.payload) > 4194304
                or not isinstance(self.encryptor, str) or self.encryptor not in {'age', 'rage', 'fnox'}
                or not isinstance(self.decryptors, tuple) or not self.decryptors
                or any(not isinstance(name, str) for name in self.decryptors)
                or len(set(self.decryptors)) != len(self.decryptors)
                or any(name not in {'age', 'rage', 'fnox'} for name in self.decryptors)):
            raise Stop('finite bounded positive client case required')
        if self.label in REFUSAL_LABELS:
            if self.payload != PAYLOAD or self.encryptor != 'age' or 'fnox' in self.decryptors:
                raise Stop('fixed age-produced refusal workflow required')
        if self.label in {'duplicate', 'or_shared', 'or_recovery'}:
            if self.payload != PAYLOAD or self.encryptor != 'age' or 'fnox' in self.decryptors:
                raise Stop('fixed age-produced recovery workflow required')
            if self.label in {'or_shared', 'or_recovery'} and self.decryptors != ('age',):
                raise Stop('native PQ shared recovery uses the pinned age reader')
        if self.label == 'control' or self.label.startswith('component_'):
            if self.encryptor != 'age' or self.payload != PAYLOAD or 'fnox' in self.decryptors:
                raise Stop('fixed age-produced component workflow required')
        if self.label.startswith('fnox_'):
            if self.encryptor != 'fnox' or self.decryptors != ('fnox',) or self.payload != PAYLOAD:
                raise Stop('fixed isolated fnox case required')
        elif self.encryptor == 'fnox' or 'fnox' in self.decryptors:
            raise Stop('fnox requires its explicit workflow case')
        if self.label.startswith('bytes_') and int(self.label[6:]) != len(self.payload):
            raise Stop('case label must match its public payload length')


def minimal_cases():
    return (ClientCase('minimal', PAYLOAD),)


def positive_cases():
    payloads = [('first', PAYLOAD), ('warm', PAYLOAD)]
    pattern = bytes(range(256))
    payloads += [('bytes_' + str(size), (pattern * ((size + 255) // 256))[:size]) for size in SIZES]
    return tuple(ClientCase(label, payload, source, ('age', 'rage'))
                 for label, payload in payloads for source in ('age', 'rage'))
