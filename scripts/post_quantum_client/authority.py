"""Public references and scoped authority for disposable client campaigns."""
from dataclasses import dataclass
import re

PREFIX = 'age-tpm-wsl-post-quantum-client-'


class Stop(RuntimeError):
    """A campaign must stop; no cleanup authority is implied by this error."""


@dataclass(frozen=True)
class Namespace:
    directory: str

    def __post_init__(self):
        if re.fullmatch(re.escape(PREFIX) + '[0-9a-f]{32}', self.directory) is None:
            raise Stop('reserved lowercase-hex client namespace required')

    @property
    def key_name(self):
        return 'age-tpm-wsl-pq-' + self.directory[len(PREFIX):]


@dataclass(frozen=True)
class PublicIdentity:
    encoded: bytes

    @classmethod
    def parse(cls, encoded, namespace):
        if (not isinstance(encoded, bytes) or len(encoded) != 1300
                or encoded[:3] != b'\x03\x00\x02'
                or encoded[1252:] != b'\x2f' + namespace.key_name.encode('ascii')):
            raise Stop('canonical namespace-bound public identity required')
        public = encoded[3:1252]
        # ML-KEM-768's encoded polynomial coefficients must be canonical.
        for offset in range(0, 1152, 3):
            first, middle, last = public[offset:offset + 3]
            if (first | ((middle & 15) << 8)) >= 3329 or ((middle >> 4) | (last << 4)) >= 3329:
                raise Stop('noncanonical ML-KEM coefficient')
        point = public[1184:]
        prime = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        curve_b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
        x, y = int.from_bytes(point[1:33], 'big'), int.from_bytes(point[33:], 'big')
        if point[0] != 4 or x >= prime or y >= prime or (y * y - x * x * x + 3 * x - curve_b) % prime:
            raise Stop('canonical on-curve uncompressed P-256 point required')
        return cls(encoded)

    @classmethod
    def from_hex(cls, text, namespace):
        if not isinstance(text, str) or re.fullmatch('[0-9a-f]{2600}', text) is None:
            raise Stop('canonical retained public identity required')
        return cls.parse(bytes.fromhex(text), namespace)


@dataclass(frozen=True)
class Observation:
    sid: str
    root_absent: bool
    key_absent: bool

    def validate(self):
        if (not isinstance(self.sid, str) or re.fullmatch(r'S-1-[0-9]+(?:-[0-9]+)+', self.sid) is None
                or type(self.root_absent) is not bool or type(self.key_absent) is not bool):
            raise Stop('invalid independent Windows observation')
        return self
