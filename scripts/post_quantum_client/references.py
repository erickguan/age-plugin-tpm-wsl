"""Public age references; shared with the actual-client offline validator."""
from dataclasses import dataclass

from .authority import PublicIdentity

ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
GENERATORS = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)


def encode_reference(hrp, payload):
    """Original Bech32, including age's long encodings; no Bech32m variant."""
    words = []
    accumulator = bits = 0
    for byte in payload:
        accumulator = ((accumulator << 8) | byte) & 0xfff
        bits += 8
        while bits >= 5:
            bits -= 5
            words.append((accumulator >> bits) & 31)
    if bits:
        words.append((accumulator << (5 - bits)) & 31)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    checksum = 1
    for value in expanded + words + [0] * 6:
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ value
        for index, generator in enumerate(GENERATORS):
            if (top >> index) & 1:
                checksum ^= generator
    checksum ^= 1
    tail = [(checksum >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + '1' + ''.join(ALPHABET[value] for value in words + tail)


@dataclass(frozen=True)
class ClientReferences:
    identity: str
    recipient: str
    classical_recipient: str

    @classmethod
    def from_identity(cls, identity, namespace):
        canonical = PublicIdentity.parse(identity.encoded, namespace)
        public = canonical.encoded[3:1252]
        return cls(encode_reference('age-plugin-tpm-wsl-', canonical.encoded).upper(),
                   encode_reference('age1tagpq', public),
                   encode_reference('age1tpm-wsl', b'\x02\x00\x01' + public[1184:]))
