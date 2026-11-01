#!/usr/bin/env python3
"""Seed fuzzers with synthetic public formats and frame boundaries; no keys."""
from pathlib import Path
import argparse
import base64
import struct
import hashlib
import json

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parent / 'corpus',
                    help='destination for deterministic public corpus files')
root = parser.parse_args().output
# Public parser fixture, not a generated private key or an enrolled recipient.
recipient = bytes([1, 0x80]) + bytes(254) + bytes([1])
name = b"age-tpm-wsl-" + b"0" * 32
identity = recipient + bytes([len(name)]) + name
# SEC2 P-256 generator: public test point only, with no enrolled key.
p256 = bytes([2, 0, 1, 4]) + bytes.fromhex(
    '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
    '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
p256_identity = p256 + bytes([len(name)]) + name
seeds = {
    "formats": {"recipient": recipient, "identity": identity, "name": name,
                "empty": b"", "bad_version": bytes([255]) + recipient[1:],
                "p256_recipient": p256, "p256_identity": p256_identity,
                "unknown_suite": bytes([2, 0, 2]) + p256[3:],
                "off_curve": bytes([2, 0, 1, 4]) + bytes(64)},
    "helper_frame": {},
    "stanza": {},
}
for operation in range(1, 11):
    for length in (0, 16, 8192):
        payload = bytes([42]) * length
        frame = b"ATW1" + bytes([operation]) + struct.pack("<II", 0, length) + payload
        seeds["helper_frame"][f"op{operation}_len{length}"] = frame
seeds["helper_frame"]["error"] = b"ATW1\x03" + struct.pack("<II", 0x80090016, 0)
seeds["helper_frame"]["oversized"] = b"ATW1\x03" + struct.pack("<II", 0, 8193)
seeds["helper_frame"]["short"] = b"ATW1"
for label, operation, payload in [
    ('rsa_unwrap', 3, identity + bytes(256)),
    ('p256_unwrap', 7, struct.pack('>H', len(p256_identity)) + p256_identity + p256[3:] + bytes(32)),
    ('p256_create', 6, bytes([0, 1]) + name),
]:
    seeds['helper_frame'][label] = b'ATW1' + bytes([operation]) + struct.pack('<II', 0, len(payload)) + payload
fingerprint = base64.b64encode(bytes(32)).rstrip(b"=")
seeds["stanza"]["valid_shape"] = b"1\0" + fingerprint + b"\0\0" + bytes(256)
seeds["stanza"]["bad_version"] = b"2\0" + fingerprint + b"\0\0" + bytes(256)
seeds["stanza"]["p256_shape"] = b"2\0" + fingerprint + b"\0\0" + p256[3:] + bytes(32)
seeds["stanza"]["extra_arg"] = b"1\0" + fingerprint + b"\0extra\0" + bytes(256)
# Independent public contract fixture; the TPM areas are unusable stand-ins.
fixture = Path(__file__).resolve().parent.parent / 'notes/aws-lc-hybrid-evaluation/kat-components.json'
pq_public = bytes.fromhex(json.loads(fixture.read_text())['public_key'])
pq_recipient = b'\x03\x00\x02' + pq_public
pq_identity = pq_recipient + b'\x2fage-tpm-wsl-pq-' + b'0' * 32
pq_fixture = json.loads((fixture.parent / 'go-fixture.json').read_text())
pq_enc = bytes.fromhex(pq_fixture['enc'])
pq_body = bytes.fromhex(pq_fixture['body'])
pq_tag = bytes.fromhex(pq_fixture['routing_tag'])
assert len(pq_public) == 1249 and len(pq_enc) == 1153 and len(pq_body) == 32 and len(pq_tag) == 4
seeds['formats'].update({
    'pq_native_recipient': pq_public,
    'pq_identity': pq_identity,
    'pq_name': pq_identity[-47:],
    'pq_internal_recipient': pq_recipient,
    'pq_short_recipient': pq_public[:-1],
    'pq_trailing_recipient': pq_public + b'\0',
    'pq_short_identity': pq_identity[:-1],
    'pq_trailing_identity': pq_identity + b'\0',
    'pq_wrong_suite_identity': b'\x03\x00\x01' + pq_identity[3:],
    'pq_wrong_name_length': pq_identity[:1252] + b'\x2e' + pq_identity[1253:],
    'pq_wrong_name': pq_identity[:-1] + b'G',
    'pq_compressed_point': pq_public[:1184] + b'\x03' + pq_public[1185:],
    'pq_off_curve': pq_public[:1184] + b'\x04' + bytes(64),
})
pq_args = [base64.b64encode(value).rstrip(b'=') for value in (pq_tag, pq_enc)]
pq_stanza = b'\0'.join([*pq_args, b'', pq_body])
assert len(pq_stanza) == 1579
seeds['stanza'].update({
    'pq_shape': pq_stanza,
    'pq_padded_tag': b'\0'.join([pq_args[0] + b'==', pq_args[1], b'', pq_body]),
    'pq_padded_enc': b'\0'.join([pq_args[0], pq_args[1] + b'=', b'', pq_body]),
    'pq_short_tag': b'\0'.join([pq_args[0][:-1], pq_args[1], b'', pq_body]),
    'pq_short_enc': b'\0'.join([pq_args[0], pq_args[1][:-1], b'', pq_body]),
    'pq_extra_arg': b'\0'.join([*pq_args, b'extra', pq_body]),
    'pq_short_body': pq_stanza[:-1],
    'pq_long_body': pq_stanza + b'\0',
})
for label, operation, payload in [
    ('post_quantum_create', 8, b'\x00\x02' + pq_identity[-47:]),
    ('post_quantum_recover', 10, pq_identity[-47:]),
    ('post_quantum_unwrap', 9, b'\x05\x14' + pq_identity + pq_enc + pq_body),
    ('pq_wrong_suite', 8, b'\x00\x01' + pq_identity[-47:]),
    ('pq_wrong_identity_length', 9, b'\xff\xff' + pq_identity + pq_enc + pq_body),
]:
    seeds['helper_frame'][label] = b'ATW1' + bytes([operation]) + struct.pack('<II', 0, len(payload)) + payload
commitment = hashlib.sha256(b'ATW-PQ-RECIPIENT-v1\0age1tagpq\0' + pq_recipient).digest()
parent = bytes.fromhex('0025000b0003047200000006010000430020') + b'\x11' * 32
child = bytes.fromhex('0008000b00000452000000100020') + b'\x22' * 32
pq_record = b'ATWPQC01' + pq_identity + commitment + b''.join(struct.pack('>H', len(x)) + x for x in [parent, b'\x33' * 64, child])
assert len(pq_identity) == 1300 and len(pq_record) == 1506
assert hashlib.sha256(pq_record).hexdigest() == 'fb533a818ec43483a7e033d54bfcb7517183babed89d1e3a7ebd9994af085057'
seeds['custody_record'] = {
    'identity': pq_identity,
    'expected_and_record': pq_identity + pq_record,
    'wrong_expected': pq_identity[:-1] + b'1' + pq_record,
    'record_trailing': pq_identity + pq_record + b'\0',
    'record_oversized': pq_identity + pq_record + bytes(4097 - len(pq_record)),
    'truncated': pq_identity + pq_record[:-1],
    'empty': b'',
}
for target, entries in seeds.items():
    directory = root / target
    directory.mkdir(parents=True, exist_ok=True)
    for label, data in entries.items():
        (directory / label).write_bytes(data)
print("Seeded synthetic parser corpus; no TPM operations performed.")
