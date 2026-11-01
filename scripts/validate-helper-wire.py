#!/usr/bin/env python3
"""Send hostile binary frames to the actual Windows helper without creating keys."""
import argparse
import json
from pathlib import Path
import struct
import subprocess


def frame(operation, payload=b'', status=0):
    return b'ATW1' + bytes([operation]) + struct.pack('<II', status, len(payload)) + payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    cases = {
        'empty': b'',
        'bad_magic': b'NOPE' + frame(3)[4:],
        'unknown_operation': frame(0),
        'oversized': b'ATW1\x03' + struct.pack('<II', 0, 8193),
        'short_header': frame(3)[:10],
        'short_payload': frame(3, b'1234')[:-1],
        'trailing_data': frame(3) + b'x',
    }
    report = {'checks': {}}
    for name, request in cases.items():
        result = subprocess.run([str(args.helper.resolve())], input=request, capture_output=True, timeout=20)
        assert result.returncode != 0 and result.stdout == b'', name
        report['checks'][name] = 'pass'
    for name, request in {'invalid_identity': frame(3), 'nonzero_request_status': frame(3, status=1),
                          'invalid_create_name': frame(1, b'not-an-allowed-name'),
                          'unknown_suite': frame(6, b'\x00\x02age-tpm-wsl-' + b'0' * 32),
                          'short_suite': frame(6, b'\x00'),
                          'short_new_unwrap': frame(7, b'\x00'),
                          'oversized_identity_length': frame(7, b'\xff\xff')}.items():
        result = subprocess.run([str(args.helper.resolve())], input=request, capture_output=True, timeout=20)
        assert result.returncode == 0, name
        output = result.stdout
        assert len(output) == 13 and output[:5] == request[:5], name
        status, length = struct.unpack('<II', output[5:])
        assert status != 0 and length == 0, name
        report['checks'][name] = 'pass'
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
