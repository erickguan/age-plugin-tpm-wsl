#!/usr/bin/env python3
"""Check fixture framing with malformed requests only; never prepare a root/key.

Valid authority matching is covered by the pure Rust tests. Every request here
has an invalid helper payload even if sent to a production executable by mistake.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import subprocess

INVALID = 0xA0010001
NAMESPACE = 'age-tpm-wsl-post-quantum-client-00000000000000000000000000000000'
BASE = ('--acknowledge', 'isolated-disposable-only', '--namespace', NAMESPACE, '--serve')


def frame(operation, payload=b'', status=0):
    return b'ATW1' + bytes([operation]) + struct.pack('<II', status, len(payload)) + payload


@dataclass(frozen=True)
class Case:
    name: str
    request: bytes
    operation: int | None
    arguments: tuple[str, ...] = BASE


def cases():
    malformed_create = frame(8, b'\x00\x01' + b'age-tpm-wsl-pq-' + b'0' * 32)
    return [
        Case('missing_acknowledgment', b'', None, ()),
        Case('bad_acknowledgment', b'', None, ('--acknowledge', 'no', *BASE[2:])),
        Case('production_namespace', b'', None, (*BASE[:3], 'age-plugin-tpm-wsl', '--serve')),
        Case('short_header', b'ATW', None),
        Case('bad_magic', b'FAIL' + frame(8)[4:], None),
        Case('unknown_operation', frame(255), None),
        Case('oversized_length', b'ATW1\x08' + struct.pack('<II', 0, 8193), None),
        Case('trailing_data', malformed_create + b'x', None),
        Case('forbidden_status_payload', frame(8, b'x', 1), None),
        Case('wrong_suite', malformed_create, 8),
        Case('short_create', frame(8, b'\x00\x02x'), 8),
        Case('short_unwrap', frame(9, b'\x05\x14short'), 9),
        Case('short_inspect', frame(2, b'\x03\x00\x02'), 2),
        Case('short_delete', frame(4, b'\x03\x00\x02'), 4),
        Case('empty_legacy_create', frame(1), 1),
    ]


def measure(executable, case):
    result = subprocess.run([str(executable), *case.arguments], input=case.request,
                            capture_output=True, timeout=15)
    if case.operation is None:
        passed = result.returncode != 0 and not result.stdout
    else:
        expected = frame(case.operation, status=INVALID)
        passed = result.returncode == 0 and result.stdout == expected
    return {'result': 'pass' if passed else 'fail', 'exit_code': result.returncode,
            'stdout_bytes': len(result.stdout),
            'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open('x') as reserved:
        reserved.write('{"result": "incomplete"}\n')
    report = {'result': 'incomplete', 'scope': 'malformed framing only; no root/key creation or live lifecycle',
              'validator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(), 'checks': {}}
    try:
        for case in cases():
            report['checks'][case.name] = measure(executable, case)
            print(case.name + ': ' + report['checks'][case.name]['result'], flush=True)
            if report['checks'][case.name]['result'] != 'pass':
                raise RuntimeError('fixture framing check failed: ' + case.name)
        report['result'] = 'pass'
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report['result'] = 'fail'
        report['error'] = str(error)
        raise
    finally:
        args.report.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
