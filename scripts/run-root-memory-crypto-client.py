#!/usr/bin/env python3
"""Run the existing isolated software client matrix against current root producers."""
import argparse
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    if not __debug__:
        raise RuntimeError('software client validation requires active Python assertions')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', choices=['age', 'rage', 'fnox'], required=True)
    parser.add_argument('--algorithm', choices=['rsa2048', 'p256-hpke'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = ROOT / 'scripts' / ('validate-fnox.py' if args.client == 'fnox' else 'validate-age.py')
    spec = importlib.util.spec_from_file_location('root_software_client', source)
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    client.ROOT = ROOT
    sys.argv = [str(source), '--algorithm', args.algorithm, '--output', str(args.output)]
    if args.client != 'fnox':
        sys.argv += ['--client', args.client]
    client.main()


if __name__ == '__main__':
    main()
