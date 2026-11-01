#!/usr/bin/env python3
"""Scan both actual PQ workspace target graphs without changing their lock."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

PROJECT = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    inputs = [PROJECT / name for name in ['Cargo.toml', 'Cargo.lock', 'helper/Cargo.toml', 'crates/post_quantum/Cargo.toml', 'vendor/aws-lc-rs-provenance.json']]
    report = {'result': 'fail', 'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_sha256': {str(p.relative_to(PROJECT)): sha256(p) for p in inputs},
              'scanner_sha256': sha256(Path(__file__)), 'scans': [],
              'limits': ['Exact locked workspace graph with target filtering; workspace development fixtures remain included',
                         'Windows enables the module receiver feature; Linux scan does not request it',
                         'Default advisory policy and all raw diagnostics retained; local safe-crate provenance and upstream registry identity are separate gates',
                         'No formal cryptographic audit, FIPS certification or production custody/client acceptance claim']}
    try:
        for label, target, features in [('windows', 'x86_64-pc-windows-gnu', ['--features', 'age-tpm-wsl-post-quantum/seed-restoration']),
                                         ('linux', 'x86_64-unknown-linux-gnu', [])]:
            command = ['cargo', 'deny', '--manifest-path', str(PROJECT / 'Cargo.toml'), '--workspace', '--locked', '--target', target] + features + ['--format', 'json', 'check', 'advisories']
            print('Scanning actual workspace ' + label + ' graph', flush=True)
            p = subprocess.run(command, cwd=PROJECT, text=True, capture_output=True, timeout=300)
            raw = p.stdout + p.stderr
            path = args.report.with_name(args.report.stem + '-' + label + '.jsonl')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(raw)
            summaries = [r['fields']['advisories'] for line in raw.splitlines() if (r := json.loads(line)).get('type') == 'summary' and 'advisories' in r.get('fields', {})]
            report['scans'].append({'target': target, 'command': command, 'exit_code': p.returncode,
                                    'raw_path': str(path), 'raw_sha256': hashlib.sha256(raw.encode()).hexdigest(), 'summaries': summaries})
            print(label + ': ' + json.dumps(summaries), flush=True)
            if p.returncode != 0 or len(summaries) != 1 or summaries[0]['errors'] != 0:
                raise RuntimeError(label + ' advisory scan failed')
        for name, digest in report['source_sha256'].items():
            if sha256(PROJECT / name) != digest:
                raise RuntimeError('scan input changed: ' + name)
        report['result'] = 'pass'
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved workspace advisory report:', args.report, flush=True)


if __name__ == '__main__':
    main()
