#!/usr/bin/env python3
"""Scan exact original and proposed HKDF evaluation feature graphs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'notes/hkdf-memory-evaluation'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    accepted_path = FOLDER / 'validation-features.json'
    proposal_path = FOLDER / 'project-proposal.json'
    accepted, proposal = json.loads(accepted_path.read_text()), json.loads(proposal_path.read_text())
    if accepted['result'] != 'pass' or proposal['result'] != 'pass' or digest(accepted_path) != proposal['validation_report_sha256']:
        raise RuntimeError('accepted exact-feature HKDF validation and project proposal required')
    for path, expected in accepted['source_sha256'].items():
        if digest(ROOT / path) != expected:
            raise RuntimeError('accepted HKDF input changed: ' + path)
    source = Path(proposal['destination']) / 'hkdf-sources'
    original_lock_hash = digest(FOLDER / 'Cargo.lock')
    root_lock_hash = digest(ROOT / 'Cargo.lock')
    report = {'result': 'fail', 'validation_report_sha256': digest(accepted_path), 'proposal_sha256': digest(proposal_path),
              'root_lock_sha256': root_lock_hash, 'original_fixture_lock_sha256': original_lock_hash,
              'scanner_sha256': digest(Path(__file__)), 'scans': [],
              'limits': ['Isolated default/optional/windows unit graphs only; actual project graph scans are separate',
                         'Original registry graphs preserve both upstream HKDF identities; local source semantics reviewed separately',
                         'Default advisory policy and raw diagnostics retained; no suppression, root mutation or native operations']}
    try:
        with tempfile.TemporaryDirectory(prefix='hkdf-advisories-', dir=ROOT / 'target') as directory:
            fixture = Path(directory)
            for name in ['Cargo.toml', 'Cargo.lock', 'boundary-fixtures.json']:
                shutil.copyfile(FOLDER / name, fixture / name)
            shutil.copytree(FOLDER / 'src', fixture / 'src')
            text = (fixture / 'Cargo.toml').read_text() + '\n[patch.crates-io]\n'
            for alias, version in [('hkdf-v012', '0.12.4'), ('hkdf-v013', '0.13.0')]:
                package = accepted['staged_provenance']['packages'][version]
                observed = {str(path.relative_to(source / ('hkdf-' + version))): digest(path) for path in (source / ('hkdf-' + version)).rglob('*') if path.is_file()}
                if observed != package['patched_sha256']:
                    raise RuntimeError('proposed source differs from tested HKDF')
                text += alias + ' = { package = "hkdf", path = ' + json.dumps(str(source / ('hkdf-' + version))) + ' }\n'
            (fixture / 'Cargo.toml').write_text(text)
            subprocess.run(['cargo', 'update', '--offline', '--manifest-path', str(fixture / 'Cargo.toml'), '--package', 'hkdf@0.12.4', '--package', 'hkdf@0.13.0'],
                           check=True, capture_output=True, timeout=120)
            original = tomllib.loads((FOLDER / 'Cargo.lock').read_text())['package']
            patched = tomllib.loads((fixture / 'Cargo.lock').read_text())['package']
            if [p for p in original if p['name'] != 'hkdf'] != [p for p in patched if p['name'] != 'hkdf']:
                raise RuntimeError('HKDF companion changed non-HKDF locked package')
            for version in ['0.12.4', '0.13.0']:
                old = next(p for p in original if p['name'] == 'hkdf' and p['version'] == version)
                new = next(p for p in patched if p['name'] == 'hkdf' and p['version'] == version)
                expected = {k: v for k, v in old.items() if k not in {'source', 'checksum'}}
                expected['dependencies'] = sorted(old['dependencies'] + ['zeroize'])
                if new != expected:
                    raise RuntimeError('unexpected HKDF unit graph delta')
            patched_lock_hash = digest(fixture / 'Cargo.lock')
            report['patched_fixture_lock_sha256'] = patched_lock_hash
            profiles = [('default-linux', 'x86_64-unknown-linux-gnu', []),
                        ('kdf-linux', 'x86_64-unknown-linux-gnu', ['--features', 'kdf-api']),
                        ('all-windows', 'x86_64-pc-windows-gnu', ['--all-features'])]
            for graph, manifest in [('registry', FOLDER / 'Cargo.toml'), ('patched', fixture / 'Cargo.toml')]:
                for profile, target, features in profiles:
                    command = ['cargo', 'deny', '--manifest-path', str(manifest), '--locked', '--offline', '--target', target] + features + ['--format', 'json', 'check', 'advisories']
                    print('Scanning ' + graph + ' ' + profile, flush=True)
                    process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=300)
                    raw = process.stdout + process.stderr
                    path = args.report.with_name(args.report.stem + '-' + graph + '-' + profile + '.jsonl')
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(raw)
                    summaries = [row['fields']['advisories'] for line in raw.splitlines() if (row := json.loads(line)).get('type') == 'summary' and 'advisories' in row.get('fields', {})]
                    report['scans'].append({'graph': graph, 'profile': profile, 'target': target, 'feature_args': features,
                                            'exit_code': process.returncode, 'raw_path': str(path), 'raw_sha256': digest(path), 'summaries': summaries})
                    if process.returncode != 0 or len(summaries) != 1 or summaries[0]['errors'] != 0:
                        raise RuntimeError(graph + ' ' + profile + ' advisory scan failed')
            if digest(fixture / 'Cargo.lock') != patched_lock_hash:
                raise RuntimeError('patched fixture graph changed during scans')
        if digest(FOLDER / 'Cargo.lock') != original_lock_hash or digest(ROOT / 'Cargo.lock') != root_lock_hash:
            raise RuntimeError('original/root graphs changed during scans')
        for path, expected in accepted['source_sha256'].items():
            if digest(ROOT / path) != expected:
                raise RuntimeError('HKDF source input changed during scans')
        for version, package in accepted['staged_provenance']['packages'].items():
            directory = source / ('hkdf-' + version)
            if {str(path.relative_to(directory)): digest(path) for path in directory.rglob('*') if path.is_file()} != package['patched_sha256']:
                raise RuntimeError('tested HKDF source changed during scans')
        if digest(Path(__file__)) != report['scanner_sha256'] or digest(accepted_path) != report['validation_report_sha256']:
            raise RuntimeError('scanner or accepted source evidence changed')
        report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, StopIteration, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved HKDF unit/registry advisory report:', args.report, flush=True)


if __name__ == '__main__':
    main()
