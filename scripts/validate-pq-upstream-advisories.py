#!/usr/bin/env python3
"""Retain upstream AWS-LC advisory visibility for the reviewed local source patch."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib

PROJECT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--validation-report', type=Path, default=PROJECT / 'notes/pq-module-validation.json')
    args = parser.parse_args()
    validated = json.loads(args.validation_report.read_text())
    lock = PROJECT / validated.get('lock_path', 'crates/post_quantum/Cargo.lock')
    lock_hash = hashlib.sha256(lock.read_bytes()).hexdigest()
    if validated['result'] != 'pass' or lock_hash != validated['lock_sha256']:
        raise RuntimeError('current validated staged lock required')
    provenance = json.loads((PROJECT / 'vendor/aws-lc-rs-provenance.json').read_text())
    report = {'result': 'fail', 'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'validated_lock_sha256': lock_hash, 'validated_lock_path': str(lock.relative_to(PROJECT)),
              'validation_report_sha256': hashlib.sha256(args.validation_report.read_bytes()).hexdigest(),
              'validator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'steps': [], 'limits': ['Companion scan of the checksum-verified upstream registry identity; not a replacement for the exact staged graph scan',
                                    'Registry API lacks the local experimental feature; the identical native all-bindings feature is enabled directly',
                                    'Advisories match upstream package/version/source; local code changes require separate exact provenance checks and independent review',
                                    'Offline scan reuses the advisory database refreshed by the primary staged-graph scan; no suppressed warnings or certification claim']}

    def run(command, label, *, json_output=False, allow_failure=False):
        p = subprocess.run(command, cwd=PROJECT, text=True, capture_output=True, timeout=300)
        print(label + ': exit ' + str(p.returncode), flush=True)
        report['steps'].append({'check': label, 'command': command, 'exit_code': p.returncode,
                                'stdout_sha256': hashlib.sha256(p.stdout.encode()).hexdigest(),
                                'stderr_sha256': hashlib.sha256(p.stderr.encode()).hexdigest()})
        if p.returncode != 0 and not allow_failure:
            print(p.stderr, end='', flush=True)
            raise RuntimeError(label + ' failed')
        return json.loads(p.stdout) if json_output else p

    try:
        with tempfile.TemporaryDirectory(prefix='pq-upstream-advisories-') as directory:
            fixture = Path(directory)
            (fixture / 'src').mkdir()
            (fixture / 'src/lib.rs').write_text('// Dependency metadata only; this crate is never built or executed.\n')
            safe_features = sorted(set(next(p['features'] for p in validated['resolved_features'] if p['name'] == 'aws-lc-rs')) - {'aws-lc-sys', 'experimental-kem-seed'})
            native_features = sorted(next(p['features'] for p in validated['resolved_features'] if p['name'] == 'aws-lc-sys'))
            manifest = '[package]\nname="pq-upstream-advisory-identity"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\naws-lc-rs={version="=1.18.2",default-features=false,features=' + json.dumps(safe_features) + '}\naws-lc-sys={version="=0.46.0",default-features=false,features=' + json.dumps(native_features) + '}\n'
            (fixture / 'Cargo.toml').write_text(manifest)
            report['companion_manifest'] = manifest
            manifest_args = ['--manifest-path', str(fixture / 'Cargo.toml')]
            run(['cargo', 'generate-lockfile', '--offline'] + manifest_args, 'companion registry lock')
            metadata = run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1'] + manifest_args,
                           'registry identities and native feature correspondence', json_output=True)
            nodes = {n['id']: n for n in metadata['resolve']['nodes']}
            report['registry_identities'] = []
            for name in ['aws-lc-rs', 'aws-lc-sys']:
                actual = next(p for p in metadata['packages'] if p['name'] == name)
                expected = next(p for p in validated['resolved_features'] if p['name'] == name)
                expected_features = set(expected['features']) - {'experimental-kem-seed'}
                if actual['version'] != expected['version'] or not actual['source'].startswith('registry+') or set(nodes[actual['id']]['features']) != expected_features:
                    raise RuntimeError('registry/native identity or feature mismatch: ' + name)
                report['registry_identities'].append({'name': name, 'version': actual['version'], 'source': actual['source'], 'features': nodes[actual['id']]['features']})
            packages = tomllib.loads((fixture / 'Cargo.lock').read_text())['package']
            safe = next(p for p in packages if p['name'] == 'aws-lc-rs')
            if safe['checksum'] != provenance['registry_archive_sha256']:
                raise RuntimeError('upstream registry checksum mismatch')
            report['safe_registry_archive_sha256'] = safe['checksum']
            report['companion_lock_sha256'] = hashlib.sha256((fixture / 'Cargo.lock').read_bytes()).hexdigest()
            p = run(['cargo', 'deny'] + manifest_args + ['--offline', '--locked', '--target', 'x86_64-pc-windows-gnu', '--format', 'json', 'check', 'advisories'], 'upstream registry advisory visibility', allow_failure=True)
            raw = p.stdout + p.stderr
            raw_path = args.report.with_suffix('.jsonl')
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(raw)
            report['raw_sha256'] = hashlib.sha256(raw.encode()).hexdigest()
            report['raw_path'] = str(raw_path)
            report['summaries'] = [r['fields']['advisories'] for line in raw.splitlines() if (r := json.loads(line)).get('type') == 'summary' and 'advisories' in r.get('fields', {})]
            if p.returncode != 0 or len(report['summaries']) != 1 or report['summaries'][0]['errors'] != 0:
                raise RuntimeError('upstream registry advisory scan did not pass')
            if hashlib.sha256(lock.read_bytes()).hexdigest() != lock_hash:
                raise RuntimeError('staged lock changed')
            report['result'] = 'pass'
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved upstream advisory visibility report:', args.report, flush=True)


if __name__ == '__main__':
    main()
