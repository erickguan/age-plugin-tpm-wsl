#!/usr/bin/env python3
"""Scan original SDK registry identities in the otherwise exact root graph."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    provenance = json.loads((ROOT / 'vendor/age-sdk-provenance.json').read_text())
    baseline = ROOT / provenance['root_before_adoption_lock']
    if digest(baseline) != provenance['root_before_adoption_lock_sha256']:
        raise RuntimeError('original SDK registry lock evidence changed')
    inputs = [ROOT / p for p in ['Cargo.toml', 'Cargo.lock', 'helper/Cargo.toml', 'crates/post_quantum/Cargo.toml',
                                  'crates/custody-fs/Cargo.toml', 'vendor/age-sdk-provenance.json']]
    inputs += [baseline, Path(__file__).resolve()]
    report = {'result': 'fail', 'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_sha256': {str(p.relative_to(ROOT)): digest(p) for p in inputs}, 'scans': [],
              'limits': ['SDK registry companion of current root graph; AWS-LC remains its exact local source and has separate registry visibility evidence',
                         'Only SDK source/checksum identities differ; no build, native operation, installation or root-file mutation',
                         'Default advisory policy/raw diagnostics retained; not a substitute for local SDK source review or primary actual-root scans']}
    try:
        subprocess.run(['python3', str(ROOT / 'scripts/vendor-age-sdk.py'), '--check'], check=True, capture_output=True, timeout=30)
        with tempfile.TemporaryDirectory(prefix='root-sdk-advisories-', dir=ROOT / 'target') as directory:
            temporary = Path(directory)
            for folder in ['src', 'tests', 'examples', 'vendor']:
                (temporary / folder).symlink_to(ROOT / folder, target_is_directory=True)
            for folder in ['helper', 'crates/post_quantum', 'crates/custody-fs']:
                target = temporary / folder
                target.mkdir(parents=True)
                shutil.copyfile(ROOT / folder / 'Cargo.toml', target / 'Cargo.toml')
                (target / 'src').symlink_to(ROOT / folder / 'src', target_is_directory=True)
            manifest = (ROOT / 'Cargo.toml').read_text()
            for name in ['age-core', 'age-plugin']:
                line = name + ' = { path = "vendor/' + name + '" }\n'
                if manifest.count(line) != 1:
                    raise RuntimeError('unexpected actual root SDK selector')
                manifest = manifest.replace(line, '')
            (temporary / 'Cargo.toml').write_text(manifest)
            original = tomllib.loads(baseline.read_text())['package']
            lock = (ROOT / 'Cargo.lock').read_text()
            for name in ['age-core', 'age-plugin']:
                expected = next(p for p in original if p['name'] == name)
                if expected['checksum'] != provenance['packages'][name]['archive_sha256']:
                    raise RuntimeError('SDK original registry archive mismatch')
                anchor = 'name = ' + json.dumps(name) + '\nversion = ' + json.dumps(expected['version']) + '\n'
                if lock.count(anchor) != 1:
                    raise RuntimeError('unexpected SDK lock entry')
                lock = lock.replace(anchor, anchor + 'source = ' + json.dumps(expected['source']) + '\nchecksum = ' + json.dumps(expected['checksum']) + '\n')
            (temporary / 'Cargo.lock').write_text(lock)
            actual_packages = tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
            companion_packages = tomllib.loads(lock)['package']
            for actual, companion in zip(actual_packages, companion_packages, strict=True):
                if actual['name'] in {'age-core', 'age-plugin'}:
                    if actual != {k: v for k, v in companion.items() if k not in {'source', 'checksum'}}:
                        raise RuntimeError('SDK companion changed package metadata')
                elif actual != companion:
                    raise RuntimeError('SDK companion changed another package')
            manifest_args = ['--manifest-path', str(temporary / 'Cargo.toml')]
            process = subprocess.run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1'] + manifest_args,
                                     capture_output=True, text=True, timeout=60)
            if process.returncode != 0:
                raise RuntimeError('SDK registry companion metadata failed: ' + process.stderr)
            metadata = json.loads(process.stdout)
            report['sdk_registry_identities'] = []
            for name in ['age-core', 'age-plugin']:
                package = next(p for p in metadata['packages'] if p['name'] == name)
                if package['version'] != provenance['packages'][name]['version'] or not package['source'].startswith('registry+'):
                    raise RuntimeError('SDK registry companion source/version mismatch')
                report['sdk_registry_identities'].append({'name': name, 'version': package['version'], 'source': package['source']})
            report['other_root_lock_records_unchanged'] = True
            report['companion_lock_sha256'] = digest(temporary / 'Cargo.lock')
            for label, target, features in [('linux', 'x86_64-unknown-linux-gnu', []),
                                             ('windows', 'x86_64-pc-windows-gnu', ['--features', 'age-tpm-wsl-post-quantum/seed-restoration'])]:
                command = ['cargo', 'deny'] + manifest_args + ['--workspace', '--locked', '--offline', '--target', target] + features + ['--format', 'json', 'check', 'advisories']
                process = subprocess.run(command, capture_output=True, text=True, timeout=300)
                raw = process.stdout + process.stderr
                raw_path = args.report.with_name(args.report.stem + '-' + label + '.jsonl')
                raw_path.parent.mkdir(parents=True, exist_ok=True)
                raw_path.write_text(raw)
                summaries = [entry['fields']['advisories'] for line in raw.splitlines()
                             if (entry := json.loads(line)).get('type') == 'summary' and 'advisories' in entry.get('fields', {})]
                report['scans'].append({'target': target, 'exit_code': process.returncode, 'raw_path': str(raw_path),
                                        'raw_sha256': digest(raw_path), 'summaries': summaries})
                if process.returncode != 0 or len(summaries) != 1 or summaries[0]['errors'] != 0:
                    raise RuntimeError(label + ' SDK root-registry advisory scan failed')
            if digest(temporary / 'Cargo.lock') != report['companion_lock_sha256']:
                raise RuntimeError('companion graph changed during scan')
        if any(digest(ROOT / path) != expected for path, expected in report['source_sha256'].items()):
            raise RuntimeError('actual root graph evidence changed during scan')
        report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved root SDK registry advisory report:', args.report, flush=True)


if __name__ == '__main__':
    main()
