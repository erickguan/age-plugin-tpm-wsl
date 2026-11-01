#!/usr/bin/env python3
"""Stage or verify the exact accepted age SDK sources; never install a binary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

PROJECT = Path(__file__).resolve().parents[1]
PROVENANCE = PROJECT / 'vendor/age-sdk-provenance.json'
VERSIONS = {'age-core': '0.12.0', 'age-plugin': '0.7.0'}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_tree(directory, expected):
    files = {str(path.relative_to(directory)): digest(path) for path in directory.rglob('*') if path.is_file()}
    if files != expected or directory.is_symlink() or any(path.is_symlink() for path in directory.rglob('*')):
        raise RuntimeError('SDK source tree differs from accepted hashes: ' + str(directory))


def accepted_patches(report_path, validated):
    patches = {}
    for name in VERSIONS:
        patch = report_path.parent / (name + '-memory.patch')
        if digest(patch) != validated['patch_sha256'][patch.name]:
            raise RuntimeError('accepted SDK patch changed: ' + name)
        patches[name] = patch
    return patches


def preserve_baseline(path, content):
    if path.exists():
        if path.read_bytes() != content:
            raise RuntimeError('existing pre-adoption root lock evidence differs')
        return
    # Publish complete bytes without replacing another invocation's evidence.
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.sdk-baseline-') as temporary:
        temporary.write(content)
        temporary.flush()
        try:
            os.link(temporary.name, path)
        except FileExistsError:
            if path.read_bytes() != content:
                raise RuntimeError('pre-adoption root lock evidence appeared with different bytes') from None


def publish_sources(temporary, record):
    staged_provenance = temporary / 'age-sdk-provenance.json'
    staged_provenance.write_text(json.dumps(record, indent=2) + '\n')
    created = []
    try:
        for name, version in VERSIONS.items():
            destination = PROJECT / 'vendor' / name
            destination.mkdir()  # Exclusive reservation; never adopt an existing tree.
            created.append(destination)
            os.replace(temporary / (name + '-' + version), destination)
        PROVENANCE.touch(exist_ok=False)
        created.append(PROVENANCE)
        os.replace(staged_provenance, PROVENANCE)
        return verify_sources()
    except BaseException as failure:
        cleanup_errors = []
        for destination in reversed(created):
            try:
                if destination.is_dir() and not destination.is_symlink():
                    shutil.rmtree(destination)
                else:
                    destination.unlink()
            except OSError:
                cleanup_errors.append(str(destination))
        if cleanup_errors:
            raise RuntimeError('SDK source publication failed; rollback failed for: ' + ', '.join(cleanup_errors)) from failure
        raise


def verify_sources():
    record = json.loads(PROVENANCE.read_text())
    if record['schema'] != 1 or set(record['packages']) != set(VERSIONS):
        raise RuntimeError('unexpected SDK provenance schema/packages')
    report_path = PROJECT / record['validation_report']
    if digest(report_path) != record['validation_report_sha256']:
        raise RuntimeError('accepted SDK validation report changed')
    validated = json.loads(report_path.read_text())
    if validated['result'] != 'pass' or record['patch_sha256'] != validated['patch_sha256']:
        raise RuntimeError('accepted SDK validation or patch identity changed')
    if record['root_before_adoption_lock_sha256'] != validated['source_sha256']['Cargo.lock']:
        raise RuntimeError('pre-adoption graph differs from accepted validation')
    accepted_patches(report_path, validated)
    for name, version in VERSIONS.items():
        package = record['packages'][name]
        if package != validated['staged_provenance']['packages'][name] or package['version'] != version:
            raise RuntimeError('SDK provenance differs from accepted package: ' + name)
        verify_tree(PROJECT / 'vendor' / name, package['final_sha256'])
    baseline = PROJECT / record['root_before_adoption_lock']
    if digest(baseline) != record['root_before_adoption_lock_sha256']:
        raise RuntimeError('original root graph evidence changed')
    return record


def stage(report_path):
    report_path = report_path.resolve()
    relative_report = str(report_path.relative_to(PROJECT))
    validated = json.loads(report_path.read_text())
    if validated['result'] != 'pass':
        raise RuntimeError('passing final SDK software validation required')
    # This check is for initial staging, before root dependency selectors change.
    for path, expected in validated['source_sha256'].items():
        if digest(PROJECT / path) != expected:
            raise RuntimeError('SDK validation input changed before staging: ' + path)
    if PROVENANCE.exists() or any((PROJECT / 'vendor' / name).exists() for name in VERSIONS):
        raise RuntimeError('SDK source/provenance destination already exists; use --check')
    patches = accepted_patches(report_path, validated)
    cache = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))) / 'registry/cache'
    (PROJECT / 'vendor').mkdir(exist_ok=True)
    # Prepare on the publication filesystem so final moves cannot become copies.
    with tempfile.TemporaryDirectory(prefix='.age-sdk-source-', dir=PROJECT / 'vendor') as directory:
        temporary = Path(directory)
        for name, version in VERSIONS.items():
            package = validated['staged_provenance']['packages'][name]
            if package['version'] != version:
                raise RuntimeError('unexpected SDK version')
            archives = [p for p in cache.glob(f'*/{name}-{version}.crate') if digest(p) == package['archive_sha256']]
            if len(archives) != 1:
                raise RuntimeError('expected one checksum-matching SDK archive: ' + name)
            with tarfile.open(archives[0]) as archive:
                archive.extractall(temporary, filter='data')
            source = temporary / (name + '-' + version)
            verify_tree(source, package['original_sha256'])
            subprocess.run(['patch', '--batch', '--fuzz=0', '--strip=1', '--directory', str(source), '--input', str(patches[name])],
                           check=True, capture_output=True, timeout=30)
            verify_tree(source, package['final_sha256'])
            manifest = tomllib.loads((source / 'Cargo.toml').read_text())
            if manifest['package']['name'] != name or manifest['package']['version'] != version or manifest['package']['license'] != 'MIT OR Apache-2.0':
                raise RuntimeError('unexpected original SDK identity/license')
        # All package and receipt bytes are complete before publishing final names.
        baseline = PROJECT / 'notes/protocol-memory-evaluation/root-before-adoption.lock'
        original_lock = (PROJECT / 'Cargo.lock').read_bytes()
        preserve_baseline(baseline, original_lock)
        record = {'schema': 1, 'scope': 'Exact accepted SDK source copies; root integration and deployment are separate gates',
                  'validation_report': relative_report, 'validation_report_sha256': digest(report_path),
                  'root_before_adoption_lock': str(baseline.relative_to(PROJECT)),
                  'root_before_adoption_lock_sha256': hashlib.sha256(original_lock).hexdigest(),
                  'packages': validated['staged_provenance']['packages'],
                  'patch_sha256': validated['patch_sha256'],
                  'limits': ['Preserves original archive files, dependency manifests and license declarations',
                             'No Cargo selector/lock update, registry mutation, key operation or installation',
                             'Ordinary publication failures roll back only new destinations; abrupt-kill durability is not claimed',
                             'Plain source copies; comprehensive erasure and physical media wiping are not claimed']}
        return publish_sources(temporary, record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--stage', action='store_true', help='create new verified source copies; refuse existing destinations')
    action.add_argument('--check', action='store_true', help='verify existing source/provenance copies without writes')
    parser.add_argument('--validation-report', type=Path, default=PROJECT / 'notes/protocol-memory-evaluation/validation-final.json')
    args = parser.parse_args()
    record = stage(args.validation_report) if args.stage else verify_sources()
    print(json.dumps({'result': 'pass', 'scope': record['scope'],
                      'packages': {name: {'version': p['version'], 'files': len(p['final_sha256'])} for name, p in record['packages'].items()},
                      'provenance_sha256': digest(PROVENANCE)}))


if __name__ == '__main__':
    main()
