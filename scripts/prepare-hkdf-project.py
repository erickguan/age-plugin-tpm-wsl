#!/usr/bin/env python3
"""Prepare a project-wide HKDF source proposal; never change root selectors."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def metadata(manifest):
    process = subprocess.run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1', '--manifest-path', str(manifest)],
                             capture_output=True, text=True, timeout=60)
    if process.returncode != 0:
        raise RuntimeError('project proposal metadata failed: ' + process.stderr)
    return json.loads(process.stdout)


def tree_hashes(source):
    return {str(path.relative_to(source)): digest(path) for path in source.rglob('*') if path.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validation-report', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    validation_path = args.validation_report.resolve()
    accepted = json.loads(validation_path.read_text())
    if accepted['result'] != 'pass':
        raise RuntimeError('passing isolated HKDF validation required')
    for path, expected in accepted['source_sha256'].items():
        if digest(ROOT / path) != expected:
            raise RuntimeError('isolated HKDF validation input changed: ' + path)
    for path, expected in accepted['patch_sha256'].items():
        if digest(validation_path.parent / path) != expected:
            raise RuntimeError('accepted HKDF patch artifact changed')
    required = {'original-default-linux', 'original-kdf-linux', 'patched-default-linux', 'patched-kdf-linux', 'patched-all-linux', 'patched-all-windows'}
    if set(accepted.get('configurations', {})) != required:
        raise RuntimeError('full feature/platform evidence required')
    for config in accepted['configurations'].values():
        if digest(config['metadata_path']) != config['metadata_sha256']:
            raise RuntimeError('accepted configuration graph changed')
    destination = args.destination.resolve()
    if ROOT not in destination.parents or 'target' not in destination.relative_to(ROOT).parts:
        raise RuntimeError('project proposal must use new ignored target storage')
    destination.mkdir(parents=True, exist_ok=False)
    root_hash = digest(ROOT / 'Cargo.lock')
    original_metadata = metadata(ROOT / 'Cargo.toml')
    cache = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))) / 'registry/cache'
    stage = destination / 'hkdf-sources'
    stage.mkdir()
    for version, package in accepted['staged_provenance']['packages'].items():
        if version not in {'0.12.4', '0.13.0'} or package['version'] != version:
            raise RuntimeError('unexpected accepted HKDF version')
        archives = [p for p in cache.glob('*/hkdf-' + version + '.crate') if digest(p) == package['original_archive_sha256']]
        if len(archives) != 1:
            raise RuntimeError('expected one accepted original HKDF archive')
        with tarfile.open(archives[0]) as content:
            content.extractall(stage, filter='data')
        source = stage / ('hkdf-' + version)
        if tree_hashes(source) != package['original_sha256']:
            raise RuntimeError('original HKDF archive file map differs')
        patch = validation_path.parent / ('hkdf-' + version + '-memory.patch')
        subprocess.run(['patch', '--batch', '--fuzz=0', '--strip=1', '--directory', str(source), '--input', str(patch)],
                       check=True, capture_output=True, timeout=30)
        if tree_hashes(source) != package['patched_sha256']:
            raise RuntimeError('proposed HKDF sources differ from tested source')
    if set(accepted['staged_provenance']['packages']) != {'0.12.4', '0.13.0'}:
        raise RuntimeError('both HKDF families required')
    for folder in ['src', 'tests', 'examples', 'vendor']:
        (destination / folder).symlink_to(ROOT / folder, target_is_directory=True)
    for folder in ['helper', 'crates/post_quantum', 'crates/custody-fs']:
        target = destination / folder
        target.mkdir(parents=True)
        shutil.copyfile(ROOT / folder / 'Cargo.toml', target / 'Cargo.toml')
        (target / 'src').symlink_to(ROOT / folder / 'src', target_is_directory=True)
    manifest = (ROOT / 'Cargo.toml').read_text()
    anchor = '[patch.crates-io]\n'
    if manifest.count(anchor) != 1:
        raise RuntimeError('expected one actual root patch table')
    additions = ''.join(alias + ' = { package = "hkdf", path = ' + json.dumps(str(stage / ('hkdf-' + version))) + ' }\n'
                        for alias, version in [('hkdf-v012', '0.12.4'), ('hkdf-v013', '0.13.0')])
    (destination / 'Cargo.toml').write_text(manifest.replace(anchor, anchor + additions))
    shutil.copyfile(ROOT / 'Cargo.lock', destination / 'Cargo.lock')
    subprocess.run(['cargo', 'update', '--offline', '--manifest-path', str(destination / 'Cargo.toml'),
                    '--package', 'hkdf@0.12.4', '--package', 'hkdf@0.13.0'], check=True, capture_output=True, timeout=120)
    before = tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
    after = tomllib.loads((destination / 'Cargo.lock').read_text())['package']
    if [p for p in before if p['name'] != 'hkdf'] != [p for p in after if p['name'] != 'hkdf']:
        raise RuntimeError('HKDF proposal changed another locked package')
    for version in ['0.12.4', '0.13.0']:
        old = next(p for p in before if p['name'] == 'hkdf' and p['version'] == version)
        new = next(p for p in after if p['name'] == 'hkdf' and p['version'] == version)
        expected = {k: v for k, v in old.items() if k not in {'source', 'checksum'}}
        expected['dependencies'] = sorted(old['dependencies'] + ['zeroize'])
        if new != expected:
            raise RuntimeError('unexpected HKDF locked dependency delta')
    proposed_metadata = metadata(destination / 'Cargo.toml')
    def features(value):
        nodes = {n['id']: n for n in value['resolve']['nodes']}
        return {(p['name'], p['version']): nodes[p['id']]['features'] for p in value['packages']}
    if features(original_metadata) != features(proposed_metadata):
        raise RuntimeError('HKDF root proposal changed enabled feature sets')
    if digest(ROOT / 'Cargo.lock') != root_hash:
        raise RuntimeError('actual root graph changed during proposal')
    record = {'result': 'pass', 'scope': 'Project-wide HKDF-only source proposal; no root adoption',
              'validation_report_sha256': digest(validation_path), 'destination': str(destination),
              'root_lock_sha256': root_hash, 'proposed_lock_sha256': digest(destination / 'Cargo.lock'),
              'all_non_hkdf_lock_records_unchanged': True, 'only_added_hkdf_dependency': 'zeroize1.9.1',
              'resolved_features_unchanged': True, 'hkdf_provenance': accepted['staged_provenance']['packages'],
              'limits': ['Project vectors/both-target execution/source binding/advisory review still required',
                         'Source/vendor symlinks target immutable root inputs; no source-mutating command is run',
                         'No live TPM, installation or provider operations']}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(record, indent=2) + '\n')
    args.report.with_suffix('.lock').write_bytes((destination / 'Cargo.lock').read_bytes())
    print('Saved project HKDF proposal:', args.report)


if __name__ == '__main__':
    main()
