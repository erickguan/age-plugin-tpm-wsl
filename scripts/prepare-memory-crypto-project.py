#!/usr/bin/env python3
"""Compose accepted HKDF/HMAC source proposals without changing active selectors."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
REPORTS = {
    'hkdf': ROOT / 'notes/hkdf-memory-evaluation/validation-features.json',
    'hkdf_project': ROOT / 'notes/hkdf-memory-evaluation/project-validation-host-bound.json',
    'hmac': ROOT / 'notes/hmac-memory-evaluation/patched-validation.json',
    'hmac_upstream': ROOT / 'notes/hmac-memory-evaluation/upstream-validation.json',
}
FAMILIES = {'hkdf': ['0.12.4', '0.13.0'], 'hmac': ['0.12.1', '0.13.0']}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def files(directory):
    return {str(path.relative_to(directory)): digest(path) for path in directory.rglob('*') if path.is_file()}


def verify_evidence(value):
    """Verify paired artifact paths/hashes; source manifests need not still exist."""
    if isinstance(value, dict):
        pairs = [('path', 'sha256'), ('metadata_path', 'metadata_sha256'),
                 ('build_resolution_metadata_path', 'build_resolution_metadata_sha256'),
                 ('compiler_artifacts_path', 'compiler_artifacts_sha256'), ('raw_path', 'raw_sha256')]
        for path_key, hash_key in pairs:
            if path_key in value and hash_key in value and digest(value[path_key]) != value[hash_key]:
                raise RuntimeError('accepted evidence artifact changed: ' + str(value[path_key]))
        for child in value.values():
            verify_evidence(child)
    elif isinstance(value, list):
        for child in value:
            verify_evidence(child)


def hkdf_project_snapshot():
    path = ROOT / 'notes/hkdf-memory-evaluation/validate-project.py'
    spec = importlib.util.spec_from_file_location('hkdf_project', path)
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    proposal = json.loads((path.parent / 'project-proposal.json').read_text())
    return validator.snapshot(Path(proposal['destination']), proposal)


def metadata(manifest):
    p = subprocess.run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1', '--manifest-path', str(manifest)],
                       capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        raise RuntimeError(p.stderr)
    return json.loads(p.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    reports = {}
    reviewed_project = None
    inputs = {str(path.relative_to(ROOT)): digest(path) for path in
              [Path(__file__), ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', ROOT / 'notes/hkdf-memory-evaluation/validate-project.py']}
    for key, path in REPORTS.items():
        value = json.loads(path.read_text())
        if value['result'] != 'pass':
            raise RuntimeError('accepted isolated/project/upstream gate required: ' + key)
        if key == 'hkdf_project':
            reviewed_project = hkdf_project_snapshot()
            if reviewed_project != value['source_sha256']:
                raise RuntimeError('accepted HKDF project source snapshot changed')
        else:
            for name, expected in value['source_sha256'].items():
                if digest(ROOT / name) != expected:
                    raise RuntimeError('accepted gate source changed: ' + name)
                inputs[name] = expected
        verify_evidence(value)
        reports[key] = value
        inputs[str(path.relative_to(ROOT))] = digest(path)
    destination = args.destination.resolve()
    if ROOT not in destination.parents or 'target' not in destination.relative_to(ROOT).parts:
        raise RuntimeError('combined proposal requires new ignored target storage')
    destination.mkdir(parents=True, exist_ok=False)
    cache = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))) / 'registry/cache'
    source = destination / 'crypto-sources'
    source.mkdir()
    source_provenance = {}
    for family, versions in FAMILIES.items():
        accepted = reports[family]
        packages = accepted['staged_provenance']['packages']
        if set(packages) != set(versions):
            raise RuntimeError('unexpected crypto family versions')
        source_provenance[family] = packages
        folder = ROOT / 'notes' / (family + '-memory-evaluation')
        for version in versions:
            record = packages[version]
            archives = [p for p in cache.glob('*/' + family + '-' + version + '.crate') if digest(p) == record['original_archive_sha256']]
            if len(archives) != 1:
                raise RuntimeError('one accepted original crypto archive required')
            with tarfile.open(archives[0]) as archive:
                archive.extractall(source, filter='data')
            package = source / (family + '-' + version)
            if files(package) != record['original_sha256']:
                raise RuntimeError('original crypto source map mismatch')
            patch = folder / (family + '-' + version + '-memory.patch')
            if digest(patch) != record['patch_sha256'] or digest(patch) != accepted['patch_sha256'][patch.name]:
                raise RuntimeError('accepted crypto patch changed')
            inputs[str(patch.relative_to(ROOT))] = digest(patch)
            subprocess.run(['patch', '--batch', '--fuzz=0', '--strip=1', '--directory', str(package), '--input', str(patch)],
                           check=True, capture_output=True, timeout=30)
            if files(package) != record['patched_sha256']:
                raise RuntimeError('combined crypto sources differ from tested source')
    for folder in ['src', 'tests', 'examples', 'vendor']:
        (destination / folder).symlink_to(ROOT / folder, target_is_directory=True)
    for folder in ['helper', 'crates/post_quantum', 'crates/custody-fs']:
        target = destination / folder
        target.mkdir(parents=True)
        shutil.copyfile(ROOT / folder / 'Cargo.toml', target / 'Cargo.toml')
        (target / 'src').symlink_to(ROOT / folder / 'src', target_is_directory=True)
    manifest = (ROOT / 'Cargo.toml').read_text()
    if manifest.count('[patch.crates-io]\n') != 1:
        raise RuntimeError('one actual root patch table required')
    additions = ''.join(family + '-' + alias + ' = { package = ' + json.dumps(family) + ', path = ' + json.dumps(str(source / (family + '-' + version))) + ' }\n'
                        for family, versions in FAMILIES.items() for alias, version in zip(['v012', 'v013'], versions))
    (destination / 'Cargo.toml').write_text(manifest.replace('[patch.crates-io]\n', '[patch.crates-io]\n' + additions))
    shutil.copyfile(ROOT / 'Cargo.lock', destination / 'Cargo.lock')
    command = ['cargo', 'update', '--offline', '--manifest-path', str(destination / 'Cargo.toml')]
    for family, versions in FAMILIES.items():
        for version in versions:
            command += ['--package', family + '@' + version]
    subprocess.run(command, check=True, capture_output=True, timeout=120)
    original = tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
    proposed = tomllib.loads((destination / 'Cargo.lock').read_text())['package']
    if [p for p in original if p['name'] not in FAMILIES] != [p for p in proposed if p['name'] not in FAMILIES]:
        raise RuntimeError('combined proposal changed another locked package')
    for family, versions in FAMILIES.items():
        for version in versions:
            old = next(p for p in original if p['name'] == family and p['version'] == version)
            new = next(p for p in proposed if p['name'] == family and p['version'] == version)
            expected = {key: value for key, value in old.items() if key not in {'source', 'checksum'}}
            expected['dependencies'] = sorted(old['dependencies'] + ['zeroize'])
            if new != expected:
                raise RuntimeError('unexpected combined crypto locked delta')
    def features(value):
        nodes = {node['id']: node for node in value['resolve']['nodes']}
        return {(p['name'], p['version']): nodes[p['id']]['features'] for p in value['packages']}
    if features(metadata(ROOT / 'Cargo.toml')) != features(metadata(destination / 'Cargo.toml')):
        raise RuntimeError('combined proposal changed resolved feature sets')
    if any(digest(ROOT / name) != expected for name, expected in inputs.items()) or hkdf_project_snapshot() != reviewed_project:
        raise RuntimeError('combined proposal inputs changed')
    report = {'result': 'pass', 'scope': 'Four exact accepted HKDF/HMAC source proposals; active root unchanged',
              'destination': str(destination), 'source_sha256': inputs, 'crypto_provenance': source_provenance,
              'hkdf_project_source_sha256': reviewed_project,
              'root_lock_sha256': digest(ROOT / 'Cargo.lock'), 'proposed_lock_sha256': digest(destination / 'Cargo.lock'),
              'all_non_crypto_lock_records_unchanged': True, 'resolved_features_unchanged': True,
              'limits': ['Combined project/platform/software-client/advisory/final-source gates still required before root adoption',
                         'Source/vendor symlinks target immutable root inputs; source-mutating commands excluded',
                         'No native TPM, installation, provider or custody operation']}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    args.report.with_suffix('.lock').write_bytes((destination / 'Cargo.lock').read_bytes())
    print('Saved combined crypto proposal:', args.report)


if __name__ == '__main__':
    main()
