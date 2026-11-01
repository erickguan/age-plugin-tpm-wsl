#!/usr/bin/env python3
"""Prepare a ctutils-only proposal outside the active root workspace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def metadata(manifest):
    process = subprocess.run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1', '--manifest-path', str(manifest)],
                             capture_output=True, text=True, timeout=60)
    if process.returncode != 0:
        raise RuntimeError('proposal metadata failed: ' + process.stderr)
    return json.loads(process.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    destination = args.destination.resolve()
    if destination == ROOT or ROOT not in destination.parents or 'target' not in destination.relative_to(ROOT).parts:
        raise RuntimeError('proposal must use new ignored target storage within this project')
    before_hash = digest(ROOT / 'Cargo.lock')
    original_metadata = metadata(ROOT / 'Cargo.toml')
    destination.mkdir(parents=True, exist_ok=False)
    report = {'result': 'fail', 'scope': 'ctutils-only isolated proposal; no root adoption, native work or installation',
              'root_lock_sha256': before_hash, 'destination': str(destination), 'staged': False}
    try:
        for folder in ['src', 'tests', 'examples', 'vendor']:
            (destination / folder).symlink_to(ROOT / folder, target_is_directory=True)
        for folder in ['helper', 'crates/post_quantum', 'crates/custody-fs']:
            target = destination / folder
            target.mkdir(parents=True)
            shutil.copyfile(ROOT / folder / 'Cargo.toml', target / 'Cargo.toml')
            (target / 'src').symlink_to(ROOT / folder / 'src', target_is_directory=True)
        for name in ['Cargo.toml', 'Cargo.lock']:
            shutil.copyfile(ROOT / name, destination / name)
        process = subprocess.run(['cargo', 'update', '--offline', '--manifest-path', str(destination / 'Cargo.toml'),
                                  '--package', 'ctutils', '--precise', '0.4.4'], capture_output=True, text=True, timeout=120)
        if process.returncode != 0:
            raise RuntimeError('fixed release proposal update failed: ' + process.stderr)
        before = tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
        after = tomllib.loads((destination / 'Cargo.lock').read_text())['package']
        if [p for p in before if p['name'] != 'ctutils'] != [p for p in after if p['name'] != 'ctutils']:
            raise RuntimeError('ctutils proposal changed another locked package')
        old = next(p for p in before if p['name'] == 'ctutils')
        new = next(p for p in after if p['name'] == 'ctutils')
        if old['version'] != '0.4.3' or new['version'] != '0.4.4' or old['source'] != new['source'] or old.get('dependencies') != new.get('dependencies'):
            raise RuntimeError('unexpected proposed ctutils identity/dependency delta')
        proposed_metadata = metadata(destination / 'Cargo.toml')
        def features(value):
            nodes = {node['id']: node for node in value['resolve']['nodes']}
            return {(p['name'], 'fixed-version' if p['name'] == 'ctutils' else p['version']): nodes[p['id']]['features'] for p in value['packages']}
        if features(original_metadata) != features(proposed_metadata):
            raise RuntimeError('ctutils proposal changed enabled feature sets')
        cache = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))) / 'registry/cache'
        archives = [path for path in cache.glob('*/ctutils-0.4.4.crate') if digest(path) == new['checksum']]
        if len(archives) != 1:
            raise RuntimeError('expected one checksum-matching ctutils0.4.4 registry archive')
        report.update(before=old, after=new, other_locked_packages_unchanged=True, enabled_feature_sets_unchanged=True,
                      proposed_lock_sha256=digest(destination / 'Cargo.lock'), registry_archive_sha256=new['checksum'],
                      metadata_source=next(p['source'] for p in proposed_metadata['packages'] if p['name'] == 'ctutils'), staged=True)
        if digest(ROOT / 'Cargo.lock') != before_hash:
            raise RuntimeError('active root graph changed during proposal')
        saved_lock = args.report.with_name(args.report.stem + '.lock')
        saved_lock.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(destination / 'Cargo.lock', saved_lock)
        report['proposed_lock_path'] = str(saved_lock)
        report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, StopIteration, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved ctutils isolated proposal:', args.report, flush=True)


if __name__ == '__main__':
    main()
