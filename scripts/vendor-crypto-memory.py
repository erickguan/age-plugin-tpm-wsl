#!/usr/bin/env python3
"""Select only fully accepted crypto source copies, or check their exact provenance."""
import argparse
import json
import os
import re
from pathlib import Path
import stat
import shutil
import subprocess
import tempfile

from memory_crypto_inputs import FAMILIES, ROOT, digest, load, snapshot

VENDOR = ROOT / 'vendor/crypto-memory'
PROVENANCE = ROOT / 'vendor/crypto-memory-provenance.json'


def files(directory):
    return {str(path.relative_to(directory)): digest(path) for path in directory.rglob('*') if path.is_file()}


def replace_selector(path, data):
    mode = path.stat().st_mode & 0o777
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.crypto-selector-', delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            temporary.chmod(mode)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def receipt_paths(requested):
    sidecar = requested.with_suffix('.metadata.json')
    if requested.is_symlink() or sidecar.is_symlink():
        raise RuntimeError('adoption evidence cannot use symlinked record paths')
    record = requested.resolve()
    metadata_path = record.with_suffix('.metadata.json')
    if record.parent != (ROOT / 'notes/crypto-memory-integration').resolve():
        raise RuntimeError('adoption evidence must stay in notes/crypto-memory-integration')
    for path in [record, metadata_path]:
        if path.exists() or path.is_symlink():
            raise RuntimeError('adoption evidence requires new non-symlinked files')
    return record, metadata_path


def publish_receipt(path, data, owned):
    # Exclusive creation also rejects a dangling link introduced after preflight.
    with path.open('xb') as output:
        status = os.fstat(output.fileno())
        owned[path] = (status.st_dev, status.st_ino)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def retire_receipts(owned, reason, selector_status):
    errors = []
    try:
        directory = Path(tempfile.mkdtemp(prefix='crypto-adoption-failed-', dir=ROOT / 'target'))
    except OSError as error:
        return None, [{'path': str(ROOT / 'target'), 'error': 'cannot create failure diagnostics: ' + str(error)}]
    retired = []
    for index, (path, identity) in enumerate(owned.items()):
        try:
            status = path.lstat()
            if not stat.S_ISREG(status.st_mode) or (status.st_dev, status.st_ino) != identity:
                raise RuntimeError('owned adoption receipt changed; retirement refused')
            destination = directory / (str(index) + '-' + path.name + '.uncommitted')
            path.rename(destination)
            retired.append({'original_path': str(path), 'uncommitted_path': str(destination)})
        except (OSError, RuntimeError) as error:
            errors.append({'path': str(path), 'error': str(error)})
    failure = {'result': 'failed; receipts are not acceptance', 'reason': reason,
               'selector_rollback': selector_status, 'uncommitted_receipts': retired, 'retirement_errors': errors,
               'vendor_copies': str(VENDOR), 'limits': ['Owned source copies retained for diagnosis; retirement errors require explicit resolution']}
    try:
        (directory / 'failure.json').write_text(json.dumps(failure, indent=2) + '\n')
    except OSError as error:
        errors.append({'path': str(directory / 'failure.json'), 'error': 'cannot publish failure diagnostics: ' + str(error)})
    return directory, errors


def metadata():
    env = os.environ.copy()
    env['RUSTC_WRAPPER'] = ''
    process = subprocess.run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1', '--manifest-path', str(ROOT / 'Cargo.toml')],
                             cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    if process.returncode != 0:
        raise RuntimeError(process.stderr)
    return json.loads(process.stdout)


def feature_map(value):
    nodes = {node['id']: node for node in value['resolve']['nodes']}
    return {(package['name'], package['version']): nodes[package['id']]['features'] for package in value['packages']}


def check_sources(record):
    if VENDOR.is_symlink():
        raise RuntimeError('selected crypto vendor root must be owned directory storage')
    for family, versions in FAMILIES.items():
        for version in versions:
            source = VENDOR / (family + '-' + version)
            if source.is_symlink() or any(path.is_symlink() for path in source.rglob('*')) or files(source) != record['crypto_provenance'][family][version]['patched_sha256']:
                raise RuntimeError('selected crypto source differs from accepted package: ' + family + version)
    if digest(ROOT / 'Cargo.toml') != record['root_manifest_sha256'] or digest(ROOT / 'Cargo.lock') != record['root_lock_sha256']:
        raise RuntimeError('selected root selectors differ from accepted adoption')
    value = metadata()
    for family, versions in FAMILIES.items():
        for version in versions:
            package = next(p for p in value['packages'] if p['name'] == family and p['version'] == version)
            if package['source'] is not None or Path(package['manifest_path']).resolve() != (VENDOR / (family + '-' + version) / 'Cargo.toml').resolve():
                raise RuntimeError('root selected an unexpected crypto package')
    return value


def main():
    if not __debug__:
        raise RuntimeError('crypto source adoption requires active Python assertions')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--validation-report', type=Path, default=ROOT / 'notes/crypto-memory-integration/validation-assertions.json')
    parser.add_argument('--record', type=Path, default=ROOT / 'notes/crypto-memory-integration/adoption.json')
    args = parser.parse_args()
    if args.check:
        record = json.loads(PROVENANCE.read_text())
        check_sources(record)
        print('Selected crypto package maps and root selectors match accepted source provenance.')
        return
    record_path, metadata_path = receipt_paths(args.record)
    if any((ROOT / name).is_symlink() for name in ['Cargo.toml', 'Cargo.lock']):
        raise RuntimeError('refusing to replace symlinked root selector files')
    if VENDOR.exists() or VENDOR.is_symlink() or PROVENANCE.exists() or PROVENANCE.is_symlink():
        raise RuntimeError('refusing to overwrite existing crypto vendor storage/provenance')
    validation_path = args.validation_report.resolve()
    validation = json.loads(validation_path.read_text())
    proposal_path = ROOT / 'notes/crypto-memory-integration/proposal.json'
    proposal = json.loads(proposal_path.read_text())
    workspace = Path(proposal['destination'])
    if validation['result'] != 'pass' or not validation['source_snapshot_unchanged'] or len(validation['clients']) != 6:
        raise RuntimeError('passing corrected combined software/client acceptance required')
    if not any(step['check'] == 'client optimization boundary regressions' and step['exit_code'] == 0 for step in validation['steps']):
        raise RuntimeError('optimization guard acceptance required before source selection')
    if digest(proposal_path) != validation['proposal_sha256'] or snapshot(workspace, proposal) != validation['source_sha256']:
        raise RuntimeError('combined accepted source/proposal changed')
    prepare = load(ROOT / 'scripts/prepare-memory-crypto-project.py', 'crypto_evidence')
    prepare.verify_evidence(validation)
    for client in validation['clients']:
        if digest(client['report']) != client['sha256']:
            raise RuntimeError('accepted software client report changed')
    test_path = ROOT / 'scripts/test_vendor_crypto_memory.py'
    test = subprocess.run(['python3', str(test_path)], cwd=ROOT, capture_output=True, text=True, timeout=30)
    if test.returncode != 0 or re.search(r'Ran 9 tests\b', test.stderr) is None:
        raise RuntimeError('source adoption path/publication regressions failed or cases missing')
    before = validation['source_sha256'].copy()
    for path in [Path(__file__), test_path]:
        before[str(path.relative_to(ROOT))] = digest(path)
    original_manifest, original_lock = (ROOT / 'Cargo.toml').read_bytes(), (ROOT / 'Cargo.lock').read_bytes()
    original_features = feature_map(metadata())
    additions = ''.join(family + '-' + alias + ' = { package = ' + json.dumps(family) + ', path = ' + json.dumps(str((VENDOR / (family + '-' + version)).relative_to(ROOT))) + ' }\n'
                        for family, versions in FAMILIES.items() for alias, version in zip(['v012', 'v013'], versions))
    if original_manifest.decode().count('[patch.crates-io]\n') != 1:
        raise RuntimeError('one original root patch table required')
    new_manifest = original_manifest.decode().replace('[patch.crates-io]\n', '[patch.crates-io]\n' + additions).encode()
    new_lock = (workspace / 'Cargo.lock').read_bytes()
    record = {'result': 'source selected; actual-root execution pending', 'scope': 'Exact accepted HKDF/HMAC source selection; no deployment/native operation',
              'validation_report': str(validation_path), 'validation_report_sha256': digest(validation_path), 'proposal_sha256': digest(proposal_path),
              'before_source_sha256': before, 'crypto_provenance': proposal['crypto_provenance'],
              'adoption_regressions': {'tests': 9, 'exit_code': test.returncode, 'source_sha256': digest(test_path)},
              'root_manifest_before_sha256': digest(ROOT / 'Cargo.toml'), 'root_lock_before_sha256': digest(ROOT / 'Cargo.lock'),
              'root_manifest_before_text': original_manifest.decode(), 'root_lock_before_text': original_lock.decode(),
              'limits': ['Only the root manifest/lock and new owned vendor files change',
                         'Actual-root software/client/feature/advisory/source acceptance still required',
                         'No install, provider/enrollment, live TPM, cleanup or persistence operation']}
    selectors_started = False
    owned_receipts = {}
    try:
        VENDOR.mkdir()
        for family, versions in FAMILIES.items():
            for version in versions:
                source = workspace / 'crypto-sources' / (family + '-' + version)
                destination = VENDOR / source.name
                shutil.copytree(source, destination)
                if files(destination) != proposal['crypto_provenance'][family][version]['patched_sha256']:
                    raise RuntimeError('vendor copy differs from accepted crypto source')
        if snapshot(workspace, proposal) != validation['source_sha256'] or any(digest(ROOT / name) != value for name, value in before.items()):
            raise RuntimeError('accepted inputs changed before root selector update')
        selectors_started = True
        replace_selector(ROOT / 'Cargo.toml', new_manifest)
        replace_selector(ROOT / 'Cargo.lock', new_lock)
        record.update(root_manifest_sha256=digest(ROOT / 'Cargo.toml'), root_lock_sha256=digest(ROOT / 'Cargo.lock'))
        actual = check_sources(record)
        if feature_map(actual) != original_features:
            raise RuntimeError('root source selection changed resolved feature sets')
        for name, expected in before.items():
            if name not in {'Cargo.toml', 'Cargo.lock'} and digest(ROOT / name) != expected:
                raise RuntimeError('unrelated accepted source changed during adoption')
        record['resolved_features_unchanged'] = True
        record['source_sha256'] = {name: digest(ROOT / name) for name in before}
        for path in VENDOR.rglob('*'):
            if path.is_file():
                record['source_sha256'][str(path.relative_to(ROOT))] = digest(path)
        record_bytes = (json.dumps(record, indent=2) + '\n').encode()
        record_path.parent.mkdir(parents=True, exist_ok=True)
        publish_receipt(metadata_path, (json.dumps(actual, indent=2) + '\n').encode(), owned_receipts)
        publish_receipt(record_path, record_bytes, owned_receipts)
        publish_receipt(PROVENANCE, record_bytes, owned_receipts)
        print('Selected exact crypto source copies; actual-root acceptance remains pending:', record_path)
    except (OSError, ValueError, RuntimeError, StopIteration, subprocess.SubprocessError) as error:
        selector_status = 'not started'
        rollback_error = None
        if selectors_started:
            try:
                if (ROOT / 'Cargo.toml').read_bytes() not in {original_manifest, new_manifest} or (ROOT / 'Cargo.lock').read_bytes() not in {original_lock, new_lock}:
                    raise RuntimeError('root selectors changed unexpectedly; automatic rollback refused')
                replace_selector(ROOT / 'Cargo.toml', original_manifest)
                replace_selector(ROOT / 'Cargo.lock', original_lock)
                selector_status = 'original selectors restored'
            except (OSError, RuntimeError) as failure:
                rollback_error = failure
                selector_status = 'failed or refused: ' + str(failure)
        directory, retirement_errors = retire_receipts(owned_receipts, str(error), selector_status)
        details = 'source selection failed; selector rollback: ' + selector_status
        if retirement_errors:
            details += '; receipt retirement incomplete: ' + json.dumps(retirement_errors, sort_keys=True)
        else:
            details += '; receipts retired'
        details += '; inspect ' + str(directory)
        if rollback_error is not None or retirement_errors:
            raise RuntimeError(details) from (rollback_error or error)
        raise RuntimeError(details) from error


if __name__ == '__main__':
    main()
