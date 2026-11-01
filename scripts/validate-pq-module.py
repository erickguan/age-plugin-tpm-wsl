#!/usr/bin/env python3
"""Check the shared PQ module, exact patch provenance and consumer feature isolation."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib

PROJECT = Path(__file__).resolve().parents[1]
MODULE = PROJECT / 'crates/post_quantum'
VENDOR = PROJECT / 'vendor/aws-lc-rs'


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--windows', action='store_true', help='also build, lint and execute public software fixtures in Windows')
    args = parser.parse_args()
    env = os.environ.copy()
    env.update(RUSTC_WRAPPER='', CARGO_TARGET_DIR=str(PROJECT / 'target/pq-module'))
    workspace = 'crates/post_quantum' in tomllib.loads((PROJECT / 'Cargo.toml').read_text())['workspace']['members']
    lock = PROJECT / 'Cargo.lock' if workspace else MODULE / 'Cargo.lock'
    inputs = list((MODULE / 'src').rglob('*.rs'))
    if workspace:
        inputs += [PROJECT / n for n in ['Cargo.toml', 'helper/Cargo.toml', 'notes/pq-workspace-graph-delta.json']]
        inputs += list((PROJECT / 'src').rglob('*.rs')) + list((PROJECT / 'helper/src').rglob('*.rs'))
    inputs += [MODULE / n for n in ['Cargo.toml', 'source-origin.json']]
    inputs += [PROJECT / n for n in ['vendor/aws-lc-rs-provenance.json', 'notes/aws-lc-mlkem-evaluation/aws-lc-rs-seed.patch', 'scripts/windows-linker.sh']]
    inputs += [PROJECT / n for n in ['notes/aws-lc-hybrid-evaluation/go-fixture.json', 'notes/aws-lc-hybrid-evaluation/kat-components.json', 'notes/pq-construction/ietf-hpke-pq-05-mlkem768p256.json', 'notes/pq-construction/concrete-03-mlkem768p256.json']]
    inputs += [Path(__file__).resolve()]
    inputs += [p for p in VENDOR.rglob('*') if p.is_file()]
    report = {'result': 'fail', 'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_sha256': {str(p.relative_to(PROJECT)): sha256(p) for p in sorted(inputs)}, 'steps': [],
              'workspace_integration': workspace, 'lock_path': str(lock.relative_to(PROJECT)),
              'limits': [('Workspace dependency/feature adoption only; production PQ scheme and Windows custody adapter remain unimplemented' if workspace else 'Staged module outside production workspace; no production scheme or dependency adoption'),
                         'Public software fixtures only; no hardware keys, persistent objects, storage or installation',
                         'No independent PQ recovery, erasure, attestation or cryptographic certification claim']}

    def run(command, label, expected=0):
        print('Running', label, flush=True)
        p = subprocess.run(command, cwd=PROJECT, env=env, text=True, capture_output=True, timeout=900)
        report['steps'].append({'check': label, 'command': command, 'exit_code': p.returncode,
                                'expected_exit_code': expected, 'stdout_sha256': hashlib.sha256(p.stdout.encode()).hexdigest(),
                                'stderr_sha256': hashlib.sha256(p.stderr.encode()).hexdigest()})
        if p.stderr:
            print(p.stderr, end='', flush=True)
        if '--message-format=json' not in command and '--format-version' not in command:
            print(p.stdout, end='', flush=True)
        if p.returncode != expected:
            raise RuntimeError(label + ' failed')
        return p.stdout

    try:
        provenance = json.loads((PROJECT / 'vendor/aws-lc-rs-provenance.json').read_text())
        patch = PROJECT / provenance['patch']
        if sha256(patch) != provenance['patch_sha256']:
            raise RuntimeError('seed patch changed')
        actual_files = {str(p.relative_to(VENDOR)) for p in VENDOR.rglob('*') if p.is_file()}
        if actual_files != set(provenance['files']):
            raise RuntimeError('unexpected local dependency files')
        for name, digests in provenance['files'].items():
            if sha256(VENDOR / name) != digests['patched_sha256']:
                raise RuntimeError('local dependency source drift: ' + name)
        archives = list((Path.home() / '.cargo/registry/cache').glob('*/aws-lc-rs-1.18.2.crate'))
        if len(archives) != 1 or sha256(archives[0]) != provenance['registry_archive_sha256']:
            raise RuntimeError('verified original archive unavailable')
        with tempfile.TemporaryDirectory(prefix='check-vendored-seed-') as directory:
            with tarfile.open(archives[0]) as archive:
                archive.extractall(directory, filter='data')
            original = Path(directory) / 'aws-lc-rs-1.18.2'
            for name, digests in provenance['files'].items():
                if sha256(original / name) != digests['original_sha256']:
                    raise RuntimeError('original archive source mismatch: ' + name)
            run(['patch', '--batch', '--fuzz=0', '--strip=1', '--directory', str(original), '--input', str(patch)], 'exact reviewed patch reproduction')
            if any(sha256(original / name) != sha256(VENDOR / name) for name in actual_files):
                raise RuntimeError('vendored source differs from exact patch reproduction')
        origin = json.loads((MODULE / 'source-origin.json').read_text())
        for name, hashes in origin['source_files'].items():
            if sha256(PROJECT / hashes['original']) != hashes['original_sha256'] or sha256(MODULE / name) != hashes['staged_sha256']:
                raise RuntimeError('relocated source origin mismatch: ' + name)
        report['provenance_verified'] = True
        manifest = ['--manifest-path', str(MODULE / 'Cargo.toml')]
        receiver_feature = 'age-tpm-wsl-post-quantum/seed-restoration' if workspace else 'seed-restoration'
        run(['cargo', 'fmt'] + manifest + ['--check'], 'module formatting')
        if workspace:
            delta = json.loads((PROJECT / 'notes/pq-workspace-graph-delta.json').read_text())
            allowed = {tuple(p) for p in delta['registry_identity_union']}
            actual = {(p['name'], p['version'], p['source'], p['checksum']) for p in tomllib.loads(lock.read_text())['package'] if 'source' in p}
            if sha256(lock) != delta['current_lock_sha256'] or not actual <= allowed:
                raise RuntimeError('workspace graph differs from recorded accepted-identity union')
        else:
            baseline = tomllib.loads(lock.read_text())['package']
            registry_before = {(p['name'], p['version'], p.get('source'), p.get('checksum')) for p in baseline if 'source' in p and p['name'] != 'aws-lc-rs'}
            run(['cargo', 'update', '--offline'] + manifest + ['--package', 'aws-lc-rs'], 'resolve staged local seed interface')
            resolved = tomllib.loads(lock.read_text())['package']
            registry_after = {(p['name'], p['version'], p.get('source'), p.get('checksum')) for p in resolved if 'source' in p}
            if registry_after != registry_before:
                raise RuntimeError('relocation changed other registry package identities')
        report['lock_sha256'] = sha256(lock)
        metadata = json.loads(run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1'] + manifest + ['--features', receiver_feature], 'exact enabled package/features'))
        packages = {p['name']: p for p in metadata['packages']}
        native = packages['aws-lc-sys']
        safe = packages['aws-lc-rs']
        if safe['source'] is not None or safe['version'] != '1.18.2' or Path(safe['manifest_path']).parent != VENDOR or native['version'] != '0.46.0' or not native['source'].startswith('registry+'):
            raise RuntimeError('unexpected backend identity')
        nodes = {n['id']: n for n in metadata['resolve']['nodes']}
        if any('evaluation' in p['name'] or p['name'] == 'pq-custody-binding' for p in metadata['packages']):
            raise RuntimeError('staged module still imports an evaluation package')
        def exact_package(name, version):
            selected = [p for p in metadata['packages'] if p['name'] == name and p['version'] == version]
            if len(selected) != 1:
                raise RuntimeError('missing or ambiguous package: ' + name + '@' + version)
            return selected[0]

        def dependency(package, name):
            selected = [d['pkg'] for d in nodes[package['id']]['deps'] if d['name'] == name]
            if len(selected) != 1:
                raise RuntimeError('missing or ambiguous dependency edge: ' + package['name'] + ' -> ' + name)
            return selected[0]

        hpke = exact_package('hpke', '0.14.1')
        pq = exact_package('age-tpm-wsl-post-quantum', '0.1.0')
        if dependency(pq, 'hpke') != hpke['id']:
            raise RuntimeError('PQ module does not select the reviewed HPKE package')
        wiping = {'chacha20poly1305': '0.11.0', 'poly1305': '0.9.1', 'sha2': '0.11.1',
                  'aes-gcm': '0.11.1', 'aes': '0.9.3', 'ghash': '0.6.0'}
        selected = {name: exact_package(name, version) for name, version in wiping.items()}
        for name, package in selected.items():
            if 'zeroize' not in nodes[package['id']]['features']:
                raise RuntimeError('missing wiping feature: ' + name + '@' + package['version'])
        for owner, edge, target in [(hpke, 'chacha20poly1305', 'chacha20poly1305'),
                                     (hpke, 'aes_gcm', 'aes-gcm'), (hpke, 'sha2', 'sha2'),
                                     (selected['chacha20poly1305'], 'poly1305', 'poly1305'),
                                     (selected['aes-gcm'], 'aes', 'aes'), (selected['aes-gcm'], 'ghash', 'ghash')]:
            if dependency(owner, edge) != selected[target]['id']:
                raise RuntimeError('HPKE wiping check does not match actual dependency edge: ' + edge)
        report['hpke_wiping_packages'] = [{'name': p['name'], 'version': p['version'], 'id': p['id'], 'features': nodes[p['id']]['features']} for p in selected.values()]
        report['other_crypto_versions'] = [{'name': p['name'], 'version': p['version'], 'features': nodes[p['id']]['features']} for p in metadata['packages'] if p['name'] in wiping and p['version'] != wiping[p['name']]]
        report['resolved_features'] = [{'name': p['name'], 'version': p['version'], 'source': p['source'], 'features': nodes[p['id']]['features']} for p in metadata['packages']]
        run(['cargo', 'test', '--locked', '--offline'] + manifest + (['--workspace'] if workspace else []), 'default workspace/classical and public codec tests' if workspace else 'public-only module and codec tests')
        run(['cargo', 'test', '--locked', '--offline'] + manifest + ['--features', receiver_feature], 'seed-enabled vectors and opaque receiver tests')
        run(['cargo', 'clippy', '--locked', '--offline'] + manifest + (['--workspace'] if workspace else []) + ['--all-targets', '--features', receiver_feature, '--', '--deny', 'warnings'], 'Linux workspace/module Clippy')
        if workspace:
            tree_base = ['cargo', 'tree', '--locked', '--offline', '--edges', 'normal,build', '--prefix', 'none', '--format', '{p}|{f}']
            linux_tree = run(tree_base + ['--package', 'age-plugin-tpm-wsl', '--target', 'x86_64-unknown-linux-gnu'], 'actual Linux plugin feature isolation')
            if not any(line.startswith('aws-lc-rs ') for line in linux_tree.splitlines()) or not any(line.startswith('age-tpm-wsl-pq ') for line in linux_tree.splitlines()) or 'experimental-kem-seed' in linux_tree or 'seed-restoration' in linux_tree:
                raise RuntimeError('Linux public consumer enables private seed restoration or is absent')
            windows_tree = run(tree_base + ['--package', 'age-tpm-wsl-helper', '--target', 'x86_64-pc-windows-gnu'], 'actual Windows helper private feature selection')
            if any(feature not in windows_tree for feature in ['seed-restoration', 'experimental-kem-seed', 'all-bindings']):
                raise RuntimeError('Windows helper missing required private seed/native feature')
            report['consumer_features'] = {'linux': [line for line in linux_tree.splitlines() if line.startswith(('age-tpm-wsl-pq ', 'aws-lc-rs ', 'aws-lc-sys '))], 'windows': [line for line in windows_tree.splitlines() if line.startswith(('age-tpm-wsl-pq ', 'aws-lc-rs ', 'aws-lc-sys '))]}
        else:
            default_metadata = json.loads(run(['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'] + manifest, 'public-only feature isolation'))
            safe_node = next(n for n in default_metadata['resolve']['nodes'] if n['id'] == safe['id'])
            if 'experimental-kem-seed' in safe_node['features']:
                raise RuntimeError('public-only build enables private seed interface')
        report['public_only_seed_feature_disabled'] = True
        with tempfile.TemporaryDirectory(prefix='check-seed-interface-off-') as directory:
            probe = Path(directory)
            (probe / 'src').mkdir()
            (probe / 'src/main.rs').write_text('fn main() { let _ = aws_lc_rs::kem::DecapsulationKey::from_seed(&aws_lc_rs::kem::ML_KEM_768, &[0u8; 64]); }\n')
            (probe / 'Cargo.toml').write_text('[package]\nname="seed-interface-off"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\naws-lc-rs={path=' + json.dumps(str(VENDOR)) + ',default-features=false,features=["alloc","non-fips","prebuilt-nasm"]}\n')
            probe_manifest = ['--manifest-path', str(probe / 'Cargo.toml')]
            run(['cargo', 'generate-lockfile', '--offline'] + probe_manifest, 'feature-off probe lock')
            output = run(['cargo', 'check', '--offline', '--locked'] + probe_manifest + ['--message-format=json'], 'feature-off seed API compile rejection', expected=101)
            errors = [v['message'] for line in output.splitlines() if (v := json.loads(line)).get('reason') == 'compiler-message' and v['message']['level'] == 'error']
            if not errors or any((e.get('code') or {}).get('code') != 'E0599' or 'from_seed' not in e['message'] for e in errors):
                raise RuntimeError('feature-off probe failed for another reason')
            report['public_only_seed_api_rejected'] = True
        if args.windows:
            tool = PROJECT / 'target/windows-toolchain/usr/bin'
            env.update(PATH=str(tool) + os.pathsep + env.get('PATH', ''),
                       CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=str(PROJECT / 'scripts/windows-linker.sh'),
                       CC_x86_64_pc_windows_gnu=str(PROJECT / 'scripts/windows-linker.sh'),
                       AR_x86_64_pc_windows_gnu=str(tool / 'x86_64-w64-mingw32-ar'))
            target = ['--target', 'x86_64-pc-windows-gnu']
            output = run(['cargo', 'test', '--no-run', '--offline', '--locked'] + manifest + target + ['--features', receiver_feature, '--message-format=json'], 'Windows module test build')
            executables = [Path(v['executable']) for line in output.splitlines() if (v := json.loads(line)).get('reason') == 'compiler-artifact' and v.get('executable')]
            if len(executables) != 1:
                raise RuntimeError('expected one Windows module test binary')
            run(['cargo', 'clippy', '--offline', '--locked'] + manifest + target + ['--all-targets', '--features', receiver_feature, '--', '--deny', 'warnings'], 'Windows module Clippy')
            if workspace:
                run(['cargo', 'build', '--locked', '--offline', '--package', 'age-tpm-wsl-helper'] + target, 'Windows consumer helper build')
                run(['cargo', 'clippy', '--locked', '--offline', '--package', 'age-tpm-wsl-helper'] + target + ['--all-targets', '--', '--deny', 'warnings'], 'Windows consumer helper Clippy')
            report['windows_executable_sha256'] = sha256(executables[0])
            run([str(executables[0]), '--test-threads=1'], 'native Windows public-fixture tests')
        for name, digest in report['source_sha256'].items():
            if sha256(PROJECT / name) != digest:
                raise RuntimeError('source changed during validation: ' + name)
        if sha256(lock) != report['lock_sha256']:
            raise RuntimeError('lock changed during validation')
        report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved staged module report:', args.report, flush=True)


if __name__ == '__main__':
    main()
