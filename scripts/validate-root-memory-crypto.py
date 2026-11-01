#!/usr/bin/env python3
"""Validate current selected crypto sources and the original registry companion."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from memory_crypto_inputs import FAMILIES, ROOT, digest, load
from root_memory_crypto_inputs import snapshot

FOLDER = ROOT / 'notes/crypto-memory-integration'


def main():
    if not __debug__:
        raise RuntimeError('combined crypto validation requires active Python assertions')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    adoption_path = FOLDER / 'adoption.json'
    adoption = json.loads(adoption_path.read_text())
    workspace = ROOT
    manifest = ['--manifest-path', str(ROOT / 'Cargo.toml')]
    build = ROOT / 'target'
    registry = Path(tempfile.mkdtemp(prefix='root-crypto-registry-', dir=build))
    (registry / 'Cargo.toml').write_text(adoption['root_manifest_before_text'])
    (registry / 'Cargo.lock').write_text(adoption['root_lock_before_text'])
    for folder in ['src', 'tests', 'examples', 'vendor']:
        (registry / folder).symlink_to(ROOT / folder, target_is_directory=True)
    for folder in ['helper', 'crates/post_quantum', 'crates/custody-fs']:
        target = registry / folder
        target.mkdir(parents=True)
        shutil.copyfile(ROOT / folder / 'Cargo.toml', target / 'Cargo.toml')
        (target / 'src').symlink_to(ROOT / folder / 'src', target_is_directory=True)
    registry_before = {str(path.relative_to(registry)): digest(path) for path in registry.rglob('Cargo.*') if path.is_file() and not path.is_symlink()}
    checker = load(ROOT / 'notes/hkdf-memory-evaluation/validate-project.py', 'compiled_units')
    report = {'result': 'fail', 'adoption_sha256': digest(adoption_path), 'registry_companion': str(registry), 'steps': [], 'configurations': {}, 'scans': [], 'clients': [],
              'limits': ['Current root software/source acceptance; no installation or native acceptance follows',
                         'Windows software tests only; exact native lifecycle remains ignored',
                         'All client keys/configs use isolated software fixtures; no native identity argument forwarded',
                         'No provider, production enrollment, installation, persistence or cleanup operation',
                         'Functional/source acceptance does not establish comprehensive erasure or timing behavior']}
    env = os.environ.copy()
    env.update(RUSTC_WRAPPER='', CARGO_TARGET_DIR=str(build))
    base_env = env.copy()
    args.report.parent.mkdir(parents=True, exist_ok=True)

    def save(name, text):
        path = args.report.with_name(args.report.stem + '-' + name)
        path.write_text(text)
        return {'path': str(path), 'sha256': digest(path)}

    def run(command, label, config=None, counts=None, artifacts=False):
        print('Running ' + label, flush=True)
        p = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=900)
        row = {'check': label, 'command': command, 'exit_code': p.returncode,
               'test_summaries': [list(s) for s in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', p.stdout)],
               'stdout_sha256': hashlib.sha256(p.stdout.encode()).hexdigest(),
               'stderr_sha256': hashlib.sha256(p.stderr.encode()).hexdigest(),
               'failed_tests': re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. FAILED$', p.stdout, re.MULTILINE)}
        report['steps'].append(row)
        if p.stderr:
            print(p.stderr, end='', flush=True)
        if config:
            row['configuration'] = config
        if artifacts:
            units = []
            for line in p.stdout.splitlines():
                if not line.startswith('{'):
                    continue
                item = json.loads(line)
                if item.get('reason') == 'compiler-artifact':
                    units.append(item)
                elif item.get('reason') == 'compiler-message' and item.get('message', {}).get('rendered'):
                    print(item['message']['rendered'], end='', flush=True)
            row['compiler_artifacts'] = save(label.replace(' ', '-') + '-artifacts.jsonl', ''.join(json.dumps(u, sort_keys=True) + '\n' for u in units))
            row['compiled_units'] = checker.compiled_unit_records(units, report['configurations'][config])
        if p.returncode != 0 or (counts is not None and row['test_summaries'] != counts):
            raise RuntimeError(label + ' failed or expected test sets missing')
        return p.stdout

    def capture(key, target, features, original_registry):
        manifest_args = ['--manifest-path', str(registry / 'Cargo.toml')] if original_registry else manifest
        full = run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1'] + manifest_args + features, key + ' complete build graph')
        filtered = run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1', '--filter-platform', target] + manifest_args + features, key + ' target graph')
        build_record, target_record = save(key + '-build-metadata.json', full), save(key + '-target-metadata.json', filtered)
        metadata = json.loads(full)
        nodes = {n['id']: n for n in metadata['resolve']['nodes']}
        configuration = {'target': target, 'feature_args': features, 'metadata_path': target_record['path'], 'metadata_sha256': target_record['sha256'],
                         'build_resolution_metadata_path': build_record['path'], 'build_resolution_metadata_sha256': build_record['sha256'],
                         'scope': 'Target/build workspace supersets; per-build compiler units record actual features', 'crypto_packages': []}
        report['configurations'][key] = configuration
        for family, versions in FAMILIES.items():
            for version in versions:
                package = next(p for p in metadata['packages'] if p['name'] == family and p['version'] == version)
                if original_registry:
                    if package['source'] != 'registry+https://github.com/rust-lang/crates.io-index':
                        raise RuntimeError('original crypto registry identity missing')
                elif package['source'] is not None or Path(package['manifest_path']).resolve() != (ROOT / 'vendor/crypto-memory' / (family + '-' + version) / 'Cargo.toml').resolve():
                    raise RuntimeError('combined crypto source selection mismatch')
                configuration['crypto_packages'].append({'name': family, 'version': version, 'package_id': package['id'], 'features': nodes[package['id']]['features'], 'manifest_path': package['manifest_path']})
        command = ['cargo', 'deny'] + manifest_args + ['--workspace', '--offline', '--locked', '--target', target] + features + ['--format', 'json', 'check', 'advisories']
        print('Scanning ' + key, flush=True)
        p = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
        raw = p.stdout + p.stderr
        summaries = [r['fields']['advisories'] for line in raw.splitlines() if (r := json.loads(line)).get('type') == 'summary' and 'advisories' in r.get('fields', {})]
        report['scans'].append({'configuration': key, 'command': command, 'exit_code': p.returncode, 'raw': save(key + '-advisories.jsonl', raw), 'summaries': summaries})
        if p.returncode != 0 or len(summaries) != 1 or summaries[0]['errors'] != 0:
            raise RuntimeError(key + ' advisory scan failed')
        return metadata

    def require_seed(units, enabled):
        configuration = report['configurations'][report['steps'][-1]['configuration']]
        metadata = json.loads(Path(configuration['build_resolution_metadata_path']).read_text())
        for name, feature in [('age-tpm-wsl-post-quantum', 'seed-restoration'), ('aws-lc-rs', 'experimental-kem-seed')]:
            identities = {package['id'] for package in metadata['packages'] if package['name'] == name}
            selected = [unit for unit in units if unit['package_id'] in identities]
            if not selected or any((feature in unit['features']) != enabled for unit in selected):
                raise RuntimeError('actual consumer seed feature separation failed: ' + name)

    try:
        report['optimization_controls'] = []
        for script in ['run-root-memory-crypto-client.py', 'validate-root-memory-crypto.py']:
            for mode in ['flag', 'environment']:
                control_env = env.copy()
                control_env.pop('PYTHONOPTIMIZE', None)
                command = ['python3'] + (['-O'] if mode == 'flag' else []) + [str(ROOT / 'scripts' / script), '--help']
                if mode == 'environment':
                    control_env['PYTHONOPTIMIZE'] = '1'
                control = subprocess.run(command, cwd=ROOT, env=control_env, capture_output=True, text=True, timeout=30)
                if control.returncode == 0 or 'requires active Python assertions' not in control.stderr:
                    raise RuntimeError('actual-root optimized CLI did not refuse before argument/client activity')
                report['optimization_controls'].append({'script': script, 'mode': mode, 'exit_code': control.returncode, 'result': 'rejected before argument/client activity'})
        run(['python3', str(ROOT / 'scripts/test_memory_crypto_client.py')], 'client optimization boundary regressions')
        run(['python3', str(ROOT / 'scripts/vendor-age-sdk.py'), '--check'], 'unchanged SDK source provenance')
        before = snapshot()
        report['source_sha256'] = before
        for name, target, features in [('linux', 'x86_64-unknown-linux-gnu', []),
                                       ('linux-seed', 'x86_64-unknown-linux-gnu', ['--features', 'age-tpm-wsl-post-quantum/seed-restoration']),
                                       ('windows', 'x86_64-pc-windows-gnu', []),
                                       ('windows-seed', 'x86_64-pc-windows-gnu', ['--features', 'age-tpm-wsl-post-quantum/seed-restoration'])]:
            original = capture('registry-' + name, target, features, True)
            proposed = capture('combined-' + name, target, features, False)
            def feature_map(value):
                nodes = {n['id']: n for n in value['resolve']['nodes']}
                return {(p['name'], p['version']): nodes[p['id']]['features'] for p in value['packages']}
            if feature_map(original) != feature_map(proposed):
                raise RuntimeError('combined configuration changed resolved features')
        linux = ['--target', 'x86_64-unknown-linux-gnu']
        run(['cargo', 'test', '--offline', '--locked', '--message-format=json'] + manifest + linux + ['--workspace'], 'combined Linux workspace tests', 'combined-linux', artifacts=True)
        summaries = report['steps'][-1]['test_summaries']
        if sum(int(row[0]) for row in summaries) != 38 or any(row[1:] != ['0', '0'] for row in summaries):
            raise RuntimeError('expected 38 combined Linux tests missing')
        require_seed(report['steps'][-1]['compiled_units'], False)
        run(['cargo', 'test', '--offline', '--locked', '--message-format=json'] + manifest + linux + ['--package', 'age-tpm-wsl-post-quantum', '--features', 'seed-restoration'],
            'combined Linux hybrid HPKE', 'combined-linux-seed', [['14', '0', '0'], ['0', '0', '0']], True)
        require_seed(report['steps'][-1]['compiled_units'], True)
        run(['cargo', 'clippy', '--offline', '--locked', '--no-deps', '--workspace', '--all-targets', '--message-format=json'] + manifest + linux + ['--', '--deny', 'warnings'],
            'combined Linux consumer clippy', 'combined-linux', artifacts=True)
        run(['cargo', 'build', '--offline', '--locked', '--package', 'age-plugin-tpm-wsl', '--bins', '--examples', '--message-format=json'] + manifest,
            'combined software client producers', 'combined-linux', artifacts=True)
        require_seed(report['steps'][-1]['compiled_units'], False)
        producer_dir = build
        producers = {'plugin': producer_dir / 'debug/age-plugin-tpm-wsl', 'fixture': producer_dir / 'debug/examples/software_fixture'}
        actual_producers = report['steps'][-1]['compiled_units']
        for path in producers.values():
            if len([unit for unit in actual_producers if unit.get('executable') and Path(unit['executable']).resolve() == path.resolve()]) != 1:
                raise RuntimeError('actual-root producer not emitted at the exact client path')
        report['producers'] = {key: {'path': str(path), 'sha256': digest(path)} for key, path in producers.items()}
        for client in ['age', 'rage', 'fnox']:
            for algorithm in ['rsa2048', 'p256-hpke']:
                if any(digest(p['path']) != p['sha256'] for p in report['producers'].values()):
                    raise RuntimeError('client producer association changed')
                output = args.report.with_name(args.report.stem + '-' + client + '-' + algorithm + '.json')
                run(['python3', str(ROOT / 'scripts/run-root-memory-crypto-client.py'), '--client', client, '--algorithm', algorithm, '--output', str(output)],
                    'combined ' + client + ' ' + algorithm + ' software', 'combined-linux')
                value = json.loads(output.read_text())
                if value['mode'] != 'software fixture' or value['algorithm'] != algorithm:
                    raise RuntimeError('unexpected client validation mode')
                if client == 'fnox':
                    if set(value['checks']) != {'direct_get', 'offline_sync_encryption', 'persistent_cache_get', 'cache_helper_failure'} or any(v['result'] != 'pass' for v in value['checks'].values()):
                        raise RuntimeError('fnox software controls missing')
                elif [item['bytes'] for item in value['sizes']] != [0, 4, 256, 1024, 2048, 4096, 8192, 65535, 65536, 65537, 1048576, 4194304] or any(item['result'] != 'pass' for item in value['sizes']) or any(value.get(key) != 'pass' for key in ['offline_identity_encryption', 'duplicate_recipients', 'native_recovery_recipient', 'wrong_identity', 'wrong_plugin_identity', 'payload_corruption', 'stanza_version', 'helper_timeout', 'helper_interruption', 'helper_malformed']):
                    raise RuntimeError('age/rage software payload/control matrix missing')
                report['clients'].append({'client': client, 'algorithm': algorithm, 'report': str(output), 'sha256': digest(output)})
        if any(digest(p['path']) != p['sha256'] for p in report['producers'].values()):
            raise RuntimeError('client producer bytes/association changed')
        env.clear()
        env.update(base_env)
        tools = ROOT / 'target/windows-toolchain/usr/bin'
        linker = ROOT / 'scripts/windows-linker.sh'
        env.update(PATH=str(tools) + os.pathsep + env.get('PATH', ''), CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=str(linker),
                   CC_x86_64_pc_windows_gnu=str(linker), AR_x86_64_pc_windows_gnu=str(tools / 'x86_64-w64-mingw32-ar'))
        for package in ['age-tpm-wsl-post-quantum', 'age-tpm-wsl-helper']:
            features = ['--features', 'seed-restoration'] if package == 'age-tpm-wsl-post-quantum' else []
            config = 'combined-windows-seed' if features else 'combined-windows'
            raw = run(['cargo', 'test', '--offline', '--locked', '--lib' if features else '--bins', '--message-format=json'] + manifest + ['--package', package] + features + ['--target', 'x86_64-pc-windows-gnu', '--no-run'],
                      package + ' combined Windows build', config, artifacts=True)
            require_seed(report['steps'][-1]['compiled_units'], True)
            executables = [Path(a['executable']) for line in raw.splitlines() if (a := json.loads(line)).get('reason') == 'compiler-artifact' and a.get('executable') and a.get('profile', {}).get('test')]
            if len(executables) != 1:
                raise RuntimeError('expected one combined Windows package executable')
            binary = executables[0]
            report.setdefault('executables', {})[package] = {'path': str(binary), 'sha256': digest(binary)}
            if not features:
                listing = run([str(binary), '--ignored', '--list'], 'combined helper ignored lifecycle identity', config)
                if [line for line in listing.splitlines() if line.endswith(': test')] != ['post_quantum::store::native_tests::isolated_native_case: test']:
                    raise RuntimeError('unexpected ignored native test identity')
            run([str(binary), '--test-threads=1'], package + ' combined Windows software', config, [['14', '0', '0']] if features else [['17', '0', '1']])
        run(['cargo', 'clippy', '--offline', '--locked', '--no-deps', '--package', 'age-tpm-wsl-helper', '--all-targets', '--message-format=json'] + manifest + ['--target', 'x86_64-pc-windows-gnu', '--', '--deny', 'warnings'],
            'combined Windows helper clippy', 'combined-windows', artifacts=True)
        require_seed(report['steps'][-1]['compiled_units'], True)
        registry_after = {str(path.relative_to(registry)): digest(path) for path in registry.rglob('Cargo.*') if path.is_file() and not path.is_symlink()}
        if snapshot() != before or digest(adoption_path) != report['adoption_sha256'] or registry_after != registry_before:
            raise RuntimeError('actual root sources, adoption receipt or registry companion changed')
        report['registry_companion_source_sha256'] = registry_before
        report['source_snapshot_unchanged'] = True
        report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, StopIteration, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        raise
    finally:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved combined crypto project validation:', args.report, flush=True)


if __name__ == '__main__':
    main()
