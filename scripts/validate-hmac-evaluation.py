#!/usr/bin/env python3
"""Validate isolated HMAC guards with compiled units, advisories and source binding."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'notes/hmac-memory-evaluation'
VERSIONS = ['0.12.1', '0.13.0']


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def file_map(directory):
    return {str(path.relative_to(directory)): digest(path) for path in directory.rglob('*') if path.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    baseline_path = FOLDER / 'baseline-validation.json'
    baseline = json.loads(baseline_path.read_text())
    if baseline['result'] != 'pass' or not baseline['source_snapshot_unchanged']:
        raise RuntimeError('passing unchanged-source original HMAC baseline required')
    before = baseline['source_sha256'].copy()
    for key, count in [('default-linux', 18), ('all-linux', 22)]:
        profile = baseline['profiles'][key]
        if profile['exit_code'] != 0 or profile['test_summaries'] != [[str(count), '0', '0']]:
            raise RuntimeError('original HMAC baseline case counts mismatch')
        for path_field, hash_field in [('metadata_path', 'metadata_sha256'), ('compiler_artifacts_path', 'compiler_artifacts_sha256')]:
            path = Path(profile[path_field]).resolve()
            if digest(path) != profile[hash_field]:
                raise RuntimeError('original HMAC baseline evidence changed')
            before[str(path.relative_to(ROOT))] = profile[hash_field]
    before.update({str(path.relative_to(ROOT)): digest(path) for path in
                   [baseline_path, Path(__file__), ROOT / 'scripts/windows-linker.sh', ROOT / 'notes/hkdf-memory-evaluation/src/lib.rs']})

    def check_inputs():
        if any(digest(ROOT / name) != expected for name, expected in before.items()):
            raise RuntimeError('accepted source/driver/baseline inputs changed')
        return True

    check_inputs()
    report = {'result': 'fail', 'source_sha256': before, 'steps': [], 'configurations': {}, 'scans': [],
              'limits': ['Isolated HMAC guards only; active root and reviewed HKDF sources unchanged',
                         'Live guarded pad/output owners only; underlying digest/block-buffer/caller/compiler/register/move copies excluded',
                         'No native TPM, provider, installation or cleanup operations',
                         'Independent source review and combined project/actual-root acceptance remain separate gates']}
    env = os.environ.copy()
    env.update(RUSTC_WRAPPER='', CARGO_TARGET_DIR=str(ROOT / 'target/hmac-isolated-validation-build'))
    args.report.parent.mkdir(parents=True, exist_ok=True)

    def save_raw(suffix, raw):
        path = args.report.with_name(args.report.stem + '-' + suffix)
        path.write_text(raw)
        return {'path': str(path), 'sha256': digest(path)}

    def run(command, label, configuration=None, count=None, artifact_kind=None):
        print('Running ' + label, flush=True)
        p = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=600)
        summaries = [list(row) for row in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', p.stdout)]
        step = {'check': label, 'command': command, 'exit_code': p.returncode, 'test_summaries': summaries,
                'stdout_sha256': hashlib.sha256(p.stdout.encode()).hexdigest(), 'stderr_sha256': hashlib.sha256(p.stderr.encode()).hexdigest(),
                'failed_tests': re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. FAILED$', p.stdout, re.MULTILINE)}
        report['steps'].append(step)
        if p.stderr:
            print(p.stderr, end='', flush=True)
        if configuration:
            if configuration not in report['configurations']:
                raise RuntimeError('step configuration missing')
            step['configuration'] = configuration
        if artifact_kind:
            artifacts = []
            for line in p.stdout.splitlines():
                if not line.startswith('{'):
                    continue
                row = json.loads(line)
                if row.get('reason') == 'compiler-artifact':
                    artifacts.append(row)
                elif row.get('reason') == 'compiler-message' and row.get('message', {}).get('rendered'):
                    print(row['message']['rendered'], end='', flush=True)
            step['compiler_artifacts'] = save_raw(label.replace(' ', '-') + '-artifacts.jsonl', ''.join(json.dumps(a, sort_keys=True) + '\n' for a in artifacts))
            full = report['configurations'][configuration]['build_metadata']
            if digest(full['path']) != full['sha256']:
                raise RuntimeError('build-resolution evidence changed')
            nodes = {n['id']: n for n in json.loads(Path(full['path']).read_text())['resolve']['nodes']}
            if not artifacts or any(a['package_id'] not in nodes or not set(a['features']).issubset(nodes[a['package_id']]['features']) for a in artifacts):
                raise RuntimeError('compiled units not covered by complete build-resolution envelope')
            step['compiled_units'] = [{key: a[key] for key in ['package_id', 'features', 'target', 'profile', 'executable']} for a in artifacts]
        if p.returncode != 0 or (count is not None and summaries != [[str(count), '0', '0']]):
            raise RuntimeError(label + ' failed or required cases missing')
        return p.stdout

    def capture(key, manifest, target, features, source=None, original=None):
        manifest_args = ['--manifest-path', str(manifest)]
        full = run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1'] + manifest_args + features, key + ' complete build metadata')
        filtered = run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1', '--filter-platform', target] + manifest_args + features, key + ' target metadata')
        metadata = json.loads(full)
        nodes = {node['id']: node for node in metadata['resolve']['nodes']}
        record = {'target': target, 'feature_args': features, 'build_metadata': save_raw(key + '-build-metadata.json', full),
                  'target_metadata': save_raw(key + '-target-metadata.json', filtered),
                  'scope': 'Workspace resolution envelopes; actual compiled features retained per build unit', 'hmac_packages': []}
        report['configurations'][key] = record
        for version in VERSIONS:
            package = next(p for p in metadata['packages'] if p['name'] == 'hmac' and p['version'] == version)
            if source:
                if package['source'] is not None or Path(package['manifest_path']).resolve() != (source / ('hmac-' + version) / 'Cargo.toml').resolve():
                    raise RuntimeError('patched HMAC source selection mismatch')
                old_package = next(p for p in original['packages'] if p['name'] == 'hmac' and p['version'] == version)
                old_nodes = {node['id']: node for node in original['resolve']['nodes']}
                if old_nodes[old_package['id']]['features'] != nodes[package['id']]['features']:
                    raise RuntimeError('HMAC feature delta')
                added = [d for d in package['dependencies'] if d not in old_package['dependencies']]
                if len(added) != 1 or added[0]['name'] != 'zeroize' or added[0]['req'] != '=1.9.1' or added[0]['uses_default_features'] or added[0]['optional'] or any(d not in package['dependencies'] for d in old_package['dependencies']):
                    raise RuntimeError('unexpected HMAC dependency metadata delta')
            elif package['source'] != 'registry+https://github.com/rust-lang/crates.io-index':
                raise RuntimeError('upstream companion lost original registry HMAC identity')
            record['hmac_packages'].append({'version': version, 'package_id': package['id'], 'manifest_path': package['manifest_path'], 'features': nodes[package['id']]['features']})
        command = ['cargo', 'deny'] + manifest_args + ['--locked', '--offline', '--target', target] + features + ['--format', 'json', 'check', 'advisories']
        print('Scanning ' + key, flush=True)
        p = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
        raw = p.stdout + p.stderr
        summaries = [row['fields']['advisories'] for line in raw.splitlines() if (row := json.loads(line)).get('type') == 'summary' and 'advisories' in row.get('fields', {})]
        report['scans'].append({'configuration': key, 'command': command, 'exit_code': p.returncode, 'raw': save_raw(key + '-advisories.jsonl', raw), 'summaries': summaries})
        if p.returncode != 0 or len(summaries) != 1 or summaries[0]['errors'] != 0:
            raise RuntimeError(key + ' advisory scan failed')
        return metadata

    try:
        report['tool_versions'] = {}
        for name, command in [('rustc', ['rustc', '--version', '--verbose']), ('cargo', ['cargo', '--version']), ('cargo-deny', ['cargo', 'deny', '--version'])]:
            report['tool_versions'][name] = run(command, name + ' version').strip()
        run(['python3', str(FOLDER / 'generate-fixtures.py')], 'independent fixture correspondence')
        run(['cargo', 'fmt', '--manifest-path', str(FOLDER / 'Cargo.toml'), '--check'], 'fixture formatting')
        with tempfile.TemporaryDirectory(prefix='hmac-acceptance-', dir=ROOT / 'target') as directory:
            temporary = Path(directory)
            stage = temporary / 'stage'
            run(['python3', str(FOLDER / 'prepare-hmac.py'), '--destination', str(stage)], 'checksum archive patch staging')
            provenance = json.loads((stage / 'provenance.json').read_text())
            if provenance['result'] != 'pass':
                raise RuntimeError('HMAC stage preparation failed')
            report['staged_provenance'] = provenance
            fixture = temporary / 'fixture'
            fixture.mkdir()
            for name in ['Cargo.toml', 'Cargo.lock', 'hmac-fixtures.json']:
                shutil.copyfile(FOLDER / name, fixture / name)
            shutil.copytree(FOLDER / 'src', fixture / 'src')
            manifest = fixture / 'Cargo.toml'
            text = manifest.read_text() + '\n[patch.crates-io]\n'
            for alias, version in [('hmac-v012', '0.12.1'), ('hmac-v013', '0.13.0')]:
                text += alias + ' = { package = "hmac", path = ' + json.dumps(str(stage / ('hmac-' + version))) + ' }\n'
                candidate = json.loads((ROOT / 'target/hmac-memory-candidate-v1/provenance.json').read_text())['packages'][version]
                if candidate != provenance['packages'][version]:
                    raise RuntimeError('reconstructed HMAC differs from independently reviewed candidate')
                if (stage / ('hmac-' + version) / 'src/wiping_bytes.rs').read_bytes().rstrip(b'\n') != (FOLDER / 'src/wiping_bytes.rs').read_bytes().rstrip(b'\n'):
                    raise RuntimeError('tested guard differs from staged HMAC guard beyond trailing newlines')
            report['guard_test_source_comparison'] = 'identical implementation; only trailing newlines normalized'
            manifest.write_text(text)
            manifest_args = ['--manifest-path', str(manifest)]
            run(['cargo', 'update', '--offline'] + manifest_args + ['--package', 'hmac@0.12.1', '--package', 'hmac@0.13.0'], 'temporary HMAC source selectors')
            original_lock = tomllib.loads((FOLDER / 'Cargo.lock').read_text())['package']
            patched_lock = tomllib.loads((fixture / 'Cargo.lock').read_text())['package']
            if [p for p in original_lock if p['name'] != 'hmac'] != [p for p in patched_lock if p['name'] != 'hmac']:
                raise RuntimeError('non-HMAC locked record changed')
            for version in VERSIONS:
                old = next(p for p in original_lock if p['name'] == 'hmac' and p['version'] == version)
                new = next(p for p in patched_lock if p['name'] == 'hmac' and p['version'] == version)
                expected = {k: v for k, v in old.items() if k not in {'source', 'checksum'}}
                expected['dependencies'] = sorted(old['dependencies'] + ['zeroize'])
                if new != expected:
                    raise RuntimeError('unexpected HMAC lock delta')
            fixture_before = file_map(fixture)
            report['proposed_fixture_sha256'] = fixture_before
            report['proposed_lock_sha256'] = digest(fixture / 'Cargo.lock')
            report['proposed_lock_packages'] = patched_lock
            for platform, target in [('linux', 'x86_64-unknown-linux-gnu'), ('windows', 'x86_64-pc-windows-gnu')]:
                if platform == 'windows':
                    tools = ROOT / 'target/windows-toolchain/usr/bin'
                    linker = ROOT / 'scripts/windows-linker.sh'
                    env.update(PATH=str(tools) + os.pathsep + env.get('PATH', ''), CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=str(linker),
                               CC_x86_64_pc_windows_gnu=str(linker), AR_x86_64_pc_windows_gnu=str(tools / 'x86_64-w64-mingw32-ar'))
                for profile, features, count in [('default', [], 18), ('all', ['--all-features'], 22)]:
                    key = profile + '-' + platform
                    original = capture('registry-' + key, FOLDER / 'Cargo.toml', target, features)
                    capture('patched-' + key, manifest, target, features, stage, original)
                    command = ['cargo', 'test', '--offline', '--locked', '--lib', '--message-format=json', '--target', target] + manifest_args + features
                    if platform == 'windows':
                        raw = run(command + ['--no-run'], key + ' build', 'patched-' + key, artifact_kind='test')
                        executables = [Path(a['executable']) for line in raw.splitlines() if (a := json.loads(line)).get('reason') == 'compiler-artifact' and a.get('executable') and a.get('profile', {}).get('test')]
                        if len(executables) != 1:
                            raise RuntimeError('expected one Windows HMAC fixture executable')
                        binary = executables[0]
                        report.setdefault('windows_executables', {})[key] = {'path': str(binary), 'sha256': digest(binary), 'build_step': key + ' build'}
                        run([str(binary), '--test-threads=1'], key + ' execution', 'patched-' + key, count)
                    else:
                        run(command, key + ' tests', 'patched-' + key, count, 'test')
                run(['cargo', 'clippy', '--offline', '--locked', '--no-deps', '--all-targets', '--all-features', '--message-format=json', '--target', target] + manifest_args + ['--', '--deny', 'warnings'], platform + ' fixture clippy', 'patched-all-' + platform, artifact_kind='lint')
            if file_map(fixture) != fixture_before:
                raise RuntimeError('proposed fixture source/manifest/file set changed')
            report['patch_sha256'] = {}
            for version, package in provenance['packages'].items():
                if file_map(stage / ('hmac-' + version)) != package['patched_sha256']:
                    raise RuntimeError('HMAC staged source/file set changed')
                patch_name = 'hmac-' + version + '-memory.patch'
                if digest(stage / patch_name) != package['patch_sha256']:
                    raise RuntimeError('staged patch differs from tested source')
                shutil.copyfile(stage / patch_name, FOLDER / patch_name)
                report['patch_sha256'][patch_name] = digest(FOLDER / patch_name)
        check_inputs()
        report['source_snapshot_unchanged'] = True
        report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, StopIteration, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        raise
    finally:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved isolated HMAC validation:', args.report, flush=True)


if __name__ == '__main__':
    main()
