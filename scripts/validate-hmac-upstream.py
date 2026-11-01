#!/usr/bin/env python3
"""Run pinned upstream SHA-256/SHA-512 HMAC suites on registry and guarded sources."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'notes/hmac-memory-evaluation'
CANDIDATE = ROOT / 'target/hmac-memory-candidate-v1'
CHECKER = ROOT / 'notes/hkdf-memory-evaluation/validate-project.py'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def files(directory):
    return {str(path.relative_to(directory)): digest(path) for path in directory.rglob('*') if path.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    destination = args.destination.resolve()
    if ROOT not in destination.parents or 'target' not in destination.relative_to(ROOT).parts:
        raise RuntimeError('upstream suites require new ignored target storage')
    destination.mkdir(parents=True, exist_ok=False)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    provenance = json.loads((CANDIDATE / 'provenance.json').read_text())
    root_packages = tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
    root_versions = {(p['name'], p['version']) for p in root_packages}
    before = {str(path.relative_to(ROOT)): digest(path) for path in [ROOT / 'Cargo.lock', Path(__file__), CHECKER, CANDIDATE / 'provenance.json', ROOT / 'scripts/windows-linker.sh']}
    spec = importlib.util.spec_from_file_location('compiled_unit_checker', CHECKER)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    report = {'result': 'fail', 'scope': 'Upstream RFC4231/Wycheproof SHA256/SHA512 suites; source selectors remain isolated',
              'source_sha256': before, 'steps': [], 'configurations': {}, 'scans': [], 'fixture_provenance': {},
              'limits': ['Only applicable SHA256/SHA512 upstream suites; MD5/SHA1/SHA224/SHA384/Streebog not claimed',
                         'Original macro bodies/invocations and binary vector data retained; imports/suite selection narrowed',
                         'blobby dev-only parsers are additional test dependencies; production crypto versions must match root',
                         'No native TPM, provider, installation or root-selector operation',
                         'Functional vectors do not prove physical erasure or timing behavior']}
    env = os.environ.copy()
    env.update(RUSTC_WRAPPER='', CARGO_TARGET_DIR=str(ROOT / 'target/hmac-upstream-build'))
    base_env = env.copy()

    def save(name, data):
        path = args.report.with_name(args.report.stem + '-' + name)
        path.write_text(data)
        return {'path': str(path), 'sha256': digest(path)}

    def run(command, label, config=None, count=None, artifacts=False):
        print('Running ' + label, flush=True)
        p = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=600)
        row = {'check': label, 'command': command, 'exit_code': p.returncode,
               'test_summaries': [list(s) for s in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', p.stdout)],
               'stdout_sha256': hashlib.sha256(p.stdout.encode()).hexdigest(), 'stderr_sha256': hashlib.sha256(p.stderr.encode()).hexdigest(),
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
                unit = json.loads(line)
                if unit.get('reason') == 'compiler-artifact':
                    units.append(unit)
                elif unit.get('reason') == 'compiler-message' and unit.get('message', {}).get('rendered'):
                    print(unit['message']['rendered'], end='', flush=True)
            row['compiler_artifacts'] = save(label.replace(' ', '-') + '-artifacts.jsonl', ''.join(json.dumps(u, sort_keys=True) + '\n' for u in units))
            row['compiled_units'] = checker.compiled_unit_records(units, report['configurations'][config])
        if p.returncode != 0 or (count is not None and row['test_summaries'] != [[str(count), '0', '0']]):
            raise RuntimeError(label + ' failed or expected upstream functions missing')
        return p.stdout

    def capture(key, manifest, target, feature_args, version, graph):
        full = run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1', '--manifest-path', str(manifest)] + feature_args, key + ' build metadata')
        filtered = run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1', '--filter-platform', target, '--manifest-path', str(manifest)] + feature_args, key + ' target metadata')
        build = save(key + '-build-metadata.json', full)
        target_record = save(key + '-target-metadata.json', filtered)
        record = {'target': target, 'feature_args': feature_args, 'metadata_path': target_record['path'], 'metadata_sha256': target_record['sha256'],
                  'build_resolution_metadata_path': build['path'], 'build_resolution_metadata_sha256': build['sha256'],
                  'scope': 'Target/full workspace envelopes; exact features come from compiler artifacts'}
        report['configurations'][key] = record
        metadata = json.loads(full)
        package = next(p for p in metadata['packages'] if p['name'] == 'hmac' and p['version'] == version)
        if graph == 'patched':
            if package['source'] is not None or Path(package['manifest_path']).resolve() != (CANDIDATE / ('hmac-' + version) / 'Cargo.toml').resolve():
                raise RuntimeError('upstream suite selected wrong patched HMAC')
        elif package['source'] != 'registry+https://github.com/rust-lang/crates.io-index':
            raise RuntimeError('upstream companion lost registry identity')
        record['hmac_package_id'] = package['id']
        command = ['cargo', 'deny', '--manifest-path', str(manifest), '--locked', '--offline', '--target', target] + feature_args + ['--format', 'json', 'check', 'advisories']
        print('Scanning ' + key, flush=True)
        p = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
        raw = p.stdout + p.stderr
        summaries = [row['fields']['advisories'] for line in raw.splitlines() if (row := json.loads(line)).get('type') == 'summary' and 'advisories' in row.get('fields', {})]
        report['scans'].append({'configuration': key, 'command': command, 'exit_code': p.returncode, 'raw': save(key + '-advisories.jsonl', raw), 'summaries': summaries})
        if p.returncode != 0 or len(summaries) != 1 or summaries[0]['errors'] != 0:
            raise RuntimeError(key + ' advisory scan failed')

    try:
        if provenance['result'] != 'pass' or digest(ROOT / 'Cargo.lock') != provenance['root_lock_sha256']:
            raise RuntimeError('original candidate/root provenance mismatch')
        for version, suffix, digest_version, sha_version, blob_version, expected in [
                ('0.12.1', '012', '0.10.7', '0.10.9', '0.3.1', 8), ('0.13.0', '013', '0.11.3', '0.11.1', '0.4.0', 4)]:
            package_record = provenance['packages'][version]
            source = CANDIDATE / ('hmac-' + version)
            if files(source) != package_record['patched_sha256']:
                raise RuntimeError('reviewed HMAC candidate changed')
            original = (source / 'tests/mod.rs').read_text()
            if digest(source / 'tests/mod.rs') != package_record['original_sha256']['tests/mod.rs']:
                raise RuntimeError('original upstream test source changed')
            if suffix == '012':
                invocations = [item for item in re.findall(r'test!\(.*?\);', original, re.DOTALL)
                               if re.search(r'hmac_sha(?:256|512)_(?:rfc4231|wycheproof)', item)]
                prefix = original[:original.index('use sha1::Sha1;')] + 'use sha2::{Sha256, Sha512};\n\n'
                selected = prefix + '\n'.join(invocations) + '\n'
                data_names = ['sha256.blb', 'sha512.blb', 'wycheproof-sha256.blb', 'wycheproof-sha512.blb']
                features = 'reset = ["hmac/reset"]\nstd = ["hmac/std"]\n'
            else:
                prefix = original[:original.index('// Test vectors from RFC 2104')]
                invocations = re.findall(r'new_test!\(hmac_sha(?:256|512)_(?:rfc4231|wycheproof),.*?\);', original, re.DOTALL)
                selected = prefix + '\n'.join(invocations) + '\n'
                data_names = ['hmac_sha256_rfc4231.blb', 'hmac_sha512_rfc4231.blb', 'hmac_sha256_wycheproof.blb', 'hmac_sha512_wycheproof.blb']
                features = 'zeroize = ["hmac/zeroize"]\n'
            if len(invocations) != expected:
                raise RuntimeError('upstream test selection count mismatch')
            for graph in ['registry', 'patched']:
                env.clear()
                env.update(base_env)
                name = 'hmac-upstream-' + suffix + '-' + graph
                fixture = destination / name
                (fixture / 'src/data').mkdir(parents=True)
                (fixture / 'src/lib.rs').write_text('#[cfg(test)]\nmod upstream;\n')
                (fixture / 'src/upstream.rs').write_text(selected)
                for data in data_names:
                    if digest(source / 'tests/data' / data) != package_record['original_sha256']['tests/data/' + data]:
                        raise RuntimeError('upstream binary vector changed')
                    shutil.copyfile(source / 'tests/data' / data, fixture / 'src/data' / data)
                manifest = fixture / 'Cargo.toml'
                sha_features = ', default-features = false, features = ["zeroize"]' if suffix == '013' else ''
                text = '[package]\nname = ' + json.dumps(name) + '\nversion = "0.1.0"\nedition = "2024"\npublish = false\n\n[workspace]\n\n[features]\n' + features
                text += '\n[dependencies]\nhmac = "=' + version + '"\ndigest = { version = "=' + digest_version + '", features = ["dev"] }\n'
                text += 'sha2 = { version = "=' + sha_version + '"' + sha_features + ' }\nblobby = "=' + blob_version + '"\n'
                if graph == 'patched':
                    text += '\n[patch.crates-io]\nhmac = { path = ' + json.dumps(str(source)) + ' }\n'
                manifest.write_text(text)
                shutil.copyfile(ROOT / 'Cargo.lock', fixture / 'Cargo.lock')
                # Resolve/fetch only the public dev parser additions. Existing
                # locked crypto versions must survive the exact checks below.
                run(['cargo', 'metadata', '--format-version', '1', '--manifest-path', str(manifest)], name + ' public dev dependency preparation')
                locked = tomllib.loads((fixture / 'Cargo.lock').read_text())['package']
                for package in locked:
                    if package['name'] == name:
                        continue
                    if package['name'] == 'blobby':
                        if package['version'] != blob_version:
                            raise RuntimeError('unexpected upstream dev parser version')
                        if suffix == '013':
                            pinned = next(p for p in tomllib.loads((source / 'Cargo.lock').read_text())['package'] if p['name'] == 'blobby')
                            if package.get('checksum') != pinned['checksum']:
                                raise RuntimeError('new-family parser checksum differs from upstream lock')
                    elif (package['name'], package['version']) not in root_versions:
                        raise RuntimeError('upstream suite changed a reviewed crypto/dependency version: ' + package['name'])
                fixture_before = files(fixture)
                report['fixture_provenance'][name] = {'path': str(fixture), 'files_sha256': fixture_before, 'lock_packages': locked,
                                                      'upstream_test_sha256': package_record['original_sha256']['tests/mod.rs'], 'selected_functions': expected}
                for platform, target in [('linux', 'x86_64-unknown-linux-gnu'), ('windows', 'x86_64-pc-windows-gnu')]:
                    env.clear()
                    env.update(base_env)
                    if platform == 'windows':
                        tools = ROOT / 'target/windows-toolchain/usr/bin'
                        linker = ROOT / 'scripts/windows-linker.sh'
                        env.update(PATH=str(tools) + os.pathsep + env.get('PATH', ''), CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=str(linker),
                                   CC_x86_64_pc_windows_gnu=str(linker), AR_x86_64_pc_windows_gnu=str(tools / 'x86_64-w64-mingw32-ar'))
                    for profile, args_features in [('default', []), ('all', ['--all-features'])]:
                        key = suffix + '-' + graph + '-' + profile + '-' + platform
                        capture(key, manifest, target, args_features, version, graph)
                        if graph == 'registry' and platform == 'windows':
                            continue
                        command = ['cargo', 'test', '--offline', '--locked', '--lib', '--message-format=json', '--target', target, '--manifest-path', str(manifest)] + args_features
                        if platform == 'windows':
                            raw = run(command + ['--no-run'], key + ' build', key, artifacts=True)
                            executables = [Path(row['executable']) for line in raw.splitlines() if (row := json.loads(line)).get('reason') == 'compiler-artifact' and row.get('executable') and row.get('profile', {}).get('test')]
                            if len(executables) != 1:
                                raise RuntimeError('expected one upstream Windows suite executable')
                            binary = executables[0]
                            report.setdefault('executables', {})[key] = {'path': str(binary), 'sha256': digest(binary)}
                            run([str(binary), '--test-threads=1'], key + ' execution', key, expected)
                        else:
                            run(command, key + ' tests', key, expected, True)
                if files(fixture) != fixture_before:
                    raise RuntimeError('upstream fixture source/data/lock set changed')
        for version, record in provenance['packages'].items():
            if files(CANDIDATE / ('hmac-' + version)) != record['patched_sha256']:
                raise RuntimeError('reviewed HMAC source changed during upstream campaign')
        if any(digest(ROOT / name) != expected for name, expected in before.items()):
            raise RuntimeError('upstream driver/source/root inputs changed')
        report['source_snapshot_unchanged'] = True
        report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, StopIteration, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        raise
    finally:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved upstream HMAC suite validation:', args.report, flush=True)


if __name__ == '__main__':
    main()
