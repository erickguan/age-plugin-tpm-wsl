#!/usr/bin/env python3
"""Build, replay public seeds and fuzz the four local parser targets with Rust ASan."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'notes/post-quantum-parser-fuzz.json'
WORK = ROOT / 'target/post-quantum-parser-fuzz'
TARGETS = {'formats': 4096, 'stanza': 4096, 'helper_frame': 8300, 'custody_record': 8300}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, log, environment, timeout):
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open('x') as stream:
        result = subprocess.run(command, cwd=ROOT, env=environment, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=timeout)
    item = {'command': [str(arg) for arg in command], 'exit_code': result.returncode,
            'log': str(log.relative_to(ROOT)), 'log_sha256': sha(log)}
    if result.returncode:
        raise RuntimeError('command failed; inspect ' + str(log.relative_to(ROOT)))
    return item


def main():
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    with REPORT.open('x') as stream:
        stream.write('{"result":"incomplete"}\n')
    paths = {Path(__file__).resolve(), ROOT / 'fuzz/seed-corpus.py'}
    for directory in ('src', 'crates/post_quantum', 'fuzz/fuzz_targets'):
        paths.update((ROOT / directory).rglob('*.rs'))
    paths.update(ROOT / name for name in ('Cargo.toml', 'Cargo.lock', 'crates/post_quantum/Cargo.toml',
                 'fuzz/Cargo.toml', 'fuzz/Cargo.lock', 'vendor/aws-lc-rs/Cargo.toml',
                 'vendor/aws-lc-rs/src/kem.rs', 'vendor/aws-lc-rs-provenance.json',
                 'notes/aws-lc-hybrid-evaluation/kat-components.json',
                 'notes/aws-lc-hybrid-evaluation/go-fixture.json'))
    sources = {str(path.relative_to(ROOT)): sha(path) for path in sorted(paths)}
    environment = dict(os.environ, RUSTC_WRAPPER='', CARGO_NET_OFFLINE='true')
    record = {'result': 'incomplete', 'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_sha256': sources, 'campaigns': [],
              'limits': ['Bounded local Linux parser checks only; no helpers, TPM operations or machine keys',
                         'Rust AddressSanitizer enabled; native AWS-LC C instrumentation is not claimed',
                         'A clean run covers only its inputs and duration; no general correctness or timing guarantee']}
    try:
        record['compiler'] = subprocess.check_output(['rustc', '+nightly', '--version', '--verbose'],
                                                     cwd=ROOT, env=environment, text=True).strip()
        record['cargo_fuzz'] = subprocess.check_output(['cargo', 'fuzz', '--version'],
                                                       cwd=ROOT, env=environment, text=True).strip()
        metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--manifest-path', 'fuzz/Cargo.toml',
                              '--offline', '--locked', '--format-version', '1'], cwd=ROOT, env=environment))
        nodes = {node['id']: node['features'] for node in metadata['resolve']['nodes']}
        packages = metadata['packages']
        for package in packages:
            if (package['name'] == 'age-tpm-wsl-post-quantum' and 'seed-restoration' in nodes[package['id']]
                    or package['name'] == 'aws-lc-rs' and 'experimental-kem-seed' in nodes[package['id']]):
                raise RuntimeError('private seed restoration enabled in public Linux fuzz graph')
        record['resolved_packages'] = [{'name': p['name'], 'version': p['version'], 'source': p['source'],
                                       'features': nodes[p['id']]} for p in packages]
        print('Preparing deterministic public seeds and all four Rust ASan targets.', flush=True)
        record['seeding'] = run([sys.executable, 'fuzz/seed-corpus.py', '--output', str(WORK / 'seeds')],
                                WORK / 'seed.log', environment, 30)
        record['build'] = run(['cargo', '+nightly', 'fuzz', 'build', '--target-dir', str(WORK / 'build'),
                              '--sanitizer', 'address'], WORK / 'build.log', environment, 1500)
        for target, maximum in TARGETS.items():
            print('Replaying seeds and running bounded ASan campaign: ' + target, flush=True)
            binary = WORK / 'build/x86_64-unknown-linux-gnu/release' / target
            seeds = sorted((WORK / 'seeds' / target).iterdir())
            replay = run([str(binary), '-runs=0', *[str(seed) for seed in seeds]],
                         WORK / (target + '-replay.log'), environment, 120)
            corpus = WORK / 'mutations' / target
            corpus.mkdir(parents=True, exist_ok=False)
            campaign = run([str(binary), str(corpus), str(WORK / 'seeds' / target), '-max_total_time=30',
                            '-runs=1000000', '-max_len=' + str(maximum), '-timeout=10',
                            '-artifact_prefix=' + str(WORK) + '/'],
                           WORK / (target + '-fuzz.log'), environment, 90)
            completed = re.findall(r'Done (\d+) runs in (\d+) second', (WORK / (target + '-fuzz.log')).read_text())
            if len(completed) != 1:
                raise RuntimeError('missing campaign completion for ' + target)
            record['campaigns'].append({'target': target, 'binary_sha256': sha(binary),
                 'seed_sha256': {seed.name: sha(seed) for seed in seeds}, 'max_len': maximum,
                 'replay': replay, 'campaign': campaign, 'runs': int(completed[0][0]),
                 'seconds': int(completed[0][1])})
            print(target + ': ' + completed[0][0] + ' runs, ' + completed[0][1] + ' seconds, pass.', flush=True)
        if sources != {name: sha(ROOT / name) for name in sources}:
            raise RuntimeError('source changed during validation')
        record['result'] = 'pass'
    except BaseException as error:
        record['result'] = 'fail'
        record['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        REPORT.write_text(json.dumps(record, indent=2) + '\n')
        print('Saved local parser evidence: ' + str(REPORT.relative_to(ROOT)), flush=True)


if __name__ == '__main__':
    main()
