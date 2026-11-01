#!/usr/bin/env python3
"""Run bounded ASan campaigns on the new PQ helper payloads and production codecs."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

PROJECT = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    inputs = list((PROJECT / 'src').rglob('*.rs')) + list((PROJECT / 'crates/post_quantum/src').rglob('*.rs')) + list((PROJECT / 'fuzz/fuzz_targets').glob('*.rs'))
    inputs += [PROJECT / name for name in ['Cargo.toml', 'Cargo.lock', 'crates/post_quantum/Cargo.toml', 'fuzz/Cargo.toml', 'fuzz/Cargo.lock', 'fuzz/seed-corpus.py', 'vendor/aws-lc-rs-provenance.json', 'vendor/aws-lc-rs/Cargo.toml', 'vendor/aws-lc-rs/src/kem.rs', 'notes/aws-lc-hybrid-evaluation/kat-components.json', 'notes/aws-lc-hybrid-evaluation/go-fixture.json']]
    inputs.append(Path(__file__).resolve())
    report = {'result': 'fail', 'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_sha256': {str(p.relative_to(PROJECT)): sha256(p) for p in sorted(inputs)}, 'campaigns': [],
              'limits': ['Bounded Linux public parser fuzzing only; no helpers, keys, secrets, Windows API calls or storage enrollments',
                         'Rust AddressSanitizer enabled; native AWS-LC C instrumentation is not claimed',
                         'Fuzz workspace now selects reviewed production PQ codecs and exact local safe-crate patch; no evaluation package is linked',
                         'A clean run describes the exercised inputs and duration; no formal audit, cryptographic-strength or complete-erasure claim']}
    env = os.environ.copy()
    env.update(RUSTC_WRAPPER='', CARGO_NET_OFFLINE='true')
    try:
        subprocess.run(['python3', 'fuzz/seed-corpus.py'], cwd=PROJECT, env=env, check=True, timeout=30)
        metadata = json.loads(subprocess.run(['cargo', 'metadata', '--manifest-path', 'fuzz/Cargo.toml', '--offline', '--locked', '--format-version', '1'], cwd=PROJECT, env=env, check=True, capture_output=True, text=True, timeout=60).stdout)
        if any('evaluation' in p['name'] or p['name'] == 'pq-custody-binding' for p in metadata['packages']):
            raise RuntimeError('fuzzer still links an evaluation package')
        safe = next(p for p in metadata['packages'] if p['name'] == 'aws-lc-rs')
        native = next(p for p in metadata['packages'] if p['name'] == 'aws-lc-sys')
        if safe['version'] != '1.18.2' or safe['source'] is not None or Path(safe['manifest_path']).parent != PROJECT / 'vendor/aws-lc-rs' or native['version'] != '0.46.0' or not native['source'].startswith('registry+'):
            raise RuntimeError('unexpected fuzzer AWS-LC identity')
        report['resolved_features'] = [{'name': p['name'], 'version': p['version'], 'source': p['source'], 'features': next(n['features'] for n in metadata['resolve']['nodes'] if n['id'] == p['id'])} for p in metadata['packages']]
        for target in ['helper_frame', 'custody_record']:
            command = ['cargo', '+nightly', 'fuzz', 'run', target, '--target-dir', str(PROJECT / 'target/pq-wire-fuzz'), '--sanitizer', 'address', '--', '-max_total_time=30', '-runs=500000', '-max_len=8300']
            print('Running bounded ASan ' + target, flush=True)
            p = subprocess.run(command, cwd=PROJECT, env=env, capture_output=True, text=True, timeout=1200)
            raw = p.stdout + p.stderr
            log = args.report.with_name(args.report.stem + '-' + target + '.log')
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(raw)
            matches = re.findall(r'Done (\d+) runs in (\d+) second', raw)
            report['campaigns'].append({'target': target, 'command': command, 'exit_code': p.returncode,
                                       'log_path': str(log), 'log_sha256': hashlib.sha256(raw.encode()).hexdigest(),
                                       'completed': [{'runs': int(n), 'seconds': int(t)} for n, t in matches]})
            print(target + ': exit ' + str(p.returncode) + '; completed ' + str(matches), flush=True)
            if p.returncode != 0 or not matches:
                raise RuntimeError(target + ' failed; inspect retained log/artifact')
        command = ['cargo', 'deny', '--manifest-path', 'fuzz/Cargo.toml', '--locked', '--target', 'x86_64-unknown-linux-gnu', '--format', 'json', 'check', 'advisories']
        p = subprocess.run(command, cwd=PROJECT, env=env, capture_output=True, text=True, timeout=300)
        raw = p.stdout + p.stderr
        log = args.report.with_name(args.report.stem + '-advisories.jsonl')
        log.write_text(raw)
        summaries = [r['fields']['advisories'] for line in raw.splitlines() if (r := json.loads(line)).get('type') == 'summary' and 'advisories' in r.get('fields', {})]
        report['advisories'] = {'command': command, 'exit_code': p.returncode, 'raw_path': str(log), 'raw_sha256': hashlib.sha256(raw.encode()).hexdigest(), 'summaries': summaries}
        if p.returncode != 0 or len(summaries) != 1 or summaries[0]['errors'] != 0:
            raise RuntimeError('fuzz workspace advisory scan failed')
        for name, digest in report['source_sha256'].items():
            if sha256(PROJECT / name) != digest:
                raise RuntimeError('source or lock changed during fuzzing: ' + name)
        report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved PQ parser fuzz evidence:', args.report, flush=True)


if __name__ == '__main__':
    main()
