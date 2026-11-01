#!/usr/bin/env python3
"""Validate only the reviewed ctutils fixed-version change in the fuzz workspace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'notes/crypto-memory-integration'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    paths = [ROOT / 'Cargo.lock', ROOT / 'fuzz/Cargo.toml', ROOT / 'fuzz/Cargo.lock', FOLDER / 'fuzz-before.lock', Path(__file__)]
    paths += list((ROOT / 'fuzz/fuzz_targets').glob('*.rs'))
    before = {str(path.relative_to(ROOT)): digest(path) for path in paths}
    report = {'result': 'fail', 'source_sha256': before, 'steps': [],
              'limits': ['Separate fuzz graph only; root acceptance/selected source unchanged',
                         'No parser or wire-format edits; compile check is not a sanitizer campaign or timing proof',
                         'Default advisory policy; historical vulnerable graph/diagnostics retained without suppression',
                         'Fuzz keeps its existing registry SDK/crypto identities and exact local AWS source']}
    env = os.environ.copy()
    env.update(RUSTC_WRAPPER='', CARGO_TARGET_DIR=str(ROOT / 'target/fuzz-ctutils-check'))
    args.report.parent.mkdir(parents=True, exist_ok=True)

    def run(command, label):
        print('Running ' + label, flush=True)
        p = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=900)
        report['steps'].append({'check': label, 'command': command, 'exit_code': p.returncode,
                                'stdout_sha256': hashlib.sha256(p.stdout.encode()).hexdigest(),
                                'stderr_sha256': hashlib.sha256(p.stderr.encode()).hexdigest()})
        if p.stderr:
            print(p.stderr, end='', flush=True)
        if p.returncode != 0:
            raise RuntimeError(label + ' failed')
        return p.stdout

    try:
        original = tomllib.loads((FOLDER / 'fuzz-before.lock').read_text())['package']
        updated = tomllib.loads((ROOT / 'fuzz/Cargo.lock').read_text())['package']
        fixed = next(p for p in tomllib.loads((ROOT / 'Cargo.lock').read_text())['package'] if p['name'] == 'ctutils')
        old = next(p for p in original if p['name'] == 'ctutils')
        new = next(p for p in updated if p['name'] == 'ctutils')
        if old['version'] != '0.4.3' or new != fixed or new['version'] != '0.4.4':
            raise RuntimeError('fuzz fixed package differs from reviewed root record')
        if [{k: v for k, v in old.items() if k not in {'version', 'checksum'}}] != [{k: v for k, v in new.items() if k not in {'version', 'checksum'}}]:
            raise RuntimeError('ctutils fuzz metadata changed beyond version/checksum')
        if [p for p in original if p['name'] != 'ctutils'] != [p for p in updated if p['name'] != 'ctutils']:
            raise RuntimeError('another fuzz locked package changed')
        report['package_delta'] = {'original': old, 'fixed': new}
        with tempfile.TemporaryDirectory(prefix='fuzz-ctutils-original-', dir=ROOT / 'target') as directory:
            temporary = Path(directory)
            text = (ROOT / 'fuzz/Cargo.toml').read_text()
            for relative, absolute in [('..', ROOT), ('../crates/post_quantum', ROOT / 'crates/post_quantum'), ('../vendor/aws-lc-rs', ROOT / 'vendor/aws-lc-rs')]:
                anchor = 'path = ' + json.dumps(relative)
                if text.count(anchor) != 1:
                    raise RuntimeError('unexpected original fuzz manifest path anchor')
                text = text.replace(anchor, 'path = ' + json.dumps(str(absolute)))
            (temporary / 'Cargo.toml').write_text(text)
            shutil.copyfile(FOLDER / 'fuzz-before.lock', temporary / 'Cargo.lock')
            (temporary / 'fuzz_targets').symlink_to(ROOT / 'fuzz/fuzz_targets', target_is_directory=True)
            old_raw = run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1', '--manifest-path', str(temporary / 'Cargo.toml')], 'historical fuzz feature graph')
            new_raw = run(['cargo', 'metadata', '--offline', '--locked', '--format-version', '1', '--manifest-path', str(ROOT / 'fuzz/Cargo.toml')], 'fixed fuzz feature graph')
            for name, raw in [('before', old_raw), ('fixed', new_raw)]:
                path = args.report.with_name(args.report.stem + '-' + name + '-metadata.json')
                path.write_text(raw)
                report[name + '_metadata'] = {'path': str(path), 'sha256': digest(path)}
            def features(raw):
                value = json.loads(raw)
                nodes = {n['id']: n for n in value['resolve']['nodes']}
                return {(p['name'], 'fixed-ctutils' if p['name'] == 'ctutils' else p['version']): nodes[p['id']]['features'] for p in value['packages']}
            if features(old_raw) != features(new_raw):
                raise RuntimeError('fuzz feature selections changed')
            report['resolved_features_unchanged'] = True
        run(['cargo', 'check', '--offline', '--locked', '--bins', '--manifest-path', str(ROOT / 'fuzz/Cargo.toml')], 'all four fixed fuzz targets compile')
        command = ['cargo', 'deny', '--manifest-path', str(ROOT / 'fuzz/Cargo.toml'), '--locked', '--offline', '--format', 'json', 'check', 'advisories']
        p = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
        raw = p.stdout + p.stderr
        path = args.report.with_name(args.report.stem + '-advisories.jsonl')
        path.write_text(raw)
        summaries = [row['fields']['advisories'] for line in raw.splitlines() if (row := json.loads(line)).get('type') == 'summary' and 'advisories' in row.get('fields', {})]
        report['advisories'] = {'command': command, 'exit_code': p.returncode, 'raw_path': str(path), 'raw_sha256': digest(path), 'summaries': summaries}
        if p.returncode or len(summaries) != 1 or summaries[0]['errors']:
            raise RuntimeError('fixed fuzz advisory scan failed')
        if any(digest(ROOT / name) != value for name, value in before.items()):
            raise RuntimeError('fuzz source or locked graph changed during validation')
        report['source_snapshot_unchanged'] = True
        report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, StopIteration, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        raise
    finally:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved fuzz dependency remediation:', args.report, flush=True)


if __name__ == '__main__':
    main()
