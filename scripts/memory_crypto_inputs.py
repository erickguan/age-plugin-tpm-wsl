"""Source binding for the isolated four-package crypto proposal."""
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = {'hkdf': ['0.12.4', '0.13.0'], 'hmac': ['0.12.1', '0.13.0']}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot(workspace, proposal):
    if proposal['result'] != 'pass' or Path(proposal['destination']).resolve() != workspace.resolve():
        raise RuntimeError('exact combined proposal required')
    paths = {ROOT / name for name in proposal['source_sha256']}
    for name, expected in proposal['source_sha256'].items():
        if digest(ROOT / name) != expected:
            raise RuntimeError('accepted composition input changed: ' + name)
    prepare_path = ROOT / 'scripts/prepare-memory-crypto-project.py'
    prepare = load(prepare_path, 'crypto_prepare')
    if prepare.hkdf_project_snapshot() != proposal['hkdf_project_source_sha256']:
        raise RuntimeError('accepted HKDF project source snapshot changed')
    for path in prepare.REPORTS.values():
        prepare.verify_evidence(json.loads(path.read_text()))
    baseline_path = ROOT / 'notes/ctutils-evaluation/root-software-fixed.json'
    baseline = json.loads(baseline_path.read_text())
    if baseline['result'] != 'pass':
        raise RuntimeError('accepted fixed-root baseline required')
    paths.add(baseline_path)
    for name, expected in baseline['source_sha256'].items():
        path = ROOT / name
        if digest(path) != expected:
            raise RuntimeError('reviewed root source changed: ' + name)
        paths.add(path)
    for folder in ['src', 'tests', 'examples', 'vendor', 'helper/src', 'crates/post_quantum/src', 'crates/custody-fs/src']:
        if (workspace / folder).resolve() != (ROOT / folder).resolve():
            raise RuntimeError('proposal source link differs from reviewed root: ' + folder)
    for folder in ['src', 'tests', 'helper/src', 'crates/post_quantum/src', 'crates/custody-fs/src']:
        for path in (workspace / folder).rglob('*.rs'):
            name = str(path.relative_to(workspace))
            if baseline['source_sha256'].get(name) != digest(path):
                raise RuntimeError('unreviewed proposal Rust source: ' + name)
    rsa_path = ROOT / 'notes/rsa-backend-validation.json'
    rsa = json.loads(rsa_path.read_text())
    if rsa['result'] not in {'pass', 'pass on tested machine'}:
        raise RuntimeError('accepted software fixture source authority required')
    paths.add(rsa_path)
    for path in (ROOT / 'examples').rglob('*.rs'):
        name = str(path.relative_to(ROOT))
        if rsa['source_sha256'].get(name) != digest(path):
            raise RuntimeError('software fixture source differs from accepted RSA source')
        paths.add(path)
    vector_records = [ROOT / 'notes/hpke-evaluation/vector-provenance.json', ROOT / 'notes/fixtures/p256-hpke-go-provenance.json', ROOT / 'notes/pq-workspace-validation.json']
    rfc, go, pq = [json.loads(path.read_text()) for path in vector_records]
    if pq['result'] != 'pass':
        raise RuntimeError('accepted PQ vector provenance required')
    vectors = {'notes/hpke-evaluation/rfc9180-p256-vector.json': rfc['extracted_sha256'],
               'notes/fixtures/p256-hpke-go.json': go['fixture_sha256'], go['generator']: go['generator_sha256']}
    for name in ['notes/pq-construction/ietf-hpke-pq-05-mlkem768p256.json', 'notes/pq-construction/concrete-03-mlkem768p256.json', 'notes/aws-lc-hybrid-evaluation/kat-components.json']:
        vectors[name] = pq['source_sha256'][name]
    for name, expected in vectors.items():
        if digest(ROOT / name) != expected:
            raise RuntimeError('approved vector/generator source changed: ' + name)
        paths.add(ROOT / name)
    paths.update(vector_records)
    additions = ''.join(family + '-' + alias + ' = { package = ' + json.dumps(family) + ', path = ' + json.dumps(str(workspace / 'crypto-sources' / (family + '-' + version))) + ' }\n'
                        for family, versions in FAMILIES.items() for alias, version in zip(['v012', 'v013'], versions))
    if (workspace / 'Cargo.toml').read_text() != (ROOT / 'Cargo.toml').read_text().replace('[patch.crates-io]\n', '[patch.crates-io]\n' + additions):
        raise RuntimeError('combined manifest selectors differ from reviewed proposal')
    if digest(workspace / 'Cargo.lock') != proposal['proposed_lock_sha256']:
        raise RuntimeError('combined proposed lock changed')
    for name in ['Cargo.toml', 'Cargo.lock', 'helper/Cargo.toml', 'crates/post_quantum/Cargo.toml', 'crates/custody-fs/Cargo.toml']:
        path = workspace / name
        if '/' in name and digest(path) != baseline['source_sha256'][name]:
            raise RuntimeError('copied consumer manifest changed')
        paths.add(path)
    for family, versions in FAMILIES.items():
        for version in versions:
            source = workspace / 'crypto-sources' / (family + '-' + version)
            record = proposal['crypto_provenance'][family][version]
            observed = {str(path.relative_to(source)): digest(path) for path in source.rglob('*') if path.is_file()}
            if observed != record['patched_sha256']:
                raise RuntimeError('combined source differs from tested crypto: ' + family + version)
            paths.update(source / name for name in observed)
    aws_path = ROOT / 'vendor/aws-lc-rs-provenance.json'
    aws = json.loads(aws_path.read_text())
    paths.add(aws_path)
    for name, record in aws['files'].items():
        path = ROOT / 'vendor/aws-lc-rs' / name
        if digest(path) != record['patched_sha256']:
            raise RuntimeError('reviewed AWS-LC source changed')
        paths.add(path)
    paths.update(ROOT / 'scripts' / name for name in ['memory_crypto_inputs.py', 'validate-memory-crypto-project.py', 'run-memory-crypto-client.py', 'test_memory_crypto_client.py', 'validate-age.py', 'validate-fnox.py', 'vendor-age-sdk.py'])
    paths.add(ROOT / 'notes/crypto-memory-integration/proposal.json')
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}
