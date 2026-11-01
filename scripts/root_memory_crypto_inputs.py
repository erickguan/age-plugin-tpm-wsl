"""Check the sealed source-selection transition and current root crypto inputs."""
import hashlib
import json
from pathlib import Path

from memory_crypto_inputs import ROOT, digest, load

FOLDER = ROOT / 'notes/crypto-memory-integration'


def snapshot():
    record_path = FOLDER / 'adoption.json'
    provenance_path = ROOT / 'vendor/crypto-memory-provenance.json'
    if record_path.read_bytes() != provenance_path.read_bytes():
        raise RuntimeError('root adoption receipt/provenance disagree')
    record = json.loads(record_path.read_text())
    if record['result'] != 'source selected; actual-root execution pending' or not record['resolved_features_unchanged']:
        raise RuntimeError('reviewed root source selection required')
    inputs = record['source_sha256'].copy()
    for name, expected in inputs.items():
        if digest(ROOT / name) != expected:
            raise RuntimeError('selected source/accepted input changed: ' + name)
    transfer = load(ROOT / 'scripts/vendor-crypto-memory.py', 'selected_crypto')
    transfer.check_sources(record)
    for name, expected in record['before_source_sha256'].items():
        if name not in {'Cargo.toml', 'Cargo.lock'} and inputs.get(name) != expected:
            raise RuntimeError('source transition changed unrelated accepted input')
    for name in ['root_manifest_before_text', 'root_lock_before_text']:
        if hashlib.sha256(record[name].encode()).hexdigest() != record[name.replace('_text', '_sha256')]:
            raise RuntimeError('original selector text no longer matches its receipt')
    for path in [record_path, provenance_path, ROOT / 'scripts/root_memory_crypto_inputs.py',
                 ROOT / 'scripts/validate-root-memory-crypto.py', ROOT / 'scripts/run-root-memory-crypto-client.py']:
        inputs[str(path.relative_to(ROOT))] = digest(path)
    return inputs
