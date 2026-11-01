"""Read and bind accepted fixture evidence before staging; never executes code."""
from dataclasses import dataclass
import json
from pathlib import Path
import re

from .authority import Stop
from .process import BinaryPin, digest

APPROVED_REPORT = 'notes/post-quantum-client-fixture-authentication.json'
APPROVED_SHA256 = 'c4fb37788821040d951ca52b89a71bcb68ebcc1456940f7a3849eb2468b1bf0e'
WIRE_CONTROLS = {'missing_acknowledgment', 'bad_acknowledgment', 'production_namespace',
                 'short_header', 'bad_magic', 'unknown_operation', 'oversized_length',
                 'trailing_data', 'forbidden_status_payload', 'wrong_suite', 'short_create',
                 'short_unwrap', 'short_inspect', 'short_delete', 'empty_legacy_create'}


def sha256_text(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise Stop('canonical SHA-256 required')
    return value


def object_fields(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Stop('duplicate evidence field')
        value[key] = item
    return value


def relative_file(root, name):
    if (not isinstance(name, str) or not name or Path(name).is_absolute()
            or any(part in {'', '.', '..'} for part in name.split('/'))):
        raise Stop('root-relative evidence path required')
    path = (root / name).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise Stop('evidence/source path escaped repository')
    return path


@dataclass(frozen=True)
class Artifact:
    path: Path
    sha256: str

    def verify(self):
        if not self.path.is_absolute() or not self.path.is_file() or digest(self.path) != sha256_text(self.sha256):
            raise Stop('validated artifact digest mismatch')


@dataclass(frozen=True)
class FixtureInputs:
    root: Path
    report: Artifact
    wire: Artifact
    executable: Artifact
    software_test: Artifact
    sources: dict

    @classmethod
    def approved(cls, root):
        return cls.load(root, APPROVED_REPORT, APPROVED_SHA256)

    @classmethod
    def load(cls, root, report_name, approved_hash):
        root = Path(root).resolve(strict=True)
        report = Artifact(relative_file(root, report_name), sha256_text(approved_hash))
        report.verify()
        try:
            value = json.loads(report.path.read_bytes(), object_pairs_hook=object_fields)
            if (value['result'] != 'pass' or value['scope'] != 'software/build/framing readiness only; no root/key/lifecycle operations'
                    or not value['steps'] or not value['source_sha256']):
                raise Stop('passing fixture software evidence required')
            for step in value['steps']:
                if (type(step['exit_code']) is not int or type(step['expected_failure']) is not bool
                        or ((step['exit_code'] != 0) != step['expected_failure'])):
                    raise Stop('fixture build/test result mismatch')
            sources = {str(relative_file(root, name)): sha256_text(expected)
                       for name, expected in value['source_sha256'].items()}
            executables = value['executables']
            if set(executables) != {'protocol_fixture', 'software_test'}:
                raise Stop('exact protocol/software executable bindings required')
            artifacts = []
            for key in ('protocol_fixture', 'software_test'):
                item = executables[key]
                path = Path(item['path'])
                if not path.is_absolute() or not path.resolve(strict=True).is_relative_to(root):
                    raise Stop('fixture executable escaped repository')
                artifacts.append(Artifact(path.resolve(strict=True), sha256_text(item['sha256'])))
            wire = Artifact(relative_file(root, value['wire_report']), sha256_text(value['wire_sha256']))
            wire.verify()
            framing = json.loads(wire.path.read_bytes(), object_pairs_hook=object_fields)
            if (framing['result'] != 'pass' or framing['executable_sha256'] != artifacts[0].sha256
                    or framing['validator_sha256'] != value['source_sha256']['scripts/validate-post-quantum-fixture-wire.py']
                    or set(framing['checks']) != WIRE_CONTROLS
                    or any(check['result'] != 'pass' for check in framing['checks'].values())):
                raise Stop('wire evidence does not bind the validated fixture')
            inputs = cls(root, report, wire, *artifacts, sources)
            inputs.verify()
            return inputs
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            raise Stop('invalid fixture readiness evidence') from None

    def verify(self):
        for artifact in (self.report, self.wire, self.executable, self.software_test):
            artifact.verify()
        for name, expected in self.sources.items():
            if digest(name) != expected:
                raise Stop('validated fixture source changed')

    def stage(self, directory, runtime_hashes):
        """Copy only the approved executable; require a complete runtime snapshot.

        Cargo output is verified before copying, then the private clone carries
        executable authority. Later Cargo rebuilds cannot replace that clone.
        """
        self.verify()
        required = set((self.root / 'scripts/post_quantum_client').glob('*.py'))
        required |= {self.root / 'scripts/post_quantum_client/observe-windows.ps1',
                     self.root / 'scripts/post_quantum_client_wrapper.py'}
        runtime = {str(relative_file(self.root, name)): sha256_text(expected)
                   for name, expected in runtime_hashes.items()}
        if not {str(path) for path in required}.issubset(runtime):
            raise Stop('complete controller/observer/wrapper source snapshot required')
        sources = dict(self.sources)
        for name, expected in runtime.items():
            if name in sources and sources[name] != expected:
                raise Stop('conflicting fixture/runtime source bindings')
            sources[name] = expected
        sources.update({str(self.report.path): self.report.sha256, str(self.wire.path): self.wire.sha256})
        return BinaryPin.stage(self.executable.path, self.executable.sha256, directory, sources)
