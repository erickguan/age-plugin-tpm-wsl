"""Explicit runtime approval and exact executable/source pins for native mode."""
from dataclasses import dataclass, replace
import json
from pathlib import Path
import sys

from .authority import Stop
from .inputs import (APPROVED_SHA256, Artifact, FixtureInputs, object_fields,
                     relative_file, sha256_text)
from .process import BinaryPin, digest

ENTRY = 'scripts/validate-post-quantum-clients-native.py'
OFFLINE = 'scripts/validate-post-quantum-offline-clients.py'
OFFLINE_CHECKS = {'classical_control', 'native_hybrid_recipient', 'hybrid_identity',
                  'duplicate_hybrid_recipients', 'mixed_plugin_groups',
                  'mixed_same_plugin_identity_and_recipient'}


@dataclass(frozen=True)
class StagedRuntime:
    helper: BinaryPin
    plugin: BinaryPin
    age: BinaryPin
    python: Artifact
    age_version: str
    entry: Path
    rage: BinaryPin | None = None
    rage_version: str | None = None
    fnox: BinaryPin | None = None
    fnox_version: str | None = None
    keygen: BinaryPin | None = None
    keygen_version: str | None = None

    def client(self, name):
        if name == 'age':
            return self.age, self.age_version
        if name == 'rage' and self.rage is not None and self.rage_version is not None:
            return self.rage, self.rage_version
        if name == 'fnox' and self.fnox is not None and self.fnox_version is not None:
            return self.fnox, self.fnox_version
        if name == 'age_keygen' and self.keygen is not None and self.keygen_version is not None:
            return self.keygen, self.keygen_version
        raise Stop('requested client is not approved and staged')

    def verify(self):
        self.python.verify()
        for pin in (self.helper, self.plugin, self.age, self.rage, self.fnox, self.keygen):
            if pin is not None:
                pin.verify()

    def with_public(self, artifact):
        artifact.verify()
        def bound(pin):
            return replace(pin, source_hashes={**pin.source_hashes, str(artifact.path): artifact.sha256})
        return replace(self, helper=bound(self.helper), plugin=bound(self.plugin), age=bound(self.age),
                       rage=bound(self.rage) if self.rage is not None else None,
                       fnox=bound(self.fnox) if self.fnox is not None else None,
                       keygen=bound(self.keygen) if self.keygen is not None else None)


@dataclass(frozen=True)
class RuntimeInputs:
    root: Path
    report: Artifact
    offline: Artifact
    sources: dict
    python: Artifact
    plugin: Artifact
    age: Artifact
    rage: Artifact
    age_version: str
    rage_version: str
    fnox: Artifact | None = None
    fnox_version: str | None = None
    keygen: Artifact | None = None
    keygen_version: str | None = None

    @classmethod
    def load(cls, root, name, expected_hash):
        root = Path(root).resolve(strict=True)
        report = Artifact(relative_file(root, name), sha256_text(expected_hash))
        report.verify()
        try:
            data = json.loads(report.path.read_bytes(), object_pairs_hook=object_fields)
            if (data['result'] != 'pass' or data['role'] != 'native-driver-readiness'
                    or data['fixture_report_sha256'] != APPROVED_SHA256
                    or not data['source_sha256']):
                raise Stop('explicitly approved complete driver readiness required')
            required = {str(path.relative_to(root)) for path in (root / 'scripts/post_quantum_client').glob('*.py')}
            required |= {'scripts/post_quantum_client/observe-windows.ps1',
                         'scripts/post_quantum_client_wrapper.py', ENTRY, OFFLINE}
            sources = data['source_sha256']
            if not required.issubset(sources):
                raise Stop('driver readiness omits a runtime source')
            for path, expected in sources.items():
                if digest(relative_file(root, path)) != sha256_text(expected):
                    raise Stop('runtime readiness source changed')
            sources = dict(sources)
            if name in sources and sources[name] != report.sha256:
                raise Stop('runtime report cannot redefine its own pin')
            sources[name] = report.sha256
            binaries = data['binaries']
            if set(binaries) not in ({'python', 'plugin', 'age', 'rage'},
                                     {'python', 'plugin', 'age', 'rage', 'fnox'},
                                     {'python', 'plugin', 'age', 'rage', 'fnox', 'age_keygen'}):
                raise Stop('exact interpreter/plugin/client pins required')
            artifacts = []
            for label in ('python', 'plugin', 'age', 'rage'):
                item = binaries[label]
                path = Path(item['path'])
                if not path.is_absolute():
                    raise Stop('absolute executable path required')
                artifacts.append(Artifact(path.resolve(strict=True), sha256_text(item['sha256'])))
            if artifacts[0].path != Path(sys.executable).resolve(strict=True):
                raise Stop('driver must use the approved interpreter')
            offline = Artifact(relative_file(root, data['offline_report']), sha256_text(data['offline_report_sha256']))
            offline.verify()
            public = json.loads(offline.path.read_bytes(), object_pairs_hook=object_fields)
            age, rage = public['clients']['age'], public['clients']['rage']
            if (public['result'] != 'pass' or set(public['clients']) != {'age', 'rage'}
                    or any(set(client['checks']) != OFFLINE_CHECKS for client in public['clients'].values())
                    or public['plugin_sha256'] != artifacts[1].sha256
                    or age['executable_sha256'] != artifacts[2].sha256
                    or rage['executable_sha256'] != artifacts[3].sha256
                    or public['reference_encoder_sha256'] != sources['scripts/post_quantum_client/references.py']
                    or public['source_sha256'] != sources[OFFLINE]
                    or any(check['result'] != 'pass' for client in public['clients'].values()
                           for check in client['checks'].values())):
                raise Stop('offline proof does not bind the selected plugin/client/encoder')
            if any(not isinstance(client['version'], str) or not 1 <= len(client['version']) <= 100
                   for client in (age, rage)):
                raise Stop('bounded public client version required')
            offline_name = str(offline.path.relative_to(root))
            if offline_name in sources and sources[offline_name] != offline.sha256:
                raise Stop('conflicting offline evidence pin')
            sources[offline_name] = offline.sha256
            fnox = fnox_version = None
            if 'fnox' in binaries:
                item = binaries['fnox']
                path = Path(item['path'])
                if not path.is_absolute():
                    raise Stop('absolute fnox executable path required')
                fnox = Artifact(path.resolve(strict=True), sha256_text(item['sha256']))
                fnox_version = data['fnox_version']
                if not isinstance(fnox_version, str) or not fnox_version.startswith('fnox ') or not 6 <= len(fnox_version) <= 100:
                    raise Stop('bounded public fnox version required')
            keygen = keygen_version = None
            if 'age_keygen' in binaries:
                item = binaries['age_keygen']
                path = Path(item['path'])
                if not path.is_absolute():
                    raise Stop('absolute key generator path required')
                keygen = Artifact(path.resolve(strict=True), sha256_text(item['sha256']))
                keygen_version = data['age_keygen_version']
                if not isinstance(keygen_version, str) or not 1 <= len(keygen_version) <= 100:
                    raise Stop('bounded public key generator version required')
            inputs = cls(root, report, offline, sources, *artifacts, age['version'], rage['version'],
                         fnox, fnox_version, keygen, keygen_version)
            inputs.verify()
            return inputs
        except (KeyError, ValueError, TypeError, AttributeError, RecursionError):
            raise Stop('invalid runtime readiness evidence') from None

    def verify(self):
        for artifact in (self.report, self.offline, self.python, self.plugin, self.age, self.rage):
            artifact.verify()
        if self.fnox is not None:
            self.fnox.verify()
        if self.keygen is not None:
            self.keygen.verify()
        for path, expected in self.sources.items():
            if digest(relative_file(self.root, path)) != expected:
                raise Stop('approved runtime source changed')

    def stage(self, run):
        self.verify()
        run.verify()
        fixture = FixtureInputs.approved(self.root)
        helper = fixture.stage(run.path, self.sources)
        common = dict(helper.source_hashes)
        common[str(self.python.path)] = self.python.sha256
        plugin = BinaryPin.stage(self.plugin.path, self.plugin.sha256, run.path, common, 'age-plugin-tpm-wsl')
        age = BinaryPin.stage(self.age.path, self.age.sha256, run.path, common, 'age')
        rage = BinaryPin.stage(self.rage.path, self.rage.sha256, run.path, common, 'rage')
        fnox = None
        if self.fnox is not None:
            fnox = BinaryPin.stage(self.fnox.path, self.fnox.sha256, run.path, common, 'fnox')
            common[fnox.path] = fnox.sha256
        keygen = None
        if self.keygen is not None:
            keygen = BinaryPin.stage(self.keygen.path, self.keygen.sha256, run.path, common, 'age-keygen')
            common[keygen.path] = keygen.sha256
        common.update({plugin.path: plugin.sha256, age.path: age.sha256, rage.path: rage.sha256})
        result = StagedRuntime(replace(helper, source_hashes=dict(common)),
                               replace(plugin, source_hashes=dict(common)),
                               replace(age, source_hashes=dict(common)), self.python,
                               self.age_version, self.root / 'scripts/post_quantum_client_wrapper.py',
                               replace(rage, source_hashes=dict(common)), self.rage_version,
                               replace(fnox, source_hashes=dict(common)) if fnox is not None else None, self.fnox_version,
                               replace(keygen, source_hashes=dict(common)) if keygen is not None else None, self.keygen_version)
        result.verify()
        return result
