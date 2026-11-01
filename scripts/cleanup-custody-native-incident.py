#!/usr/bin/env python3
"""Preflight one retained incident enrollment; execute matching cleanup only after approval.

The incident is the failed campaign report itself; its journal identity and exclusive
creation receipt are the cleanup authority. The executable is bound to the current
passing software validation: the validated bytes are staged once outside Cargo's
reusable output pathname, and the imported controller is the exact source bound by
that validation. The delete/remove-root/absence paths must be unchanged from the
incident's own bound sources (allowlisted corrections only).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import types

ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = 'scripts/validate-pq-custody-native.py'
PREFIX = 'age-tpm-wsl-pq-native-'
# The only sources allowed to differ between the incident's binding and the current
# software validation: the corrected harness fixture/test and the driver gate count.
ALLOWED_SOURCE_CHANGES = {'helper/src/post_quantum/store/native_tests.rs', CONTROLLER}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verified_controller(software):
    """Return the controller source bound by the software validation, refusing a live mismatch."""
    expected = software['source_sha256'].get(CONTROLLER)
    if not isinstance(expected, str) or not expected:
        raise RuntimeError('software report must bind the native controller source')
    source = (ROOT / CONTROLLER).read_bytes()
    if hashlib.sha256(source).hexdigest() != expected:
        raise RuntimeError('live native controller differs from the current software validation')
    return source, expected


def staged_digest(path):
    """Hash a staging entry without following symlinks, refusing anything not an
    exclusively linked regular file owned by this user with staging permissions."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as failure:
        raise RuntimeError('staged executable is not a safe regular file') from failure
    try:
        status = os.fstat(descriptor)
        if (not stat.S_ISREG(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o500
                or status.st_uid != os.geteuid() or status.st_nlink != 1):
            raise RuntimeError('staged executable is not an exclusively owned mode-0500 regular file')
        hasher = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            hasher.update(chunk)
        return hasher.hexdigest()
    finally:
        os.close(descriptor)


def stage_executable(software, staging_directory):
    """Read the validated executable once and stage those exact bytes for execution."""
    expected = software['native_test_sha256']
    data = Path(software['native_test_path']).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('current tested native executable changed')
    staging_directory.mkdir(parents=True, exist_ok=True)
    staged = staging_directory / ('cleanup-' + expected[:16] + '.exe')
    if os.path.lexists(staged):
        if staged_digest(staged) != expected:
            raise RuntimeError('existing staged executable differs; refusing replacement')
        return staged, expected
    descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o500)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    if staged_digest(staged) != expected:
        raise RuntimeError('staged executable bytes differ from the validated software report')
    return staged, expected


def preflight(incident_path, software_path, staging_directory):
    incident_path, software_path = Path(incident_path), Path(software_path)
    incident = json.loads(incident_path.read_text())
    software = json.loads(software_path.read_text())
    if incident.get('result') != 'fail' or incident.get('executed') is not True or incident.get('cleanup_stopped') is not True:
        raise RuntimeError('incident must be an executed campaign that stopped on cleanup uncertainty')
    if software.get('result') != 'pass':
        raise RuntimeError('current software validation must pass before incident cleanup')
    windows_steps = [s for s in software['steps'] if s['check'] == 'native Windows scripted TPM and lifecycle tests']
    if len(windows_steps) != 1 or windows_steps[0]['exit_code'] != 0 or windows_steps[0]['test_summaries'] != [['17', '0', '1']]:
        raise RuntimeError('software report must pass all 17 Windows software tests and skip exactly the one native lifecycle case')
    controller_source, controller_sha256 = verified_controller(software)
    staged, executable_sha256 = stage_executable(software, Path(staging_directory))
    incident_sources, current_sources = incident['source_sha256'], software['source_sha256']
    if set(incident_sources) != set(current_sources):
        raise RuntimeError('incident and current source bindings cover different files')
    changed = sorted(name for name in incident_sources if incident_sources[name] != current_sources[name])
    if not set(changed) <= ALLOWED_SOURCE_CHANGES:
        raise RuntimeError('current sources changed beyond the allowlisted incident corrections: ' + ', '.join(changed))
    journal = Path(incident['public_reference_journal'])
    status = journal.lstat()
    if not stat.S_ISREG(status.st_mode) or stat.S_IMODE(status.st_mode) != 0o600 or status.st_uid != os.getuid():
        raise RuntimeError('retained public reference journal ownership/mode mismatch')
    references = json.loads(journal.read_text())
    if len(references) != 1:
        raise RuntimeError('retained journal must hold exactly one namespace')
    namespace, encoded = next(iter(references.items()))
    suffix = namespace.removeprefix(PREFIX)
    if namespace != PREFIX + suffix or len(suffix) != 32 or any(c not in '0123456789abcdef' for c in suffix):
        raise RuntimeError('invalid retained native namespace')
    name = 'age-tpm-wsl-pq-' + suffix
    identity = bytes.fromhex(encoded)
    if len(identity) != 1300 or identity[:3] != b'\x03\x00\x02' or identity[1252:] != b'\x2f' + name.encode():
        raise RuntimeError('saved expected public identity is not canonical')
    creates = [step for step in incident['native_steps'] if step.get('operation') == 'create-final'
               and step.get('namespace') == namespace]
    if len(creates) != 1:
        raise RuntimeError('one original exclusive creation receipt required')
    created = creates[0].get('result', {})
    if (created.get('result') != 'pass' or created.get('root_created_exclusively') is not True or created.get('name') != name
            or created.get('expected_identity_sha256') != hashlib.sha256(identity).hexdigest()
            or created.get('expected_identity_bytes') != 1300):
        raise RuntimeError('original creation authority mismatch')
    for step in incident['native_steps']:
        if (step.get('namespace') == namespace and step.get('operation') in {'delete', 'remove-root'}
                and isinstance(step.get('result'), dict) and step['result'].get('result') == 'pass'):
            raise RuntimeError('incident already removed the retained namespace')
    public = {'namespace': namespace, 'name': name,
              'expected_identity_sha256': hashlib.sha256(identity).hexdigest(), 'expected_identity_bytes': 1300,
              'executable': str(staged), 'executable_source_path': software['native_test_path'],
              'executable_sha256': executable_sha256,
              'incident_sha256': digest(incident_path), 'software_report_sha256': digest(software_path),
              'journal_sha256': digest(journal), 'journal_path': str(journal), 'journal_mode': '0600',
              'journal_device': status.st_dev, 'journal_inode': status.st_ino,
              'incident_windows_sid': incident['before']['windows_sid'],
              'source_changes_since_incident': changed}
    return public, encoded, journal, controller_source


def matching_cleanup(campaign, snapshot, expected_sid, namespace):
    before = snapshot()
    if before['windows_sid'] != expected_sid:
        raise RuntimeError('cleanup caller Windows SID differs from original incident')
    campaign.invoke(namespace, 'delete')
    campaign.invoke(namespace, 'remove-root')
    absent = campaign.invoke(namespace, 'absence')
    if absent.get('key_absent') is not True or absent.get('root_absent') is not True:
        raise RuntimeError('separate-process exact key/root absence not verified')
    after = snapshot()
    if after['windows_sid'] != expected_sid or namespace in after['objects']:
        raise RuntimeError('independent reserved-namespace absence not verified')
    return before, after


def append_checkpoint(output, report):
    output.write(json.dumps(report, sort_keys=True) + '\n')
    output.flush()
    os.fsync(output.fileno())


def recovery_checkpoints(report, persist, activity=None, remove_journal=None):
    persist(report)
    if activity is None:
        return
    report['executed'] = True
    before, after = activity()
    report.update(result='verified absent; public journal retained pending durable checkpoint', before=before, after=after,
                  absence_verified=True, journal_removed_after_verified_absence=False)
    # Durable evidence is a prerequisite for removing the public authority.
    persist(report)
    remove_journal()
    report.update(result='pass; matching incident cleanup only', journal_removed_after_verified_absence=True)
    persist(report)


def main():
    if not __debug__:
        raise RuntimeError('incident cleanup requires active Python assertions')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--incident', type=Path, required=True, help='failed campaign report that stopped on cleanup uncertainty')
    parser.add_argument('--software-report', type=Path, required=True, help='current passing software validation binding the cleanup executable')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--execute', action='store_true', help='only after explicit approval of this one retained incident cleanup')
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        raise RuntimeError('cleanup evidence must use a new report file')
    public, encoded, journal, controller_source = preflight(
        args.incident, args.software_report, ROOT / 'target/pq-custody-incident-executables')
    controller_path = ROOT / CONTROLLER
    report = {'result': 'preflight pass; execution not authorized by this report', 'executed': False, 'native_steps': [],
              'cleanup_stopped': False, 'authority': public,
              'controller_sha256': hashlib.sha256(controller_source).hexdigest(),
              'runner_sha256': digest(Path(__file__)),
              'limits': ['Only the named retained enrollment with its exact saved public identity',
                         'Original failed campaign/fatal state preserved; no denial-batch/matrix retry or new enrollment',
                         'No repair, fallback, recursive root deletion, unrelated TPM enumeration/reset/flush or installation',
                         'A cleanup pass does not establish original transient release, native matrix acceptance or persistence']}
    campaign = None
    output = None
    primary = None
    publication_errors = []

    def activity():
        nonlocal campaign
        # Execute the exact controller source bound by the current software validation.
        controller = types.ModuleType('incident_controller')
        controller.__file__ = str(controller_path)
        exec(compile(controller_source, str(controller_path), 'exec'), controller.__dict__)
        campaign = controller.Campaign(Path(public['executable']), os.environ.copy(), report)
        campaign.references[public['namespace']] = encoded
        campaign.roots.add(public['namespace'])
        return matching_cleanup(campaign, lambda: controller.snapshot(campaign.env),
                                public['incident_windows_sid'], public['namespace'])

    def remove_journal():
        if digest(journal) != public['journal_sha256'] or digest(public['executable']) != public['executable_sha256']:
            raise RuntimeError('retained journal or staged cleanup executable changed during cleanup')
        status = journal.lstat()
        if not stat.S_ISREG(status.st_mode) or (status.st_dev, status.st_ino) != (public['journal_device'], public['journal_inode']):
            raise RuntimeError('retained public journal ownership changed during cleanup')
        journal.unlink()
        if journal.exists():
            raise RuntimeError('checked local public journal remains')

    try:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        output = args.report.open('x')
        recovery_checkpoints(report, lambda state: append_checkpoint(output, state),
                             activity if args.execute else None, remove_journal if args.execute else None)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        primary = error
        if campaign is not None:
            campaign.fatal = True
        report.update(result='fail; no further mutation permitted', cleanup_stopped=True, error=str(error))
        if output is not None:
            try:
                append_checkpoint(output, report)
            except (OSError, ValueError) as failure:
                publication_errors.append(str(failure))
    finally:
        if output is not None:
            try:
                output.close()
            except OSError as failure:
                publication_errors.append(str(failure))
    if primary is not None or publication_errors:
        if campaign is not None:
            campaign.fatal = True
        report['cleanup_stopped'] = True
        message = str(primary) if primary is not None else 'cleanup evidence finalization failed'
        if publication_errors:
            message += '; evidence publication/finalization errors: ' + '; '.join(publication_errors)
        raise RuntimeError(message) from primary
    print('Saved retained-incident cleanup checkpoint evidence:', args.report)


if __name__ == '__main__':
    main()
