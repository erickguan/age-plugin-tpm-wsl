#!/usr/bin/env python3
"""Validate reviewed Windows test-only custody; native execution requires --execute."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

PROJECT = Path(__file__).resolve().parents[1]
PREFIX = 'age-tpm-wsl-pq-native-'
MARKER = 'ATW_PQ_NATIVE_REPORT='
TEST = 'post_quantum::store::native_tests::isolated_native_case'
SCOPE = 'ignored Windows test-only isolated Store; no production root access'
VARIABLES = {'ATW_PQ_NATIVE_ACK', 'ATW_PQ_NATIVE_MODE', 'ATW_PQ_NATIVE_NAMESPACE', 'ATW_PQ_NATIVE_EXPECTED'}
SNAPSHOT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$path = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$names = @(Get-ChildItem -LiteralPath $path -Force | Where-Object { $_.Name.StartsWith('age-tpm-wsl-pq-native-') } | Select-Object -ExpandProperty Name | Sort-Object)
$drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($path))
[ordered]@{objects=$names; filesystem=$drive.DriveFormat; windows_version=[Environment]::OSVersion.Version.ToString(); windows_sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value} | ConvertTo-Json -Compress
"""


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def process_metadata(process):
    """Retain process evidence without recording untrusted output contents."""
    metadata = {'exit_code': getattr(process, 'returncode', None),
                'timed_out': isinstance(process, subprocess.TimeoutExpired)}
    for stream in ('stdout', 'stderr'):
        value = getattr(process, stream, None)
        data = value.encode() if isinstance(value, str) else value
        metadata[stream + '_bytes'] = len(data) if data is not None else None
        metadata[stream + '_sha256'] = hashlib.sha256(data).hexdigest() if data is not None else None
        if stream == 'stdout':
            metadata['marker_count'] = sum(MARKER.encode() in line for line in data.splitlines()) if data is not None else None
    return metadata


class NativeError(RuntimeError):
    pass


class Campaign:
    def __init__(self, executable, env, report, *, execute=subprocess.run, journal_directory=None):
        self.executable, self.env, self.report = executable, env, report
        self.execute = execute
        self.fatal = False
        self.references = {}
        self.roots = set()
        self.journal = None
        self.journal_directory = journal_directory or PROJECT / 'target/pq-custody-native-validation'

    def save_reference(self, namespace, encoded):
        # Capture authority BEFORE any fallible journal operation.
        self.references[namespace] = encoded
        if self.journal is None:
            self.journal_directory.mkdir(parents=True, exist_ok=True)
            descriptor, path = tempfile.mkstemp(prefix='public-custody-references-', suffix='.json', dir=self.journal_directory)
            os.close(descriptor)
            self.journal = Path(path)
            self.report['public_reference_journal'] = str(self.journal)
        self.journal.write_text(json.dumps(self.references, indent=2) + '\n')

    def invoke(self, namespace, mode, *, expected_error=None):
        if self.fatal and mode != 'absence':
            raise NativeError('native cleanup failure or uncertainty latched; no further mutation permitted')
        suffix = namespace.removeprefix(PREFIX)
        if namespace != PREFIX + suffix or len(suffix) != 32 or any(c not in '0123456789abcdef' for c in suffix):
            raise NativeError('invalid native namespace')
        env = {k: v for k, v in self.env.items() if k not in VARIABLES}
        env.update(ATW_PQ_NATIVE_ACK='isolated-disposable-only', ATW_PQ_NATIVE_MODE=mode, ATW_PQ_NATIVE_NAMESPACE=namespace)
        if namespace in self.references:
            env['ATW_PQ_NATIVE_EXPECTED'] = self.references[namespace]
        forwarded = [v for v in env.get('WSLENV', '').split(':') if v and v.split('/')[0] not in VARIABLES]
        env['WSLENV'] = ':'.join(forwarded + [v + '/w' for v in sorted(VARIABLES) if v in env])
        command = [str(self.executable), '--exact', TEST, '--ignored', '--nocapture', '--test-threads=1']
        print('Running isolated native ' + mode + ' ' + namespace, flush=True)
        started = time.monotonic()
        p = None

        def record_step(process, **fields):
            self.report['native_steps'].append({
                'operation': mode, 'namespace': namespace,
                'seconds': round(time.monotonic() - started, 3),
                **process_metadata(process), **fields})

        def stop_uncertain(message, process=None):
            # Preserve the stop condition BEFORE hashing or recording evidence.
            self.fatal = True
            self.report['cleanup_stopped'] = True
            record_step(p if process is None else process, diagnostic_error=message)
            raise NativeError(message) from None

        try:
            p = self.execute(command, env=env, capture_output=True, text=False, timeout=180)
            stdout = p.stdout.decode('utf-8') if isinstance(p.stdout, bytes) else p.stdout
            matches = [line.split(MARKER, 1)[1] for line in stdout.splitlines() if MARKER in line]
            if len(matches) != 1:
                raise NativeError('native result missing or ambiguous; cleanup state is unknown')
            body = json.loads(matches[0])
            if not isinstance(body, dict):
                raise NativeError('native result has invalid schema; cleanup state is unknown')
        except (OSError, ValueError, RecursionError, subprocess.SubprocessError, NativeError) as failure:
            message = str(failure) if isinstance(failure, NativeError) else 'native process or report failed; cleanup state is unknown'
            stop_uncertain(message, failure if isinstance(failure, subprocess.TimeoutExpired) else p)
        name = 'age-tpm-wsl-pq-' + suffix
        # Validate the complete response class BEFORE accepting root/reference
        # authority or making the narrowly allowed controlled-failure exception.
        if (body.get('scope') != SCOPE or body.get('namespace') != namespace
                or body.get('name') != name or body.get('operation') != mode):
            stop_uncertain('native response authority/scope mismatch; no destructive cleanup permitted')
        result = body.get('result')
        failed = body.get('cleanup_failed')
        status_is_integer = type(p.returncode) is int
        has_error = isinstance(body.get('error'), str) and bool(body['error'])
        ordinary = (status_is_integer and isinstance(result, str)
                    and ((result == 'pass' and p.returncode == 0 and failed is False)
                         or (result == 'fail' and p.returncode == 1 and failed is False and has_error)))
        genuine_fatal = (status_is_integer and result == 'fail' and p.returncode == 97
                         and failed is True and has_error)
        controlled = (status_is_integer and mode in {'fault-absence', 'fault-close'} and p.returncode == 97
                      and result == 'controlled_failure' and failed is True and has_error
                      and body.get('controlled_only_after_real_release') is True
                      and type(body.get('actual_transient_flushes')) is int and body['actual_transient_flushes'] == 1
                      and type(body.get('actual_absence_checks')) is int and body['actual_absence_checks'] == 1
                      and body.get('actual_context_closed') is True and body.get('destructive_continuation') is False)
        if not (ordinary or genuine_fatal or controlled):
            stop_uncertain('unrecognized native result/exit/cleanup combination; cleanup state is unknown')
        # Latch genuine fatal status BEFORE hashing, recording results or IO.
        if genuine_fatal:
            self.fatal = True
        self.report['cleanup_stopped'] = self.fatal
        if mode.startswith('create-') and body.get('root_created_exclusively') is True:
            self.roots.add(namespace)
        public = dict(body)
        encoded = public.pop('expected_identity_hex', None)
        if encoded is not None:
            try:
                identity = bytes.fromhex(encoded)
                if len(identity) != 1300 or identity[:3] != b'\x03\x00\x02' or identity[1252:] != b'\x2f' + name.encode():
                    raise ValueError('invalid canonical public response')
            except (ValueError, TypeError):
                stop_uncertain('native public reference is invalid; no cleanup authority inferred')
            public['expected_identity_sha256'] = hashlib.sha256(identity).hexdigest()
            public['expected_identity_bytes'] = len(identity)
            # Only successful explicit create can establish initial cleanup authority.
            if mode.startswith('create-') and body.get('result') == 'pass' and p.returncode == 0:
                self.save_reference(namespace, encoded)
            elif self.references.get(namespace) != encoded:
                stop_uncertain('recovery changed the independently retained public reference')
        record_step(p, result=public)
        if self.fatal:
            raise NativeError('native cleanup failed or is unverified; stop campaign')
        if controlled:
            return body
        if expected_error is not None:
            if p.returncode != 1 or body.get('result') != 'fail' or body.get('error') != expected_error:
                raise NativeError('negative native case failed for another cause')
        elif p.returncode != 0 or body.get('result') != 'pass':
            raise NativeError('native case failed: ' + str(body.get('error', 'missing result')))
        return body

    def cleanup_owned(self, namespace):
        try:
            if self.fatal:
                # Read-only observation is permitted; NO delete, repair or retry.
                self.invoke(namespace, 'absence')
                return
            if namespace in self.references:
                self.invoke(namespace, 'delete')
            elif namespace in self.roots:
                # A failed create returned no identity. Prove key absence before
                # removing even the exclusively owned empty test root.
                absent = self.invoke(namespace, 'absence')
                if absent.get('key_absent') is not True:
                    raise NativeError('failed creation key absence is unverified')
            if namespace in self.roots:
                # An owned empty root only; native removal is non-recursive.
                self.invoke(namespace, 'remove-root')
            absent = self.invoke(namespace, 'absence')
            if absent.get('key_absent') is not True or absent.get('root_absent') is not True:
                raise NativeError('independent key/root absence not verified')
            self.references.pop(namespace, None)
            self.roots.discard(namespace)
            if self.journal is not None:
                self.journal.write_text(json.dumps(self.references, indent=2) + '\n')
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            self.fatal = True
            self.report['cleanup_stopped'] = True
            raise

def snapshot_value(value):
    if (not isinstance(value, dict) or not isinstance(value.get('objects'), list)
            or any(not isinstance(v, str) or not v.startswith(PREFIX) for v in value['objects'])
            or any(not isinstance(value.get(k), str) or not value[k] for k in ('windows_sid', 'windows_version', 'filesystem'))):
        raise NativeError('independent Windows snapshot has invalid schema')
    return value


def cleanup_uncertain(report, campaign, message):
    report.update(result='fail', cleanup_error=message, cleanup_stopped=True)
    if campaign is not None:
        campaign.fatal = True


def snapshot(env):
    p = subprocess.run(['/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe', '-NoProfile', '-NonInteractive', '-Command', SNAPSHOT], env=env, capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        raise NativeError('independent Windows namespace snapshot failed')
    return snapshot_value(json.loads(p.stdout))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--software-report', type=Path, default=PROJECT / 'notes/pq-custody-harness-software.json')
    parser.add_argument('--execute', action='store_true', help='after independent harness review, create isolated disposable test enrollments and remove only matching owned state')
    args = parser.parse_args()
    report = {'result': 'fail', 'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'executed': False,
              'native_steps': [], 'cases': [], 'cleanup_stopped': False,
              'limits': ['Ignored Windows test-only Store with exclusive fresh reserved namespaces; production helper default store is never invoked',
                         'Controlled receipt/partial/pending stops and ordinary creator rollback; no abrupt-kill, power-loss, reboot/login or wrong-machine proof',
                         'Reported-failure controls inject only after real transient flush/absence verification and real context close; no PCP keys or files in those controls',
                         'All seed, agreement and file-key values stay inside Windows; raw generated public identities retained only in ignored local cleanup journal, never the durable report',
                         'Explicit recovery establishes a new expectation; no independent PQ OR recovery route or client/label/fnox acceptance',
                         '180-second test-process limit does not change the production helper deadline or establish unattended performance']}
    campaign = None
    before = None
    try:
        software = json.loads(args.software_report.read_text())
        if software['result'] != 'pass':
            raise NativeError('current software validation must pass before native execution')
        native_steps = [s for s in software['steps'] if s['check'] == 'native Windows scripted TPM and lifecycle tests']
        if len(native_steps) != 1 or native_steps[0]['exit_code'] != 0 or native_steps[0]['test_summaries'] != [['17', '0', '1']]:
            raise NativeError('software report must pass all 17 Windows software tests and skip exactly the one native lifecycle case')
        for name, expected in software['source_sha256'].items():
            if sha256(PROJECT / name) != expected:
                raise NativeError('software report is stale: ' + name)
        executable = Path(software['native_test_path'])
        if sha256(executable) != software['native_test_sha256']:
            raise NativeError('native software executable changed')
        if 'helper/src/post_quantum/store/native_tests.rs' not in software['source_sha256'] or 'scripts/validate-pq-custody-native.py' not in software['source_sha256']:
            raise NativeError('software report must bind the reviewed native harness and driver')
        report.update(software_report_sha256=sha256(args.software_report), source_sha256=software['source_sha256'], native_test_sha256=software['native_test_sha256'])
        if not args.execute:
            report['result'] = 'pass'
            return
        env = {k: v for k, v in os.environ.items() if k not in VARIABLES}
        before = snapshot(env)
        report['before'] = before
        if before['objects']:
            raise NativeError('pre-existing native-test namespace; no cleanup of unknown state authorized')
        campaign = Campaign(executable, env, report)
        report['executed'] = True
        for mode in ['fault-absence', 'fault-close']:
            namespace = PREFIX + secrets.token_hex(16)
            pre = campaign.invoke(namespace, 'absence')
            if pre.get('root_absent') is not True:
                raise NativeError('fresh control namespace already exists')
            campaign.invoke(namespace, mode)
            campaign.cleanup_owned(namespace)
            try:
                after = snapshot(env)
                if after['objects']:
                    raise NativeError('controlled-failure namespace snapshot changed; stop')
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
                cleanup_uncertain(report, campaign, str(failure))
                raise
            report['cases'].append({'control': mode, 'namespace': namespace, 'after': after, 'result': 'pass'})
        for stage in ['final', 'pending', 'partial', 'receipt', 'rollback']:
            namespace = PREFIX + secrets.token_hex(16)
            case = {'stage': stage, 'namespace': namespace, 'result': 'fail'}
            report['cases'].append(case)
            error = None
            try:
                pre = campaign.invoke(namespace, 'absence')
                if pre.get('root_absent') is not True:
                    raise NativeError('fresh lifecycle namespace already exists')
                created = campaign.invoke(namespace, 'create-' + stage)
                if stage == 'rollback':
                    if created.get('creator_rollback_verified') is not True:
                        raise NativeError('creator rollback evidence missing')
                else:
                    if namespace not in campaign.references or created.get('retained_stage') != stage:
                        raise NativeError('explicit retained public reference missing')
                    if stage != 'final':
                        campaign.invoke(namespace, 'unwrap', expected_error='Native filesystem status 0xc0000034')
                    if stage in {'receipt', 'partial'}:
                        reason = 'Native filesystem status 0xc0000034' if stage == 'receipt' else 'invalid expected custody record'
                        campaign.invoke(namespace, 'recover', expected_error=reason)
                    else:
                        campaign.invoke(namespace, 'recover')
                        campaign.invoke(namespace, 'unwrap')
                        campaign.invoke(namespace, 'inspect')
                        if stage == 'final':
                            campaign.invoke(namespace, 'denials')
                            campaign.invoke(namespace, 'replace-pcp')
                            campaign.invoke(namespace, 'unwrap', expected_error='PCP reopen 0x80090016')
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
                error = failure
                case['error'] = str(failure)
            finally:
                try:
                    campaign.cleanup_owned(namespace)
                    after = snapshot(env)
                    case['after'] = after
                    if after['objects']:
                        campaign.fatal = True
                        raise NativeError('native namespace remains; stop, no recursive cleanup')
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
                    case['cleanup_error'] = str(failure)
                    cleanup_uncertain(report, campaign, str(failure))
                    error = error or failure
            if error is not None or campaign.fatal:
                raise NativeError('native lifecycle failed; inspect named case and retained cleanup authority')
            case['result'] = 'pass'
        for name, expected in report['source_sha256'].items():
            if sha256(PROJECT / name) != expected:
                raise NativeError('native campaign source changed: ' + name)
        if sha256(executable) != report['native_test_sha256']:
            raise NativeError('native executable changed during campaign')
        if campaign.references or campaign.roots:
            raise NativeError('owned native state still tracked')
        if campaign.journal is not None:
            campaign.journal.unlink()
            if campaign.journal.exists():
                raise NativeError('public reference journal remains')
            report['reference_journal_removed'] = True
        report['result'] = 'pass'
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
        report['error'] = str(failure)
        raise
    finally:
        if campaign is not None:
            report['cleanup_stopped'] = campaign.fatal
            report['unresolved_namespaces'] = sorted(campaign.roots | campaign.references.keys())
        if before is not None:
            try:
                after = snapshot(os.environ.copy())
                report['after'] = after
                if after['objects'] != before['objects'] or after['windows_sid'] != before['windows_sid']:
                    cleanup_uncertain(report, campaign, 'independent namespace snapshot or Windows user changed; stop')
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
                cleanup_uncertain(report, campaign, str(failure))
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('Saved isolated native custody report:', args.report, flush=True)
        if report.get('cleanup_error'):
            raise NativeError('native cleanup remains unverified')


if __name__ == '__main__':
    main()
