"""Explicit opt-in native driver. Import and default preflight run no native probe."""
import argparse
from pathlib import Path
import secrets
import sys

from .authority import Namespace, PREFIX, Stop
from .campaign import MinimalCampaign
from .cases import minimal_cases, positive_cases
from .clients import ClientEnvironment
from .component_campaign import ComponentCampaign
from .fnox import FnoxEnvironment, fnox_cases
from .fnox_daemon_clients import FnoxDaemonEnvironment
from .fnox_daemon_campaign import FnoxDaemonCampaign
from .inputs import FixtureInputs
from .observation import WindowsObserver
from .report import CampaignReport
from .run_directory import RunDirectory
from .runtime import RuntimeInputs
from .recovery_clients import RecoveryEnvironment
from .recovery_campaign import RecoveryCampaign
from .refusal_clients import RefusalEnvironment
from .refusal_campaign import RefusalCampaign

ROOT = Path(__file__).resolve().parents[2]


def main(argv=None):
    parser = argparse.ArgumentParser(description='Isolated minimal TPM client validation')
    parser.add_argument('--runtime-report', required=True, help='approved root-relative runtime report')
    parser.add_argument('--runtime-sha256', required=True, help='explicit approved report digest')
    parser.add_argument('--native', action='store_true', help='perform the explicitly selected disposable client validation')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--positive-matrix', action='store_true', help='age/rage payload boundaries and both cross-client directions')
    modes.add_argument('--fnox-positive', action='store_true', help='isolated direct and persistent local-cache fnox workflow')
    modes.add_argument('--fnox-daemon', action='store_true', help='isolated owned-daemon cold/warm/explicit-bypass workflow')
    modes.add_argument('--component-matrix', action='store_true', help='positive controls and three bounded component rejections per reader')
    modes.add_argument('--recovery-matrix', action='store_true', help='duplicate recipients and independent native-PQ OR recovery')
    modes.add_argument('--refusal-matrix', action='store_true', help='finite identity/parser/version/payload/no-downgrade refusals with native controls')
    parser.add_argument('--acknowledge', choices=['isolated-disposable-only'])
    arguments = parser.parse_args(argv)
    run = report = campaign = None
    try:
        if arguments.native and arguments.acknowledge != 'isolated-disposable-only':
            raise Stop('explicit disposable-only acknowledgment required')
        inputs = RuntimeInputs.load(ROOT, arguments.runtime_report, arguments.runtime_sha256)
        if (arguments.fnox_positive or arguments.fnox_daemon) and inputs.fnox is None:
            raise Stop('fnox mode requires its separate approved binary pin')
        if arguments.recovery_matrix and inputs.keygen is None:
            raise Stop('recovery mode requires its separate approved key generator pin')
        FixtureInputs.approved(ROOT).verify()
        if not arguments.native:
            print('Approved source/binary pins verified; no native probe or enrollment ran.')
            return 0
        run = RunDirectory.create(ROOT / '.pi')
        namespace = Namespace(PREFIX + secrets.token_hex(16))
        report = CampaignReport.create(run.path / 'report', namespace, inputs.report.sha256)
        staged = inputs.stage(run)
        client_type = FnoxDaemonEnvironment if arguments.fnox_daemon else FnoxEnvironment if arguments.fnox_positive else (
            RecoveryEnvironment if arguments.recovery_matrix else
            RefusalEnvironment if arguments.refusal_matrix else ClientEnvironment)
        clients = client_type(run, staged)
        script = 'scripts/post_quantum_client/observe-windows.ps1'
        observer = WindowsObserver(ROOT / script, inputs.sources[script], clients.env)
        cases = fnox_cases() if arguments.fnox_positive else (positive_cases() if arguments.positive_matrix else minimal_cases())
        if arguments.fnox_daemon:
            campaign = FnoxDaemonCampaign(run, namespace, report, clients, observer)
        elif arguments.component_matrix:
            campaign = ComponentCampaign(run, namespace, report, clients, observer)
        elif arguments.recovery_matrix:
            campaign = RecoveryCampaign(run, namespace, report, clients, observer)
        elif arguments.refusal_matrix:
            campaign = RefusalCampaign(run, namespace, report, clients, observer)
        else:
            campaign = MinimalCampaign(run, namespace, report, clients, observer, cases=cases)
        campaign.execute()
        print('Disposable client validation and independent cleanup passed.')
        print('Retained report:', report.path)
        return 0
    except BaseException:
        if campaign is None and report is not None:
            try:
                report.failure('preflight')
            except BaseException:
                pass
        print('Validation stopped. No automatic retry or native cleanup.', file=sys.stderr)
        if run is not None:
            print('Retained run:', run.path, file=sys.stderr)
        return 1
