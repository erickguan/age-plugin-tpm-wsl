#!/usr/bin/env python3
"""Validate the relocated custody filesystem and native cleanup/error boundary."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess

PROJECT = Path(__file__).resolve().parents[1]
ROOT = PROJECT / "crates" / "custody-fs"
SNAPSHOT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$path = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$names = @(Get-ChildItem -LiteralPath $path -Directory -Filter 'age-tpm-wsl-fs-*' | Select-Object -ExpandProperty Name)
$drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($path))
[ordered]@{directories=$names; filesystem=$drive.DriveFormat; windows_version=[Environment]::OSVersion.Version.ToString()} | ConvertTo-Json -Compress
"""


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--test-reported-cleanup-failure", choices=["unlink-report", "absence-report"],
        help="test-only negative campaign: real unlink succeeds, then a reported rollback failure must stop execution")
    args = parser.parse_args()
    env = os.environ.copy()
    for name in ("ATW_FS_TEST_ROLLBACK_MODE", "ATW_FS_TEST_ROLLBACK_NAMESPACE"):
        env.pop(name, None)
    # Keep all stages uncached in a dedicated directory. Mixing kache hard-linked
    # read-only outputs with raw rustc caused Clippy metadata replacement failures.
    env["RUSTC_WRAPPER"] = ""
    env["CARGO_TARGET_DIR"] = str(PROJECT / "target" / "windows-custody-fs-validation")
    steps = []
    source_files = list((ROOT / "src").rglob("*.rs"))
    source_files += [ROOT / "Cargo.toml", ROOT / "source-origin.json", Path(__file__).resolve(),
        PROJECT / "Cargo.toml", PROJECT / "Cargo.lock", PROJECT / "helper/Cargo.toml",
        PROJECT / "notes/custody-fs-workspace-graph.json", PROJECT / "scripts/windows-linker.sh"]
    origin = json.loads((ROOT / "source-origin.json").read_text())
    for name, hashes in origin["source_files"].items():
        if sha256(PROJECT / hashes["original"]) != hashes["original_sha256"] or sha256(ROOT / name) != hashes["relocated_sha256"]:
            raise RuntimeError("filesystem relocation changed accepted Rust bytes: " + name)
    report = {"result": "fail", "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "steps": steps, "source_sha256": {str(p.relative_to(PROJECT)): sha256(p) for p in sorted(source_files)},
        "rust_sources_byte_identical": True,
        "limits": ["Relocated workspace filesystem operations with public stand-in bytes; no TPM keys or secrets created",
            "No production storage, seed/public binding or recovery acceptance; helper dispatch unchanged",
            "Flush/rename success is not power-loss, reboot/login or physical-media erasure proof",
            "Permissions do not defend against the authorized live user or administrators",
            "Native tests use a main process and controlled rollback child processes; separate PowerShell checks directory cleanup"]}

    def run(argv, label, timeout=180):
        print("Running " + label, flush=True)
        completed = subprocess.run(argv, env=env, capture_output=True, text=True, check=False, timeout=timeout)
        steps.append({"check": label, "exit_code": completed.returncode,
            "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest()})
        if completed.stderr:
            print(completed.stderr, end="", flush=True)
        if completed.returncode != 0:
            diagnostics = []
            for line in completed.stdout.splitlines():
                if not line.startswith("{"):
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if record.get("reason") == "compiler-message" and record["message"].get("rendered"):
                    diagnostics.append(record["message"]["rendered"])
            failure = "\n".join(diagnostics) if diagnostics else completed.stdout[-16000:]
            print(failure, end="", flush=True)
            steps[-1]["failure_stdout"] = failure
            steps[-1]["failure_stderr"] = completed.stderr[-16000:]
            raise RuntimeError(label + " failed")
        return completed.stdout

    powershell = ["/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "-NoProfile", "-NonInteractive", "-Command", SNAPSHOT]
    before = None
    try:
        manifest = ["--manifest-path", str(ROOT / "Cargo.toml")]
        run(["cargo", "fmt"] + manifest + ["--check"], "formatting")
        result = run(["cargo", "test", "--offline", "--locked"] + manifest, "Linux namespace rejection tests")
        print(result, end="", flush=True)
        run(["cargo", "clippy", "--offline", "--locked"] + manifest + ["--all-targets", "--", "--deny", "warnings"], "Linux Clippy")
        toolchain = PROJECT / "target" / "windows-toolchain" / "usr" / "bin"
        linker = PROJECT / "scripts" / "windows-linker.sh"
        if not linker.is_file() or not toolchain.is_dir():
            raise RuntimeError("prepare the existing Windows toolchain before validation")
        env.update({"PATH": str(toolchain) + os.pathsep + env.get("PATH", ""),
            "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER": str(linker), "RUSTC_WRAPPER": "",
            "CC_x86_64_pc_windows_gnu": str(linker),
            "AR_x86_64_pc_windows_gnu": str(toolchain / "x86_64-w64-mingw32-ar")})
        target = ["--target", "x86_64-pc-windows-gnu"]
        artifacts = run(["cargo", "test", "--offline", "--locked"] + manifest + target
            + ["--no-run", "--message-format=json"], "Windows native-test cross-build")
        executables = [Path(record["executable"]) for line in artifacts.splitlines()
            if (record := json.loads(line)).get("reason") == "compiler-artifact"
            and record.get("profile", {}).get("test") and record.get("executable")]
        if len(executables) != 1:
            raise RuntimeError("expected one Windows library-test executable")
        run(["cargo", "clippy", "--offline", "--locked"] + manifest + target
            + ["--all-targets", "--", "--deny", "warnings"], "Windows Clippy")
        if not args.test_reported_cleanup_failure:
            run(["cargo", "build", "--offline", "--locked", "--package", "age-tpm-wsl-helper"] + target,
                "actual Windows consumer helper build", timeout=900)
            run(["cargo", "clippy", "--offline", "--locked", "--package", "age-tpm-wsl-helper"] + target
                + ["--all-targets", "--", "--deny", "warnings"], "actual Windows consumer helper Clippy", timeout=900)
        before = json.loads(run(powershell, "independent pre-test directory snapshot"))
        report["before"] = before
        report["windows_test_executable"] = {"name": executables[0].name, "sha256": sha256(executables[0])}
        # Fatal cleanup uses process::exit, which bypasses libtest's captured
        # output flush. Keep namespace and both errors visible on every campaign.
        native_args = [str(executables[0]), "--test-threads=1", "--nocapture"]
        if args.test_reported_cleanup_failure:
            import secrets
            namespace = "age-tpm-wsl-fs-" + secrets.token_hex(16)
            report["controlled_reported_cleanup_fault"] = {
                "mode": args.test_reported_cleanup_failure, "namespace": namespace,
                "limit": "Reported failure injected only after real owned unlink succeeds; this campaign must fail"}
            env.update({"ATW_FS_TEST_ROLLBACK_MODE": args.test_reported_cleanup_failure,
                "ATW_FS_TEST_ROLLBACK_NAMESPACE": namespace})
            # Linux subprocess environment variables require explicit WSL interop
            # forwarding. These are public test controls, not paths or secrets.
            forwarded = [entry for entry in env.get("WSLENV", "").split(":")
                if entry and entry.split("/")[0] not in
                {"ATW_FS_TEST_ROLLBACK_MODE", "ATW_FS_TEST_ROLLBACK_NAMESPACE"}]
            env["WSLENV"] = ":".join(forwarded + ["ATW_FS_TEST_ROLLBACK_MODE/w",
                "ATW_FS_TEST_ROLLBACK_NAMESPACE/w"])
            native_args.append("native_cleanup_failure_")
        native = run(native_args, "native Windows filesystem tests")
        report["native_test_stdout"] = native
        print(native, end="", flush=True)
        if any(sha256(PROJECT / name) != expected for name, expected in report["source_sha256"].items()):
            raise RuntimeError("filesystem sources changed during validation")
        report["result"] = "pass"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        raise
    finally:
        if before is not None:
            try:
                after = json.loads(run(powershell, "independent post-test directory snapshot"))
                report["after"] = after
                report["independent_cleanup"] = "pass" if sorted(after["directories"]) == sorted(before["directories"]) else "fail"
                if report["independent_cleanup"] != "pass":
                    report["result"] = "fail"
                    report["cleanup_error"] = "directory snapshot changed; stop and investigate owned objects"
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                report["result"] = "fail"
                report["cleanup_error"] = str(error)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print("Saved filesystem report: " + str(args.report), flush=True)
        if report["result"] != "pass" and "cleanup_error" in report:
            raise RuntimeError("filesystem cleanup failed or remains unverified")


if __name__ == "__main__":
    main()
