#!/usr/bin/env python3
"""Check failing validator evidence for test-only reported cleanup errors."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    inputs = [Path(__file__).resolve(), ROOT / "validate-custody-fs.py", PROJECT / "Cargo.lock"]
    source_sha256 = {str(p.relative_to(PROJECT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    results = []
    for mode in ("unlink-report", "absence-report"):
        report = args.output.with_name(args.output.stem + "-" + mode + ".json")
        process = subprocess.run([sys.executable, str(ROOT / "validate-custody-fs.py"),
            "--report", str(report), "--test-reported-cleanup-failure", mode], check=False)
        evidence = json.loads(report.read_text())
        native = [s for s in evidence["steps"] if s["check"] == "native Windows filesystem tests"]
        # A genuine cleanup failure or leftover is never an expected control.
        if evidence.get("independent_cleanup") != "pass" or evidence["before"]["directories"] != evidence["after"]["directories"]:
            raise RuntimeError("real cleanup failure during reported-error control; stop")
        assert process.returncode != 0 and evidence["result"] == "fail"
        assert len(native) == 1 and native[0]["exit_code"] == 97
        assert "ATW_TEST_CONTINUED_AFTER_CLEANUP_ERROR" not in native[0].get("failure_stdout", "")
        assert evidence["controlled_reported_cleanup_fault"]["mode"] == mode
        diagnostic = native[0].get("failure_stderr", "")
        assert "structured cleanup failure" in diagnostic
        assert "injected post-create verification failure" in diagnostic
        assert evidence["controlled_reported_cleanup_fault"]["namespace"] in diagnostic
        assert ("injected unlink-result failure" if mode == "unlink-report" else
            "new storage object absence not verified") in diagnostic
        results.append({"mode": mode, "validator_exit": process.returncode,
            "native_exit": native[0]["exit_code"], "independent_cleanup": "pass",
            "report": str(report), "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest()})
    if any(hashlib.sha256((PROJECT / name).read_bytes()).hexdigest() != digest for name, digest in source_sha256.items()):
        raise RuntimeError("cleanup-control inputs changed during validation")
    args.output.write_text(json.dumps({"result": "pass", "cases": results, "source_sha256": source_sha256,
        "limit": "Reported-error injection after actual unlink success; not a real leaked-object or forced-timeout experiment"}, indent=2) + "\n")


if __name__ == "__main__":
    main()
