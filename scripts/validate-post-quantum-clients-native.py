"""Uninstalled driver entry; native mode requires approved runtime pins and ack."""
from pathlib import Path
import sys

# Permit the pinned interpreter's isolated mode without ambient PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from post_quantum_client.native_cli import main

if __name__ == '__main__':
    raise SystemExit(main())
