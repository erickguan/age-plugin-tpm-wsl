"""Uninstalled entry point; the driver must invoke its pinned Python explicitly."""
from post_quantum_client.wrapper import main

if __name__ == '__main__':
    raise SystemExit(main())
