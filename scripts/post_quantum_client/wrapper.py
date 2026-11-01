"""Uninstalled plugin-side IPC frontend. Stdout contains one protocol frame only."""
import argparse
from pathlib import Path
import socket
import sys

from .authority import Stop
from .channel import (ACK, LIMIT, REQUEST_END, RESPONSE_END, Channel, check_peer,
                      private_parent, socket_identity, validate_frame)


def forward_stdio(path, owner_pid, stdin, stdout, seconds=10):
    # Read EOF before connecting so trailing/oversized requests cannot start work.
    request = validate_frame(stdin.read(LIMIT + 1), request=True)
    if type(owner_pid) is not int or owner_pid <= 0:
        raise Stop('explicit owning controller PID required')
    path = Path(path)
    private_parent(path)
    socket_identity(path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        channel = Channel(stream, seconds)
        channel.bounded().connect(str(path))
        check_peer(stream, owner_pid)
        channel.send(request + REQUEST_END)
        returned = channel.frame()
        channel.marker(RESPONSE_END)
        # No capture, JSON conversion, digest or diagnostic includes these bytes.
        if stdout.write(returned) != len(returned):
            raise Stop('incomplete protocol output')
        stdout.flush()
        channel.send(ACK)
        stream.shutdown(socket.SHUT_WR)
        channel.eof()


def main():
    parser = argparse.ArgumentParser(description='Private disposable-client protocol frontend')
    parser.add_argument('--socket', required=True)
    parser.add_argument('--owner-pid', required=True, type=int)
    arguments = parser.parse_args()
    try:
        forward_stdio(arguments.socket, arguments.owner_pid, sys.stdin.buffer, sys.stdout.buffer)
        return 0
    except (OSError, ValueError, Stop):
        print('Disposable client IPC failed; retain campaign state.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
