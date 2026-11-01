"""Bounded local socket framing. Bytes stay in memory and are never recorded."""
import os
import socket
import stat
import struct
import time
from pathlib import Path

from .authority import Stop

LIMIT = 8192 + 13
REQUEST_END, RESPONSE_END, ACK = b'R', b'S', b'A'


def private_parent(path):
    path = Path(path)
    info = path.parent.lstat()
    if (not path.is_absolute() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or len(os.fsencode(path)) > 107):
        raise Stop('absolute short socket path in an owned private directory required')
    return info.st_dev, info.st_ino


def socket_identity(path):
    info = Path(path).lstat()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise Stop('owned private socket required')
    return info.st_dev, info.st_ino


def check_peer(stream, owner_pid=None):
    pid, uid, _ = struct.unpack('=iII', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != os.getuid() or (owner_pid is not None and pid != owner_pid):
        raise Stop('unexpected local controller peer')


def validate_frame(data, request=False):
    if not isinstance(data, bytes) or len(data) < 13 or data[:5] != b'ATW1\x09':
        raise Stop('IPC permits only post-quantum unwrap frames')
    status, length = struct.unpack('<II', data[5:13])
    if length > 8192 or len(data) != 13 + length or (status and (request or length)):
        raise Stop('invalid bounded IPC frame')
    return data


class Channel:
    def __init__(self, stream, seconds):
        self.stream = stream
        self.deadline = time.monotonic() + seconds

    def bounded(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Stop('local channel deadline exceeded')
        self.stream.settimeout(remaining)
        return self.stream

    def send(self, data):
        self.bounded().sendall(data)

    def exact(self, count):
        data = bytearray()
        while len(data) < count:
            block = self.bounded().recv(count - len(data))
            if not block:
                raise Stop('incomplete local channel exchange')
            data.extend(block)
        return bytes(data)

    def frame(self, request=False):
        header = self.exact(13)
        if header[:5] != b'ATW1\x09':
            raise Stop('unexpected local frame header')
        length = struct.unpack('<I', header[9:13])[0]
        if length > 8192:
            raise Stop('local frame bound exceeded')
        return validate_frame(header + self.exact(length), request)

    def marker(self, expected):
        if self.exact(1) != expected:
            raise Stop('invalid local exchange marker')

    def eof(self):
        if self.bounded().recv(1):
            raise Stop('trailing local exchange data')
