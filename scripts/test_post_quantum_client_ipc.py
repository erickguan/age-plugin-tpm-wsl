"""Real local sockets and fake native operations; never invokes a Windows helper."""
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from post_quantum_client.authority import Namespace, PREFIX, Stop
from post_quantum_client.channel import Channel, RESPONSE_END
from post_quantum_client.controller import Controller, frame
from post_quantum_client.endpoint import Endpoint
from post_quantum_client.journal import Journal, Session
from post_quantum_client.process import BinaryPin, ProcessResult, digest
from post_quantum_client.wrapper import forward_stdio
from test_post_quantum_client_controller import FakeWindows


class IPCTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.directory.chmod(0o700)
        source = self.directory / 'source'
        source.write_bytes(b'fixed fake source')
        executable = self.directory / 'original'
        executable.write_bytes(b'fake executable, never launched')
        pin = BinaryPin.stage(executable, digest(executable), self.directory, {str(source): digest(source)})
        self.namespace = Namespace(PREFIX + '0' * 32)
        self.journal = Journal.create(self.directory / 'journal', self.namespace, 'S-1-5-21-1001', pin.record())
        self.native = FakeWindows(self.namespace, self.journal)
        self.controller = Controller(self.journal, {}, self.native.observe, self.native.run)
        self.controller.admin('prepare')
        self.controller.forward(frame(8, b'\x00\x02' + self.namespace.key_name.encode()))
        self.request = frame(9, b'\x05\x14' + self.native.identity + b'\x01' * 1153 + b'\x02' * 32)
        self.path = self.directory / 'socket'
        self.endpoint = Endpoint(self.path, self.controller, seconds=1)
        self.threads = []
        self.results = []

    def tearDown(self):
        for thread in self.threads:
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive(), 'local test thread did not terminate')
        self.endpoint.close()
        self.temporary.cleanup()

    def start_server(self):
        def serve():
            try:
                self.results.append(self.endpoint.serve_once(wait_seconds=1))
            except BaseException:
                self.results.append('stopped')
        thread = threading.Thread(target=serve, daemon=True)
        self.threads.append(thread)
        thread.start()
        return thread

    def joined(self, thread):
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def connect(self):
        stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stream.connect(str(self.path))
        return stream

    def assert_stopped(self):
        self.assertTrue(self.controller.summary()['cleanup_stopped'])
        count = len(self.native.calls)
        with self.assertRaises(Stop):
            self.controller.forward(frame(4, self.native.identity))
        self.assertEqual(len(self.native.calls), count)

    def test_full_roundtrip_acknowledges_stdout_and_retains_one_owner(self):
        server = self.start_server()
        output = io.BytesIO()
        forward_stdio(self.path, os.getpid(), io.BytesIO(self.request), output)
        self.joined(server)
        self.assertEqual(output.getvalue(), frame(9, b'\x5a' * 16))
        self.assertEqual(self.results, [True])
        self.assertTrue(self.controller.summary()['continuation_owned'])
        self.assertFalse(self.controller.summary()['cleanup_stopped'])
        self.assertNotIn('5a' * 16, self.journal.path.read_text())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_real_wrapper_process_uses_owner_socket_without_reopening_journal(self):
        server = self.start_server()
        entry = Path(__file__).parent / 'post_quantum_client_wrapper.py'
        result = subprocess.run([sys.executable, str(entry), '--socket', str(self.path),
                                 '--owner-pid', str(os.getpid())], input=self.request,
                                capture_output=True, timeout=3)
        self.joined(server)
        # Captured bytes here are the fixed public dummy from FakeWindows,
        # never a generated file key or output of an actual Windows helper.
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, frame(9, b'\x5a' * 16))
        self.assertEqual(result.stderr, b'')
        self.assertEqual(self.results, [True])

    def test_interruption_after_durable_result_but_before_ack_latches_owner(self):
        original = Channel.marker
        def interrupted(channel, expected):
            if expected == b'A':
                raise KeyboardInterrupt('simulated owner interruption')
            return original(channel, expected)
        with patch.object(Channel, 'marker', interrupted):
            server = self.start_server()
            try:
                forward_stdio(self.path, os.getpid(), io.BytesIO(self.request), io.BytesIO())
            except (Stop, OSError):
                pass
            self.joined(server)
        self.assertEqual(self.results, ['stopped'])
        self.assert_stopped()

    def test_flush_failure_prevents_ack_and_stops_owner(self):
        class BrokenFlush(io.BytesIO):
            def flush(self):
                raise BrokenPipeError('disposable flush failure')
        server = self.start_server()
        with self.assertRaises(BrokenPipeError):
            forward_stdio(self.path, os.getpid(), io.BytesIO(self.request), BrokenFlush())
        self.joined(server)
        self.assert_stopped()

    def test_journal_lock_blocks_delete_until_delivery_acknowledgment(self):
        server = self.start_server()
        with self.connect() as stream:
            channel = Channel(stream, 1)
            channel.send(self.request + b'R')
            channel.frame()
            channel.marker(RESPONSE_END)
            count = len(self.native.calls)
            with self.assertRaises(Stop):
                self.controller.forward(frame(4, self.native.identity))
            self.assertEqual(len(self.native.calls), count)
            self.assertTrue(self.native.key)
            channel.send(b'A')
            stream.shutdown(socket.SHUT_WR)
        self.joined(server)
        self.assert_stopped()

    def test_interrupt_after_success_append_blocks_cleanup_before_outer_handler(self):
        original_append = Session.append
        original_fail = self.endpoint.fail
        attempted = []
        def interrupt_after_receipt(session, event):
            original_append(session, event)
            if event.get('kind') == 'success' and event.get('operation') == 'unwrap':
                raise KeyboardInterrupt('after durable success and marker removal')
        def outer_handler():
            try:
                self.controller.forward(frame(4, self.native.identity))
                attempted.append('deleted')
            except Stop:
                attempted.append('blocked')
            original_fail()
        with patch.object(Session, 'append', interrupt_after_receipt), patch.object(self.endpoint, 'fail', outer_handler):
            server = self.start_server()
            with self.assertRaises((Stop, OSError)):
                forward_stdio(self.path, os.getpid(), io.BytesIO(self.request), io.BytesIO())
            self.joined(server)
        self.assertEqual(attempted, ['blocked'])
        self.assertNotIn('delete', self.native.calls)
        self.assertTrue(self.native.key)
        self.assert_stopped()

    def test_expected_numeric_rejection_is_relayed_with_ack_without_fatality(self):
        self.native.override = lambda _: ProcessResult(0, frame(9, status=0xA0010001))
        server = self.start_server()
        output = io.BytesIO()
        forward_stdio(self.path, os.getpid(), io.BytesIO(self.request), output)
        self.joined(server)
        self.assertEqual(output.getvalue(), frame(9, status=0xA0010001))
        self.assertFalse(self.controller.summary()['cleanup_stopped'])

    def test_wrapper_rejects_lifecycle_trailing_oversize_and_bad_status_before_connect(self):
        for request in [frame(4, self.native.identity), self.request + b'x', b'x' * 9000,
                        frame(9, status=1), b'ATW1']:
            with self.subTest(length=len(request)):
                with self.assertRaises(Stop):
                    forward_stdio(self.path, os.getpid(), io.BytesIO(request), io.BytesIO())
        self.assertEqual(self.native.calls, ['prepare', 'create'])
        self.assertFalse(self.controller.summary()['cleanup_stopped'])

    def test_server_independently_rejects_lifecycle_before_native_work(self):
        server = self.start_server()
        with self.connect() as stream:
            stream.sendall(frame(4, self.native.identity) + b'R')
            stream.shutdown(socket.SHUT_WR)
        self.joined(server)
        self.assertEqual(self.native.calls, ['prepare', 'create'])
        self.assert_stopped()

    def test_output_failure_closes_without_ack_and_stops_owner(self):
        class BrokenOutput:
            def write(self, _):
                raise BrokenPipeError('disposable test pipe closed')
        server = self.start_server()
        with self.assertRaises(BrokenPipeError):
            forward_stdio(self.path, os.getpid(), io.BytesIO(self.request), BrokenOutput())
        self.joined(server)
        self.assert_stopped()

    def test_ack_deadline_stops_owner_and_cannot_trigger_cleanup(self):
        self.endpoint.seconds = 0.1
        server = self.start_server()
        with self.connect() as stream:
            channel = Channel(stream, 1)
            channel.send(self.request + b'R')
            channel.frame()
            channel.marker(RESPONSE_END)
            # Deliberately withhold acknowledgment; no polling or sleeps.
            self.joined(server)
        self.assert_stopped()

    def test_wrong_ack_or_trailing_ack_bytes_stop_after_response(self):
        server = self.start_server()
        with self.connect() as stream:
            channel = Channel(stream, 1)
            channel.send(self.request + b'R')
            channel.frame()
            channel.marker(RESPONSE_END)
            channel.send(b'AX')
            stream.shutdown(socket.SHUT_WR)
        self.joined(server)
        self.assert_stopped()

    def test_wrong_server_pid_is_rejected_before_sending_request(self):
        server = self.start_server()
        with self.assertRaises(Stop):
            forward_stdio(self.path, os.getpid() + 1, io.BytesIO(self.request), io.BytesIO())
        self.joined(server)
        self.assertEqual(self.native.calls, ['prepare', 'create'])
        self.assert_stopped()

    def test_existing_entry_is_never_replaced_and_reopened_journal_cannot_host(self):
        original_inode = self.path.stat().st_ino
        with self.assertRaises(OSError):
            Endpoint(self.path, self.controller)
        self.assertEqual(self.path.stat().st_ino, original_inode)
        reopened = Controller(Journal(self.journal.path), {}, self.native.observe, self.native.run)
        with self.assertRaises(Stop):
            Endpoint(self.directory / 'another', reopened)
        self.assertFalse((self.directory / 'another').exists())

    def test_endpoint_close_retains_unknown_replacement_entry(self):
        moved = self.directory / 'old-socket'
        self.path.rename(moved)
        self.path.write_bytes(b'unrelated local file')
        try:
            with self.assertRaises(Stop):
                self.endpoint.close()
            self.assertEqual(self.path.read_bytes(), b'unrelated local file')
            self.assert_stopped()
        finally:
            self.path.unlink()
            moved.rename(self.path)

    def test_idle_accept_does_not_invent_a_request_or_poison_owner(self):
        self.assertFalse(self.endpoint.serve_once(wait_seconds=0.01))
        self.assertFalse(self.controller.summary()['cleanup_stopped'])
        self.assertEqual(self.native.calls, ['prepare', 'create'])

    def test_active_request_blocks_endpoint_retirement(self):
        entered, release = threading.Event(), threading.Event()
        def delayed(_):
            entered.set()
            if not release.wait(timeout=1):
                raise Stop('test synchronization failed')
            return ProcessResult(0, frame(9, b'\x5a' * 16))
        self.native.override = delayed
        server = self.start_server()
        client_errors = []
        def client():
            try:
                forward_stdio(self.path, os.getpid(), io.BytesIO(self.request), io.BytesIO())
            except (Stop, OSError):
                client_errors.append(True)
        client_thread = threading.Thread(target=client, daemon=True)
        self.threads.append(client_thread)
        client_thread.start()
        try:
            self.assertTrue(entered.wait(timeout=1))
            with self.assertRaises(Stop):
                self.endpoint.close()
            self.assertTrue(self.path.exists())
        finally:
            release.set()
        self.joined(client_thread)
        self.joined(server)
        self.assertEqual(client_errors, [])
        self.assertEqual(self.results, [True])


if __name__ == '__main__':
    unittest.main()
