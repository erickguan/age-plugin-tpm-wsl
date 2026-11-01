"""Prepared component requests through real clients/IPC and fake INVALID only."""
import base64
import unittest

import test_post_quantum_client_clients as support
from post_quantum_client.authority import Namespace, PREFIX, PublicIdentity, Stop
from post_quantum_client.controller import Controller, frame
from post_quantum_client.journal import AUTHENTICATION_FAILED, Journal
from post_quantum_client.mutations import Mutation, PreparedRead, SingleHybrid
from post_quantum_client.outcomes import ReadKind
from post_quantum_client.process import ProcessResult
from post_quantum_client.service import ClientService
from test_post_quantum_client_controller import FakeWindows, SID


class MutationTests(unittest.TestCase):
    def setUp(self):
        # Reuse the actual staged public-client fixture, never its native binary.
        self.fixture = support.ClientEnvironmentTests()
        self.fixture.setUp()
        self.clients = self.fixture.environment()
        self.clients.preflight(); self.clients.prepare(self.fixture.reference)
        self.namespace = Namespace(PREFIX + '0' * 32)
        self.journal = Journal.create(self.fixture.run.path / 'journal', self.namespace, SID,
                                      self.clients.inputs.helper.record())
        self.native = FakeWindows(self.namespace, self.journal)
        self.controller = Controller(self.journal, self.clients.env, self.native.observe, self.native.run)
        self.controller.admin('prepare')
        self.controller.forward(frame(8, b'\x00\x02' + self.namespace.key_name.encode()))
        self.identity = PublicIdentity.parse(self.native.identity, self.namespace)
        self.service = ClientService(self.fixture.run.path / 's', self.controller).start()
        encrypted = self.clients.encrypt(client='age')
        self.assertTrue(encrypted.measurement.passed)
        self.original = encrypted.output
        self.native.override = lambda operation: ProcessResult(0, frame(9, status=AUTHENTICATION_FAILED))

    def tearDown(self):
        try:
            if not self.service.endpoint.closed: self.service.abandon()
        finally: self.fixture.tearDown()  # Fake Windows state only.

    def prepared(self, mutation):
        return PreparedRead(self.namespace, self.identity, self.original, mutation)

    def test_control_roundtrips_the_exact_age_output(self):
        control = self.prepared(Mutation.CONTROL)
        self.assertTrue(control.ciphertext() == self.original)
        self.assertNotIn(self.original.hex(), repr(control))
        self.assertNotIn(self.identity.encoded.hex(), repr(control))

    def test_each_mutation_changes_only_its_component_and_rebinds_public_routing(self):
        original = SingleHybrid.parse(self.original, self.prepared(Mutation.CONTROL).public)
        for mutation in (Mutation.MLKEM, Mutation.P256, Mutation.WRAPPED_TAG):
            prepared = self.prepared(mutation)
            changed = SingleHybrid.parse(prepared.ciphertext(), prepared.public)
            self.assertTrue(changed.mac == original.mac and changed.payload == original.payload)
            if mutation is Mutation.MLKEM:
                self.assertEqual(changed.enc[0], original.enc[0] ^ 1)
                self.assertTrue(changed.enc[1:] == original.enc[1:] and changed.body == original.body)
            elif mutation is Mutation.P256:
                self.assertTrue(changed.enc[:1088] == original.enc[:1088])
                self.assertTrue(changed.enc[1088:] == prepared.public[1184:])
                self.assertTrue(changed.body == original.body)
            else:
                self.assertTrue(changed.enc == original.enc and changed.body[:-1] == original.body[:-1])
                self.assertEqual(changed.body[-1], original.body[-1] ^ 1)

    def test_actual_age_and_rage_route_all_prepared_components_to_the_owning_fake_helper(self):
        for mutation in (Mutation.MLKEM, Mutation.P256, Mutation.WRAPPED_TAG):
            for client in ('age', 'rage'):
                decision = self.prepared(mutation).execute(self.clients, self.controller, client)
                self.assertIs(decision.kind, ReadKind.AUTHENTICATION_REJECTED)
                self.assertFalse(decision.measurement.passed)
        self.service.quiesce()
        self.assertEqual(self.service.calls, 6)
        self.assertEqual(self.native.calls.count('unwrap'), 6)
        self.assertFalse(self.controller.summary()['cleanup_stopped'])

    def test_changed_encapsulation_without_rebound_routing_is_refused_before_client_execution(self):
        parsed = SingleHybrid.parse(self.original, self.identity.encoded[3:1252])
        lines = self.original.split(b'\n', 3)
        parts = lines[1].split(b' ')
        enc = bytearray(parsed.enc); enc[0] ^= 1
        parts[3] = base64.b64encode(enc).rstrip(b'=')
        lines[1] = b' '.join(parts)
        with self.assertRaises(Stop):
            PreparedRead(self.namespace, self.identity, b'\n'.join(lines), Mutation.MLKEM)
        self.assertEqual(self.native.calls.count('unwrap'), 0)

    def test_prepared_identity_cannot_be_substituted_for_current_enrollment(self):
        namespace = Namespace(PREFIX + '1' * 32)
        identity = PublicIdentity.parse(self.identity.encoded[:1252] + b'\x2f' + namespace.key_name.encode(), namespace)
        prepared = PreparedRead(namespace, identity, self.original, Mutation.MLKEM)
        with self.assertRaises(Stop): prepared.execute(self.clients, self.controller)
        self.assertTrue(self.controller.summary()['cleanup_stopped'])
        self.assertEqual(self.native.calls.count('unwrap'), 0)

    def test_malformed_or_unbounded_header_inputs_are_not_prepared(self):
        for ciphertext in (b'', self.original + b'extra', self.original.replace(b'-> mlkem768p256tag', b'-> unknown', 1),
                           self.original.replace(b'age-encryption.org/v1', b'age-encryption.org/v2', 1)):
            with self.assertRaises(Stop): PreparedRead(self.namespace, self.identity, ciphertext, Mutation.MLKEM)
        with self.assertRaises(Stop): PreparedRead(self.namespace, self.identity, self.original, 'unbounded-kind')


if __name__ == '__main__':
    unittest.main()
