"""One finite refusal plan and its required diagnostic categories."""
from enum import Enum

from .diagnostics import Diagnostic


class Refusal(Enum):
    CONTROL = ('control', Diagnostic.UNKNOWN)
    WRONG_IDENTITY = ('wrong_identity', Diagnostic.NO_MATCH)
    STANZA_SHAPE = ('malformed_stanza', Diagnostic.STANZA_SHAPE)
    FILE_VERSION = ('unsupported_file_version', Diagnostic.FILE_VERSION)
    IDENTITY_VERSION = ('unsupported_identity_version', Diagnostic.IDENTITY_VERSION)
    NO_DOWNGRADE = ('no_downgrade', Diagnostic.NO_MATCH)
    PAYLOAD_AUTH = ('payload_auth', Diagnostic.PAYLOAD_AUTH)

    @property
    def label(self):
        return self.value[0]

    @property
    def diagnostic(self):
        return self.value[1]

    @classmethod
    def for_label(cls, label):
        return next((case for case in cls if case.label == label), None)


LOCAL_REFUSALS = frozenset(case for case in Refusal if case not in {Refusal.CONTROL, Refusal.PAYLOAD_AUTH})
REFUSAL_LABELS = frozenset(case.label for case in Refusal if case is not Refusal.CONTROL)
REFUSAL_PLAN = tuple((case, reader) for case in Refusal for reader in ('age', 'rage'))
