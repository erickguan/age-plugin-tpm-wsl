"""Fixed client diagnostics only; raw stderr never crosses this interface."""
from enum import Enum


class Diagnostic(Enum):
    UNKNOWN = 'unknown'
    NO_MATCH = 'no-matching-identity'
    STANZA_SHAPE = 'invalid-pq-stanza-shape'
    FILE_VERSION = 'unsupported-file-version'
    IDENTITY_VERSION = 'unsupported-identity-version'
    PAYLOAD_AUTH = 'payload-authentication-failure'


def classify(client, raw):
    """Recognize confirmed English messages; this is not a read verdict.

    Callers still need exact prepared input, exit/output checks and the expected
    original-Journal transition. The pinned reader and isolated locale belong
    to that invocation. An ambiguous or operational message stays unknown.
    """
    if client not in {'age', 'rage'} or not isinstance(raw, bytes):
        return Diagnostic.UNKNOWN
    try:
        text = raw.decode('utf-8').replace('\u2068', '').replace('\u2069', '').lower()
    except UnicodeError:
        return Diagnostic.UNKNOWN
    operational = ('helper', 'not found', 'failed to start', 'failed to run', 'could not run',
                   'could not communicate', 'failed to communicate', 'timed out', 'timeout',
                   'permission denied', 'broken pipe', 'input/output error', 'plugin died',
                   'unexpected eof', 'truncated', 'header mac is invalid', 'bad header mac')
    if any(marker in text for marker in operational):
        return Diagnostic.UNKNOWN
    matches = set()
    no_match = ('no identity matched any of the recipients' if client == 'age'
                else 'no matching keys found')
    if no_match in text:
        matches.add(Diagnostic.NO_MATCH)
    if 'invalid post-quantum stanza shape' in text:
        matches.add(Diagnostic.STANZA_SHAPE)
    if 'unsupported recipient version or suite' in text:
        matches.add(Diagnostic.IDENTITY_VERSION)
    if (client == 'age' and 'parsing age header' in text and 'unexpected intro' in text
            or client == 'rage' and 'unknown age format.' in text):
        matches.add(Diagnostic.FILE_VERSION)
    payload = ('failed to decrypt and authenticate payload chunk' if client == 'age'
               else 'decryption error')
    if payload in text:
        matches.add(Diagnostic.PAYLOAD_AUTH)
    return matches.pop() if len(matches) == 1 else Diagnostic.UNKNOWN
