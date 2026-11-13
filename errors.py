"""Fixed, content-free guidance: never display a server's exception text."""


import fcntl
import os
import re
from contextlib import contextmanager
from pathlib import Path

BUSY_CODES = frozenset({'PLUGIN_BUSY', 'SPOOL_BUSY'})

# Only fixed local RuntimeError codes are eligible; never arbitrary message text.
LOCAL_CODES = frozenset({
    'ALREADY_CONFIGURED', 'ALREADY_CONFIGURED_OR_EXCHANGE_UNCERTAIN',
    'RUN_HERMES_FIRST', 'ENROLLMENT_UNAVAILABLE_ASK_FOR_FRESH_CODE',
    'ENROLLMENT_RESPONSE_INVALID', 'DAEMON_BELONGS_TO_DIFFERENT_HERMES_PROFILE',
    'DAEMON_NOT_FOUND', 'DAEMON_IDENTITY_MISMATCH', 'DAEMON_READ_KEY_MISSING',
    'CREDENTIAL_INVALID', 'PRIVATE_FILE_UNSAFE', 'DAEMON_MIGRATION_FAILED',
    'DAEMON_LAYOUT_AMBIGUOUS_USE_EXPLICIT_ROOT', 'SCHEDULER_CHANGED',
    'DAEMON_STOP_UNVERIFIED', 'MCP_REMOVAL_FAILED', 'LEGACY_HISTORY_NEEDS_SUPPORT',
    'SOURCE_ROW_MISSING', 'SOURCE_ROW_SIZE_LIMIT', 'SOURCE_READ_TIMEOUT',
    'SOURCE_CHANGED', 'HERMES_SCHEMA_UNSUPPORTED', 'SOURCE_NOT_READONLY',
    'SOURCE_PATH_UNSAFE', 'SOURCE_NOT_REGULAR', 'SOURCE_CREDENTIAL_NAME'})


def cause(error, *, native_id=None):
    """No repr/message, locals, absolute paths, or foreign traceback frames."""
    from chatstone.collectors.policy import SourceDenied
    code = getattr(error, 'code', None)
    if not isinstance(code, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{1,79}', code):
        code = str(error) if (type(error) is RuntimeError or isinstance(error, SourceDenied)) and str(error) in LOCAL_CODES else None
    frames = []
    plugin = Path(__file__).resolve().parent
    client = Path(__import__('chatstone.client.spool', fromlist=['Spool']).__file__).resolve().parent
    collectors = client.parent/'collectors'
    tb = error.__traceback__
    while tb:
        path = Path(tb.tb_frame.f_code.co_filename).resolve()
        if any(path.is_relative_to(base) for base in (plugin, client, collectors)):
            frames.append(f'{path.name}:{tb.tb_lineno} {tb.tb_frame.f_code.co_name}')
        tb = tb.tb_next
    value = {'exception': type(error).__name__, 'frames': frames[-4:]}
    if code:
        value['code'] = code
    native_id = native_id if native_id is not None else getattr(error, 'native_id', None)
    if type(native_id) is int:
        value['native_id'] = native_id
    return value


def describe(value):
    label = value.get('code') or value['exception']
    if 'native_id' in value:
        label += '; native ID '+str(value['native_id'])
    return label + ('; '+ ' <- '.join(value['frames']) if value['frames'] else '')


@contextmanager
def status_lock(home):
    # Independent of the sync lease: even a failed lease acquisition can record
    # a cause without overwriting a concurrent owner's successful snapshot.
    from .config import root
    fd = os.open(root(home)/'.status.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def save_failure(home, error):
    if getattr(error, 'code', None) in BUSY_CODES:
        return None
    from .config import read_private, root, write_private
    value = cause(error)
    path = root(home)/'status.json'
    with status_lock(home):
        try:
            previous = read_private(path)
        except (FileNotFoundError, ValueError):
            previous = {}
        previous.update(last_cause=value, last_error=describe(value), last_error_code=value.get('code'))
        write_private(path, previous)
    return value


def guidance(code):
    if code in ('INGEST_CAPACITY_EXCEEDED', 'QUOTA_EXCEEDED'):
        return ('Server capacity refused this upload. Queued data is kept. Ask the operator '
                'to raise the device/tenant allowance or free server capacity; sync retries automatically.')
    if code in ('UNAUTHORIZED', 'FORBIDDEN', 'INVALID_KEY', 'KEY_REVOKED', 'INGEST_DISABLED'):
        return ('Server refused device access. Queued data is kept. Ask the operator to restore '
                'this device\'s ingest access; do not re-enroll or delete its queue.')
    if code in ('RATE_LIMITED', 'SERVICE_UNAVAILABLE', 'DEADLINE_EXCEEDED', 'REQUEST_TIMEOUT'):
        return 'Server temporarily unavailable or busy. Queued data is kept; sync retries automatically.'
    if code in ('DELIVERY_REFUSED', 'SPOOL_REJECTED', 'INVALID_RECORD', 'INVALID_ACK'):
        return ('Server refused or could not confirm an upload. Queued data is kept. '
                'Ask support to inspect the refusal; do not delete the queue.')
    return ('Sync unavailable. Queued data is kept. Check connectivity and device access; '
            'if this persists, ask support. Run hermes chatstone status.')
