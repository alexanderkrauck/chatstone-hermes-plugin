"""Acquire selected Hermes SQLite rows before exposing them to consumers.

POSIX only; trusted local store directories, not hostile uploaded databases.
One unchanged native acquisition deadline includes draining and reaping; slow
normalization/encoding cannot hold the read transaction open. Selected canonical
rows spool to a private, automatically removed tempfile in the caller's temp
directory, capped at 1 GiB including length headers, never pickle or a DB copy.
Only a successfully reaped worker exposes rows; unreaped ownership is retained.
Complete means this committed SQLite read snapshot, not future writes.
"""
import json
import multiprocessing
import os
import re
import sqlite3
import struct
import tempfile
import time

from .normalization import canonical
from .opencode import _READERS, OpenCodeRejected, _receive_frame
from .policy import SourceDenied

_SECONDS = 35.0
_ROW_BYTES = 250_000_000
_CHUNK = 1024 * 1024
_SPOOL_BYTES = 1024 * 1024 * 1024


class ReaderUnreaped(SourceDenied):
    def __init__(self, process):
        super().__init__('SOURCE_READER_UNREAPED')
        self.process = process


def _limits():
    import resource
    import sys

    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # Darwin rejects RLIMIT_AS (including Python 3.14 on Apple silicon).
        # RLIMIT_RSS is not an enforced substitute. Keep CPU/alarm and explicit
        # row/spool bounds there; Linux retains its original address-space cap.
        if sys.platform != 'darwin':
            resource.setrlimit(resource.RLIMIT_AS, (640 * 1024 * 1024, 640 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (31, 31))
    except (OSError, ValueError):
        raise SourceDenied('READER_RLIMIT_UNSUPPORTED') from None


def _worker(writer, path, sample=None):
    import signal

    from .hermes import _native_rows

    try:
        _limits()
        signal.setitimer(signal.ITIMER_REAL, _SECONDS)
        from .hermes import incremental_rows
        selected = (_native_rows(path) if sample is None else
                    (raw for raw, seq in incremental_rows(path, after=0, limit=sample)))
        for raw in selected:
            data = canonical(raw)
            if len(data) > _ROW_BYTES:
                raise SourceDenied('SOURCE_ROW_SIZE_LIMIT')
            for start in range(0, len(data), _CHUNK):
                writer.send_bytes(b'D' + data[start:start + _CHUNK])
            writer.send_bytes(b'R')
        writer.send_bytes(b'Z')
    except (sqlite3.Error, OSError, ValueError, TypeError, OverflowError,
            RecursionError, MemoryError) as error:
        code = ('SOURCE_READ_BUSY' if isinstance(error, sqlite3.OperationalError)
                and getattr(error, 'sqlite_errorcode', None) in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
                else 'HERMES_SOURCE_INVALID')
        if isinstance(error, SourceDenied) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', str(error)):
            code = str(error)
        try:
            writer.send_bytes(b'E' + code.encode('ascii'))
        except OSError:
            pass
    finally:
        writer.close()


def _decode(data):
    from .hermes import _valid_native_input

    raw = json.loads(data)
    if type(raw) is not dict:
        raise SourceDenied('HERMES_SOURCE_INVALID')
    # Restore only our closed generated evidence object and canonical BLOB tag;
    # ordinary JSON-looking source TEXT remains an ordinary string.
    for key, value in raw.items():
        if key == 'native_input':
            if not _valid_native_input(value):
                raise SourceDenied('HERMES_SOURCE_INVALID')
            continue
        if isinstance(value, dict):
            if set(value) != {'$bytes_hex'} or not isinstance(value['$bytes_hex'], str):
                raise SourceDenied('HERMES_SOURCE_INVALID')
            raw[key] = bytes.fromhex(value['$bytes_hex'])
    return raw


def _reap(process, deadline, complete):
    if process.pid is not None:
        remaining = max(0, deadline - time.monotonic())
        process.join(timeout=max(0, remaining - 0.2) if complete else min(0.05, remaining / 4))
        if process.exitcode is None:
            process.terminate()
            process.join(timeout=min(0.1, max(0, deadline - time.monotonic()) / 2))
        if process.exitcode is None:
            process.kill()
            process.join(timeout=max(0, deadline - time.monotonic()))
        if process.exitcode is None:
            raise ReaderUnreaped(process)
    code = process.exitcode
    process.close()
    _READERS.discard(process)
    return code


def rows(path, *, sample=None):
    if os.name != 'posix':
        raise SourceDenied('SOURCE_PLATFORM_UNSUPPORTED')
    deadline = time.monotonic() + _SECONDS
    receive_deadline = deadline - min(1.0, _SECONDS / 5)
    try:
        with tempfile.TemporaryFile(mode='w+b') as spool:
            context = multiprocessing.get_context('spawn')
            reader, writer = context.Pipe(duplex=False)
            process = context.Process(target=_worker, args=(writer, path, sample), daemon=True)
            _READERS.add(process)
            complete = False
            try:
                process.start()
                writer.close()
                pending = bytearray()
                total = 0
                while True:
                    frame = _receive_frame(reader, receive_deadline)
                    if frame[:1] == b'D':
                        if len(pending) + len(frame) - 1 > _ROW_BYTES:
                            raise SourceDenied('SOURCE_ROW_SIZE_LIMIT')
                        pending.extend(frame[1:])
                    elif frame == b'R' and pending:
                        total += 4 + len(pending)
                        if total > _SPOOL_BYTES:
                            raise SourceDenied('SOURCE_SPOOL_SIZE_LIMIT')
                        spool.write(struct.pack('!I', len(pending)))
                        spool.write(pending)
                        pending = bytearray()
                    elif frame == b'Z' and not pending:
                        complete = True
                        break
                    elif frame[:1] == b'E' and re.fullmatch(rb'[A-Z][A-Z0-9_]{0,63}', frame[1:]):
                        raise SourceDenied(bytes(frame[1:]).decode('ascii'))
                    else:
                        raise SourceDenied('HERMES_SOURCE_INVALID')
            finally:
                writer.close()
                reader.close()
                exitcode = _reap(process, deadline, complete)
            if exitcode != 0:
                raise SourceDenied('HERMES_SOURCE_INVALID')
            spool.seek(0)
            remaining = total
            while remaining:
                header = spool.read(4)
                if len(header) != 4:
                    raise SourceDenied('HERMES_SOURCE_INVALID')
                size, = struct.unpack('!I', header)
                if not 0 < size <= min(_ROW_BYTES, remaining - 4):
                    raise SourceDenied('HERMES_SOURCE_INVALID')
                data = spool.read(size)
                if len(data) != size:
                    raise SourceDenied('HERMES_SOURCE_INVALID')
                remaining -= 4 + size
                yield _decode(data)
            if spool.read(1):
                raise SourceDenied('HERMES_SOURCE_INVALID')
    except OpenCodeRejected as error:
        raise SourceDenied(str(error)) from None
    except (EOFError, OSError, ValueError) as error:
        if isinstance(error, SourceDenied):
            raise
        raise SourceDenied('HERMES_SOURCE_INVALID') from None


# The legacy whole-reader above is intentionally unchanged. The explicit durable
# route below owns one finite phase and returns metadata only, never raw rows.
def _acquisition_worker(writer, path, state, seconds, parent_pid):
    import signal
    import sys

    from chatstone.client.hermes_acquisition import _perform_step

    try:
        if sys.platform == 'linux':
            import ctypes
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
                raise SourceDenied('ACQUISITION_PARENT_LOST')
        _limits()
        signal.setitimer(signal.ITIMER_REAL, seconds)
        result = canonical(_perform_step(path, state, time.monotonic() + seconds))
        if len(result) > 16384:
            raise SourceDenied('ACQUISITION_METADATA_LIMIT')
        writer.send_bytes(b'J' + result)
        writer.send_bytes(b'Z')
    except (OSError, ValueError, TypeError, sqlite3.Error, MemoryError, OverflowError,
            RecursionError) as error:
        # Never transport exception objects, paths, SQL or source contents.
        code = (str(error) if isinstance(error, SourceDenied) and
                re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', str(error)) else 'ACQUISITION_STEP_FAILED')
        try:
            writer.send_bytes(b'E' + code.encode('ascii'))
        except OSError:
            pass
    finally:
        writer.close()


def acquisition_step(path, state, *, deadline):
    """Execute one protected durable phase; require terminal, EOF and reap.

    No checkpoint is authorized by a terminal frame alone. Parent retains exact
    ownership through ReaderUnreaped. Linux workers die if their parent dies;
    other POSIX workers retain the finite native alarm (not a Darwin proof).
    """
    if os.name != 'posix':
        raise SourceDenied('SOURCE_PLATFORM_UNSUPPORTED')
    context = multiprocessing.get_context('spawn')
    reader, writer = context.Pipe(duplex=False)
    seconds = min(20.0 if state['phase'] == 'PREPARING' else 30.0,
                  deadline - time.monotonic() - 1.0)
    if seconds <= 0:
        reader.close()
        writer.close()
        raise SourceDenied('SOURCE_READ_TIMEOUT')
    process = context.Process(target=_acquisition_worker,
                              args=(writer, path, state, seconds, os.getpid()), daemon=True)
    _READERS.add(process)
    complete, result = False, None
    try:
        try:
            process.start()
            writer.close()
            frame = _receive_frame(reader, deadline - 1.0)
            if frame.startswith(b'E') and re.fullmatch(rb'[A-Z][A-Z0-9_]{0,63}', frame[1:]):
                raise SourceDenied(frame[1:].decode('ascii'))
            if not frame.startswith(b'J') or len(frame) > 16385:
                raise SourceDenied('ACQUISITION_STEP_FAILED')
            result = json.loads(frame[1:])
            if type(result) is not dict or _receive_frame(reader, deadline - 1.0) != b'Z':
                raise SourceDenied('ACQUISITION_PROTOCOL')
            try:
                _receive_frame(reader, deadline - 1.0)
            except EOFError:
                complete = True
            if not complete:
                raise SourceDenied('ACQUISITION_PROTOCOL')
        finally:
            writer.close()
            reader.close()
            exitcode = _reap(process, deadline, complete)
        if exitcode != 0 or time.monotonic() >= deadline:
            raise SourceDenied('ACQUISITION_STEP_FAILED')
        return result
    except OpenCodeRejected as error:
        raise SourceDenied(str(error)) from None
    except (EOFError, OSError, ValueError) as error:
        if isinstance(error, SourceDenied):
            raise
        raise SourceDenied('ACQUISITION_STEP_FAILED') from None
