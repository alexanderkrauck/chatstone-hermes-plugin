"""Bounded explicit OpenCode SQLite input (synthetic column profile only).

No discovery, backup/dump, file-URL fetch, credential-table read or source write.
A fresh spawned reader uses Unix SQLite readonly_shm=1 as well as mode=ro:
mode=ro alone can mutate WAL SHM read marks, including via a caller's existing
writable SQLite mapping. Only selected rows cross the private bounded pipe.
The read transaction closes before any message is yielded.

ParseLimits archive fields bound rows PER TABLE, canonical bytes per selected
row, and total selected canonical bytes. Hard ceilings: 100k rows/table, 4 MiB
row, 16 MiB selected snapshot, 512 MiB source+sidecars, JSON depth 64 / 100k
nodes per data object, 30-second SQLite work / 35-second reader deadline.

Native IDs are literal nonempty strings; no trimming, fallbacks or fragments.
Raw includes every allowlisted column and the original JSON strings, not
unselected columns. Messages/parts order by (time_created, id), grouped by
literal session ID. Parent/project/time fields stay in raw (contracts unchanged).

POSIX trusted local directories only. Directory and file acquisition is
O_NOFOLLOW with inode checks. Like Hermes, stdlib SQLite reopens by pathname;
this is NOT a VFS-level defense against hostile concurrent path replacement.
Use a trusted store directory, never an attacker-controlled uploaded database.
Spawn requires an importable module/normal multiprocessing-safe application.
"""
from __future__ import annotations

import json
import math
import multiprocessing
import os
import selectors
import sqlite3
import stat
import struct
import time
from collections import defaultdict
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from pathlib import Path

from .binary import extract_content
from .contracts import ParsedRecord, ParseLimits, Part, SourceIdentity
from .normalization import canonical, record
from .policy import SourceDenied, checked_path, directory_anchor

_COLUMNS = {
    'project': ('id', 'worktree', 'time_created', 'time_updated'),
    'session': ('id', 'project_id', 'parent_id', 'directory', 'title', 'time_created', 'time_updated'),
    'message': ('id', 'session_id', 'time_created', 'time_updated', 'data'),
    'part': ('id', 'message_id', 'session_id', 'time_created', 'time_updated', 'data'),
}
_ROW_CAP = 4 * 1024 * 1024
_TOTAL_CAP = 16 * 1024 * 1024
_READ_SECONDS = 30.0
_WORKER_SECONDS = 35.0
# Strong ownership survives a cleanup failure, even if the caller drops its error.
# Remove a handle only after waitpid-backed exitcode proves it has been reaped.
_READERS = set()


class OpenCodeRejected(ValueError):
    """Coded source rejection; no source/private payload in diagnostics."""


def _limits(limits):
    for value in (limits.max_text_bytes, limits.max_attachment_bytes,
                  limits.max_archive_members, limits.max_archive_member_bytes,
                  limits.max_archive_uncompressed_bytes):
        if type(value) is not int or value < 0:
            raise OpenCodeRejected('LIMIT_INVALID')


@contextmanager
def _source_files(path):
    with directory_anchor(path.parent) as parent, ExitStack() as stack:
        total = 0
        for suffix in ('', '-wal', '-shm', '-journal'):
            try:
                metadata = os.stat(path.name + suffix, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                if suffix:
                    continue
                raise
            if not stat.S_ISREG(metadata.st_mode):
                raise SourceDenied('SOURCE_NOT_REGULAR')
            total += metadata.st_size
            if total > 512 * 1024 * 1024:
                raise OpenCodeRejected('SOURCE_SIZE_LIMIT')
            fd = os.open(path.name + suffix, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
            stack.callback(os.close, fd)
            acquired = os.fstat(fd)
            if (acquired.st_ino, acquired.st_dev) != (metadata.st_ino, metadata.st_dev):
                raise SourceDenied('SOURCE_CHANGED')
        yield


def _json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError
            result[key] = item
        return result

    def invalid(value):
        raise ValueError

    try:
        data = json.loads(value, object_pairs_hook=pairs, parse_constant=invalid)
        if not isinstance(data, dict):
            raise TypeError
        pending, count = [(data, 0)], 0
        while pending:
            item, depth = pending.pop()
            count += 1
            if depth > 64 or count > 100_000:
                raise OpenCodeRejected('OPENCODE_JSON_LIMIT')
            if isinstance(item, str):
                item.encode('utf-8')
            elif isinstance(item, float) and not math.isfinite(item):
                raise ValueError
            elif isinstance(item, dict):
                for key in item:
                    key.encode('utf-8')
                pending.extend((v, depth + 1) for v in item.values())
            elif isinstance(item, list):
                pending.extend((v, depth + 1) for v in item)
        return data
    except OpenCodeRejected:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise OpenCodeRejected('OPENCODE_JSON_INVALID') from None


def _row(row):
    for field, value in row.items():
        if field in {'id', 'project_id', 'session_id', 'message_id'}:
            if not isinstance(value, str) or not value or len(value.encode()) > 4096:
                raise OpenCodeRejected('OPENCODE_ROW_INVALID')
        elif field.startswith('time_'):
            if type(value) is not int:
                raise OpenCodeRejected('OPENCODE_ROW_INVALID')
        elif field == 'data':
            if not isinstance(value, str):
                raise OpenCodeRejected('OPENCODE_ROW_INVALID')
        elif not isinstance(value, (str, type(None))):
            raise OpenCodeRejected('OPENCODE_ROW_INVALID')


def _part(data):
    kind = data.get('type')
    if not isinstance(kind, str):
        raise OpenCodeRejected('OPENCODE_PART_INVALID')
    if kind in {'text', 'reasoning'} and not isinstance(data.get('text', ''), str):
        raise OpenCodeRejected('OPENCODE_PART_INVALID')
    if kind == 'file' and not isinstance(data.get('url', ''), str):
        raise OpenCodeRejected('OPENCODE_PART_INVALID')
    if kind == 'tool':
        state = data.get('state', {})
        if not isinstance(state, dict) or any(
            not isinstance(data.get(key), (str, type(None))) for key in ('callID', 'tool')
        ) or any(not isinstance(state.get(key, ''), str) for key in ('status', 'output', 'error')):
            raise OpenCodeRejected('OPENCODE_PART_INVALID')
        attached = state.get('attachments', [])
        if not isinstance(attached, list) or any(
            not isinstance(item, dict) or not isinstance(item.get('url'), str) for item in attached
        ):
            raise OpenCodeRejected('OPENCODE_PART_INVALID')


def _validate(tables):
    indexed = {}
    for name, rows in tables.items():
        index = {}
        for row in rows:
            _row(row)
            if row['id'] in index:
                raise OpenCodeRejected('OPENCODE_ID_DUPLICATE')
            index[row['id']] = row
            if 'data' in row:
                data = _json(row['data'])
                if name == 'part':
                    _part(data)
        indexed[name] = index
    for session in tables['session']:
        if session['project_id'] not in indexed['project']:
            raise OpenCodeRejected('OPENCODE_RELATION_INVALID')
    for message in tables['message']:
        if message['session_id'] not in indexed['session']:
            raise OpenCodeRejected('OPENCODE_RELATION_INVALID')
    for part in tables['part']:
        message = indexed['message'].get(part['message_id'])
        if message is None or message['session_id'] != part['session_id']:
            raise OpenCodeRejected('OPENCODE_RELATION_INVALID')


def _snapshot(path, limits):
    """Private worker helper; never use in a process with writable SQLite handles."""
    deadline = time.monotonic() + _READ_SECONDS
    with _source_files(path), ExitStack() as stack:
        connection = sqlite3.connect(path.as_uri() + '?mode=ro&readonly_shm=1', uri=True, timeout=1)
        stack.callback(connection.close)
        stack.callback(connection.rollback)
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _ROW_CAP)
        connection.execute('PRAGMA query_only=ON')
        if connection.execute('PRAGMA query_only').fetchone() != (1,):
            raise SourceDenied('SOURCE_NOT_READONLY')
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA temp_store=MEMORY')
        connection.execute('PRAGMA cache_size=-2048')
        connection.execute('BEGIN')
        tables, total = {}, 0
        cap = min(limits.max_archive_members, 100_000)
        for table, columns in _COLUMNS.items():
            schema = connection.execute('SELECT type, sql FROM sqlite_schema WHERE name=?',
                                        (table,)).fetchone()
            if (not schema or schema[0] != 'table' or schema[1] is None
                    or 'VIRTUAL' in schema[1].upper().split()[:3]):
                raise OpenCodeRejected('OPENCODE_SCHEMA_UNSUPPORTED')
            actual = {row[1]: row[6] for row in connection.execute(f'PRAGMA table_xinfo("{table}")')}
            if not set(columns) <= actual.keys() or any(actual[c] for c in columns):
                raise OpenCodeRejected('OPENCODE_SCHEMA_UNSUPPORTED')
            selected = ', '.join(f'"{table}"."{column}"' for column in columns)
            cursor = connection.execute(f'SELECT {selected} FROM "{table}" LIMIT ?', (cap + 1,))
            rows = []
            for values in cursor:
                if time.monotonic() >= deadline:
                    raise OpenCodeRejected('SOURCE_READ_TIMEOUT')
                if len(rows) == cap:
                    raise OpenCodeRejected('SOURCE_RECORD_LIMIT')
                row = dict(zip(columns, values, strict=True))
                _row(row)
                size = len(canonical(row))
                if size > min(limits.max_archive_member_bytes, _ROW_CAP):
                    raise OpenCodeRejected('SOURCE_ROW_SIZE_LIMIT')
                total += size
                if total > min(limits.max_archive_uncompressed_bytes, _TOTAL_CAP):
                    raise OpenCodeRejected('SOURCE_SIZE_LIMIT')
                rows.append(row)
            tables[table] = rows
        return tables


def _read_worker(pipe, path, limits):
    # Only bounded data goes into IPC, never stderr/stdout/logs or a DB backup.
    try:
        try:
            result = {'tables': _snapshot(path, limits)}
        except SourceDenied as error:
            result = {'denied': str(error)}
        except OpenCodeRejected as error:
            result = {'error': str(error)}
        except sqlite3.Error as error:
            code = getattr(error, 'sqlite_errorcode', None)
            result = {'error': 'SOURCE_ROW_SIZE_LIMIT' if code == sqlite3.SQLITE_TOOBIG else
                      'SOURCE_READ_TIMEOUT' if code == sqlite3.SQLITE_INTERRUPT else
                      'OPENCODE_SOURCE_INVALID'}
        except (OSError, ValueError, TypeError, OverflowError, RecursionError):
            result = {'error': 'OPENCODE_SOURCE_INVALID'}
        pipe.send_bytes(canonical(result))
    finally:
        pipe.close()


def _receive_frame(reader, deadline):
    """POSIX Connection.send_bytes framing, with bounded nonblocking reads.

    poll()/recv_bytes() is not a timed receive: readiness may be only one header
    byte. Recheck the same deadline for every header/body chunk, including a
    continuously readable/trickled body. Never allocate the announced length
    before checking the cap. No auxiliary reader process or thread is needed.
    """
    fd = reader.fileno()
    os.set_blocking(fd, False)
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)

        def exact(size):
            data = bytearray()
            while len(data) < size:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise OpenCodeRejected('SOURCE_READ_TIMEOUT')
                try:
                    chunk = os.read(fd, min(size - len(data), 64 * 1024))
                except BlockingIOError:
                    continue
                if not chunk:
                    raise EOFError
                data.extend(chunk)
            return data

        size, = struct.unpack('!i', exact(4))
        if size == -1:
            size, = struct.unpack('!Q', exact(8))
        if not 0 <= size <= _TOTAL_CAP + 1024 * 1024:
            raise ValueError
        payload = exact(size)
        if time.monotonic() >= deadline:
            raise OpenCodeRejected('SOURCE_READ_TIMEOUT')
        return payload


def _reap_reader(process, deadline):
    """Never extend the operation budget or discard a possibly live child."""
    if process.pid is not None:
        try:
            process.join(timeout=min(0.05, max(0, deadline - time.monotonic()) / 4))
            if process.exitcode is None:
                process.terminate()
                process.join(timeout=min(0.1, max(0, deadline - time.monotonic()) / 2))
            if process.exitcode is None:
                process.kill()
                process.join(timeout=max(0, deadline - time.monotonic()))
        finally:
            if process.exitcode is None:
                error = OpenCodeRejected('SOURCE_READER_UNREAPED')
                error.process = process
                raise error from None
    process.close()
    _READERS.discard(process)


def _isolated_snapshot(path, limits):
    deadline = time.monotonic() + _WORKER_SECONDS
    if _WORKER_SECONDS <= 0:
        raise OpenCodeRejected('SOURCE_READ_TIMEOUT')
    # Reserve cleanup *inside* the one overall budget, not after a 35s receive.
    receive_deadline = deadline - min(1.0, _WORKER_SECONDS / 5)
    context = multiprocessing.get_context('spawn')
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_read_worker, args=(writer, path, limits), daemon=True)
    _READERS.add(process)
    try:
        process.start()
        writer.close()
        try:
            result = json.loads(_receive_frame(reader, receive_deadline))
        except OpenCodeRejected:
            raise
        except (EOFError, OSError, ValueError):
            raise OpenCodeRejected('OPENCODE_SOURCE_INVALID') from None
        if time.monotonic() >= receive_deadline:
            raise OpenCodeRejected('SOURCE_READ_TIMEOUT')
        if 'denied' in result:
            raise SourceDenied(result['denied'])
        if 'error' in result:
            raise OpenCodeRejected(result['error'])
        return result['tables']
    finally:
        writer.close()
        reader.close()
        _reap_reader(process, deadline)


def _project(raw, identity, limits, seq):
    text, parts, attachments, warnings = [], [], {}, []

    def extract(value):
        extracted = extract_content(value, limits=limits)
        parts.extend(extracted.parts)
        attachments.update((a.sha256, a) for a in extracted.attachments)
        warnings.extend(extracted.warnings)
        return extracted.content

    def file_url(url):
        if url.lower().startswith('data:'):
            extract(url)
        else:
            warnings.append('ATTACHMENT_REFERENCE_UNREAD')

    for part in raw['parts']:
        data = json.loads(part['data'])
        kind = data.get('type')
        if kind == 'text':
            text.append(extract(data.get('text', '')))
        elif kind == 'reasoning':
            parts.append(Part(kind='reasoning', text=extract(data.get('text', ''))))
        elif kind == 'tool':
            state = data.get('state', {})
            arguments = extract(canonical(state.get('input')).decode())
            link = {'call_id': data.get('callID'), 'name': data.get('tool')}
            parts.append(Part(kind='tool_call', arguments_json=arguments, **link))
            if state.get('status') in {'completed', 'error'}:
                field = 'error' if state['status'] == 'error' else 'output'
                parts.append(Part(kind='tool_result', text=extract(state.get(field, '')), **link))
            elif state.get('status') not in {'pending', 'running'}:
                warnings.append('TOOL_STATE_UNKNOWN')
            for attached in state.get('attachments', []):
                file_url(attached['url'])
        elif kind == 'file':
            file_url(data.get('url', ''))
        else:
            warnings.append('PART_UNSUPPORTED')
    message = raw['message']
    role = json.loads(message['data']).get('role')
    if not isinstance(role, (str, type(None))):
        role = None
        warnings.append('ROLE_INVALID')
    parsed = record(raw=raw, identity=identity, session=raw['session']['id'],
                    native_id=message['id'], seq=seq, ts=message['time_created'] / 1000,
                    native_role=role, text='\n'.join(text), limits=limits,
                    parts=parts, warnings=warnings)
    attachments.update((a.sha256, a) for a in parsed.attachments)
    return replace(parsed, attachments=tuple(attachments.values()))


def parse_opencode(db_path: Path, *, identity: SourceIdentity,
                   limits: ParseLimits) -> Iterator[ParsedRecord]:
    """Yield selected message records; reject malformed input before first yield."""
    _limits(limits)
    path = checked_path(db_path)
    if path.name != 'opencode.db':
        raise SourceDenied('SOURCE_NOT_ALLOWLISTED')
    try:
        with _source_files(path):
            tables = _isolated_snapshot(path, limits)
    except OSError:
        raise OpenCodeRejected('OPENCODE_SOURCE_INVALID') from None
    _validate(tables)
    sessions = {row['id']: row for row in tables['session']}
    projects = {row['id']: row for row in tables['project']}
    parts = defaultdict(list)
    for part in sorted(tables['part'], key=lambda p: (p['time_created'], p['id'])):
        parts[part['message_id']].append(part)
    sequences = defaultdict(int)
    for message in sorted(tables['message'], key=lambda m: (m['session_id'], m['time_created'], m['id'])):
        session = sessions[message['session_id']]
        raw = {'session': session, 'project': projects[session['project_id']],
               'message': message, 'parts': parts[message['id']]}
        seq = sequences[session['id']]
        sequences[session['id']] += 1
        yield _project(raw, identity, limits, seq)
