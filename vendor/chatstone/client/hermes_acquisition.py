"""Explicit protected Hermes acquisition and replay under the existing Spool lock.

One sibling retains failed input; validated rows use crash-atomic spool admission.
Only completed positive delivery permits retirement. Trusted single-owner
storage is required: checksums detect damage, not hostile same-UID rewrites.
"""
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import struct
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from chatstone.collectors.normalization import canonical
from chatstone.collectors.policy import SourceDenied, checked_path, directory_anchor

_POLICY = {'capture_bytes': 2 * 1024**3, 'selected_bytes': 1536 * 1024**2,
           'metadata_bytes': 128 * 1024**2, 'active_seconds': 600.0,
           'age_seconds': 86400.0, 'slice_rows': 4096, 'slice_bytes': 64 * 1024**2,
           'slice_seconds': 10.0, 'row_bytes': 250_000_000}
_NAMES = {'state.json', 'state.next', 'snapshot.sqlite3', 'snapshot.sqlite3-journal',
          'manifest.sqlite3', 'manifest.sqlite3-journal', 'selected.bin'}
_ZERO = '00' * 32


def _deny(code='ACQUISITION_CORRUPT'):
    # Even an active caller handler attaches context on raise. Clear the actual
    # slots after raising, then bare-reraise so no private chain is reattached.
    try:
        raise SourceDenied(code) from None
    except SourceDenied as error:
        error.__context__ = None
        error.__cause__ = None
        raise


def _file(path, mode=None):
    with directory_anchor(path.parent) as parent:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    modes = mode if isinstance(mode, tuple) else (mode,)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
            or (mode is not None and stat.S_IMODE(info.st_mode) not in modes)
            or info.st_mode & 0o022):
        _deny('ACQUISITION_UNSAFE')
    return {'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size,
            'mtime': info.st_mtime_ns, 'ctime': info.st_ctime_ns}


def _source(path):
    info = _file(checked_path(path))
    for suffix in ('-wal', '-shm', '-journal'):
        side = path.with_name(path.name + suffix)
        try:
            _file(side)
        except FileNotFoundError:
            pass
    return info


@contextmanager
def _open(path, flags=os.O_RDONLY, mode=0o600):
    with directory_anchor(path.parent) as parent:
        fd = os.open(path.name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)):
                _deny('ACQUISITION_UNSAFE')
            with os.fdopen(fd, 'r+b' if flags & (os.O_RDWR | os.O_WRONLY) else 'rb',
                           closefd=False) as stream:
                yield stream
        finally:
            os.close(fd)


def _directory(path):
    with directory_anchor(path) as fd:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            _deny('ACQUISITION_UNSAFE')
        if set(os.listdir(fd)) - _NAMES:
            _deny('ACQUISITION_UNSAFE')
        for name in os.listdir(fd):
            # A failed copy remains private/writable for explicit disposition.
            # Clean finalized checkpoints independently require exactly 0400.
            _file(path / name, (0o400, 0o600) if name == 'snapshot.sqlite3' else 0o600)


def _syncdir(path):
    with directory_anchor(path) as fd:
        os.fsync(fd)


def _save(path, state):
    data = canonical({'state': state, 'sha256': hashlib.sha256(canonical(state)).hexdigest()})
    if len(data) > 16384:
        _deny('ACQUISITION_METADATA_LIMIT')
    with _open(path / 'state.next', os.O_RDWR | os.O_CREAT | os.O_EXCL) as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(path / 'state.next', path / 'state.json')
    _syncdir(path)


def _fail(path, state, error):
    """Attempt one terminal record, never retry work or repair a partial save.

    A failed terminal write leaves persistence uncertain, even if an older
    checkpoint is readable. The caller must stop; storage may be unable to
    retain that fact for a fresh process. No durable FAILED claim is made then.
    """
    from chatstone.collectors.hermes_reader import ReaderUnreaped

    ordinary = (OSError, sqlite3.Error, SourceDenied)
    translate = isinstance(error, ordinary) and not isinstance(error, ReaderUnreaped)
    code = (str(error) if isinstance(error, SourceDenied) and
            re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', str(error)) else 'ACQUISITION_STEP_FAILED')
    state.update(phase='FAILED', error=code, inflight=True, settlement=None)
    try:
        _save(path, state)
        # Preparation also created this directory. Its entry must be durable
        # before a terminal-persistence acknowledgement, not just state.json.
        _syncdir(path.parent)
    except BaseException as secondary:
        code = 'ACQUISITION_PERSISTENCE_UNCERTAIN'
        # The first cancellation, unexpected exception or process owner wins.
        # An ordinary I/O primary cannot swallow a new cancellation/owner.
        if translate and (not isinstance(secondary, ordinary) or isinstance(secondary, ReaderUnreaped)):
            secondary.add_note(code)
            raise
    if translate:
        _deny(code)
    # Cancellation, unexpected exceptions and the exact unreaped-process owner
    # are re-raised by the caller, never replaced by a generic SourceDenied.
    if code == 'ACQUISITION_PERSISTENCE_UNCERTAIN':
        error.add_note(code)


def _load(path):
    _directory(path)
    with _open(path / 'state.json') as stream:
        data = stream.read(16385)
    if len(data) > 16384:
        _deny()
    try:
        envelope = json.loads(data)
        state = envelope['state']
        if envelope['sha256'] != hashlib.sha256(canonical(state)).hexdigest() or state['version'] != 1:
            _deny()
    except (ValueError, KeyError, TypeError):
        _deny()
    return state


def _headroom(path, state):
    # Reserve remaining acquisition allocation plus the existing spool's DB and
    # rollback-journal allowance and 64 MiB filesystem slack. No preallocation
    # claim: other filesystem users can consume space; recheck each phase.
    present = sum((path / n).lstat().st_size for n in os.listdir(path))
    p = state['policy']
    needed = max(0, p['capture_bytes'] + p['selected_bytes'] + p['metadata_bytes'] - present)
    if shutil.disk_usage(path).free < needed + state['spool_reserve'] + 64 * 1024**2:
        _deny('ACQUISITION_DISK_LIMIT')
    metadata = sum((path / n).lstat().st_size for n in os.listdir(path)
                   if n not in ('snapshot.sqlite3', 'selected.bin'))
    if metadata > p['metadata_bytes']:
        _deny('ACQUISITION_METADATA_LIMIT')


def _ro(path, deadline):
    connection = sqlite3.connect(path.as_uri() + '?mode=ro&vfs=unix&readonly_shm=1',
                                 uri=True, timeout=1.0)
    connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    connection.execute('PRAGMA query_only=ON')
    if connection.execute('PRAGMA query_only').fetchone() != (1,):
        connection.close()
        _deny('SOURCE_NOT_READONLY')
    connection.execute('PRAGMA trusted_schema=OFF')
    connection.execute('PRAGMA temp_store=MEMORY')
    connection.execute('PRAGMA cache_size=-2048')
    connection.execute('BEGIN')
    return connection


def _checktime(deadline):
    if time.monotonic() >= deadline:
        _deny('SOURCE_READ_TIMEOUT')


def _capture(path, state, deadline):
    source = Path(state['binding']['source_path'])
    before = _source(source)
    if (before['device'], before['inode']) != (state['binding']['source_device'],
                                               state['binding']['source_inode']):
        _deny('ACQUISITION_BINDING_MISMATCH')
    target = path / 'snapshot.sqlite3'
    with _open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL):
        pass
    connection = dest = None
    try:
        connection = _ro(source, deadline)
        count = connection.execute('SELECT COUNT(*) FROM messages').fetchone()[0]
        pages = connection.execute('PRAGMA page_count').fetchone()[0]
        page_size = connection.execute('PRAGMA page_size').fetchone()[0]
        if pages * page_size > state['policy']['capture_bytes']:
            _deny('ACQUISITION_CAPTURE_LIMIT')
        dest = sqlite3.connect(target, timeout=1.0)
        dest.execute('PRAGMA journal_mode=OFF')

        def progress(status, remaining, total):
            _checktime(deadline)
            if total * page_size > state['policy']['capture_bytes']:
                _deny('ACQUISITION_CAPTURE_LIMIT')
            _headroom(path, state)

        connection.backup(dest, pages=1024, progress=progress, sleep=0.01)
        if dest.execute('PRAGMA journal_mode=DELETE').fetchone() != ('delete',):
            _deny()
    finally:
        if dest is not None:
            dest.close()
        if connection is not None:
            connection.rollback()
            connection.close()
    digest = hashlib.sha256()
    with _open(target, os.O_RDWR) as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
            _checktime(deadline)
        stream.flush()
        os.fchmod(stream.fileno(), 0o400)
        os.fsync(stream.fileno())
    _syncdir(path)
    _checktime(deadline)
    return {'phase': 'CAPTURED', 'total': count, 'snapshot_hash': digest.hexdigest(),
            'files': {'snapshot.sqlite3': _file(target, 0o400)}}


def _perform_step(path, state, deadline):
    _directory(path)
    _headroom(path, state)
    if state['phase'] == 'PREPARING':
        return _capture(path, state, deadline)
    if state['phase'] == 'CAPTURED':
        return _order(path, state, deadline)
    if state['phase'] in ('ORDERED', 'ACQUIRING'):
        return _acquire(path, state, deadline)
    if state['phase'] == 'VALIDATING':
        return _validate(path, state, deadline)
    _deny('ACQUISITION_PHASE')


class Acquisition:
    """A single explicit epoch, used only while its existing Spool stays open."""

    @staticmethod
    def _settle(state):
        # A successful final checkpoint still retains its FULL allowance.
        # Only a later call can know it returned durably. Charge elapsed wall
        # and monotonic time through now (including idle, conservatively).
        # Clock rollback/reboot never earns a refund. In-flight failure never
        # reaches settlement. This bounds crash renewal without pretending a
        # final fsync costs a preselected millisecond allowance.
        previous = state.get('settlement')
        if previous:
            wall = time.time() - previous['wall']
            mono = time.monotonic() - previous['mono']
            used = 35.0 if min(wall, mono) < 0 else min(35.0, max(wall, mono, previous['minimum']))
            state['spent'] -= 35.0 - used
            state['settlement'] = None

    def __init__(self, spool, source):
        self.spool, self.source = spool, checked_path(Path(source))
        self.path = spool.path.with_name(spool.path.name + '.acquisition')
        self._guard()

    def _binding(self):
        if self.spool._lock is None or self.spool._db is None:
            _deny('ACQUISITION_LOCK_REQUIRED')
        lock = os.fstat(self.spool._lock)
        current = (self.spool.path / '.lock').lstat()
        if (lock.st_dev, lock.st_ino) != (current.st_dev, current.st_ino):
            _deny('ACQUISITION_LOCK_REQUIRED')
        row = self.spool._db.execute('SELECT install,source,host,destination,version '
                                     'FROM identity WHERE id=1').fetchone()
        if row != (self.spool.install_id, self.spool.source, self.spool.host,
                   self.spool.destination, 2) or row[1] != 'hermes':
            _deny('ACQUISITION_BINDING_MISMATCH')
        source = _source(self.source)
        return {'source_path': str(self.source), 'source_device': source['device'],
                'source_inode': source['inode'], 'install': row[0], 'source': row[1],
                'host': row[2], 'destination': row[3]}

    def _guard(self):
        state = _load(self.path)
        if state['binding'] != self._binding():
            _deny('ACQUISITION_BINDING_MISMATCH')
        # Interrupted/failed work can have an owned, uncommitted tail. Retain
        # it without repair; only finalized clean phases require exact extents.
        if state['inflight'] and state['phase'] != 'REPLAYING':
            return state
        if state['phase'] in ('RETIRING', 'RETIRED'):
            return state
        for name, receipt in state['files'].items():
            if name not in ('snapshot.sqlite3', 'manifest.sqlite3', 'selected.bin'):
                _deny()
            if _file(self.path / name, 0o400 if name == 'snapshot.sqlite3' else 0o600) != receipt:
                _deny('ACQUISITION_FILE_CHANGED')
        return state

    @classmethod
    def prepare(cls, spool, source):
        started, wall = time.monotonic(), time.time()
        obj = cls.__new__(cls)
        obj.spool, obj.source = spool, checked_path(Path(source))
        obj.path = spool.path.with_name(spool.path.name + '.acquisition')
        binding = obj._binding()
        with directory_anchor(obj.path.parent):
            try:
                obj.path.mkdir(mode=0o700)
            except FileExistsError:
                try:
                    old = obj._guard()
                except (OSError, SourceDenied):
                    raise FileExistsError from None
                if old['phase'] != 'RETIRED' or set(os.listdir(obj.path)) != {'state.json'}:
                    raise FileExistsError
                binding_old = {k: old['binding'][k] for k in
                               ('source_path', 'source_device', 'source_inode')}
                binding_old['seal'] = old['seal']
                complete = spool.epoch_status(old['epoch_id'], binding=binding_old)
                if not complete['complete'] or spool.status()['pending']:
                    _deny('ACQUISITION_UNRESOLVED')
        pages = spool._db.execute('PRAGMA max_page_count').fetchone()[0]
        state = {'version': 1, 'epoch_id': str(uuid4()), 'phase': 'PREPARING',
                 'binding': binding, 'created': time.time(), 'spent': 35.0, 'inflight': True,
                 'policy': dict(_POLICY), 'spool_reserve': pages * 4096 * 3 + 8192,
                 'files': {}, 'total': None, 'next_ordinal': 0, 'selected_bytes': 0,
                 'validated': 0, 'error': None}
        try:
            _save(obj.path, state)
            _headroom(obj.path, state)
            state.update(inflight=False, settlement={'wall': wall, 'mono': started,
                                                    'minimum': time.monotonic() - started})
            _save(obj.path, state)
            _syncdir(obj.path.parent)
        except BaseException as error:
            _fail(obj.path, state, error)
            raise
        return obj

    def status(self):
        """Read-only metadata and binding check. Does not scan selected payloads."""
        state = self._guard()
        phase, error = state['phase'], state['error']
        if phase != 'FAILED' and ((state['inflight'] and phase != 'REPLAYING')
                                  or (self.path / 'state.next').exists()):
            phase, error = 'FAILED', 'ACQUISITION_INTERRUPTED'
        elif (phase not in ('RETIRING', 'RETIRED')
              and time.time() - state['created'] >= state['policy']['age_seconds']):
            phase, error = 'EXPIRED', 'ACQUISITION_EXPIRED'
        return {k: state[k] for k in ('epoch_id', 'total', 'next_ordinal', 'selected_bytes',
                                      'validated', 'spent')} | {'phase': phase, 'error': error}

    def sealed_descriptor(self):
        """Validated storage descriptor, NOT rows or a delivery authorization.

        Current source/spool binding and file identity/extents/timestamps are
        checked now. Actual payloads were hashed during bounded validation.
        A future replay adapter must recheck each stored digest before exposing
        a row and charge its complete work to this same epoch budget.
        """
        state = self._guard()
        if self.status()['phase'] not in ('SEALED', 'REPLAYING'):
            _deny('ACQUISITION_NOT_SEALED')
        binding = {k: state['binding'][k] for k in
                   ('source_path', 'source_device', 'source_inode')}
        binding['seal'] = state['seal']
        return {'epoch_id': state['epoch_id'], 'binding': binding, 'total': state['total'],
                'selected_bytes': state['selected_bytes'], 'files': state['files']}

    def advance(self, *, rows=4096):
        """One finite phase; no row exposure. Failure retains the entire sibling."""
        from chatstone.collectors.hermes_reader import acquisition_step

        started, wall = time.monotonic(), time.time()
        state = self._guard()
        if type(rows) is not int or not 1 <= rows <= state['policy']['slice_rows']:
            _deny('ACQUISITION_REQUEST')
        if self.status()['phase'] in ('FAILED', 'EXPIRED'):
            _deny(self.status()['error'] or 'ACQUISITION_FAILED')
        if state['phase'] == 'SEALED':
            return self.status()
        self._settle(state)
        try:
            if state['spent'] + 35.0 > state['policy']['active_seconds']:
                state.update(phase='EXPIRED', error='ACQUISITION_BUDGET')
                _save(self.path, state)
            else:
                state.update(spent=state['spent'] + 35.0, inflight=True)
                _save(self.path, state)  # Must return durably before native work.
                _headroom(self.path, state)
                work = dict(state, step_rows=rows)
                result = acquisition_step(self.path, work, deadline=started + 34.0)
                _checktime(started + 34.0)
                if state['binding'] != self._binding():
                    _deny('ACQUISITION_BINDING_MISMATCH')
                state.update(result)
                state.update(inflight=False, settlement={'wall': wall, 'mono': started,
                                                         'minimum': time.monotonic() - started})
                _save(self.path, state)
                _checktime(started + 35.0)
        except BaseException as error:
            _fail(self.path, state, error)
            raise
        if state['phase'] == 'EXPIRED':
            _deny('ACQUISITION_BUDGET')
        return self.status()


    def replay(self, *, rows=4096):
        """Bounded validated replay; the existing spool owns the durable ordinal.

        A process lost during replay may reopen from that transaction's ordinal;
        it does not mutate captured files or repeat a source acquisition. Partial
        state.next/error persistence remains a visible stop, never repaired here.
        """
        from chatstone.collectors.contracts import ParseLimits, SourceIdentity
        from chatstone.collectors.hermes import _parts
        from chatstone.collectors.normalization import record

        started, wall = time.monotonic(), time.time()
        descriptor = self.sealed_descriptor()
        state = self._guard()
        if type(rows) is not int or not 1 <= rows <= state['policy']['slice_rows']:
            _deny('ACQUISITION_REQUEST')
        self._settle(state)
        if state['spent'] + 35.0 > state['policy']['active_seconds']:
            _deny('ACQUISITION_BUDGET')
        state.update(phase='REPLAYING', spent=state['spent'] + 35.0,
                     inflight=True, settlement=None)
        _save(self.path, state)
        deadline = started + 34.0
        limits = ParseLimits()
        identity = SourceIdentity('hermes', self.spool.host)
        warnings = {}

        def normalize(raw, seq):
            parts, codes = _parts(raw, limits)
            tool_result = (raw['tool_call_id'], raw['tool_name']) if raw['role'] == 'tool' else None
            parsed = record(raw=raw, identity=identity, session=raw['session_id'],
                            native_id=str(raw['id']), seq=seq, ts=raw['timestamp'],
                            native_role=raw['role'], text=raw['content'] or '', limits=limits,
                            native_source=raw['native_source'], parts=parts, warnings=codes,
                            tool_result=tool_result)
            for code in parsed.message.warnings:
                warnings[code] = warnings.get(code, 0) + 1
            return parsed

        manifest = None
        try:
            position = self.spool.begin_epoch(descriptor['epoch_id'],
                                             binding=descriptor['binding'], total=descriptor['total'])
            start = position['next_ordinal']
            manifest = _ro(self.path / 'manifest.sqlite3', deadline)
            selected_rows = manifest.execute('SELECT ordinal,offset,size,digest FROM rows '
                                             'WHERE ordinal>=? ORDER BY ordinal LIMIT ?',
                                             (start, rows))

            def selected():
                with _open(self.path / 'selected.bin') as stream:
                    for expected, (ordinal, offset, size, digest) in enumerate(selected_rows, start):
                        if ordinal != expected or not 0 < size <= state['policy']['row_bytes']:
                            _deny('ACQUISITION_MANIFEST_INVALID')
                        stream.seek(offset)
                        if stream.read(4) != struct.pack('!I', size):
                            _deny('ACQUISITION_PAYLOAD_INVALID')
                        data = stream.read(size)
                        if len(data) != size or hashlib.sha256(data).digest() != digest:
                            _deny('ACQUISITION_PAYLOAD_INVALID')
                        raw = _raw(data)
                        _checktime(deadline)
                        yield raw['session_id'], raw

            iterator = selected()
            try:
                result = self.spool.admit_epoch(descriptor['epoch_id'], binding=descriptor['binding'],
                                                start=start, rows=iterator, normalize=normalize)
            finally:
                iterator.close()
            _checktime(deadline)
            if state['binding'] != self._binding():
                _deny('ACQUISITION_BINDING_MISMATCH')
            state.update(inflight=False, settlement={'wall': wall, 'mono': started,
                                                     'minimum': time.monotonic() - started})
            _save(self.path, state)
            _checktime(started + 35.0)
            return result | {'warnings': warnings}
        except BaseException as error:
            _fail(self.path, state, error)
            raise
        finally:
            if manifest is not None:
                manifest.close()

    def retire(self):
        """Remove only successfully admitted AND positively delivered originals.

        A small RETIRED state remains for crash-safe reuse. A RETIRING marker is
        durable before unlinking, so interrupted cleanup can finish idempotently.
        """
        state = self._guard()
        if self.status()['phase'] not in ('SEALED', 'REPLAYING', 'RETIRING', 'RETIRED'):
            _deny('ACQUISITION_NOT_SEALED')
        binding = {k: state['binding'][k] for k in
                   ('source_path', 'source_device', 'source_inode')}
        binding['seal'] = state['seal']
        position = self.spool.epoch_status(state['epoch_id'], binding=binding)
        queue = self.spool.status()
        if (not position['complete'] or queue['pending'] or queue['errors']
                or queue['rejected'] or queue['retryable']):
            _deny('ACQUISITION_UNRESOLVED')
        state.update(phase='RETIRING', inflight=False, settlement=None)
        _save(self.path, state)
        with directory_anchor(self.path) as fd:
            for name in ('snapshot.sqlite3', 'manifest.sqlite3', 'selected.bin'):
                try:
                    _file(self.path / name)
                    os.unlink(name, dir_fd=fd)
                except FileNotFoundError:
                    pass
            os.fsync(fd)
        state.update(phase='RETIRED', files={})
        _save(self.path, state)
        return self.status()


def _chain(previous, data):
    return hashlib.sha256(bytes.fromhex(previous) + data).hexdigest()


def _metadata(path, state, *, create=False):
    target = path / 'manifest.sqlite3'
    if create:
        with _open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL):
            pass
    else:
        _file(target, 0o600)
    con = sqlite3.connect(target, timeout=0)
    con.execute('PRAGMA journal_mode=DELETE')
    con.execute('PRAGMA synchronous=FULL')
    con.execute('PRAGMA trusted_schema=OFF')
    con.execute('PRAGMA temp_store=MEMORY')
    con.execute('PRAGMA cache_size=-2048')
    pages = (state['policy']['metadata_bytes'] - 32768) // (4096 * 3)
    if pages < 4 or con.execute('PRAGMA page_size').fetchone() != (4096,):
        con.close()
        _deny('ACQUISITION_METADATA_LIMIT')
    if con.execute('PRAGMA page_count').fetchone()[0] > pages:
        con.close()
        _deny('ACQUISITION_METADATA_LIMIT')
    con.execute(f'PRAGMA max_page_count={pages}')
    return con


def _syncfile(path):
    with _open(path) as stream:
        os.fsync(stream.fileno())


def _order(path, state, deadline):
    from chatstone.collectors.hermes import _ordered_locators

    source = manifest = None
    chain, count = _ZERO, 0
    try:
        source = _ro(path / 'snapshot.sqlite3', deadline)
        manifest = _metadata(path, state, create=True)
        manifest.execute('CREATE TABLE rows(ordinal INTEGER PRIMARY KEY, '
                         'locator INTEGER NOT NULL UNIQUE, offset INTEGER, size INTEGER, digest BLOB)')
        for (locator,) in _ordered_locators(source):
            if type(locator) is not int or count >= state['total']:
                _deny('ACQUISITION_LOCATOR_INVALID')
            manifest.execute('INSERT INTO rows(ordinal,locator) VALUES (?,?)', (count, locator))
            chain = _chain(chain, struct.pack('!Qq', count, locator))
            count += 1
            _checktime(deadline)
        if count != state['total']:
            _deny('ACQUISITION_LOCATOR_MISSING')
        manifest.commit()
    finally:
        if source is not None:
            source.close()
        if manifest is not None:
            manifest.close()
    _syncfile(path / 'manifest.sqlite3')
    with _open(path / 'selected.bin', os.O_RDWR | os.O_CREAT | os.O_EXCL) as selected:
        os.fsync(selected.fileno())
    _syncdir(path)
    _headroom(path, state)
    _checktime(deadline)
    return {'phase': 'ORDERED', 'manifest_hash': chain,
            'files': state['files'] | {'manifest.sqlite3': _file(path / 'manifest.sqlite3', 0o600),
                                      'selected.bin': _file(path / 'selected.bin', 0o600)}}


def _raw(data):
    from chatstone.collectors.hermes import (
        _DISPLAY_KINDS,
        _FIELDS,
        _INPUT_FIELDS,
        _locator,
        _valid_native_input,
    )
    from chatstone.collectors.hermes_reader import _decode

    raw = _decode(data)
    required = {*_FIELDS, 'native_source'}
    if not required <= raw.keys() <= required | {*_INPUT_FIELDS, 'native_input'}:
        _deny('HERMES_SOURCE_INVALID')
    if (('_compressed_summary' in raw and type(raw['_compressed_summary']) is not bool)
            or ('display_kind' in raw and (not isinstance(raw['display_kind'], str)
                                          or raw['display_kind'] not in _DISPLAY_KINDS))
            or ('platform_message_id' in raw and not _locator(raw['platform_message_id']))
            or ('native_input' in raw and not _valid_native_input(raw['native_input']))):
        _deny('HERMES_SOURCE_INVALID')
    if any(type(v) not in (type(None), str, bytes, int, float) or
           (type(v) is float and not math.isfinite(v)) for k, v in raw.items() if k in required):
        _deny('HERMES_SOURCE_INVALID')
    if canonical(raw) != data:
        _deny('HERMES_SOURCE_INVALID')
    return raw


def _acquire(path, state, deadline):
    from chatstone.collectors.hermes import _frozen_rows

    started = time.monotonic()
    source = manifest = None
    next_ordinal, length = state['next_ordinal'], state['selected_bytes']
    initial = length
    try:
        source = _ro(path / 'snapshot.sqlite3', deadline)
        manifest = _metadata(path, state)
        wanted = manifest.execute('SELECT ordinal,locator FROM rows WHERE ordinal>=? '
                                  'ORDER BY ordinal LIMIT ?',
                                  (next_ordinal, state['step_rows'])).fetchall()
        expected_count = min(state['step_rows'], state['total'] - next_ordinal)
        if len(wanted) != expected_count or any(o != next_ordinal + i for i, (o, _) in enumerate(wanted)):
            _deny('ACQUISITION_LOCATOR_MISSING')
        with _open(path / 'selected.bin', os.O_RDWR) as selected:
            if selected.seek(0, os.SEEK_END) != length:
                _deny('ACQUISITION_FILE_CHANGED')
            iterator = _frozen_rows(source, (loc for _, loc in wanted), deadline)
            try:
                for locator, raw in iterator:
                    data = canonical(raw)
                    if not 0 < len(data) <= state['policy']['row_bytes']:
                        _deny('SOURCE_ROW_SIZE_LIMIT')
                    _raw(data)
                    if length + 4 + len(data) > state['policy']['selected_bytes']:
                        _deny('SOURCE_SPOOL_SIZE_LIMIT')
                    selected.write(struct.pack('!I', len(data)))
                    selected.write(data)
                    result = manifest.execute('UPDATE rows SET offset=?,size=?,digest=? '
                                              'WHERE ordinal=? AND locator=? AND offset IS NULL',
                                              (length, len(data), hashlib.sha256(data).digest(),
                                               next_ordinal, locator))
                    if result.rowcount != 1:
                        _deny('ACQUISITION_LOCATOR_INVALID')
                    next_ordinal += 1
                    length += 4 + len(data)
                    _checktime(deadline)
                    if (length - initial >= state['policy']['slice_bytes'] or
                            time.monotonic() - started >= state['policy']['slice_seconds']):
                        break
            finally:
                iterator.close()
            selected.flush()
            os.fsync(selected.fileno())
        manifest.commit()
    finally:
        if source is not None:
            source.close()
        if manifest is not None:
            manifest.close()
    _syncfile(path / 'manifest.sqlite3')
    _syncdir(path)
    _headroom(path, state)
    _checktime(deadline)
    return {'phase': 'VALIDATING' if next_ordinal == state['total'] else 'ACQUIRING',
            'next_ordinal': next_ordinal, 'selected_bytes': length,
            'validated_bytes': 0, 'validation_order': _ZERO, 'validation_payload': _ZERO,
            'files': state['files'] | {'manifest.sqlite3': _file(path / 'manifest.sqlite3', 0o600),
                                      'selected.bin': _file(path / 'selected.bin', 0o600)}}


def _validate(path, state, deadline):
    started = time.monotonic()
    count, length = state['validated'], state['validated_bytes']
    initial = length
    order, payload = state['validation_order'], state['validation_payload']
    manifest = _ro(path / 'manifest.sqlite3', deadline)
    try:
        wanted = manifest.execute('SELECT ordinal,locator,offset,size,digest FROM rows '
                                  'WHERE ordinal>=? ORDER BY ordinal LIMIT ?',
                                  (count, state['step_rows'])).fetchall()
        if len(wanted) != min(state['step_rows'], state['total'] - count):
            _deny('ACQUISITION_LOCATOR_MISSING')
        with _open(path / 'selected.bin') as selected:
            selected.seek(length)
            for ordinal, locator, offset, size, digest in wanted:
                if (ordinal != count or offset != length or type(size) is not int or
                        not 0 < size <= min(state['policy']['row_bytes'],
                                           state['selected_bytes'] - length - 4)):
                    _deny('ACQUISITION_LOCATOR_INVALID')
                if selected.read(4) != struct.pack('!I', size):
                    _deny('ACQUISITION_PAYLOAD_INVALID')
                data = selected.read(size)
                if len(data) != size or hashlib.sha256(data).digest() != digest:
                    _deny('ACQUISITION_PAYLOAD_INVALID')
                _raw(data)  # Independent pass over actual stored bytes, not hashes alone.
                order = _chain(order, struct.pack('!Qq', ordinal, locator))
                payload = _chain(payload, struct.pack('!QQI', ordinal, offset, size) + digest)
                count += 1
                length += 4 + size
                _checktime(deadline)
                if (length - initial >= state['policy']['slice_bytes'] or
                        time.monotonic() - started >= state['policy']['slice_seconds']):
                    break
            finished = count == state['total']
            if finished and (selected.read(1) or length != state['selected_bytes'] or
                             order != state['manifest_hash'] or
                             manifest.execute('SELECT COUNT(*) FROM rows').fetchone() != (count,)):
                _deny('ACQUISITION_MANIFEST_INVALID')
    finally:
        manifest.close()
    result = {'phase': 'SEALED' if finished else 'VALIDATING', 'validated': count,
              'validated_bytes': length, 'validation_order': order, 'validation_payload': payload}
    if finished:
        descriptor = {'contract': 'hermes-selected-canonical-v1', 'binding': state['binding'],
                      'epoch_id': state['epoch_id'], 'total': count, 'bytes': length,
                      'snapshot_hash': state['snapshot_hash'], 'manifest_hash': order,
                      'payload_hash': payload, 'files': state['files']}
        result['seal'] = hashlib.sha256(canonical(descriptor)).hexdigest()
    _checktime(deadline)
    return result
