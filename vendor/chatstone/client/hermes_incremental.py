"""Live read-only capture: durable new-ID cursor plus bounded rolling reconciliation.

The source has no per-message update clock. Revisit 256 surviving old rows per
successful tick, so arbitrary edits (including compaction) are eventually seen.
No deletion propagation: Chatstone retains the last captured revision.
"""
import json
from pathlib import Path

from chatstone.collectors.contracts import ParseLimits, SourceIdentity
from chatstone.collectors.hermes import _parts, incremental_rows, maximum_id
from chatstone.collectors.normalization import record

from .hermes_attachments import enrich_record
from .transport import ClientError


def _binding(path):
    path = Path(path)
    info = path.stat()
    return json.dumps([str(path), info.st_dev, info.st_ino], separators=(',', ':'))


def ready(spool):
    return spool._db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                             "AND name='hermes_position'").fetchone() is not None


def prepare(spool, path, *, initial=0):
    """Explicit preparation; preserve every seen fingerprint and pending batch."""
    with spool._transaction():
        spool._db.execute('CREATE TABLE IF NOT EXISTS hermes_position '
                          '(id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, '
                          'high INTEGER NOT NULL, sweep INTEGER NOT NULL)')
        spool._db.execute('INSERT OR IGNORE INTO hermes_position VALUES (1,?,?,0)',
                          (_binding(path), initial))
    _position(spool, path)
    prepare_fresh(spool, path)


def prepare_fresh(spool, path):
    # Additive upgrade: an existing high remains the historical cursor. The
    # fence is fixed exactly once, even when an installation is updated mid-load.
    with spool._transaction():
        spool._db.execute('CREATE TABLE IF NOT EXISTS hermes_fresh '
                          '(id INTEGER PRIMARY KEY CHECK(id=1), fence INTEGER NOT NULL, '
                          'tail INTEGER NOT NULL)')
        if not spool._db.execute('SELECT 1 FROM hermes_fresh').fetchone():
            fence = maximum_id(Path(path))
            spool._db.execute('INSERT INTO hermes_fresh VALUES (1,?,?)', (fence, fence))
        if 'fresh' not in {row[1] for row in spool._db.execute('PRAGMA table_info(pending)')}:
            spool._db.execute('ALTER TABLE pending ADD COLUMN fresh INTEGER NOT NULL DEFAULT 1')
            spool._db.execute('CREATE INDEX pending_fresh ON pending(fresh,seq)')
        spool._db.execute('CREATE TABLE IF NOT EXISTS hermes_attachment_backfill '
                          '(id INTEGER PRIMARY KEY CHECK(id=1), through_id INTEGER NOT NULL, '
                          'position INTEGER NOT NULL)')
        spool._db.execute('INSERT OR IGNORE INTO hermes_attachment_backfill '
                          'SELECT 1,fence,0 FROM hermes_fresh WHERE id=1')


def resume_completed(spool, path):
    """Switch only after a fully admitted and positively delivered backfill.

    The old acquisition metadata remains untouched, including an empty failed
    next-capture attempt. No old payload, epoch or seen identity is deleted.
    """
    durable = spool._epoch_read()
    if (durable is None or durable[2] != durable[3] or durable[4]
            or spool._db.execute('SELECT 1 FROM pending LIMIT 1').fetchone()):
        raise ClientError('EPOCH_UNRESOLVED')
    high = 0
    for (native,) in spool._db.execute('SELECT native FROM seen'):
        value = json.loads(native)[1]
        if not isinstance(value, str) or not value.isdecimal():
            raise ClientError('SOURCE_CHANGED')
        high = max(high, int(value))
    prepare(spool, path, initial=high)


def _position(spool, path):
    row = spool._db.execute('SELECT binding,high,sweep FROM hermes_position WHERE id=1').fetchone()
    if row is None or row[0] != _binding(path):
        raise ClientError('SOURCE_CHANGED')
    return row[1:]


def capture(spool, path, *, live_only=False):
    high, sweep = _position(spool, path)
    prepare_fresh(spool, path)
    fence, tail = spool._db.execute('SELECT fence,tail FROM hermes_fresh WHERE id=1').fetchone()
    limits = ParseLimits()
    identity = SourceIdentity('hermes', spool.host)
    result = {'parsed': 0, 'queued': 0, 'unchanged': 0, 'complete': False}
    # New rows always get first access to queue capacity. Both cursors commit in
    # the SAME FULL-sync transaction as payload + seen fingerprint, never before.
    modes = [('tail', tail, None, 256)]
    if not live_only:
        modes += [('high', high, fence, 256)]
        if high >= fence:
            modes += [('sweep', sweep, tail, 256)]
            through_id, position = spool._db.execute(
                'SELECT through_id,position FROM hermes_attachment_backfill WHERE id=1').fetchone()
            if position < through_id:
                modes += [('attachment', position, through_id, 1024)]
    tail_complete = False
    for mode, after, through, count in modes:
        selected = incremental_rows(Path(path), after=after, through=through, limit=count)
        visited = 0
        try:
            for raw, seq in selected:
                # Leave bounded admission capacity for next tick's live tail.
                reserve = min(256, spool.max_pending // 4)
                if mode != 'tail' and reserve and spool._db.execute(
                        'SELECT count(*) FROM pending').fetchone()[0] >= spool.max_pending - reserve:
                    return result
                parts, warnings = _parts(raw, limits)
                parsed = record(raw=raw, identity=identity, session=raw['session_id'],
                                native_id=str(raw['id']), seq=seq, ts=raw['timestamp'],
                                native_role=raw['role'], text=raw['content'] or '', limits=limits,
                                native_source=raw['native_source'], parts=parts, warnings=warnings,
                                tool_result=(raw['tool_call_id'], raw['tool_name'])
                                if raw['role'] == 'tool' else None)
                parsed = enrich_record(Path(path).parent, parsed)
                prepared = spool._prepare(parsed) if mode != 'attachment' or (
                    parsed.attachments or any(p.name and p.name.startswith('attachment_')
                                              for p in parsed.message.parts)) else None
                with spool._transaction():
                    batch = spool._add_prepared(prepared) if prepared is not None else None
                    table = ('hermes_fresh' if mode == 'tail' else
                             'hermes_attachment_backfill' if mode == 'attachment' else 'hermes_position')
                    column = 'position' if mode == 'attachment' else mode
                    spool._db.execute(f'UPDATE {table} SET {column}=? WHERE id=1', (raw['id'],))
                visited += 1
                result['parsed'] += 1
                result['queued' if batch else 'unchanged'] += 1
        finally:
            selected.close()
        if mode == 'tail':
            tail_complete = visited < count
        elif mode == 'high':
            result['complete'] = visited < count and tail_complete
            if visited < count:
                with spool._transaction():
                    spool._db.execute('UPDATE hermes_position SET high=? WHERE id=1', (fence,))
        elif mode == 'attachment':
            result['complete'] = result['complete'] and visited < count
            if visited < count:
                with spool._transaction():
                    spool._db.execute('UPDATE hermes_attachment_backfill SET position=through_id WHERE id=1')
        elif visited < count:
            with spool._transaction():
                spool._db.execute('UPDATE hermes_position SET sweep=0 WHERE id=1')
    return result
